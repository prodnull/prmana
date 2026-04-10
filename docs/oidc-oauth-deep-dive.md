# OAuth 2.0 and OIDC: A Deep Dive Through unix-oidc

*From first principles to hardware-bound token delegation — how modern identity works, why it works that way, and how unix-oidc implements every layer.*

---

## Reader's Guide

This document serves three audiences simultaneously:

| Audience | Start here | Key sections |
|----------|------------|-------------|
| **New to OAuth/OIDC** | Section 1 (The Problem) | Sections 1-5 build the mental model |
| **OAuth practitioner, new to unix-oidc** | Section 6 (Architecture) | Sections 6-12 map concepts to code |
| **Security auditor** | Section 13 (Security Analysis) | Sections 13-16 cover threat model and invariants |

Every concept introduced in the theory sections is immediately grounded with a code reference showing where unix-oidc implements it. References use the format `file.rs:line` — follow them to see the actual implementation.

---

## Table of Contents

1. [The Problem: Why Identity on Unix Is Broken](#1-the-problem)
2. [OAuth 2.0: Delegated Authorization](#2-oauth-20)
3. [OpenID Connect: The Identity Layer](#3-openid-connect)
4. [JWTs: The Currency of Trust](#4-jwts)
5. [JWKS: Distributing Trust at Scale](#5-jwks)
6. [unix-oidc Architecture](#6-architecture)
7. [DPoP: Proof of Possession](#7-dpop)
8. [The Authentication Flows](#8-flows)
9. [Token Exchange: Multi-Hop Delegation](#9-token-exchange)
10. [Step-Up Authentication: CIBA](#10-ciba)
11. [Hardware-Bound Identity](#11-hardware)
12. [Workload Identity: SPIFFE and SPIRE](#12-spiffe)
13. [Security Deep Dive](#13-security)
14. [User Lifecycle: SCIM Provisioning](#14-scim)
15. [Observability and Audit](#15-audit)
16. [The Full Authentication Flow, Step by Step](#16-full-flow)

---

## 1. The Problem: Why Identity on Unix Is Broken {#1-the-problem}

SSH authentication on Unix systems has a fundamental problem: it was designed in an era when servers were pets, not cattle. The traditional model works like this:

1. A sysadmin generates an SSH key pair on their laptop
2. They copy the public key to `~/.ssh/authorized_keys` on each server
3. They authenticate by proving possession of the private key

This model has three critical failures in a modern enterprise:

**Keys are forever.** That SSH key generated in 2019? It still works on every server it was copied to. There's no expiration, no rotation, no revocation protocol built into SSH key authentication. When an employee leaves, finding and removing all their keys is digital archaeology — scattered `authorized_keys` files across hundreds of servers.

**MFA stops at the browser.** Enterprises require multi-factor authentication for email and Slack, but the same developer can SSH to production servers with nothing but a private key file. The security boundary is inconsistent.

**Compliance is painful.** "Who accessed what, when, and how did they authenticate?" Answering this requires parsing logs from dozens of sources, correlating SSH sessions with identity, and hoping the timestamps align.

### What We Actually Want

The identity infrastructure that enterprises already have — Okta, Azure AD (Entra ID), Google Workspace, Keycloak — already solves these problems for web applications. Single sign-on, MFA, session management, audit logs, automatic deprovisioning. The gap is bringing that same infrastructure to Unix PAM authentication.

That's what unix-oidc does: it bridges OIDC (the same protocol behind "Sign in with Google") to Linux PAM, with DPoP token binding to prevent token theft.

---

## 2. OAuth 2.0: Delegated Authorization {#2-oauth-20}

### The Core Insight

OAuth 2.0 (RFC 6749) solves a specific problem: *how can a user grant a third-party application limited access to their resources without sharing their password?*

The classic example: you want a photo printing service to access your Google Photos. You don't give the printing service your Google password. Instead:

1. The printing service redirects you to Google
2. You log in to Google directly (the printing service never sees your password)
3. Google asks: "This app wants to see your photos. Allow?"
4. You click "Allow"
5. Google gives the printing service a **token** — a time-limited key that grants access to photos only
6. The printing service uses that token to fetch your photos

The key participants in this exchange have formal names:

| Role | In the example | In unix-oidc |
|------|---------------|-------------|
| **Resource Owner** | You (the person with photos) | The Unix user |
| **Client** | The photo printing service | `unix-oidc-agent` daemon |
| **Authorization Server (AS)** | Google's login page | Keycloak, Okta, Entra ID |
| **Resource Server** | Google Photos API | The Linux server (via PAM) |

### Tokens, Not Passwords

The fundamental shift in OAuth is from *credentials* to *tokens*:

- A **credential** (password, SSH key) is permanent, powerful, and dangerous if stolen
- A **token** is temporary, scoped, and revocable

OAuth defines two types of tokens:

**Access Token**: A short-lived credential (minutes to hours) that grants access to specific resources. It's like a hotel key card — it opens specific doors for a limited time.

**Refresh Token**: A longer-lived credential (hours to days) used to obtain new access tokens without re-authenticating the user. It's like the hotel front desk — you go there when your key card expires.

### The Token Endpoint

The Authorization Server exposes a **token endpoint** — a single HTTP endpoint where clients exchange various "grants" for tokens. Every OAuth flow ultimately ends with a POST to the token endpoint:

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=<which_flow>&...parameters...
```

The `grant_type` parameter tells the AS which flow is being used. unix-oidc supports four:

| Grant Type | RFC | Purpose | unix-oidc usage |
|------------|-----|---------|-----------------|
| `urn:ietf:params:oauth:grant-type:device_code` | RFC 8628 | Headless/CLI device login | Primary login flow |
| `authorization_code` | RFC 6749 | Browser-based login with redirect | Alternative login flow |
| `urn:openid:params:grant-type:ciba` | CIBA Core | Backend-initiated MFA push | Sudo step-up |
| `urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 | Swap one token for another | Multi-hop SSH |

Each of these flows is covered in detail in [Section 8](#8-flows).

### OIDC Discovery: How Clients Find Endpoints

Before any OAuth flow can begin, the client needs to know where the AS endpoints are. OAuth itself doesn't define a discovery mechanism, but OIDC does.

Every OIDC-compliant AS publishes a JSON document at a well-known URL:

```
https://idp.example.com/.well-known/openid-configuration
```

This document lists every endpoint the AS supports:

```json
{
  "issuer": "https://idp.example.com",
  "authorization_endpoint": "https://idp.example.com/auth",
  "token_endpoint": "https://idp.example.com/token",
  "jwks_uri": "https://idp.example.com/certs",
  "device_authorization_endpoint": "https://idp.example.com/device",
  "backchannel_authentication_endpoint": "https://idp.example.com/ciba",
  "revocation_endpoint": "https://idp.example.com/revoke",
  "introspection_endpoint": "https://idp.example.com/introspect",
  "code_challenge_methods_supported": ["S256"]
}
```

**In unix-oidc:** The `OidcDiscovery` struct in `pam-unix-oidc/src/oidc/jwks.rs` models this document. The agent fetches it at the start of every flow — login, token exchange, CIBA step-up — to discover the correct endpoints for the configured issuer. This means unix-oidc works with *any* compliant OIDC provider without hardcoding provider-specific URLs.

---

## 3. OpenID Connect: The Identity Layer {#3-openid-connect}

### OAuth Is Not Authentication

A common misconception: OAuth 2.0 is an *authorization* framework, not an *authentication* protocol. It answers "what is this token allowed to do?" but not "who is the person behind this token?"

This distinction matters. An OAuth access token might say "this token can read photos" but it doesn't inherently tell you "this token belongs to alice@example.com."

### OIDC Adds Identity

OpenID Connect (OIDC) is a thin identity layer built on top of OAuth 2.0. It adds:

1. **The `openid` scope**: When a client requests the `openid` scope, the AS returns an ID token alongside the access token
2. **The ID Token**: A JWT containing claims about *who the user is*
3. **The UserInfo endpoint**: An API to fetch additional user profile information
4. **Standard claims**: A defined set of claims like `sub`, `email`, `preferred_username`, `name`

### Claims: The Language of Identity

A **claim** is a name-value pair that asserts something about the user. OIDC defines standard claims:

**Identity claims** -- who the user is:

| Claim | What it asserts | Our usage |
|-------|----------------|-----------|
| `sub` | Unique user ID per issuer | Identity anchor |
| `preferred_username` | Human-readable name | Maps to Unix login |
| `email` | Email address | Fallback identity |

**Security claims** -- how trust is established:

| Claim | What it asserts | Our usage |
|-------|----------------|-----------|
| `iss` | Who issued this token | Must match configured issuer |
| `aud` | Who this token is for | Must match our `client_id` |
| `exp` | When the token expires | Reject if expired |
| `iat` | When the token was issued | Freshness check |
| `jti` | Unique token identifier | Replay prevention |

**Authentication context** -- how the user proved their identity:

| Claim | What it asserts | Our usage |
|-------|----------------|-----------|
| `acr` | Authentication strength | MFA enforcement |
| `amr` | Methods used (pwd, otp, etc.) | Audit trail |

**Proof-of-possession** -- binding tokens to keys:

| Claim | What it asserts | Our usage |
|-------|----------------|-----------|
| `cnf` | Token is bound to a key (`jkt` thumbprint) | DPoP verification |
| `act` | Delegation chain (who exchanged this token) | Multi-hop SSH |

**In unix-oidc:** The `TokenClaims` struct in `pam-unix-oidc/src/oidc/token.rs` models every claim listed above. Each field maps directly to an OIDC standard claim. The `extra` field (a `HashMap<String, Value>`) captures any non-standard claims that IdPs might include — used by the username mapping pipeline when operators configure custom claim sources.

### The Username Problem

OIDC tokens carry identity, but Unix systems need a *username* — a string like `"alice"` that maps to a local account with a UID, home directory, and group memberships.

The mapping from OIDC claims to Unix usernames is not straightforward:

- Keycloak puts the username in `preferred_username`
- Azure AD puts it in `upn` (User Principal Name), which looks like `alice@corp.onmicrosoft.com`
- Google puts it in `email`
- Some IdPs use custom claims

unix-oidc solves this with a configurable **username mapping pipeline**:

```yaml
# policy.yaml
issuers:
  - issuer_url: "https://login.microsoftonline.com/tenant/v2.0"
    identity:
      username_claim: email          # Extract from this claim
      transforms:
        - strip_domain               # alice@corp.com → alice
        - lowercase                  # Alice → alice
```

**In unix-oidc:** `pam-unix-oidc/src/identity/mapper.rs` implements `UsernameMapper` with a pipeline of transforms. `pam-unix-oidc/src/policy/config.rs` defines `IdentityConfig` with `username_claim` and `transforms`. The pipeline is checked for *injectivity* — if two different OIDC identities could map to the same Unix username, authentication is rejected (`check_collision_safety()` in `pam-unix-oidc/src/identity/collision.rs`).

---

## 4. JWTs: The Currency of Trust {#4-jwts}

### Anatomy of a JWT

A JSON Web Token (RFC 7519) is a compact, URL-safe way to represent claims. It looks like this:

```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vaWRwLmV4YW1wbGUuY29tIn0.MEUCIQDa...signature...
```

Three parts separated by dots:

**1. Header** (base64url-encoded JSON):
```json
{
  "alg": "ES256",        // Signing algorithm
  "typ": "JWT",          // Token type
  "kid": "key-2024-01"   // Key ID (which key signed this)
}
```

**2. Payload** (base64url-encoded JSON):
```json
{
  "sub": "alice",
  "iss": "https://idp.example.com",
  "aud": "unix-oidc",
  "exp": 1712678400,
  "iat": 1712674800,
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

**3. Signature** (base64url-encoded bytes):
```
ECDSA-SHA256(base64url(header) + "." + base64url(payload))
```

The signature is computed over the first two parts joined by a dot. Anyone with the signer's public key can verify that the token hasn't been tampered with and was created by the expected issuer.

### Why Base64url?

JWTs use base64url encoding (RFC 4648 §5), not standard base64. The difference: `+` becomes `-`, `/` becomes `_`, and padding `=` is omitted. This makes JWTs safe to include in URLs, HTTP headers, and form parameters without escaping.

**In unix-oidc:** `TokenClaims::from_token()` in `pam-unix-oidc/src/oidc/token.rs` manually decodes the base64url payload for cases where we need to read claims without full signature verification (e.g., extracting the `iss` claim for routing before we know which JWKS to use). The `base64::engine::general_purpose::URL_SAFE_NO_PAD` engine is used consistently throughout the codebase.

### Signing Algorithms: The First Line of Defense

The `alg` header field declares which cryptographic algorithm was used to sign the token. unix-oidc accepts only asymmetric algorithms:

| Algorithm | Type | Curve/Key | Security Level |
|-----------|------|-----------|----------------|
| ES256 | ECDSA | P-256 | 128-bit |
| ES384 | ECDSA | P-384 | 192-bit |
| RS256 | RSA PKCS#1 v1.5 | 2048+ bit | 112-bit |
| RS384, RS512 | RSA PKCS#1 v1.5 | 2048+ bit | 112-bit+ |
| PS256, PS384, PS512 | RSA-PSS | 2048+ bit | 112-bit+ |
| EdDSA | Edwards curve | Ed25519/Ed448 | 128-bit+ |

**What unix-oidc explicitly rejects:**

- **`alg: "none"`** — The "none" algorithm means "no signature." Accepting it means anyone can forge any token by omitting the signature. This is not a theoretical attack — CVE-2015-9235 and similar vulnerabilities in JWT libraries accepted `alg: none` and allowed full authentication bypass.

- **HMAC algorithms (HS256, HS384, HS512)** — These are *symmetric* algorithms that use the same key for signing and verification. In a public-key context (where the signing key is private and the verification key is public), accepting HMAC enables the **algorithm confusion attack**: an attacker takes the server's public RSA key (which is, by definition, public), uses it as an HMAC secret to sign a forged token with `alg: HS256`, and the server verifies it successfully because it uses the same "key" for HMAC verification. This is CVE-2016-5431.

**In unix-oidc:** `DEFAULT_ALLOWED_ALGORITHMS` in `pam-unix-oidc/src/oidc/validation.rs` defines the allowlist — only the asymmetric algorithms above. `key_algorithm_to_algorithm()` performs an exhaustive match on the `KeyAlgorithm` enum, explicitly rejecting HS* and encryption-only algorithms. The SCIM service has its own algorithm check in `unix-oidc-scim/src/auth.rs` that enforces the same policy at the middleware level.

---

## 5. JWKS: Distributing Trust at Scale {#5-jwks}

### The Key Distribution Problem

When a server receives a JWT, it needs the signer's public key to verify the signature. But how does it get that key?

You could hardcode public keys, but then key rotation becomes a coordinated deployment event across every server. OIDC solves this with the **JSON Web Key Set (JWKS)** — a standard JSON format for publishing public keys at a URL.

### How JWKS Works

The OIDC discovery document includes a `jwks_uri` field pointing to the key set:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "key-2024-01",
      "alg": "ES256",
      "use": "sig",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    },
    {
      "kty": "RSA",
      "kid": "key-2024-02",
      "alg": "RS256",
      "n": "sXchmO7QYj0V8vY4...",
      "e": "AQAB"
    }
  ]
}
```

Each key has a `kid` (Key ID) that matches the `kid` in JWT headers. The server:

1. Decodes the JWT header to read `kid` and `alg`
2. Fetches the JWKS from the issuer's `jwks_uri`
3. Finds the key with the matching `kid`
4. Verifies the JWT signature using that key

### Key Rotation

IdPs periodically rotate their signing keys. The standard practice:

1. IdP generates a new key pair and adds the public key to the JWKS
2. IdP starts signing new tokens with the new key
3. Old tokens (signed with the old key) remain valid until they expire
4. After all old tokens have expired, the old key is removed from the JWKS

This is why servers must *cache* the JWKS but also *refresh* it periodically — to pick up new keys.

### JWKS Caching in unix-oidc

The PAM module implements a sophisticated caching strategy:

**`JwksProvider`** (`pam-unix-oidc/src/oidc/jwks.rs`) caches JWKS with a configurable TTL (default 300 seconds). Each issuer gets its own isolated cache via `IssuerJwksRegistry`. The TTL is configurable per-issuer in `policy.yaml`:

```yaml
issuers:
  - issuer_url: "https://idp.example.com"
    jwks_cache_ttl_secs: 600    # 10 minutes
    http_timeout_secs: 5         # JWKS fetch timeout
```

The SCIM service uses a different cache implementation (`JwksCache` in `unix-oidc-scim/src/auth.rs`) with TTL-based refresh and **kid-miss forced refresh** — if a JWT presents a `kid` not in the cached JWKS, the cache is immediately refreshed before rejecting. This handles key rotation mid-TTL.

### JWK Thumbprints: Key Identity

RFC 7638 defines a standard way to compute a unique fingerprint of a JWK — the **JWK Thumbprint**. This is critical for DPoP (Section 7).

The algorithm:
1. Extract the required members of the JWK in lexicographic order
2. Serialize as canonical JSON (no whitespace, sorted keys)
3. SHA-256 hash the result
4. Base64url-encode the hash

For an EC key on P-256:
```json
{"crv":"P-256","kty":"EC","x":"<base64url>","y":"<base64url>"}
```

**In unix-oidc:** `pam-unix-oidc/src/oidc/dpop.rs` computes thumbprints with hardcoded canonical field names — never from user-supplied `kty`/`crv` values. An attacker who could control the `kty` field could change the thumbprint (e.g., supplying `"kty":"oct"` to produce a different hash). The thumbprint computation in the agent (`unix-oidc-agent/src/crypto/tpm_signer.rs`) uses the same hardcoded approach.

---

## 6. unix-oidc Architecture {#6-architecture}

### The Two-Component Model

unix-oidc separates concerns into two binaries that communicate via IPC:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              User's Machine                                  │
│                                                                              │
│   ┌─────────────────┐     Unix Socket IPC     ┌──────────────────────────┐ │
│   │  SSH Client      │ ────────────────────── │  unix-oidc-agent          │ │
│   │  (via SSH_ASKPASS)│                        │  (long-lived daemon)      │ │
│   └─────────────────┘                          │                          │ │
│                                                 │  - Manages DPoP keys     │ │
│                                                 │  - Holds access tokens   │ │
│                                                 │  - Signs DPoP proofs     │ │
│                                                 │  - Handles token refresh │ │
│                                                 └──────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ SSH connection (token + DPoP proof)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Linux Server                                    │
│                                                                              │
│   ┌─────────────────┐     PAM stack     ┌──────────────────────────────────┐ │
│   │  sshd            │ ─────────────── │  pam_unix_oidc.so                 │ │
│   │                  │                  │  (shared library, loaded by sshd) │ │
│   └─────────────────┘                   │                                  │ │
│                                          │  - Validates JWT signatures     │ │
│                                          │  - Verifies DPoP binding        │ │
│                                          │  - Checks issuer, audience, exp │ │
│                                          │  - Maps OIDC identity to Unix   │ │
│                                          │  - Enforces delegation policy   │ │
│                                          │  - Verifies TPM attestation     │ │
│                                          └──────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Why two components?**

The PAM module runs inside `sshd` — a privileged process that handles network connections. It must be stateless, crash-safe (a panic locks users out), and fast. It cannot hold long-lived secrets or maintain network connections.

The agent daemon runs in userspace. It maintains the DPoP signing key, manages token lifecycle (refresh, revocation), and handles interactive flows (device flow login, CIBA step-up). It communicates with the PAM module via JSON-over-Unix-socket IPC.

**IPC Protocol** (`unix-oidc-agent/src/daemon/protocol.rs`):

```json
// Request: PAM → Agent
{"action": "get_proof", "target": "server.example.com", "method": "SSH"}

// Response: Agent → PAM
{"status": "success", "token": "eyJ...", "dpop_proof": "eyJ...", "expires_in": 3600}
```

---

## 7. DPoP: Proof of Possession {#7-dpop}

### The Bearer Token Problem

Standard OAuth access tokens are **bearer tokens** — anyone who possesses the token can use it. If an attacker intercepts a bearer token (via network sniffing, log exposure, or memory dump), they can impersonate the user.

This is analogous to cash: whoever holds the $20 bill can spend it. There's no "I need to prove I'm the original recipient."

### DPoP: Binding Tokens to Keys

DPoP (Demonstrating Proof of Possession, RFC 9449) solves this by cryptographically binding each token to a specific key pair. The token is useless without the corresponding private key.

The mechanism:

1. The client generates an ephemeral key pair (the "DPoP key")
2. When requesting a token, the client includes a **DPoP proof** — a JWT signed with the DPoP private key
3. The Authorization Server binds the issued token to the DPoP key's thumbprint via the `cnf` (confirmation) claim:
   ```json
   {
     "sub": "alice",
     "cnf": {
       "jkt": "SHA-256-thumbprint-of-DPoP-public-key"
     }
   }
   ```
4. On every subsequent request, the client must include a fresh DPoP proof signed by the same key
5. The server verifies: (a) the DPoP proof is valid, and (b) the proof's key thumbprint matches the token's `cnf.jkt`

An attacker who steals the token but not the private key cannot produce valid DPoP proofs. The token is effectively locked to the client that generated the key pair.

### Anatomy of a DPoP Proof

A DPoP proof is a JWT with a specific structure:

**Header:**
```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  }
}
```

The header embeds the full public key (not just a `kid` reference). This allows the server to compute the thumbprint and match it against `cnf.jkt`.

**Payload:**
```json
{
  "jti": "unique-id-per-proof",
  "htm": "POST",
  "htu": "https://server.example.com/resource",
  "iat": 1712674800
}
```

| Claim | Purpose |
|-------|---------|
| `jti` | Unique identifier — prevents replay (each proof used exactly once) |
| `htm` | HTTP method this proof is bound to |
| `htu` | HTTP URI this proof is bound to |
| `iat` | Issued at — proof must be fresh (within clock skew tolerance) |

**In unix-oidc:**

The agent builds DPoP proofs in `unix-oidc-agent/src/crypto/dpop.rs`:
- `build_dpop_message()` constructs the header and payload
- `assemble_dpop_proof()` combines the message with the signature
- The `DPoPSigner` trait (`unix-oidc-agent/src/crypto/signer.rs`) abstracts over different signing backends: `SoftwareSigner` (in-memory P-256 key), `TpmSigner` (TPM 2.0 hardware key), `SpireSigner` (SPIRE JWT-SVID), and `YubiKeySigner` (PIV smart card)

The PAM module verifies DPoP proofs in `pam-unix-oidc/src/oidc/dpop.rs`:
- `validate_dpop_proof()` checks the `typ`, extracts the JWK, verifies the ECDSA signature, computes the thumbprint, and checks `htm`/`htu` binding
- Replay protection uses both an in-memory `JtiCache` and a persistent `FsAtomicStore` for cross-fork protection (since sshd forks per connection)

### Why "Ephemeral" Keys?

The DPoP specification recommends ephemeral key pairs — generated fresh for each session. This limits the blast radius: if a key is somehow compromised, only the current session is affected.

In unix-oidc, the DPoP key is generated at `login` time and stored in the secure credential store (keyring or encrypted file). It persists across SSH connections within a session but is destroyed on `logout` or `reset`.

The key is protected in memory by:
- `ZeroizeOnDrop` (via the `p256` crate) — key material is overwritten with zeros when dropped
- `mlock(2)` — prevents the OS from swapping key pages to disk
- Core dump disabled via `prctl(PR_SET_DUMPABLE, 0)` (Linux) or `ptrace(PT_DENY_ATTACH)` (macOS)

See `unix-oidc-agent/src/crypto/protected_key.rs` for the full memory protection implementation.

---

## 8. The Authentication Flows {#8-flows}

unix-oidc supports four OAuth grant types, each designed for a different scenario.

### 8.1 Device Authorization Grant (RFC 8628)

**When to use:** CLI/terminal login where no browser is available on the device. This is the default and most common flow.

**The problem it solves:** An SSH agent running in a terminal can't display a web page for the user to log in. The Device Authorization Grant separates the "login on a browser-capable device" step from the "receive the token on the headless device" step.

**Flow:**

```
User's Terminal                    IdP (Keycloak/Okta)              User's Phone/Browser
     │                                    │                                  │
     │ POST /device_authorization         │                                  │
     │ (client_id, scope=openid)          │                                  │
     │───────────────────────────────────>│                                  │
     │                                    │                                  │
     │ {device_code, user_code,           │                                  │
     │  verification_uri}                 │                                  │
     │<───────────────────────────────────│                                  │
     │                                    │                                  │
     │ Display: "Go to https://idp/device │                                  │
     │          Enter code: ABCD-1234"    │                                  │
     │                                    │                                  │
     │                                    │    User opens verification_uri   │
     │                                    │<─────────────────────────────────│
     │                                    │    User enters code ABCD-1234    │
     │                                    │<─────────────────────────────────│
     │                                    │    User authenticates (MFA)      │
     │                                    │<─────────────────────────────────│
     │                                    │    "Authorized!"                 │
     │                                    │─────────────────────────────────>│
     │                                    │                                  │
     │ POST /token                        │                                  │
     │ (device_code, DPoP proof)          │                                  │
     │───────────────────────────────────>│                                  │
     │                                    │                                  │
     │ {access_token, refresh_token}      │                                  │
     │ (DPoP-bound via cnf.jkt)           │                                  │
     │<───────────────────────────────────│                                  │
```

The agent polls the token endpoint every few seconds until the user completes authentication. The polling response is either `"authorization_pending"` (keep waiting) or the actual tokens.

**In unix-oidc:** `run_login()` in `unix-oidc-agent/src/main.rs` implements the full flow: OIDC discovery → device authorization request → user code display → token endpoint polling with DPoP proof → token storage. The polling interval respects the `interval` field from the device authorization response and handles `slow_down` responses by adding 5 seconds (per RFC 8628 §3.5).

### 8.2 Authorization Code + PKCE (RFC 6749 + RFC 7636)

**When to use:** Login from a machine that has a browser available. Required by some IdPs (notably Auth0 with DPoP) that don't support the Device Authorization Grant.

**The problem PKCE solves:** The original Authorization Code flow has a vulnerability: an attacker who intercepts the authorization code during the redirect can exchange it for tokens. PKCE (Proof Key for Code Exchange) prevents this.

**PKCE mechanism:**

1. Client generates a random `code_verifier` (43-128 characters)
2. Client computes `code_challenge = BASE64URL(SHA256(code_verifier))`
3. Client sends `code_challenge` in the authorization request (public)
4. IdP stores the challenge
5. Client sends `code_verifier` in the token exchange (after receiving the code)
6. IdP verifies: `SHA256(code_verifier) == stored_code_challenge`

An interceptor who sees the `code_challenge` cannot derive the `code_verifier` (SHA-256 is one-way). So even if they steal the authorization code, they can't exchange it without the verifier.

**In unix-oidc:** `unix-oidc-agent/src/auth_code.rs` implements:
- `generate_pkce()` — generates verifier and S256 challenge
- `start_callback_listener()` — ephemeral localhost HTTP server on a random port to receive the redirect
- `exchange_code()` — POST to token endpoint with `code_verifier` and DPoP proof
- State parameter (UUID) for CSRF protection

### 8.3 CIBA: Client-Initiated Backchannel Authentication

**When to use:** Step-up authentication for privileged operations (sudo). The server needs to verify the user is still present without interrupting their terminal session.

**How it works:** Instead of redirecting the user to a browser, CIBA sends an authentication request *to the user's registered device* (phone push notification, for example). The user approves on their phone, and the server receives confirmation.

```
PAM (sudo)              Agent Daemon              IdP                User's Phone
    │                        │                      │                      │
    │ StepUp{user,command}   │                      │                      │
    │───────────────────────>│                      │                      │
    │                        │                      │                      │
    │                        │ POST /ciba           │                      │
    │                        │ (login_hint, scope,  │                      │
    │                        │  binding_message,    │                      │
    │                        │  acr_values)         │                      │
    │                        │─────────────────────>│                      │
    │                        │                      │                      │
    │                        │ {auth_req_id}        │   Push notification  │
    │                        │<─────────────────────│─────────────────────>│
    │                        │                      │                      │
    │ StepUpPending          │                      │   User approves      │
    │<───────────────────────│                      │<─────────────────────│
    │                        │                      │                      │
    │                        │ POST /token          │                      │
    │                        │ (auth_req_id, DPoP)  │                      │
    │                        │─────────────────────>│                      │
    │                        │                      │                      │
    │                        │ {id_token with acr}  │                      │
    │                        │<─────────────────────│                      │
    │                        │                      │                      │
    │ StepUpComplete{acr}    │                      │                      │
    │<───────────────────────│                      │                      │
```

The `binding_message` is critical for security — it's a human-readable string displayed on the user's phone (e.g., "Approve sudo on server-01: apt install nginx"). The user verifies they initiated this specific action, preventing an attacker from piggybacking on an existing CIBA session.

**In unix-oidc:** The CIBA flow spans three modules:
- `pam-unix-oidc/src/ciba/client.rs` — builds the backchannel auth request parameters
- `unix-oidc-agent/src/daemon/socket.rs` — `handle_step_up()` initiates the flow, `poll_ciba()` runs the async poll loop with DPoP proofs on each poll
- `pam-unix-oidc/src/sudo.rs` — the PAM entry point that triggers step-up via agent IPC

ACR enforcement is **hard-fail**: if the policy requires `urn:mfa` and the IdP returns a token without it, the step-up is rejected regardless of enforcement mode settings. This is a security invariant documented in CLAUDE.md.

### 8.4 Token Exchange (RFC 8693)

**When to use:** Multi-hop SSH — a user SSHs to a jump host, and the jump host needs to SSH onward to a target server on the user's behalf.

**The problem:** The jump host has the user's access token (from the first SSH connection), but that token is DPoP-bound to the *user's* key. The jump host can't produce valid DPoP proofs because it doesn't have the user's private key.

**The solution:** The jump host *exchanges* the user's token for a new token bound to the jump host's own DPoP key. The IdP records the delegation chain in the `act` (actor) claim.

```
User                    Jump Host A              IdP                    Target Host B
  │                          │                     │                          │
  │ SSH (token + DPoP)       │                     │                          │
  │─────────────────────────>│                     │                          │
  │                          │                     │                          │
  │                          │ POST /token         │                          │
  │                          │ grant_type=          │                          │
  │                          │  token-exchange      │                          │
  │                          │ subject_token=       │                          │
  │                          │  user's token        │                          │
  │                          │ DPoP: jump's proof   │                          │
  │                          │─────────────────────>│                          │
  │                          │                     │                          │
  │                          │ {new_token with:     │                          │
  │                          │  sub: alice          │                          │
  │                          │  cnf.jkt: jump's key │                          │
  │                          │  act: {sub: jump-a}} │                          │
  │                          │<─────────────────────│                          │
  │                          │                     │                          │
  │                          │ SSH (new token + DPoP)                          │
  │                          │────────────────────────────────────────────────>│
  │                          │                     │                          │
  │                          │                     │  Validates: sig, iss,    │
  │                          │                     │  aud, DPoP binding,      │
  │                          │                     │  act.sub in allowlist,   │
  │                          │                     │  delegation depth ≤ max  │
```

The `act` claim supports recursive nesting for multi-hop chains:

```json
{
  "sub": "alice@example.com",
  "act": {
    "sub": "jump-host-b",
    "act": {
      "sub": "jump-host-a"
    }
  }
}
```

**In unix-oidc:**
- `pam-unix-oidc/src/oidc/token.rs` — `ActClaim` struct with recursive `Box<ActClaim>`, `delegation_depth()` method
- `pam-unix-oidc/src/policy/config.rs` — `DelegationConfig` with `allowed_exchangers`, `max_depth`, `exchanged_token_max_lifetime_secs`
- `pam-unix-oidc/src/oidc/validation.rs` — `validate_delegation()` checks exchanger allowlist and depth
- `unix-oidc-agent/src/exchange.rs` — RFC 8693 HTTP client
- `unix-oidc-agent/src/daemon/socket.rs` — daemon handler with OIDC discovery for token endpoint
- `pam-unix-oidc/src/auth.rs` — delegation validation wired into the PAM auth path (fail closed: tokens with `act` are rejected unless delegation is explicitly configured)

---

## 9. Hardware-Bound Identity {#11-hardware}

### Why Software Keys Aren't Enough

A software DPoP key lives in memory or on disk. A sufficiently privileged attacker (root access, memory forensics, disk image) can extract it. Once extracted, the attacker can produce valid DPoP proofs and use the stolen token.

For high-security environments, the private key must be **non-exportable** — generated inside a hardware security module and never exposed to software.

### TPM 2.0 Integration

unix-oidc supports TPM 2.0 (Trusted Platform Module) as a DPoP signing backend. The TPM is a dedicated security chip present on most modern servers and laptops.

Key properties:
- The private key is generated *inside* the TPM (`sensitiveDataOrigin` attribute)
- It cannot be exported (`fixedTPM` + `fixedParent` attributes)
- It cannot be moved to another TPM
- All signing operations happen inside the TPM — the software only sends data to be signed and receives the signature

**In unix-oidc:** `TpmSigner` in `unix-oidc-agent/src/crypto/tpm_signer.rs` implements the `DPoPSigner` trait using `tss-esapi`. Each `sign_proof()` call opens a fresh TPM context, signs, and closes it (open-sign-close pattern).

### TPM Attestation: Proving Hardware Binding

Having a TPM key is one thing. *Proving to a remote server* that the key is TPM-resident is another. Without attestation, a client could claim to use a TPM but actually use a software key.

TPM2_CC_Certify solves this: the TPM signs a statement ("certification") asserting that a specific key was created by and resides in this TPM. The certification contains the key's **Name** — a SHA-256 hash of its public area — which the verifier matches against the DPoP proof's JWK.

**In unix-oidc:**
- Agent side: `TpmSigner::certify()` produces `AttestationEvidence` (certify_info + AK signature + AK public key)
- Transport: Evidence is embedded in the DPoP proof JWT header as an `attest` field
- PAM side: `pam-unix-oidc/src/oidc/attestation.rs` performs:
  1. AK ECDSA signature verification over certify_info
  2. TPMS_ATTEST parsing to extract the certified key Name
  3. Name matching against the DPoP JWK's reconstructed TPMT_PUBLIC
- Configuration: `AttestationConfig` on `IssuerConfig` with `strict`/`warn`/`disabled` enforcement

---

## 10. Workload Identity: SPIFFE and SPIRE {#12-spiffe}

### The Machine Identity Problem

Humans authenticate with usernames and passwords. But what about machines — containers, microservices, AI agents running in GPU clusters?

SPIFFE (Secure Production Identity Framework for Everyone) provides a standard for identifying workloads. Each workload gets a **SPIFFE ID** — a URI like `spiffe://trust-domain/ns/production/sa/ml-agent`.

SPIRE (the SPIFFE Runtime Environment) is the reference implementation that issues **JWT-SVIDs** (SPIFFE Verifiable Identity Documents) — JWTs that carry the SPIFFE ID as the `sub` claim.

**In unix-oidc:** The `SpireSigner` (`unix-oidc-agent/src/crypto/spire_signer.rs`) fetches JWT-SVIDs from the local SPIRE agent via gRPC Workload API, then uses ephemeral P-256 DPoP keys for the actual SSH authentication. The SPIFFE ID is mapped to a Unix username via `SpiffeUsernameMapper` (`pam-unix-oidc/src/identity/mapper.rs`).

---

## 11. Security Deep Dive {#13-security}

### Real-World Attacks That Validate This Architecture

The defenses in unix-oidc are not theoretical. Each was motivated by attacks that have occurred in production systems. Here are verified CVEs that demonstrate why each defense layer exists.

#### Bearer token theft → DPoP proof-of-possession

**CVE-2024-3094** (xz/liblzma, March 2024) — A supply chain backdoor was embedded in the xz compression library, which is loaded by OpenSSH's sshd via systemd. The payload redirected `RSA_public_decrypt` to a malicious implementation, enabling remote authentication bypass. With traditional SSH keys, a compromised sshd grants persistent access. With DPoP-bound tokens, even a backdoored sshd can only use intercepted tokens for their remaining lifetime — and cannot produce valid DPoP proofs for new requests because the attacker lacks the client's private key.

*unix-oidc defense: DPoP binding (Section 7), short-lived tokens, per-request proof freshness.*

**CVE-2025-30066** (tj-actions/changed-files, March 2025) — A supply chain attack on a GitHub Action used by 23,000+ repositories exfiltrated CI/CD secrets — including SSH keys and access tokens — by dumping them to workflow logs. Bearer tokens leaked this way are immediately usable by anyone who reads the logs. DPoP-bound tokens are not: the attacker has the token but not the DPoP private key that the token is bound to.

*unix-oidc defense: DPoP binding makes stolen tokens useless without the corresponding key.*

#### SSH key compromise → why tokens replace keys

**CVE-2024-31497** (PuTTY, April 2024) — A bias in PuTTY's ECDSA nonce generation for the P-521 curve allowed an attacker to recover the private key from approximately 60 signatures. An attacker operating a rogue SSH server (or compromising a legitimate one) could collect enough signatures during normal logins to extract the key. With traditional SSH keys, this is permanent compromise — the stolen key works forever. With unix-oidc's token model, access is bounded by token expiration. With a TPM-backed DPoP key (Section 9), the private key cannot be extracted even with full software compromise.

*unix-oidc defense: Short-lived tokens replace permanent keys. TPM non-exportability prevents key extraction.*

#### Algorithm confusion → asymmetric-only allowlist

**CVE-2023-48223** (fast-jwt, November 2023) — The fast-jwt Node.js library allowed algorithm confusion: an attacker could sign a JWT with `alg: HS256` using the server's RSA public key as the HMAC secret. Because the public key is, by definition, public, this allowed complete token forgery and authentication bypass. The root cause: the library accepted both symmetric and asymmetric algorithms from the same verification code path.

**GHSA-f67f-6cw9-8mq4** (Hono framework, 2025) — The Hono web framework's JWK authentication middleware fell back to the JWT header's `alg` field when the matched JWK key lacked an explicit `alg`. An attacker could supply `alg: HS256` in the JWT header, causing the middleware to use HMAC verification with the RSA public key — the same class of attack as CVE-2023-48223, rediscovered in a different library.

*unix-oidc defense: `DEFAULT_ALLOWED_ALGORITHMS` in `validation.rs` is an asymmetric-only allowlist. `key_algorithm_to_algorithm()` exhaustive match explicitly rejects HS256/HS384/HS512. Algorithm pinning (SHRD-01) prevents the token's `alg` from differing from the JWKS key's advertised algorithm.*

#### Type confusion → strict claim validation

**GHSA-h395-gr6q-cpjc** (jsonwebtoken Rust, February 2026) — The jsonwebtoken crate (versions before 10.3.0) had a type confusion vulnerability: when a time-based claim like `nbf` was sent as a JSON String instead of a Number, the library marked it as "FailedToParse" and treated it identically to "NotPresent." If `validate_nbf` was enabled but `nbf` was not in `required_spec_claims`, the check was silently skipped — allowing an attacker to bypass "not before" restrictions with a token that should not yet be valid. unix-oidc upgraded to 10.3.0 within 15 minutes of the Dependabot alert.

*unix-oidc defense: Prompt dependency patching, `cargo audit` in CI, minimal dependency surface in the PAM module.*

#### What we honestly cannot prevent

Not every supply chain attack is mitigated by token binding:

- **If the PAM module itself is backdoored** (analogous to the xz attack targeting our `.so` instead of liblzma), the attacker controls the verification logic. DPoP cannot help if the verifier is compromised. Mitigation: code signing, SLSA provenance, reproducible builds.
- **Social engineering the step-up approval**: An attacker who compromises a user's session can trigger a CIBA step-up, and the user might approve a push notification they didn't initiate. Mitigation: the `binding_message` shows the specific command being approved, but user vigilance is still required.
- **IdP compromise**: If the Authorization Server itself is compromised, the attacker can issue valid tokens for any user. unix-oidc trusts the IdP's signatures — it cannot detect a legitimately-signed malicious token. Mitigation: multi-IdP redundancy (Phase 41), anomaly detection in SIEM.

### The Validation Pipeline

Every token that arrives at the PAM module passes through a rigorous validation pipeline. The order matters — cheaper checks run first:

1. **Issuer routing** — Extract `iss` from the unverified JWT payload to determine which issuer config to use
2. **JWKS fetch** — Retrieve the signing keys for this issuer (cached with TTL)
3. **Signature verification** — Cryptographic proof the token was issued by the claimed issuer
4. **Issuer validation** — Token's `iss` must match the configured issuer URL
5. **Audience validation** — Token's `aud` must include the configured `client_id` (or `expected_audience`)
6. **Expiration check** — Token's `exp` must be in the future (with clock skew tolerance)
7. **JTI replay check** — Token's `jti` must not have been seen before (cross-fork persistent store)
8. **Delegation validation** — If `act` claim present, validate exchanger allowlist + depth + lifetime
9. **DPoP binding** — If `cnf.jkt` present, verify DPoP proof signature + thumbprint match
10. **Attestation verification** — If configured, verify TPM attestation evidence in DPoP header
11. **ACR enforcement** — If `required_acr` configured, verify the `acr` claim matches
12. **Username mapping** — Extract and transform the configured claim into a Unix username
13. **User resolution** — Verify the username exists in NSS/SSSD
14. **Group policy** — Verify the user's groups intersect with `login_groups` allowlist

**In unix-oidc:** `authenticate_multi_issuer()` in `pam-unix-oidc/src/auth.rs` implements this pipeline. Each step has a corresponding error type in `AuthError` and emits OCSF audit events on failure.

### Replay Protection

JTI (JWT ID) replay protection prevents an attacker from capturing and re-using a valid token:

- Each token has a unique `jti` claim
- The PAM module records every `jti` it has seen
- If the same `jti` appears again, the token is rejected

The challenge: sshd forks a new process for each connection. An in-memory cache isn't shared across forks.

**Solution:** `FsAtomicStore` (`pam-unix-oidc/src/security/fs_store.rs`) provides cross-fork persistence via filesystem-based atomic operations. JTIs are scoped by issuer URL to prevent cross-issuer collisions.

### The Security Check Matrix

| Check | Category | Can it be disabled? |
|-------|----------|-------------------|
| Signature verification | HARD-FAIL | Never |
| Issuer validation | HARD-FAIL | Never |
| Audience validation | HARD-FAIL | Never |
| Expiration check | HARD-FAIL | Never |
| Algorithm enforcement | HARD-FAIL | Never |
| JTI replay (seen before) | HARD-FAIL | Never |
| ACR enforcement (when configured) | HARD-FAIL | Never (when required_acr is set) |
| Delegation (when act present) | HARD-FAIL | Never (fail closed without config) |
| JTI presence (missing claim) | Configurable | strict/warn/disabled |
| DPoP binding | Configurable | strict/warn/disabled per issuer |
| Attestation | Configurable | strict/warn/disabled per issuer |
| ACR presence (missing claim) | Configurable | strict/warn/disabled |

---

## 12. User Lifecycle: SCIM Provisioning {#14-scim}

### The Provisioning Gap

OIDC handles *authentication* — proving who you are. But Unix systems also need the user to *exist* — a username, UID, home directory, group memberships.

SCIM 2.0 (System for Cross-domain Identity Management, RFC 7643/7644) is the standard protocol for provisioning user accounts. When an IdP creates, modifies, or disables a user, it pushes SCIM events to the provisioning endpoint.

**In unix-oidc:** `unix-oidc-scim` is a standalone axum HTTP service that:
- Receives SCIM `/Users` CRUD operations from the IdP
- Validates requests with JWKS-verified Bearer tokens
- Translates SCIM operations to `useradd`/`usermod`/`userdel` system calls
- Enforces POSIX username rules and a 60+ entry reserved username denylist

---

## 13. The Full Authentication Flow, Step by Step {#16-full-flow}

Here is the complete flow from `ssh user@server` to shell, annotating every security check:

```
1. User runs: unix-oidc-agent login --issuer https://idp.example.com
   → Agent discovers OIDC endpoints
   → Agent generates DPoP key pair (P-256)
   → Agent initiates Device Authorization Grant
   → User authenticates in browser with MFA
   → Agent receives DPoP-bound access token
   → Token and key stored in secure credential store

2. User runs: ssh alice@server
   → SSH invokes SSH_ASKPASS (unix-oidc-agent ssh-askpass)
   → Agent generates fresh DPoP proof (bound to method=SSH, target=server)
   → If TPM signer: attestation evidence embedded in proof header
   → SSH sends token + proof to server

3. sshd receives connection
   → PAM module loaded (pam_unix_oidc.so)
   → Token extracted from keyboard-interactive prompt

4. PAM validation pipeline:
   a. Extract iss from token → route to issuer config
   b. Fetch JWKS for issuer (cached 300s)
   c. Verify JWT signature against JWKS key
   d. Verify iss matches configured issuer
   e. Verify aud contains client_id
   f. Verify exp > now - clock_skew
   g. Check jti not replayed (FsAtomicStore)
   h. If act claim: validate delegation (exchanger, depth, lifetime)
   i. Verify DPoP proof (signature, htm, htu, thumbprint = cnf.jkt)
   j. If attestation configured: verify TPM evidence
   k. If required_acr: verify acr claim
   l. Map OIDC claims → Unix username
   m. Verify user exists in NSS/SSSD
   n. Verify user groups match login_groups policy

5. Authentication succeeds
   → Session ID generated
   → OCSF audit event emitted (SSH_LOGIN_SUCCESS)
   → Shell opened

6. User runs: sudo apt install nginx
   → PAM module triggers CIBA step-up via agent
   → Agent sends push notification to user's phone
   → User approves with MFA
   → Agent receives step-up token with ACR
   → PAM verifies ACR meets sudo policy
   → sudo proceeds
```

Every step in this flow has a corresponding code path, audit event, and test. The goal is that no authentication decision is invisible — every accept and reject is logged, every check is configurable, and every bypass requires explicit operator acknowledgment.

---

## References

| Standard | Title | How unix-oidc uses it |
|----------|-------|----------------------|
| RFC 6749 | OAuth 2.0 Authorization Framework | Core token model, grant types |
| RFC 6750 | OAuth 2.0 Bearer Token Usage | Token transport (replaced by DPoP) |
| RFC 7009 | OAuth 2.0 Token Revocation | Session teardown |
| RFC 7515 | JSON Web Signature (JWS) | JWT signature structure |
| RFC 7517 | JSON Web Key (JWK) | JWKS key format |
| RFC 7518 | JSON Web Algorithms (JWA) | Algorithm identifiers |
| RFC 7519 | JSON Web Token (JWT) | Token format |
| RFC 7636 | PKCE | Auth Code flow protection |
| RFC 7638 | JSON Web Key Thumbprint | DPoP key identity |
| RFC 7643 | SCIM Core Schema | User provisioning types |
| RFC 7644 | SCIM Protocol | User provisioning endpoints |
| RFC 7662 | OAuth 2.0 Token Introspection | Token validity check |
| RFC 8414 | OAuth 2.0 Authorization Server Metadata | OIDC discovery |
| RFC 8628 | Device Authorization Grant | CLI/headless login |
| RFC 8693 | OAuth 2.0 Token Exchange | Multi-hop SSH delegation |
| RFC 9449 | DPoP | Proof-of-possession binding |
| CIBA Core 1.0 | Client-Initiated Backchannel Authentication | Sudo step-up |
| OpenID Connect Core 1.0 | OIDC | Identity claims layer |
| TCG TPM2 Part 2 | TPM Structures | Attestation evidence format |
| TCG TPM2 Part 3 | TPM Commands | TPM2_CC_Certify |
| draft-ietf-oauth-identity-chaining | Identity Chaining | Token exchange with DPoP |
| draft-ietf-oauth-attestation-based-client-auth | Client Attestation | Client authentication PoP |

---

## Appendix A: Implementation Cross-Reference

Every concept in this guide maps to specific source files. This appendix provides the exact locations.

### OIDC Discovery

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/oidc/jwks.rs:57-82` | `OidcDiscovery` struct — all endpoint URLs |
| `pam-unix-oidc/src/oidc/jwks.rs:246-270` | `fetch_discovery()` — GETs `.well-known/openid-configuration` |
| `unix-oidc-scim/src/auth.rs:25-62` | `fetch_jwks()` — async discovery + JWKS fetch for SCIM |
| `pam-unix-oidc/src/device_flow/client.rs:33-55` | `DeviceFlowClient::from_discovery()` — reads device endpoint |
| `pam-unix-oidc/src/ciba/client.rs:31-53` | `CibaClient::new()` — reads CIBA endpoint |

### JWT Structure and Claims

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/oidc/token.rs:39-95` | `TokenClaims` — all standard claims (sub, iss, aud, exp, iat, acr, amr, jti, cnf, act) |
| `pam-unix-oidc/src/oidc/token.rs:27-37` | `ActClaim` — RFC 8693 delegation chain with recursive nesting |
| `pam-unix-oidc/src/oidc/token.rs:122-127` | `ConfirmationClaim` — DPoP binding via `cnf.jkt` |
| `pam-unix-oidc/src/oidc/token.rs:211-222` | `from_token()` — base64url decode without signature verification |
| `pam-unix-oidc/src/oidc/token.rs:148-157` | `delegation_depth()` — walks recursive `act` chain |

### JWT Validation Pipeline

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/oidc/validation.rs:275-404` | `TokenValidator::validate()` — full pipeline: sig → iss → aud → exp → JTI → ACR |
| `pam-unix-oidc/src/oidc/validation.rs:407-500` | `verify_and_decode()` — JWKS key lookup, algorithm pinning, signature check |
| `pam-unix-oidc/src/oidc/validation.rs:22-32` | `DEFAULT_ALLOWED_ALGORITHMS` — asymmetric-only allowlist |
| `pam-unix-oidc/src/oidc/validation.rs:59-81` | `key_algorithm_to_algorithm()` — exhaustive KeyAlgorithm → Algorithm mapping |
| `pam-unix-oidc/src/oidc/validation.rs:430-452` | Algorithm pinning (SHRD-01) — rejects token if `alg` differs from JWKS key |

### JWKS Caching

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/oidc/jwks.rs:93-101` | `JwksProvider` — TTL-based cache with RwLock |
| `pam-unix-oidc/src/oidc/jwks.rs:316-360` | `IssuerJwksRegistry` — per-issuer isolated providers |
| `unix-oidc-scim/src/auth.rs:72-166` | `JwksCache` — async TTL cache with kid-miss forced refresh |
| `unix-oidc-scim/src/auth.rs:126-145` | `decoding_key_with_refresh()` — kid-miss triggers immediate JWKS reload |

### JWK Thumbprints (RFC 7638)

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/oidc/dpop.rs:398-413` | `compute_jwk_thumbprint()` — PAM-side, hardcoded canonical JSON |
| `unix-oidc-agent/src/crypto/thumbprint.rs:11-23` | `compute_ec_thumbprint()` — agent-side |
| `rust-oauth-dpop/src/thumbprint.rs:27-34` | `compute_thumbprint_from_coordinates()` — library implementation |

### DPoP Proof Generation (Agent Side)

| File | Key symbols |
|------|-------------|
| `unix-oidc-agent/src/crypto/dpop.rs:64-94` | `build_dpop_message()` — header + payload with embedded JWK |
| `unix-oidc-agent/src/crypto/dpop.rs:121-158` | `build_dpop_message_with_attestation()` — adds `attest` to header |
| `unix-oidc-agent/src/crypto/dpop.rs:175-181` | `assemble_dpop_proof()` — attaches 64-byte r‖s signature |
| `unix-oidc-agent/src/crypto/signer.rs` | `DPoPSigner` trait — abstracts Software/TPM/YubiKey/SPIRE backends |

### DPoP Proof Verification (PAM Side)

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/oidc/dpop.rs:165-352` | `validate_dpop_proof()` — verifies typ, sig, htm, htu, iat, JTI replay |
| `pam-unix-oidc/src/oidc/dpop.rs:356-368` | `verify_dpop_binding()` — constant-time cnf.jkt comparison |
| `pam-unix-oidc/src/oidc/dpop.rs:287-328` | JTI replay block — cross-fork persistent store |

### Device Authorization Grant (RFC 8628)

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/device_flow/client.rs:114-163` | `start_authorization()` — POST to device endpoint |
| `pam-unix-oidc/src/device_flow/client.rs:174-207` | `poll_for_token()` — blocking poll with slow_down backoff |
| `pam-unix-oidc/src/device_flow/types.rs:47-68` | `DeviceAuthResponse` — device_code, user_code, verification_uri |
| `unix-oidc-agent/src/main.rs` | `run_login()` / `run_device_flow()` — agent CLI integration |

### Auth Code + PKCE (RFC 7636)

| File | Key symbols |
|------|-------------|
| `unix-oidc-agent/src/auth_code.rs:73-79` | `generate_pkce()` — verifier + S256 challenge |
| `unix-oidc-agent/src/auth_code.rs:87-106` | `build_authorization_url()` — all required params |
| `unix-oidc-agent/src/auth_code.rs:109-160` | `start_callback_listener()` — ephemeral localhost server |
| `unix-oidc-agent/src/auth_code.rs:194-235` | `exchange_code()` — POST with code_verifier + DPoP header |

### Token Exchange (RFC 8693)

| File | Key symbols |
|------|-------------|
| `unix-oidc-agent/src/exchange.rs:80-164` | `perform_token_exchange()` — RFC 8693 HTTP client |
| `pam-unix-oidc/src/oidc/validation.rs:507-549` | `validate_delegation()` — exchanger allowlist + depth check |
| `pam-unix-oidc/src/policy/config.rs:335-348` | `DelegationConfig` — allowed_exchangers, max_depth, max_lifetime |
| `pam-unix-oidc/src/auth.rs:290-340` | Delegation wiring in PAM auth path (fail closed) |

### CIBA Step-Up Authentication

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/ciba/client.rs:60-80` | `build_backchannel_auth_params()` — login_hint, scope, binding_message |
| `pam-unix-oidc/src/ciba/client.rs:119-147` | `build_binding_message()` — 64-byte UTF-8 safe truncation |
| `pam-unix-oidc/src/ciba/types.rs:119-128` | `satisfies_acr()` — phrh satisfies phr |
| `unix-oidc-agent/src/daemon/socket.rs` | `handle_step_up()` / `poll_ciba()` — async CIBA poll loop with DPoP |
| `pam-unix-oidc/src/sudo.rs` | PAM sudo entry point triggering CIBA via agent IPC |

### TPM Attestation (ADR-018)

| File | Key symbols |
|------|-------------|
| `unix-oidc-agent/src/crypto/tpm_signer.rs:40-50` | `AttestationEvidence` struct (agent side) |
| `unix-oidc-agent/src/crypto/tpm_signer.rs` | `TpmSigner::certify()` — TPM2_CC_Certify call |
| `pam-unix-oidc/src/oidc/attestation.rs:130-175` | `verify_ak_signature()` — P-256 ECDSA over certify_info |
| `pam-unix-oidc/src/oidc/attestation.rs:177-216` | `parse_certified_name()` — TPMS_ATTEST binary parsing |
| `pam-unix-oidc/src/oidc/attestation.rs:218-274` | `match_name_to_jwk()` — Name ↔ JWK thumbprint matching |

### SPIFFE/SPIRE Workload Identity

| File | Key symbols |
|------|-------------|
| `unix-oidc-agent/src/crypto/spire_signer.rs:106-115` | `SpireSigner` — ephemeral DPoP keys + SVID caching |
| `unix-oidc-agent/src/crypto/spire_signer.rs:181-193` | `fetch_svid_async()` — gRPC Workload API call |
| `pam-unix-oidc/src/policy/config.rs:258-282` | `SpiffeMappingConfig` — SPIFFE ID → Unix username strategies |
| `pam-unix-oidc/src/identity/mapper.rs` | `SpiffeUsernameMapper` — path_suffix/regex/static_map |

### Client Attestation PoP

| File | Key symbols |
|------|-------------|
| `unix-oidc-agent/src/crypto/attestation_pop.rs:68-95` | `build_client_attestation()` — long-lived JWT |
| `unix-oidc-agent/src/crypto/attestation_pop.rs:98-116` | `build_client_attestation_pop()` — per-request PoP JWT |
| `unix-oidc-agent/src/crypto/attestation_pop.rs:137-153` | `attach_client_attestation()` — adds both HTTP headers |

### JTI Replay Protection

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/security/jti_cache.rs:76-83` | `JtiCache` — in-memory RwLock HashMap |
| `pam-unix-oidc/src/security/fs_store.rs:74-77` | `FsAtomicStore` — cross-fork filesystem persistence |
| `pam-unix-oidc/src/security/fs_store.rs:155-212` | `check_and_record()` — O_CREAT|O_EXCL atomic creation |
| `pam-unix-oidc/src/security/jti_cache.rs:339-418` | `check_and_record_fs()` — routes through FsAtomicStore |

### Session Management

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/security/session.rs:43-57` | `generate_secure_session_id()` — 128-bit CSPRNG |
| `pam-unix-oidc/src/session/mod.rs:124-158` | `write_session_record()` — atomic write via rename(2) |
| `pam-unix-oidc/src/session/mod.rs:167-198` | `delete_session_record()` — session duration computation |

### Clock Skew Handling

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/oidc/validation.rs:178-186` | `clock_skew_tolerance_secs` — configurable, default 60s |
| `pam-unix-oidc/src/oidc/validation.rs:299-303` | `exp` check — `claims.exp + tolerance < now` |
| `pam-unix-oidc/src/oidc/dpop.rs:63-83` | `DPoPConfig.clock_skew_future_secs` — DPoP iat tolerance |

### SCIM Provisioning (RFC 7643/7644)

| File | Key symbols |
|------|-------------|
| `unix-oidc-scim/src/schema.rs:80-109` | `ScimUser` — RFC 7643 User resource |
| `unix-oidc-scim/src/routes.rs:37-219` | CRUD handlers — POST/GET/PUT/DELETE /Users |
| `unix-oidc-scim/src/provisioner.rs` | `Provisioner` — useradd/userdel with username validation |
| `unix-oidc-scim/src/auth.rs:212-318` | Bearer token middleware with JWKS verification |

### Audit and Observability

| File | Key symbols |
|------|-------------|
| `pam-unix-oidc/src/audit.rs:250+` | `AuditEvent` enum — 20+ event variants |
| `pam-unix-oidc/src/audit.rs:1002-1055` | `ocsf_fields()` — OCSF 1.3.0 enrichment |
| `pam-unix-oidc/src/audit.rs:1157+` | `enriched_log_json()` — HMAC chain + OCSF fields |

---

*This document is part of the unix-oidc project. It evolves with the codebase — when new OAuth/OIDC primitives are added, this guide should be updated to explain both the standard and the implementation.*
