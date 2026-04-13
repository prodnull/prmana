# Security Guide

This guide documents the security posture of `prmana` as it exists in the codebase today. It has two goals:

1. Explain the security features the project provides.
2. Explain why key architectural decisions were made, especially where the design trades convenience for stronger security properties.

It is intentionally explicit about what is implemented, what is feature-gated, what is partially wired, and what is not ready for production.

## Table of Contents

- [Status Legend](#status-legend)
- [System Security Model](#system-security-model)
- [Security Features](#security-features)
- [Security Architecture Decisions](#security-architecture-decisions)
- [Trust Boundaries](#trust-boundaries)
- [Deployment Hardening](#deployment-hardening)
- [Current Limitations](#current-limitations)
- [Security Review Checklist](#security-review-checklist)
- [Standards and References](#standards-and-references)

---

## Status Legend

This guide uses the following labels:

- `Implemented`: present and enforced in the main path
- `Implemented, feature-gated`: present but only when the corresponding build feature is enabled
- `Partially wired`: code exists, but the main end-to-end enforcement path is incomplete
- `Planned`: design or roadmap only
- `Not production-ready`: present for development or testing, but unsafe to deploy as-is

---

## System Security Model

`prmana` has three main security-sensitive components:

1. `pam-prmana`
   - Server-side authentication enforcement
   - Validates JWTs, DPoP proofs, issuer/audience/expiry, replay protections, and local identity mapping
2. `prmana-agent`
   - Client-side broker for token acquisition and proof generation
   - Holds user credentials and signer state behind a same-UID Unix socket boundary
3. `prmana-scim`
   - Separate provisioning service for SCIM user lifecycle management
   - Deliberately isolated from the PAM module because it mutates local system accounts

The core security thesis is:

- federated identity comes from OIDC,
- proof-of-possession comes from DPoP,
- local authorization comes from Unix and directory state,
- and higher assurance comes from hardware-backed signers and auditable policy enforcement.

`prmana` is not a generic remote access fabric. Today it secures SSH and PAM-mediated privileged access on Unix-like systems.

---

## Security Features

### 1. OIDC Token Validation

Status: `Implemented`

The PAM module validates:

- JWT signature against issuer JWKS
- issuer exact match
- audience match
- expiration
- `nbf` when present
- per-issuer allowed algorithm policy

Why this matters:

- signature verification prevents forged tokens
- issuer and audience checks prevent cross-tenant and wrong-client token reuse
- algorithm allowlisting and JWKS/header algorithm cross-checking reduce algorithm confusion risk

Relevant code:

- `pam-prmana/src/oidc/validation.rs`
- `pam-prmana/src/auth.rs`

The agent currently supports interactive token acquisition via:

- OAuth device authorization grant
- OAuth authorization code + PKCE on localhost
- SPIRE Workload API for JWT-SVID acquisition when `spire` is enabled

### 2. DPoP Proof-of-Possession

Status: `Implemented`

DPoP binds access tokens to a client-held signing key. The server validates:

- DPoP proof signature
- proof freshness (`iat`)
- `htu` / `htm` target binding
- replay protections (`jti`, nonce)
- token `cnf.jkt` to proof JWK thumbprint binding

Why this matters:

- stolen tokens are not enough without the matching private key
- proofs are target-specific and short-lived
- replay windows are reduced by `jti`, nonce, and proof age enforcement

Important limitation:

- DPoP reduces blast radius; it does not protect against full client compromise.
- if an attacker can extract both token and key material from the client, they can act as that client until expiry or revocation

Relevant code:

- `pam-prmana/src/oidc/dpop.rs`
- `prmana-agent/src/crypto/dpop.rs`

### 3. Replay Protection

Status: `Implemented`

The project uses multiple replay defenses:

- DPoP `jti` replay detection
- server-issued nonce support
- short DPoP proof age windows
- issuer-scoped JTI handling
- filesystem-backed cross-fork JTI state for the PAM-side token replay path

Why this matters:

- PAM runs in a multi-process environment
- replay defenses that only work in a single thread or process are not enough for real SSH/PAM deployments

Relevant code:

- `pam-prmana/src/security/jti_cache.rs`
- `prmana-agent/tests/jti_cross_fork.rs`

### 4. Same-UID Agent IPC with Peer Credential Checks

Status: `Implemented`

The agent daemon accepts connections from the same UID and rejects cross-UID IPC using:

- `SO_PEERCRED` on Linux
- `getpeereid` on macOS
- restrictive Unix socket permissions

Why this matters:

- this blocks other local users from using or interrogating the agent
- it matches the long-established `ssh-agent` trust model

Important limitation:

- same-UID malware is inside the trust boundary
- hardware-backed signers can prevent raw key export, but not use of the agent as a signing oracle

Relevant code:

- `prmana-agent/src/daemon/socket.rs`
- `prmana-agent/src/daemon/peer_cred.rs`

### 5. Hardware-Backed Signers

Status:

- Software signer: `Implemented`
- YubiKey signer: `Implemented, feature-gated`
- TPM signer: `Implemented, feature-gated`
- SPIRE signer: `Implemented, feature-gated`

The agent supports multiple signer backends:

- software P-256 keys for portability
- YubiKey-backed signing for user-held hardware
- TPM 2.0-backed signing for non-exportable local keys
- SPIRE-backed token acquisition with independent ephemeral DPoP keys

Why this matters:

- hardware-backed signers reduce raw key extraction risk
- TPM-backed keys can make remote-use credentials non-exportable from the host
- SPIRE integration bridges workload identity into SSH/PAM without static SSH keys

Important limitation:

- same-UID clients can still request signatures from the agent
- hardware backing protects key export better than it protects against a trusted local broker being used on behalf of the same user

Relevant code:

- `prmana-agent/src/crypto/tpm_signer.rs`
- `prmana-agent/src/crypto/yubikey_signer.rs`
- `prmana-agent/src/crypto/spire_signer.rs`

### 6. Step-Up Authentication for Privileged Actions

Status: `Implemented`

The project supports CIBA-based step-up authentication for `sudo` and similar privileged operations.

Current posture:

- agent initiates and polls CIBA flows
- PAM can require an ID token from the agent response and validate it
- ACR policy can hard-fail if required assurance is not met

Why this matters:

- elevating privileges can require stronger authentication than initial SSH login
- separates baseline login from privileged action approval

Relevant code:

- `pam-prmana/src/sudo.rs`
- `prmana-agent/src/daemon/socket.rs`

### 7. Break-Glass Resilience

Status: `Implemented`

Break-glass access supports:

- explicitly configured local emergency accounts
- optional offline TOTP / OTP gating
- audit signaling for break-glass use

Why this matters:

- IdP outages should not necessarily equal total administrative lockout
- emergency access must be explicit, narrow, and auditable

Relevant code:

- `pam-prmana/src/otp.rs`
- `pam-prmana/src/policy/config.rs`

### 8. Audit Integrity and OCSF Enrichment

Status: `Implemented`

Audit events support:

- structured JSON output
- OCSF enrichment
- HMAC chaining over the enriched event payload
- offline verification tooling

Why this matters:

- tamper-evidence is most useful when it protects the actual emitted event format
- verification should be possible after collection, not only at write time

Relevant code:

- `pam-prmana/src/audit.rs`
- `pam-prmana/src/bin/audit_verify.rs`

### 9. SPIFFE / SPIRE Bridge

Status:

- SPIFFE trust via OIDC discovery: `Implemented`
- SPIFFE username mapping: `Implemented`
- SPIRE signer backend: `Implemented, feature-gated`

Why this matters:

- workloads can use existing SPIFFE identity to access Unix systems
- PAM stays on the existing JWT/JWKS trust path instead of adding a second SPIFFE-specific verifier

Relevant code:

- `pam-prmana/src/identity/mapper.rs`
- `pam-prmana/src/auth.rs`
- `prmana-agent/src/crypto/spire_signer.rs`

### 10. Token Exchange / Delegation

Status: `Implemented`

What exists:

- parsing recursive `act` claims
- exchanger allowlists
- delegation depth limits
- exchanged-token lifetime limits
- PAM-side enforcement in the main authentication path
- dedicated token-exchange IPC and agent-side exchange handling

Current scope:

- exchanged tokens are accepted only when the issuer explicitly configures delegation policy
- the `act` chain is bounded by policy depth and exchanger allowlists
- excessive exchanged-token lifetime is rejected

Relevant code:

- `pam-prmana/src/auth.rs`
- `pam-prmana/src/oidc/token.rs`
- `pam-prmana/src/oidc/validation.rs`
- `prmana-agent/src/exchange.rs`

### 11. TPM Attestation

Status: `Implemented`

What exists:

- TPM attestation evidence generation primitives
- DPoP header support for attestation payloads
- TPM-backed proof generation that includes attestation when available
- PAM-side cryptographic attestation verification in the DPoP auth path
- issuer policy for attestation enforcement

Current guarantees:

- AK signature verification over `certify_info`
- TPM `Name` extraction and matching against the DPoP proof JWK
- attestation policy enforcement (`strict` / `warn` / `disabled`)

Current limitation:

- this is key attestation, not full platform attestation
- EK certificate chain verification and platform PCR policy are still future work
- attestation freshness still relies on the DPoP proof's normal time checks rather than a separate server-provided attestation nonce

### 12. SCIM Provisioning Service

Status: `Implemented`

What exists:

- separate SCIM binary and crate
- SCIM schemas and CRUD endpoints
- username validation and reserved-account denylist
- subprocess-based account provisioning
- JWT Bearer validation against issuer JWKS with TTL-based cache refresh
- secure startup refusal unless OIDC validation is configured or the explicit dev-only bypass is used

Current limitation:

- `--insecure-no-auth` still exists as an explicit development-only bypass and must not be used in production
- the current service model is single-issuer per process
- provisioning semantics are synchronous and local-account oriented, not a full distributed identity control plane

---

## Security Architecture Decisions

This section explains the most important security-oriented design choices.

### Groups Come From SSSD / NSS, Not Token Claims

Rationale:

- IdP group claims are federation input, not authoritative Unix authorization state
- directory-backed local resolution avoids split-brain authorization
- FreeIPA / LDAP / directory state should be the source of truth for local group membership

Outcome:

- tokens authenticate identity
- local directory state authorizes Unix group membership

Related ADR:

- ADR-008

### Config Hot Reload Uses `stat(2)`, Not Signals

Rationale:

- signal-driven reloads are fragile in PAM-adjacent code and containerized deployments
- stat-based reloading is simpler, stateless, and avoids signal-handler complexity

Outcome:

- file-backed policy updates can be detected without depending on process-management integrations

Related ADR:

- ADR-009

### Audit HMAC Covers OCSF-Enriched Events

Rationale:

- operators and forensic tooling verify the final emitted event, not a pre-enrichment internal representation
- if the chain covered only the bare event, enrichment could break verification semantics

Outcome:

- the chain protects the event as actually logged

Related ADR:

- ADR-010

### Per-Issuer JWKS and HTTP Settings

Rationale:

- issuers rotate keys and behave operationally at different cadences
- global TTLs force either over-fetching or stale-key risk

Outcome:

- each issuer can tune cache and network behavior independently

Related ADR:

- ADR-011

### `required_acr` Is a Hard Fail

Rationale:

- if an operator declares a minimum authentication assurance, accepting a weaker token defeats the policy

Outcome:

- explicit required assurance is enforced, not advisory

Related ADR:

- ADR-012

### Same-UID IPC Trust Is Deliberate

Rationale:

- the agent is a per-user credential broker
- same-UID trust matches `ssh-agent` and similar local-agent models
- cross-UID isolation is enforced now; finer-grained same-UID isolation is a later enhancement

Outcome:

- realistic local trust boundary for Unix user processes
- no false promise that the agent protects against same-user malware

Related ADR:

- ADR-013

### TPM Object Attributes Favor Non-Exportable Signing

Rationale:

- the TPM key is for signing only
- attributes are chosen to make the key TPM-generated, non-exportable, and usable without accidentally enabling unrelated operations

Outcome:

- hardware-backed DPoP key constrained to the needed capability set

Related ADR:

- ADR-014

### SPIFFE Trust Uses Existing OIDC/JWKS Validation

Rationale:

- the PAM module should not grow a second trust-verification path unless necessary
- SPIRE OIDC Discovery Provider lets SPIFFE workloads enter through the same JWT validation pipeline

Outcome:

- leaner PAM trust boundary
- less duplicated verifier logic

Related ADR:

- ADR-015

### SPIRE DPoP Keys Are Independent of SVID Keys

Rationale:

- DPoP proof should bind the session attempt, not reuse the workload’s long-lived identity key
- SPIRE-managed keys may not be directly accessible
- independent ephemeral keys improve isolation

Outcome:

- JWT-SVID acts as access token
- DPoP proof uses an independent ephemeral key pair

Related ADR:

- ADR-016

### SCIM Runs as a Separate Binary

Rationale:

- provisioning code that mutates local users should not live in the PAM process
- HTTP request handling and account mutation logic deserve isolation from login-time authentication code

Outcome:

- cleaner privilege and failure boundary
- easier to harden separately

Related ADR:

- ADR-019

---

## Trust Boundaries

| Boundary | Trust Level | Main Controls |
|----------|-------------|---------------|
| Agent ↔ IdP | Semi-trusted remote | TLS, issuer pinning, token validation |
| PAM ↔ IdP JWKS/discovery | Semi-trusted remote | HTTPS, issuer matching, JWKS cache controls |
| Agent ↔ same-UID client | Trusted by design | socket permissions, peer credential checks |
| Agent ↔ other local users | Untrusted | `SO_PEERCRED` / `getpeereid`, 0600 socket |
| SSH transport | Protected channel | SSH encryption plus DPoP target binding |
| PAM ↔ local OS / NSS / SSSD | Trusted local boundary | process isolation, local directory authority |
| SCIM ↔ external caller | Untrusted network input | HTTP auth, route validation, subprocess argument safety |

The most important non-obvious trust statement is:

- `prmana-agent` is not designed to defend against same-UID malware.
- it is designed to defend against cross-user access, token replay, raw key export in stronger signer modes, and unauthenticated remote use.

---

## Deployment Hardening

### Production Requirements

- use HTTPS-only issuers and endpoints
- keep DPoP enforcement strict in production
- protect policy and audit files with root ownership and restrictive permissions
- prefer hardware-backed signers where operationally feasible
- use keyring-backed storage over file fallback where available
- configure and test break-glass deliberately, not implicitly

### File Permissions

Suggested baseline:

```bash
chmod 755 /lib/security/pam_prmana.so
chown root:root /lib/security/pam_prmana.so

chmod 600 /etc/prmana/policy.yaml
chown root:root /etc/prmana/policy.yaml

chmod 640 /var/log/prmana/audit.log
chown root:adm /var/log/prmana/audit.log
```

### Break-Glass Seed Protection

If offline OTP break-glass is used:

- keep the seed file root-owned
- reject symlinks and non-regular files
- keep permissions restrictive (`0400` or `0600`)

This is enforced in code, but deployment should still treat the file as highly sensitive.

### System Hardening

Recommended controls:

- SELinux / AppArmor confinement where available
- network egress limited to IdP and approved endpoints
- full-disk encryption for systems that may use file-backed storage
- careful control of debugging and monitoring tools on shared desktops

### Observability

Operators should monitor:

- auth failures and spikes
- replay detections
- degraded JTI store events
- break-glass usage
- step-up failures
- audit-chain verification failures

---

## Current Limitations

This section is intentionally blunt.

### Same-UID Processes Can Use the Agent

This is by design. The agent follows an `ssh-agent`-style trust model. Hardware-backed keys reduce raw extraction risk but do not prevent the agent from signing on behalf of same-UID clients.

### DPoP Does Not Defend Against Full Client Compromise

If attacker control extends to the running client process or same-user context, DPoP does not save the session by itself. It primarily protects against token theft without the matching key.

### TPM Attestation Is Not Yet Full Platform Attestation

Current TPM attestation verifies the AK signature and the certified key `Name`, which is a meaningful security property. It does not yet verify EK certificate chains, platform state, or a dedicated attestation-freshness nonce.

### Token Exchange Expands Privilege By Design

Token exchange is now enforced in the main PAM auth path, but it still widens privilege by allowing selected exchangers to mint audience-scoped delegated tokens. Keep exchanger allowlists and delegation depth deliberately narrow.

### SCIM Has an Explicit Unsafe Development Mode

The SCIM service now performs real JWT validation by default and propagates provisioning failures. However, `--insecure-no-auth` remains intentionally available for development. Production deployments must not enable it.

### Same-UID Local Threats Are a Known Residual Risk

The project raises the bar for cross-host token theft, replay, and key export. It does not claim to fully solve same-user endpoint compromise.

---

## Security Review Checklist

Before calling a feature production-ready, confirm:

- the security property is enforced in the main path, not only in helper functions
- the protocol shape is covered by round-trip tests
- the feature is documented with the right status label
- the failure mode is fail-closed for explicit security policy
- logs and audit events reflect both acceptance and rejection paths

Questions maintainers should ask:

1. Is this check actually called from the main auth or proof path?
2. Does a regression test prove the invariant end-to-end?
3. Are we documenting an aspiration as if it were implemented?
4. Does the feature widen trust boundaries or privilege without equivalent enforcement?

---

## Standards and References

Primary standards:

- RFC 9449: DPoP
- RFC 7638: JWK Thumbprint
- RFC 7519: JWT
- RFC 7517 / RFC 7518 / RFC 7515: JOSE / JWK / JWA / JWS
- RFC 8693: OAuth 2.0 Token Exchange
- RFC 7643 / RFC 7644: SCIM 2.0
- NIST SP 800-63B: Digital Identity Guidelines
- NIST SP 800-88 Rev. 1: Media Sanitization

Related project documents:

- `docs/threat-model.md`
- `docs/standards-compliance-matrix.md`
- `docs/adr/`

---

Last updated: 2026-04-09
