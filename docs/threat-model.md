# Threat Model: unix-oidc

> **Version:** 3.0
> **Date:** 2026-03-12
> **Classification:** Public
> **Method:** STRIDE per trust boundary (Microsoft SDL)

STRIDE-based threat model for the unix-oidc project -- a PAM module bridging OpenID Connect authentication to Linux/macOS with DPoP token binding (RFC 9449).

**Standards referenced**: RFC 9449 (DPoP), RFC 7638 (JWK Thumbprint), RFC 7519 (JWT), RFC 6749 (OAuth 2.0), NIST SP 800-63B (Digital Identity Authentication), NIST SP 800-88 Rev 1 (Media Sanitization).

---

## 1. System Overview

unix-oidc authenticates Unix users via OIDC tokens validated by a PAM module (`pam-unix-oidc`). A client-side agent daemon (`unix-oidc-agent`) acquires tokens from an Identity Provider (IdP), generates ephemeral DPoP key pairs for proof-of-possession binding (RFC 9449), and delivers signed proofs over a Unix domain socket to an SSH client. The SSH session transports the token and DPoP proof to the server, where the PAM module validates the token signature against the IdP's JWKS, enforces issuer/audience/expiration checks, verifies the DPoP proof signature and binding, checks JTI replay caches, and maps the `preferred_username` claim to a local Unix account via SSSD/NSS. Trust boundaries exist at six points: (1) the TLS-protected channel between agent and IdP, (2) the Unix domain socket IPC between agent and SSH client, (3) the SSH-encrypted channel carrying credentials to the server, (4) the PAM module's interface with sshd and the local OS, (5) the credential storage backends (keyrings, files) on the client, and (6) the PAM module's JWKS fetch channel to the IdP.

---

## 2. Trust Boundaries

| ID | Boundary | From | To | Transport | Key Assumption |
|----|----------|------|----|-----------|----------------|
| TB-1 | Agent <-> IdP | `unix-oidc-agent` | OIDC Identity Provider | HTTPS/TLS 1.2+ | IdP is a trusted third party; TLS cert chain is valid |
| TB-2 | Agent <-> SSH Client (IPC) | `unix-oidc-agent` daemon | SSH client process | Unix domain socket (0600) | Only the owning UID can connect; kernel enforces file permissions |
| TB-3 | SSH Client <-> sshd (Network) | SSH client (user machine) | sshd (server) | SSH encrypted channel | SSH transport integrity assumed; token/proof carried in keyboard-interactive |
| TB-4 | PAM Module <-> sshd/OS | `pam_unix_oidc.so` | sshd, NSS/SSSD, audit subsystem | In-process (shared library) + NSS calls | PAM module runs as root within sshd; must never panic |
| TB-5 | Agent <-> Storage | `unix-oidc-agent` | Keyring (Secret Service/keyutils/Keychain) or file fallback | D-Bus / kernel keyring / filesystem | Keyring access is UID-scoped; file fallback uses 0600 permissions |
| TB-6 | PAM Module <-> IdP (JWKS) | `pam_unix_oidc.so` | IdP JWKS endpoint | HTTPS/TLS | JWKS fetched only from configured issuer URL; cache survives transient failures |

---

## 3. STRIDE Analysis

### TB-1: Agent <-> IdP

| Threat | Category | Description | Severity |
|--------|----------|-------------|----------|
| T1.1 | Spoofing | Attacker impersonates IdP via DNS hijack or rogue certificate to issue forged tokens | Critical |
| T1.2 | Tampering | MITM modifies token response in transit (e.g., injecting claims) | Critical |
| T1.3 | Repudiation | IdP denies issuing a token; no client-side proof of issuance beyond the signed JWT | Low |
| T1.4 | Info Disclosure | Token or refresh token intercepted in transit | High |
| T1.5 | DoS | IdP unavailable; all OIDC authentication fails | High |
| T1.6 | Elevation | Attacker obtains valid tokens from a compromised IdP tenant | Critical |

### TB-2: Agent <-> SSH Client (IPC)

| Threat | Category | Description | Severity |
|--------|----------|-------------|----------|
| T2.1 | Spoofing | Rogue process connects to agent socket impersonating the SSH client | Medium |
| T2.2 | Tampering | Attacker modifies IPC messages (proof request/response) | Medium |
| T2.3 | Info Disclosure | Another user reads token/proof from the socket | High |
| T2.4 | DoS | Attacker floods socket with connections, exhausting agent resources | Medium |
| T2.5 | Elevation | Local attacker extracts DPoP private key via `/proc/PID/mem` or swap | High |

### TB-3: SSH Client <-> sshd (Network)

| Threat | Category | Description | Severity |
|--------|----------|-------------|----------|
| T3.1 | Spoofing | Attacker replays captured token+proof to a different server | High |
| T3.2 | Tampering | Token or proof modified during SSH transport (requires SSH compromise) | Low |
| T3.3 | Info Disclosure | Token exfiltrated from SSH channel (requires SSH compromise) | Medium |
| T3.4 | DoS | Authentication flooding against sshd | High |
| T3.5 | Elevation | Stolen bearer token (without DPoP key) used from another client | Critical |

### TB-4: PAM Module <-> sshd/OS

| Threat | Category | Description | Severity |
|--------|----------|-------------|----------|
| T4.1 | Spoofing | Attacker crafts a token with forged `preferred_username` to impersonate another Unix user | Critical |
| T4.2 | Tampering | `UNIX_OIDC_TEST_MODE` env var set in production, bypassing signature verification | Critical |
| T4.3 | Repudiation | Authentication events not logged; attacker denies access | Medium |
| T4.4 | Info Disclosure | Verbose error messages leak IdP configuration, key IDs, or internal paths to the client | Medium |
| T4.5 | DoS | PAM module panic locks users out of system | Critical |
| T4.6 | DoS | JTI/nonce cache memory exhaustion | High |
| T4.7 | Elevation | Algorithm confusion: attacker sets `alg: "none"` or symmetric algorithm in token/proof header | Critical |
| T4.8 | Elevation | Break-glass account misconfiguration allows OIDC bypass for non-emergency users | High |

### TB-5: Agent <-> Storage

| Threat | Category | Description | Severity |
|--------|----------|-------------|----------|
| T5.1 | Info Disclosure | DPoP private key recovered from file fallback on CoW filesystem (btrfs/APFS) after deletion | High |
| T5.2 | Info Disclosure | Key material swapped to disk and recovered from swap partition | Medium |
| T5.3 | Tampering | Attacker replaces stored key material to force agent to use attacker-controlled key | High |
| T5.4 | Info Disclosure | Core dump contains key material or tokens | High |

### TB-6: PAM Module <-> IdP (JWKS)

| Threat | Category | Description | Severity |
|--------|----------|-------------|----------|
| T6.1 | Spoofing | Attacker poisons JWKS cache with rogue keys, enabling forged token acceptance | Critical |
| T6.2 | DoS | JWKS endpoint unreachable; cached keys expire; all authentication fails | High |
| T6.3 | Tampering | Attacker modifies JWKS response to inject attacker-controlled public key | Critical |

---

## 4. DPoP-Specific Threats

### 4.1 Token Theft Without DPoP Key

**Scenario**: Attacker intercepts the access token but does not possess the ephemeral DPoP private key.

**Analysis**: The PAM module verifies that the DPoP proof's JWK thumbprint matches the token's `cnf.jkt` claim (`pam-unix-oidc/src/oidc/dpop.rs:371-383`, `verify_dpop_binding()`). Without the private key, the attacker cannot produce a valid ES256 signature over a fresh proof. The token is unusable. This is the core security property of RFC 9449.

**Residual risk**: If `dpop_required` is set to `Warn` or `Disabled` in policy, a stolen bearer token without DPoP proof may be accepted.

### 4.2 Token Theft With DPoP Key

**Scenario**: Attacker compromises the agent process and extracts both the access token and the DPoP signing key.

**Analysis**: Full credential compromise. The attacker can forge valid DPoP proofs for any target server. Mitigations are defense-in-depth:
- `mlock(2)` prevents swap exposure (`unix-oidc-agent/src/crypto/protected_key.rs:120-139`)
- Core dumps disabled via `prctl(PR_SET_DUMPABLE, 0)` / `ptrace(PT_DENY_ATTACH, 0)`
- `ZeroizeOnDrop` on `SigningKey` limits temporal window of key exposure in freed memory
- Token `exp` claim limits validity window
- `SecretString` wrapping prevents accidental token logging (`unix-oidc-agent/src/daemon/socket.rs:94-100`)

### 4.3 DPoP Proof Replay

**Scenario**: Attacker captures a valid DPoP proof and replays it.

**Analysis**: Three layers of replay protection:
1. **JTI uniqueness**: Global `DPOP_JTI_CACHE` (`dpop.rs:26-108`) rejects duplicate JTI values within TTL window. Double-checked locking pattern prevents TOCTOU races (`dpop.rs:52-93`).
2. **Server-issued nonce**: `DPoPNonceCache` (`nonce_cache.rs:66-134`) enforces single-use nonces via moka's atomic `remove()` -- no TOCTOU window. 256-bit CSPRNG nonces (`nonce_cache.rs:147-151`).
3. **Proof freshness**: `iat` checked against `max_proof_age` (default 60s) and `clock_skew_future_secs` (default 5s) at `dpop.rs:309-324`.

**Residual risk**: JTI cache is process-local (in-memory `HashMap`). In a multi-process PAM deployment (e.g., sshd prefork), each process has its own cache. A proof replayed to a different sshd worker process within the TTL window could bypass JTI deduplication. The nonce cache (moka-backed singleton) has the same process-scoping limitation.

### 4.4 Algorithm Confusion

**Scenario**: Attacker sets `alg: "none"` or a symmetric algorithm in the DPoP proof header to bypass signature verification.

**Analysis**: Mitigated. DPoP proof validation at `dpop.rs:264` enforces `alg == "ES256"` before any signature operation. `jwk_to_verifying_key()` at `dpop.rs:386` independently validates `kty == "EC"` and `crv == "P-256"`. P-256 coordinate lengths are validated at `dpop.rs:401` (32 bytes each). For ID tokens, the `jsonwebtoken` library's `Validation` struct is initialized with the header-specified algorithm, but issuer/audience validation and JWKS key matching provide defense-in-depth.

### 4.5 JWK Thumbprint Manipulation

**Scenario**: Attacker supplies non-canonical `kty`/`crv` values in the DPoP proof JWK to produce a different thumbprint while using a valid key.

**Analysis**: Mitigated. `compute_jwk_thumbprint()` at `dpop.rs:413-429` uses hardcoded canonical values `"EC"` and `"P-256"` for the RFC 7638 canonical JSON, ignoring user-supplied `kty`/`crv`. The actual `kty`/`crv` values are validated separately in `jwk_to_verifying_key()`. Constant-time comparison via `subtle::ConstantTimeEq` is used for all thumbprint comparisons (`dpop.rs:112-117, 376`).

### 4.6 Key Extraction from Memory

**Scenario**: Privileged attacker reads DPoP private key from agent process memory.

**Analysis**: Defense-in-depth, not a hard guarantee:
- `mlock(2)` prevents swap exposure (best-effort; `protected_key.rs:73-112`)
- `ZeroizeOnDrop` zeroes key bytes on struct drop (`protected_key.rs:156-167`)
- Box-only constructors prevent stack copies (`protected_key.rs:220-237`)
- `export_key()` returns `Zeroizing<Vec<u8>>` to ensure caller's copy is wiped (`protected_key.rs:243-245`)
- Core dump suppression prevents post-crash extraction
- **Limitation**: Root or kernel-level access can still read `/proc/PID/mem` (Linux) or use DTrace (macOS). This is an accepted residual risk -- protecting against a compromised root is out of scope (NIST SP 800-63B assumes trusted OS kernel).

---

## 5. Mitigations Matrix

| Threat ID | Threat | Mitigation | Code Reference | Status |
|-----------|--------|-----------|----------------|--------|
| T1.1 | IdP spoofing | TLS certificate validation on all IdP connections; JWKS fetched only from configured issuer URL | `pam-unix-oidc/src/oidc/jwks.rs` | Implemented |
| T1.4 | Token interception | TLS transport; DPoP binding makes intercepted tokens unusable without private key | `pam-unix-oidc/src/oidc/dpop.rs` (full file) | Implemented |
| T1.5 | IdP unavailable | JWKS cache survives transient IdP failures; break-glass accounts for emergency access | `pam-unix-oidc/src/lib.rs:92-107` | Implemented |
| T2.1 | Rogue IPC client | Socket permissions 0600 (owner-only); `get_peer_credentials()` for UID verification | `unix-oidc-agent/src/daemon/socket.rs:80-87` | Implemented |
| T2.3 | IPC token leak | Unix socket 0600; `SecretString` wrapping prevents token logging | `unix-oidc-agent/src/daemon/socket.rs:94-100` | Implemented |
| T2.5 | Key extraction via swap | `mlock(2)` on key pages; `ZeroizeOnDrop`; Box-only constructors | `unix-oidc-agent/src/crypto/protected_key.rs:120-139, 156-167` | Best-effort |
| T3.1 | Proof replay to other server | `htu` (target URI) binding in DPoP proof; server validates `htu` match | `pam-unix-oidc/src/oidc/dpop.rs:335-339` | Implemented |
| T3.4 | Auth flooding | Per-user and per-IP rate limiting before OIDC processing | `pam-unix-oidc/src/lib.rs:110-114` | Implemented |
| T3.5 | Stolen bearer token | DPoP `cnf.jkt` binding; constant-time thumbprint comparison | `pam-unix-oidc/src/oidc/dpop.rs:371-383` | Implemented |
| T4.1 | Username spoofing | `preferred_username` from validated token compared to PAM_USER; SSSD existence check | `pam-unix-oidc/src/auth.rs` | Implemented |
| T4.2 | Test mode in production | Explicit `"true"`/`"1"` check (not presence); `#[cfg(feature = "test-mode")]` compile gate | `pam-unix-oidc/src/lib.rs:60-64`, `validation.rs:149` | Implemented |
| T4.3 | Missing audit trail | `AuditEvent` logged for all auth attempts (success, failure, break-glass, rate-limit) | `pam-unix-oidc/src/lib.rs:104, 111` | Implemented |
| T4.5 | PAM panic lockout | `#![deny(unsafe_code)]`, `#![deny(clippy::unwrap_used)]`; all paths return `PamError` codes | `pam-unix-oidc/src/lib.rs:18-19` | Implemented |
| T4.6 | Cache memory exhaustion | JTI cache capped at 100K entries with forced cleanup; nonce cache uses moka bounded capacity + TTL | `dpop.rs:24,72-87`, `nonce_cache.rs:82-88` | Implemented |
| T4.7 | Algorithm confusion (DPoP) | `alg == "ES256"` enforced; `kty`/`crv` validated independently; P-256 coordinate length check | `pam-unix-oidc/src/oidc/dpop.rs:264, 386, 401` | Implemented |
| T4.8 | Break-glass misconfiguration | Requires `break_glass.enabled == true` AND user in accounts list; audit event always logged | `pam-unix-oidc/src/lib.rs:45-53, 99-107` | Implemented |
| T5.1 | CoW filesystem key recovery | `detect_cow_filesystem()` warns at startup; three-pass DoD 5220.22-M overwrite (best-effort) | `unix-oidc-agent/src/storage/secure_delete.rs` | Advisory |
| T5.2 | Swap exposure | `mlock(2)` best-effort; `mlock_probe()` at startup | `unix-oidc-agent/src/crypto/protected_key.rs:73-112` | Best-effort |
| T5.4 | Core dump key leak | `prctl(PR_SET_DUMPABLE, 0)` (Linux) / `ptrace(PT_DENY_ATTACH)` (macOS) | `unix-oidc-agent/src/security` | Best-effort |
| T6.1 | JWKS cache poisoning | JWKS fetched only from configured issuer URL over TLS; never from token claims | `pam-unix-oidc/src/oidc/jwks.rs` | Implemented |

---

## 6. Residual Risks

| ID | Risk | Severity | Acceptance Rationale |
|----|------|----------|---------------------|
| R-1 | **Process-local JTI/nonce caches** -- multi-process sshd deployments have per-process replay caches; a proof could be replayed to a sibling worker within the TTL window | Medium | sshd typically uses a single process for the authentication phase of each connection. Shared external cache adds operational complexity disproportionate to threat likelihood. DPoP proof freshness (`max_proof_age=60s`) and server-issued nonce binding limit the replay window. |
| R-2 | **Root-level key extraction** -- a compromised root can read agent memory despite `mlock`/`ZeroizeOnDrop` | High | Protecting against compromised root is out of scope (NIST SP 800-63B assumes trusted OS). Ephemeral DPoP keys and short token lifetimes limit exposure duration. HSM/TPM-backed keys are a planned future enhancement. |
| R-3 | **CoW/SSD secure deletion** -- three-pass overwrite may not destroy original blocks on APFS/btrfs or SSD with wear leveling | Medium | Documented advisory at startup per NIST SP 800-88 Rev 1, section 2.5. Full-disk encryption is the recommended mitigation. Keyring backends are preferred over file fallback. |
| R-4 | **IdP compromise** -- a compromised IdP can issue arbitrary valid tokens | Critical | Out of scope for the relying party. Mitigated by audience restriction, DPoP binding (limits token to possessing client), and short token lifetimes. Organizations should monitor IdP security posture independently. |
| R-5 | **Clock skew exploitation** -- `max_proof_age` (60s) + `clock_skew_future_secs` (5s) creates a 65-second window for proof acceptance | Low | Configurable by operator. Tighter values available for high-security deployments. NTP synchronization is a deployment prerequisite. |
| R-6 | **`dpop_required` in Warn/Disabled mode** -- bearer tokens accepted without proof-of-possession | High | Exists for IdP/client compatibility during migration. Operators must set `Strict` for production. Policy defaults to `Strict`. Documented in CLAUDE.md Security Check Decision Matrix. |
| R-7 | **JTI enforcement in Warn mode** -- tokens without JTI claim are accepted, meaning replay protection is unavailable for those tokens | Medium | Default `Warn` mode maintains v1.0 compatibility. Some IdPs omit the optional JTI claim (RFC 7519, section 4.1.7). Operators should set `Strict` when their IdP supports JTI. |
| R-8 | **ID token algorithm from header** -- `validation.rs:303` uses the token header's `alg` to select the verification algorithm rather than pinning to the JWKS-advertised algorithm | Medium | JWKS key matching by `kid` and issuer/audience validation provide defense-in-depth. Explicit cross-check recommended (see Recommendations P1-4). |

---

## 7. Recommendations

Prioritized by risk reduction impact.

### P0 -- Critical (address before production deployment)

1. **Enforce `dpop_required: strict` as the documented production default.** Ensure deployment guides, example configs, and quickstart documentation make Strict the explicit recommendation. Bearer-only mode should require deliberate opt-in with a written rationale. *(Mitigates R-6)* **Status: IMPLEMENTED** — `docs/security-guide.md` §Deployment Hardening, `examples/policy.yaml`, and `policy/config.rs` all document and default to `strict`.

2. **Add compile-time assertion that `test-mode` feature is absent in release profile.** A `#[cfg(all(feature = "test-mode", not(debug_assertions)))]` with `compile_error!` would prevent accidental release builds with signature bypass. Add a CI step that builds with `--release` and asserts the `new_insecure_for_testing` symbol is absent from the binary. *(Mitigates T4.2)* **Status: IMPLEMENTED** — `pam-unix-oidc/src/lib.rs` has `compile_error!` guard at crate root.

### P1 -- High (address in next release cycle)

3. **Externalize JTI/nonce replay cache for multi-process deployments.** Provide an optional shared-state backend (e.g., Unix domain socket to a local replay-cache sidecar, or a lightweight embedded database like `sled`) so that sshd prefork workers share a single replay cache. *(Closes R-1)* **Status:** Deferred to v2.1 (REQUIREMENTS.md SCALE-01). Current in-process moka cache is sufficient for single-process sshd deployments. The replay window is bounded by `max_proof_age=60s` and server-issued nonce binding. Multi-process deployments should use a reverse proxy or load balancer that pins connections to a single sshd worker.

4. **Pin ID token signature algorithm to the JWKS-advertised algorithm.** When a JWK is selected by `kid`, cross-check the JWK's `alg` field (if present) against the token header's `alg` before using it for verification. This prevents algorithm substitution attacks on ID tokens, analogous to the DPoP ES256 enforcement at `dpop.rs:264`. *(Closes R-8)* **Status: IMPLEMENTED** — `validation.rs:verify_and_decode()` now cross-checks `jwk.common.key_algorithm` against the token header before decoding.

5. **Implement `nbf` (not before) validation for ID tokens.** `validation.rs:308` disables `validate_nbf`. Add `nbf` validation with the same `clock_skew_tolerance_secs` applied to `exp`, preventing premature acceptance of tokens issued for future use. **Status: IMPLEMENTED** — `validate_nbf` is now enabled in `validation.rs:verify_and_decode()`.

### P2 -- Medium (address within two release cycles)

6. **Add IPC connection limits and enforce idle timeout under adversarial load** to the agent socket server. Verify `DEFAULT_IPC_IDLE_TIMEOUT_SECS` (`socket.rs:27`) is enforced and add a maximum concurrent connection limit. *(Mitigates T2.4)* **Status: IMPLEMENTED** — `socket.rs` uses `tokio::sync::Semaphore` with `MAX_CONCURRENT_CONNECTIONS=64`; idle timeout was already enforced via `tokio::time::timeout` in `handle_connection`.

7. **Implement storage backend integrity verification.** On key load from file fallback, verify a keyed MAC (e.g., HMAC-SHA256 with a machine-local secret) to detect tampering with stored key material. *(Mitigates T5.3)*

8. **Add CIBA-specific threats to this model** when CIBA backchannel authentication (`pam-unix-oidc/src/ciba/`) moves to production. CIBA introduces additional trust boundaries (backchannel notification channel, polling token endpoint) and threats (polling interception, auth_req_id replay).

### P3 -- Low (backlog / future hardening)

9. **Evaluate HSM/TPM-backed DPoP key storage** to close R-2 for high-security deployments. PKCS#11 integration would prevent key extraction even by root.

10. **Add structured threat model identifiers to audit log events** so SOC analysts can correlate detections to specific threat scenarios (e.g., `threat_id: T3.5` in a DPoP binding failure log entry).

11. **Consider `nbf` enforcement for DPoP proofs.** Currently only `iat` freshness is checked. An explicit `nbf` claim in DPoP proofs would protect against pre-generated proof stockpiling, though RFC 9449 does not mandate this claim.

---

---

## 8. Privilege Escalation Assessment (April 2026)

Three-tier adversarial review performed by Codex (source audit), validated by Claude and Gemini.

### Tier 1: Unprivileged User → Root

**Verdict: No confirmed exploit path.**

| Attack Vector | Exploitability | Impact | Mitigation |
|---------------|:---:|--------|------------|
| PAM-env token injection (`UNIX_OIDC_ACCEPT_PAM_ENV`) | Requires precondition | Arbitrary JWT fed to PAM auth — still requires valid signature, issuer, audience, username match, and SSSD existence | Explicit opt-in gate, warning logs, exact username equality, SSSD group checks |
| Break-glass OIDC bypass | Requires precondition | Widens auth surface for listed accounts — not an escalation by itself | Requires `break_glass.enabled=true` + explicit account membership |
| Session record path manipulation | Theoretical | Path traversal to overwrite arbitrary files during session lifecycle | Session ID validation (allowlist charset), 0700 dir, atomic 0600 temp file |

### Tier 2: Remote Attacker → Root

**Verdict: No confirmed exploit path.**

| Attack Vector | Exploitability | Impact | Mitigation |
|---------------|:---:|--------|------------|
| JWT forgery / algorithm confusion | Theoretical | Forged token accepted as valid | Asymmetric-only allowlist, HS*/none rejection, header/JWKS alg pinning, issuer/audience/expiry checks, unknown-issuer hard reject |
| IdP impersonation / JWKS cache poisoning | Theoretical | Attacker keys trusted for token validation | Discovery issuer must exactly match configured issuer, per-issuer JWKS registries |
| DPoP bypass for bound tokens | Theoretical | Bearer use of DPoP-bound token | Proof validation, JTI replay protection, nonce consumption, thumbprint binding |
| Test-mode shipped in production | Requires precondition | All signature verification bypassed | `compile_error!` if test-mode feature enabled in release builds |

### Tier 3: Same-User Malware → Credential/Session Abuse

**Verdict: Confirmed by design. SSH-agent trust model.**

The agent daemon treats any process running as the same UID as fully trusted. This matches OpenSSH's `ssh-agent` security model. The following primitives are available to a same-UID attacker:

| Primitive | IPC Command | Blast Radius | Mitigation |
|-----------|-------------|--------------|------------|
| **Proof issuance** | `GetProof` | Attacker gets access token + DPoP proof for attacker-chosen target | None against same-UID; hardware signers prevent key extraction but not broker-mediated signing |
| **Token refresh** | `Refresh` | Extends session lifetime, maintains persistence | Session-close cleanup eventually clears tokens |
| **Daemon shutdown** | `Shutdown` | Local DoS — user loses broker availability | Graceful drain only; no caller restriction beyond UID |
| **Credential wipe** | `SessionClosed` | Forced logout, token revocation, credential deletion | None beyond same-UID trust |
| **Step-up trigger** | `StepUp` / `StepUpResult` | Push-spam / approval fatigue; piggyback on elevated sessions | `step_up_require_id_token=true` prevents trusting unverified ACR in sudo, but doesn't prevent flow initiation |
| **Status/metrics** | `Status` / `Metrics` | Leaks username, token expiry, signer thumbprint, backend state | Same-UID-only access |

**When this matters:**
- Infostealers, malicious browser extensions, developer workstation malware
- Lateral movement as the same account
- Session hijacking within the user context

**When this is acceptable:**
- Primary goal is hardening SSH/sudo against privilege escalation (Tier 1/2)
- Users operate on managed workstations with endpoint protection
- Hardware-bound keys (TPM/YubiKey) prevent raw key extraction

**Planned mitigations (v3.1):**
1. IPC channel separation: crypto operations on user socket, admin operations on root-only socket
2. Optional per-session binding for restricted environments
3. TPM 2.0 integration makes the agent a non-exportable signing oracle

---

*Last updated: 2026-04-09. Revision required when new trust boundaries, authentication flows (e.g., CIBA production deployment), or storage backends are introduced.*
