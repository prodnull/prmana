# unix-oidc Threat Model

> **Version:** 2.0
> **Date:** 2026-03-11
> **Classification:** Public
> **Review Cycle:** Quarterly or after significant architecture changes
> **Frameworks:** STRIDE (Microsoft SDL), MITRE ATT&CK v16
> **Normative References:** RFC 9449 (DPoP), RFC 9700 (OAuth 2.0 Security BCP), RFC 7638 (JWK Thumbprint), RFC 8628 (Device Authorization Grant), CIBA Core 1.0, NIST SP 800-63B, NIST SP 800-88 Rev 1, FIPS 186-4

---

## Table of Contents

1. [System Overview and Trust Boundaries](#1-system-overview-and-trust-boundaries)
2. [STRIDE Analysis](#2-stride-analysis)
3. [MITRE ATT&CK Mapping](#3-mitre-attck-mapping)
4. [Threat Catalog](#4-threat-catalog)
5. [Specific Attack Scenarios](#5-specific-attack-scenarios)
6. [Risk Matrix](#6-risk-matrix)
7. [Recommendations](#7-recommendations)

---

## 1. System Overview and Trust Boundaries

### 1.1 System Description

unix-oidc provides OIDC-based authentication for SSH and sudo step-up on Linux/Unix systems. It replaces static SSH key-based authentication with short-lived, DPoP-bound OIDC tokens, providing centralized identity management, automated credential rotation, and centralized revocation.

### 1.2 Components

| Component | Location | Runs As | Purpose |
|-----------|----------|---------|---------|
| PAM Module (`pam_unix_oidc.so`) | Server | root (sshd process) | Validates OIDC tokens, DPoP proofs, enforces policy |
| Agent Daemon (`unix-oidc-agent`) | Client | User | Manages tokens, DPoP keys, generates proofs, CIBA step-up |
| Policy Engine | Server | root (PAM process) | YAML-based configurable security modes (Issue #10) |
| Credential Storage | Client | User | Keyring (Secret Service/keyutils/macOS Keychain) or file fallback |
| SSSD/NSS | Server | root | Unix user resolution (FreeIPA as directory authority) |
| Identity Provider (IdP) | External | N/A | Keycloak (primary), Entra ID, Okta |
| SSH Client | Client | User | Transports token + DPoP proof to server |
| SSH Server (sshd) | Server | root | Invokes PAM for authentication |

### 1.3 Data Flow

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  TB-1: USER MACHINE                                                            │
│  ┌─────────────────┐    ┌──────────────────┐                                   │
│  │ unix-oidc-agent │◄──►│ Secure Storage   │                                   │
│  │ (user daemon)   │    │ (Keychain/File)  │                                   │
│  └────────┬────────┘    └──────────────────┘                                   │
│           │ Unix Socket (TB-2)                                                  │
│  ┌────────▼────────┐                                                           │
│  │   SSH Client    │                                                           │
│  └────────┬────────┘                                                           │
└───────────┼────────────────────────────────────────────────────────────────────┘
            │ SSH + Token + DPoP Proof (TB-3: NETWORK, assumed hostile)
┌───────────▼────────────────────────────────────────────────────────────────────┐
│  TB-4: SERVER                                                                   │
│  ┌─────────────────┐    ┌──────────────────┐    ┌──────────────────┐           │
│  │   sshd          │───►│ PAM Module       │───►│ SSSD/NSS         │           │
│  │                 │    │ (pam_unix_oidc)  │    │ (user lookup)    │           │
│  └─────────────────┘    └───────┬──────────┘    └───────┬──────────┘           │
│                                 │                        │                      │
│                        TB-5: IdP Boundary        TB-6: Directory Boundary       │
└─────────────────────────────────┼────────────────────────┼──────────────────────┘
                                  ▼                        ▼
                         ┌─────────────────┐      ┌─────────────────┐
                         │ IdP (Keycloak)  │      │ FreeIPA (LDAP)  │
                         │ JWKS, Discovery │      │ User/Group DB   │
                         └─────────────────┘      └─────────────────┘
```

### 1.4 Trust Boundaries

| ID | Boundary | Trust Level | Key Assumptions |
|----|----------|-------------|-----------------|
| TB-1 | User Machine | Partially trusted | OS keychain protects secrets; user process isolation works |
| TB-2 | Agent IPC (Unix Socket) | Trusted (same user) | Socket permissions enforce owner-only access (0700) |
| TB-3 | Network | Untrusted | MITM possible; all data may be intercepted |
| TB-4 | Server | Trusted | sshd and PAM module run as root with integrity |
| TB-5 | IdP Boundary | Trusted for identity | IdP signing keys are not compromised; TLS to IdP is valid |
| TB-6 | Directory Boundary | Trusted for authorization | SSSD/FreeIPA returns correct user/group data |

### 1.5 Assets

#### Critical Assets (Compromise = Catastrophic)

| Asset | Location | Protection Mechanism |
|-------|----------|---------------------|
| DPoP Private Key | Agent memory + storage | `mlock(2)`, `ZeroizeOnDrop`, Box-only constructors, DoD 5220.22-M secure delete |
| Refresh Token | Agent storage (keyring/file) | `SecretString` wrapper, keyring backend, file mode 0600 |
| IdP Signing Key (JWKS) | IdP server | Out of scope (IdP responsibility) |
| Root Access (PAM) | Server | PAM module runs in sshd context; fail-closed design |

#### High-Value Assets

| Asset | Location | Protection Mechanism |
|-------|----------|---------------------|
| Access Token | Agent memory, SSH transport | `SecretString`, short lifetime (5-60 min), DPoP binding |
| Session State | PAM module memory | CSPRNG-generated session IDs, audit logging |
| JTI/Nonce Caches | PAM module memory | Bounded size (100K entries), TTL-based cleanup |
| Policy Configuration | Server filesystem | File permissions, figment layered config |
| OIDC Client Secret | Agent memory | `SecretString`, `expose_secret()` audit boundary |

---

## 2. STRIDE Analysis

### 2.1 Spoofing (S)

#### S-1: Forged OIDC Token

| Property | Value |
|----------|-------|
| Target | PAM Module token validation |
| Attack | Attacker crafts a JWT with forged claims |
| Mitigation Status | **Mitigated** |
| Mitigations | Mandatory JWT signature verification via JWKS (`pam-unix-oidc/src/oidc/validation.rs:151-160`); issuer validation (`validation.rs:163-168`); audience validation (`validation.rs:171-173`); algorithm enforcement restricted to ES256 for DPoP (`dpop.rs:255-257`) and JWKS-declared algorithms for ID tokens |
| Residual Risk | None under normal operation. IdP compromise would allow forged tokens. |

#### S-2: Impersonation via Stolen Token (Bearer)

| Property | Value |
|----------|-------|
| Target | SSH authentication |
| Attack | Attacker steals access token and replays it |
| Mitigation Status | **Mitigated** |
| Mitigations | DPoP binding via `cnf.jkt` claim (`auth.rs:398-408`); constant-time thumbprint comparison (`dpop.rs:360-372`); token is cryptographically bound to client's ephemeral key pair |
| Residual Risk | If DPoP is not enforced (configurable via policy), bearer token theft is possible. Policy should set `dpop_required: strict` for high-security environments. |

#### S-3: Identity Provider Spoofing

| Property | Value |
|----------|-------|
| Target | JWKS fetch / discovery |
| Attack | Attacker redirects IdP requests to a malicious server |
| Mitigation Status | **Mitigated** |
| Mitigations | TLS required for all IdP communication (`jwks.rs:216-219`); issuer URL validated against discovery document (`jwks.rs:168-173`); JWKS fetched only from configured issuer URL, never from token claims |
| Residual Risk | TLS interception proxies in enterprise environments. DNS poisoning if DNSSEC is not deployed. |

#### S-4: Username Collision via Identity Mapping

| Property | Value |
|----------|-------|
| Target | Username resolution pipeline |
| Attack | Two different IdP identities (e.g., `alice@corp.com` and `alice@evil.com`) map to the same Unix username after transforms |
| Mitigation Status | **Mitigated** |
| Mitigations | `check_collision_safety()` hard-fails on non-injective transform pipelines (`auth.rs:112-113`); `strip_domain` and `regex` transforms that discard domain information are blocked at configuration validation time |
| Residual Risk | None for configured transforms. Novel transform types added in future must be evaluated for injectivity. |

### 2.2 Tampering (T)

#### T-1: Modified Token Claims

| Property | Value |
|----------|-------|
| Target | JWT payload |
| Attack | Attacker modifies claims (username, exp, aud) in transit |
| Mitigation Status | **Mitigated** |
| Mitigations | JWT signature verification (`validation.rs:273-304`); any modification invalidates the signature |
| Residual Risk | None. This is a fundamental JWT property. |

#### T-2: DPoP Proof Tampering

| Property | Value |
|----------|-------|
| Target | DPoP proof in transit |
| Attack | Attacker modifies the DPoP proof to change target binding |
| Mitigation Status | **Mitigated** |
| Mitigations | ECDSA signature verification on the proof itself (`dpop.rs:280-282`); any modification invalidates the signature; method and target claims validated (`dpop.rs:316-329`) |
| Residual Risk | None. |

#### T-3: PAM Module Binary Tampering

| Property | Value |
|----------|-------|
| Target | `pam_unix_oidc.so` on disk |
| Attack | Attacker with root access replaces PAM module with a backdoored version |
| Mitigation Status | **Partially Mitigated** |
| Mitigations | Standard Unix file permissions; SHA-256 checksums in releases; SBOM included in releases |
| Residual Risk | An attacker with root access can replace any system binary. Binary signing (planned) and file integrity monitoring (AIDE/OSSEC) are recommended. |

#### T-4: Policy File Tampering

| Property | Value |
|----------|-------|
| Target | `/etc/unix-oidc/policy.yaml` |
| Attack | Attacker modifies policy to weaken security (e.g., `jti_enforcement: disabled`) |
| Mitigation Status | **Partially Mitigated** |
| Mitigations | File permissions (root-owned, 0644); figment config loading from fixed path (`policy/config.rs`); environment variable overrides require process-level access |
| Residual Risk | Root-level attackers can modify configuration. File integrity monitoring recommended. |

#### T-5: Agent Socket Message Injection

| Property | Value |
|----------|-------|
| Target | Unix socket IPC between SSH client and agent |
| Attack | Another process on the same machine sends crafted IPC messages to the agent socket |
| Mitigation Status | **Mitigated** |
| Mitigations | Unix socket created with owner-only permissions; agent validates all IPC messages via typed serde deserialization (`daemon/protocol.rs`); socket path in user's `XDG_RUNTIME_DIR` |
| Residual Risk | Root-level attackers can access any user's socket. |

### 2.3 Repudiation (R)

#### R-1: Denied Authentication Actions

| Property | Value |
|----------|-------|
| Target | Audit trail |
| Attack | User denies having authenticated or executed a command |
| Mitigation Status | **Mitigated** |
| Mitigations | Structured JSON audit logging to syslog (`audit.rs`); CSPRNG-generated session IDs with 64-bit entropy (`security/session.rs:40-54`); events include username, source IP, JTI, ACR, auth_time; step-up events log command and method |
| Residual Risk | Log tampering by root. Forward logs to remote SIEM for tamper-resistance. |

#### R-2: Sudo Step-Up Repudiation

| Property | Value |
|----------|-------|
| Target | Sudo audit trail |
| Attack | User executes privileged command and denies it |
| Mitigation Status | **Mitigated** |
| Mitigations | Step-up initiation, success, and failure all logged (`sudo.rs:592-621`); CIBA binding message includes command basename and hostname (`ciba/client.rs:118-134`); device flow requires explicit user interaction at IdP |
| Residual Risk | None for IdP-authenticated step-ups. |

### 2.4 Information Disclosure (I)

#### I-1: Token Leakage via Logs

| Property | Value |
|----------|-------|
| Target | Application logs, core dumps |
| Attack | Access token or DPoP key appears in logs or crash dumps |
| Mitigation Status | **Mitigated** |
| Mitigations | Access token wrapped in `secrecy::SecretString` (`daemon/socket.rs:38`); `Debug`/`Display` emit `[REDACTED]`; raw value only accessible via `expose_secret()` (two permitted audit boundaries documented); core dumps disabled via `prctl(PR_SET_DUMPABLE, 0)` on Linux and `ptrace(PT_DENY_ATTACH)` on macOS (`security.rs:28-70`) |
| Residual Risk | Core dump disabling is best-effort; container environments may override. |

#### I-2: Key Material in Swap

| Property | Value |
|----------|-------|
| Target | DPoP private key |
| Attack | Key material paged to swap, recovered from disk |
| Mitigation Status | **Partially Mitigated** |
| Mitigations | `mlock(2)` on key allocation (`crypto/protected_key.rs:190-197`); `ZeroizeOnDrop` ensures key zeroed before deallocation; Box-only constructors prevent stack copies (`protected_key.rs:174`) |
| Residual Risk | `mlock` failures (EPERM in containers, ENOMEM) are logged at WARN and non-fatal. Full-disk encryption recommended as defense in depth. |

#### I-3: Key Material on CoW/SSD Storage

| Property | Value |
|----------|-------|
| Target | Stored DPoP key and tokens on disk |
| Attack | CoW filesystem or SSD wear leveling retains copies of overwritten data |
| Mitigation Status | **Partially Mitigated (Accepted Risk)** |
| Mitigations | DoD 5220.22-M three-pass overwrite before unlink (`storage/secure_delete.rs:84-111`); CoW (btrfs/APFS) and SSD detection with WARN logging at startup and per-delete (`secure_delete.rs:144-269`); keyring backends preferred over file storage |
| Residual Risk | Overwrites may not erase all data on CoW/SSD. Full-disk encryption is the correct mitigation per NIST SP 800-88 Rev 1 section 2.5. |

#### I-4: Error Message Information Leakage

| Property | Value |
|----------|-------|
| Target | SSH client-facing error messages |
| Attack | Error messages reveal internal state (key IDs, issuer URLs, stack traces) |
| Mitigation Status | **Mitigated** |
| Mitigations | External-facing errors are generic ("Authentication failed"); detailed errors logged server-side only with structured logging; error types defined with security-appropriate messages (`validation.rs:12-54`, `dpop.rs:167-204`) |
| Residual Risk | Minimal. Some error variants (e.g., `ThumbprintMismatch`) include the values for server-side debugging but these are not exposed to clients. |

#### I-5: Client Secret Exposure in CIBA Parameters

| Property | Value |
|----------|-------|
| Target | OIDC client_secret in CIBA and device flow requests |
| Attack | Client secret logged or exposed in debug output |
| Mitigation Status | **Mitigated** |
| Mitigations | `oidc_client_secret` wrapped in `SecretString` (`daemon/socket.rs:76`); raw value accessed only at HTTP form parameter boundary |
| Residual Risk | Network-level interception of client_secret in form POST body. TLS required. |

### 2.5 Denial of Service (D)

#### D-1: JTI Cache Exhaustion

| Property | Value |
|----------|-------|
| Target | DPoP JTI cache, Token JTI cache |
| Attack | Attacker submits many unique JTIs to exhaust memory |
| Mitigation Status | **Mitigated** |
| Mitigations | DPoP JTI cache: 100K entry hard limit, forced cleanup at capacity, rejection when full after cleanup (`dpop.rs:73-87`); Token JTI cache: 100K entry limit with periodic cleanup (`jti_cache.rs:26`, `jti_cache.rs:200-212`); TTL-based automatic expiry |
| Residual Risk | An attacker sending 100K requests to fill the cache would also trigger rate limiting first. |

#### D-2: Nonce Cache Exhaustion

| Property | Value |
|----------|-------|
| Target | DPoP nonce cache |
| Attack | Attacker triggers many nonce issuances to exhaust memory |
| Mitigation Status | **Mitigated** |
| Mitigations | moka cache with bounded capacity (100K entries, 60s TTL); LRU eviction when capacity reached (`nonce_cache.rs:82-88`); nonces are server-issued, not client-controllable |
| Residual Risk | Negligible. Nonce issuance is server-controlled. |

#### D-3: Rate Limiter State Exhaustion

| Property | Value |
|----------|-------|
| Target | Per-user and per-IP rate limiter maps |
| Attack | Attacker uses many unique usernames/IPs to exhaust rate limiter memory |
| Mitigation Status | **Partially Mitigated** |
| Mitigations | TTL-based cleanup of expired entries (`rate_limit.rs:310-331`); entries auto-expire after window + lockout duration |
| Residual Risk | No hard upper bound on rate limiter HashMap size. A distributed attacker using millions of unique IPs could grow the map. Consider adding a max-entries cap. |

#### D-4: PAM Module Crash Leading to Lockout

| Property | Value |
|----------|-------|
| Target | Server SSH access |
| Attack | Malformed input causes PAM module to panic, locking out all users |
| Mitigation Status | **Mitigated** |
| Mitigations | No `unwrap()`/`expect()` in production PAM paths; all errors return PAM error codes; `SystemTime` operations use `unwrap_or_default()` (`dpop.rs:296-298`); session ID generation returns `Result` not panic (`session.rs:40`); break-glass account is mandatory deployment requirement |
| Residual Risk | Undiscovered logic bugs. Fuzz testing (`fuzz_token_parser`, `fuzz_dpop_proof`, `fuzz_policy_parser`, `fuzz_username_mapper`) mitigates this. |

#### D-5: IdP Unavailability

| Property | Value |
|----------|-------|
| Target | Authentication availability |
| Attack | IdP goes down (outage, DDoS, network partition) |
| Mitigation Status | **Mitigated** |
| Mitigations | JWKS cached with 5-minute TTL (`jwks.rs:16`); cached keys survive transient IdP failures; HTTP timeout of 10 seconds prevents indefinite blocking (`jwks.rs:19`); break-glass account provides emergency access |
| Residual Risk | Extended IdP outage beyond cache TTL. Break-glass procedures must be tested quarterly. |

### 2.6 Elevation of Privilege (E)

#### E-1: ACR Downgrade

| Property | Value |
|----------|-------|
| Target | Step-up authentication requirements |
| Attack | User authenticates with a low-assurance method (password only) when MFA is required |
| Mitigation Status | **Mitigated** |
| Mitigations | ACR validation against configured minimum (`validation.rs:237-247`); `max_auth_age` enforcement ensures fresh authentication (`validation.rs:250-267`); step-up requirements enforced per command pattern in policy |
| Residual Risk | ACR values are IdP-reported claims. If the IdP incorrectly reports ACR, the PAM module cannot detect this. |

#### E-2: Test Mode in Production

| Property | Value |
|----------|-------|
| Target | Signature verification |
| Attack | `test-mode` feature flag enabled in production build, allowing token forgery |
| Mitigation Status | **Mitigated** |
| Mitigations | `test-mode` is a compile-time feature flag (`#[cfg(feature = "test-mode")]`); requires explicit `--features test-mode` at build time; runtime check requires `UNIX_OIDC_TEST_MODE=true` or `=1` (not just presence, `sudo.rs:20-23`); CI should verify release builds exclude test features |
| Residual Risk | Operator error in build configuration. CI/CD pipeline validation recommended. |

#### E-3: Sudo Step-Up Bypass via Group Policy

| Property | Value |
|----------|-------|
| Target | Sudo step-up authentication |
| Attack | User not in authorized sudo groups attempts step-up |
| Mitigation Status | **Mitigated** |
| Mitigations | `sudo_groups` policy check runs BEFORE device flow initiation (`sudo.rs:140-159`); group membership resolved via NSS/SSSD (FreeIPA authority), not from token claims; empty `sudo_groups` list means no restriction (backward compat) |
| Residual Risk | None for configured groups. If `sudo_groups` is empty (default), all users can attempt step-up. |

#### E-4: Unauthorized IPC Commands

| Property | Value |
|----------|-------|
| Target | Agent daemon |
| Attack | Malicious process sends `Shutdown` or `StepUp` commands to agent socket |
| Mitigation Status | **Mitigated** |
| Mitigations | Unix socket ownership restricts access to the owning user; typed serde deserialization rejects malformed messages; `StepUp` requires username match with existing agent state |
| Residual Risk | Root can access any user's socket. |

---

## 3. MITRE ATT&CK Mapping

### 3.1 Initial Access (TA0001)

| Technique | ID | Relevance | unix-oidc Mitigation | File Reference |
|-----------|----|-----------|--------------------|----------------|
| Valid Accounts: Cloud Accounts | T1078.004 | Stolen OIDC tokens used for SSH | DPoP binding prevents stolen token reuse; JTI replay detection; short token lifetime | `dpop.rs:225-356`, `jti_cache.rs:107-160` |
| Phishing: Spearphishing Link | T1566.002 | Phish user's IdP credentials | Out of scope (IdP MFA responsibility); device flow URI verification reduces risk | N/A |
| External Remote Services | T1133 | SSH as entry point | PAM module enforces OIDC; DPoP binding; rate limiting | `auth.rs:92-203`, `rate_limit.rs:156-196` |
| Trusted Relationship | T1199 | Compromise IdP to access all servers | Issuer validation; JWKS from configured URL only | `jwks.rs:168-173` |

### 3.2 Execution (TA0002)

| Technique | ID | Relevance | unix-oidc Mitigation | File Reference |
|-----------|----|-----------|--------------------|----------------|
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Post-auth command execution | Sudo step-up with CIBA/device flow for privileged commands | `sudo.rs:119-184` |

### 3.3 Persistence (TA0003)

| Technique | ID | Relevance | unix-oidc Mitigation | File Reference |
|-----------|----|-----------|--------------------|----------------|
| Modify Authentication Process: Pluggable Authentication Modules | T1556.003 | Replace PAM module with backdoor | File permissions; binary checksums in releases; planned binary signing | N/A (operational control) |
| Account Manipulation: SSH Authorized Keys | T1098.004 | Add unauthorized SSH keys | unix-oidc replaces authorized_keys model; centralized IdP revocation | Architecture design |
| Valid Accounts: Cloud Accounts | T1078.004 | Persist via stolen refresh token | Refresh tokens in keyring storage; token revocation via IdP | `storage/router.rs`, `storage/keyring_store.rs` |

### 3.4 Privilege Escalation (TA0004)

| Technique | ID | Relevance | unix-oidc Mitigation | File Reference |
|-----------|----|-----------|--------------------|----------------|
| Sudo and Sudo Caching | T1548.003 | Bypass sudo step-up requirements | CIBA push/FIDO2 step-up; device flow; policy-based ACR enforcement; group policy check | `sudo.rs:119-184`, `policy/config.rs` |
| Access Token Manipulation | T1134 | Modify token claims to escalate | JWT signature verification; audience and issuer validation | `validation.rs:151-270` |

### 3.5 Defense Evasion (TA0005)

| Technique | ID | Relevance | unix-oidc Mitigation | File Reference |
|-----------|----|-----------|--------------------|----------------|
| Modify Authentication Process | T1556 | Tamper with PAM module or config | File integrity; policy config validation; fail-closed design | `policy/config.rs` |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Disable audit logging | Syslog + file audit logging; both must be suppressed; session IDs correlate across sources | `audit.rs` |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Use stolen OAuth token | DPoP binding (cnf.jkt); JTI replay protection; server nonce | `dpop.rs:225-356`, `auth.rs:398-416` |
| Indicator Removal: Clear Linux/Mac System Logs | T1070.002 | Delete audit logs | Forward to remote SIEM; syslog + file dual logging | `audit.rs` |

### 3.6 Credential Access (TA0006)

| Technique | ID | Relevance | unix-oidc Mitigation | File Reference |
|-----------|----|-----------|--------------------|----------------|
| Brute Force: Password Spraying | T1110.003 | Repeated auth attempts | Rate limiting with exponential backoff (60s to 3600s max); per-user and per-IP tracking | `rate_limit.rs:156-283` |
| Credentials from Password Stores: Keychain | T1555.001 | Extract tokens from macOS Keychain | OS keychain protection; probe-based backend detection; `mlock` for in-memory keys | `storage/router.rs:130-136`, `crypto/protected_key.rs` |
| Credentials from Password Stores: Securityd Memory | T1555.002 | Extract tokens from memory | `ZeroizeOnDrop`; `mlock`; core dump disabled; `SecretString` wrapping | `security.rs:28-70`, `crypto/protected_key.rs:153-261` |
| OS Credential Dumping: /proc/PID/mem | T1003.007 | Read agent process memory | `prctl(PR_SET_DUMPABLE, 0)` restricts `/proc/PID/mem` from non-root; `ptrace(PT_DENY_ATTACH)` on macOS | `security.rs:28-70` |
| Forge Web Credentials: Web Cookies | T1606.001 | Forge JWT tokens | Signature verification mandatory; JWKS-based key validation; algorithm enforcement | `validation.rs:273-304`, `dpop.rs:249-257` |
| Steal Application Access Token | T1528 | Intercept token during SSH auth | TLS for IdP communication; DPoP binding renders stolen token unusable without key | `dpop.rs`, `auth.rs` |
| Input Capture: Credential API Hooking | T1056.004 | Hook agent's signing operations | Box-only key constructors; `mlock`; core dump prevention | `crypto/protected_key.rs:166-261` |

### 3.7 Lateral Movement (TA0008)

| Technique | ID | Relevance | unix-oidc Mitigation | File Reference |
|-----------|----|-----------|--------------------|----------------|
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Reuse token on another server | DPoP proof bound to specific target via `htu` claim (`dpop.rs:323-329`); proof single-use via JTI cache | `dpop.rs:344-349` |
| Remote Services: SSH | T1021.004 | Pivot via SSH | Per-server DPoP binding; audience validation; step-up for sudo | `auth.rs:277-486` |
| Exploitation of Remote Services | T1210 | Exploit PAM module vulnerability | Memory-safe Rust; no `unwrap()` in PAM paths; fuzz testing | Architecture |

### 3.8 Collection (TA0009)

| Technique | ID | Relevance | unix-oidc Mitigation | File Reference |
|-----------|----|-----------|--------------------|----------------|
| Data from Local System | T1005 | Access credential files | File mode 0600; path traversal prevention in `FileStorage::key_path()` (`file_store.rs:58-61`); keyring preferred | `storage/file_store.rs:57-61` |
| Input Capture | T1056 | Capture authentication data | Token-based auth (no password typed on server); DPoP proof is single-use | Architecture |

---

## 4. Threat Catalog

### THREAT-001: Token Theft and Replay

| Property | Value |
|----------|-------|
| **ID** | THREAT-001 |
| **Category** | Spoofing, Tampering |
| **ATT&CK Technique** | T1550.001 (Use Alternate Authentication Material) |
| **Attack Surface** | Network (TB-3), Server PAM module |
| **Description** | Attacker intercepts an OIDC access token in transit (e.g., via network tap, compromised proxy) and replays it to authenticate as the victim. |
| **Likelihood** | Medium |
| **Impact** | High |
| **Risk Rating** | High |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) DPoP binding via `cnf.jkt` claim prevents use without matching private key (`auth.rs:398-408`); (2) JTI replay detection rejects second use of same token (`jti_cache.rs:107-160`, `validation.rs:186-234`); (3) Short token lifetime (5-60 min configurable at IdP); (4) Constant-time thumbprint comparison prevents timing attacks (`dpop.rs:112-117`) |
| **Residual Risk** | If DPoP is disabled (policy `dpop_required: disabled`), bearer token theft is a viable attack. Operators should enforce `dpop_required: strict` in production. |
| **Detection** | `TOKEN_VALIDATION_FAILED` audit events with `TokenReplay` reason; multiple auth attempts from different IPs with same JTI |

### THREAT-002: DPoP Proof Replay

| Property | Value |
|----------|-------|
| **ID** | THREAT-002 |
| **Category** | Spoofing |
| **ATT&CK Technique** | T1550.001 (Use Alternate Authentication Material) |
| **Attack Surface** | Network (TB-3) |
| **Description** | Attacker captures a DPoP proof and replays it with the same (also captured) access token. |
| **Likelihood** | Medium |
| **Impact** | High |
| **Risk Rating** | High |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) DPoP JTI cache rejects second use of same proof JTI within TTL window (`dpop.rs:344-349`); (2) Proof age validation rejects proofs older than `max_proof_age` (default 60s, `dpop.rs:300-305`); (3) Future-proof rejection with 5s clock skew allowance (`dpop.rs:308-313`); (4) Server nonce binding (optional, cache-backed single-use enforcement, `nonce_cache.rs:114-124`, `auth.rs:343-391`) |
| **Residual Risk** | Window of vulnerability equals `max_proof_age` (default 60s). Server nonce reduces this to single-use. |
| **Detection** | `DPoPValidationError::ReplayDetected` logged; `NonceConsumeError::ConsumedOrExpired` logged |

### THREAT-003: Algorithm Confusion / Downgrade

| Property | Value |
|----------|-------|
| **ID** | THREAT-003 |
| **Category** | Spoofing, Elevation of Privilege |
| **ATT&CK Technique** | T1606.001 (Forge Web Credentials) |
| **Attack Surface** | Token validation pipeline |
| **Description** | Attacker crafts a token with `alg: "none"` or `alg: "HS256"` (symmetric) header to bypass asymmetric signature verification. For DPoP proofs, attacker uses a weaker algorithm. |
| **Likelihood** | Medium |
| **Impact** | Critical |
| **Risk Rating** | Critical |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) DPoP proofs: only ES256 accepted (`dpop.rs:255-257`); any other algorithm rejected with `UnsupportedAlgorithm` error; (2) DPoP JWK: kty must be "EC" and crv must be "P-256" (`dpop.rs:375-379`); (3) ID tokens: algorithm determined from JWKS, not token header (server controls which algorithms are acceptable); (4) JWK thumbprint computation uses hardcoded canonical values for kty/crv, not user-supplied values (`dpop.rs:406-418`) |
| **Residual Risk** | None for DPoP proofs. ID token algorithm depends on JWKS key type; the `jsonwebtoken` crate validates against the `Validation` object which is configured from server-side settings. |
| **Detection** | `UnsupportedAlgorithm` errors in logs |

### THREAT-004: Identity Provider Compromise

| Property | Value |
|----------|-------|
| **ID** | THREAT-004 |
| **Category** | Spoofing |
| **ATT&CK Technique** | T1199 (Trusted Relationship) |
| **Attack Surface** | TB-5: IdP trust boundary |
| **Description** | Attacker compromises the IdP and obtains the token signing private key, enabling forging of arbitrary tokens. |
| **Likelihood** | Low |
| **Impact** | Critical |
| **Risk Rating** | High |
| **Mitigation Status** | Accepted Risk |
| **Mitigations** | (1) Issuer validation restricts accepted tokens to configured IdP (`validation.rs:163-168`); (2) Audience validation limits scope (`validation.rs:171-173`); (3) Break-glass account provides emergency access without IdP; (4) Federation limits blast radius to configured issuer |
| **Residual Risk** | Total authentication bypass for the compromised IdP's users. This is an inherent risk of federated identity. Incident response: disable PAM module, fall back to break-glass, wait for IdP key rotation. |
| **Detection** | Anomalous authentication patterns; tokens with unusual claims; IdP security monitoring |

### THREAT-005: Man-in-the-Middle on Token Transport

| Property | Value |
|----------|-------|
| **ID** | THREAT-005 |
| **Category** | Information Disclosure, Tampering |
| **ATT&CK Technique** | T1557 (Adversary-in-the-Middle) |
| **Attack Surface** | TB-3: Network |
| **Description** | Attacker intercepts the SSH connection and extracts the token and DPoP proof from the authentication exchange. |
| **Likelihood** | Medium |
| **Impact** | Medium |
| **Risk Rating** | Medium |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) SSH transport encrypts the authentication exchange; (2) DPoP proof is bound to specific target server (`htu` claim); captured proof is useless against a different server; (3) Proof is single-use (JTI replay protection); (4) Token is DPoP-bound; unusable without the private key even if intercepted; (5) IdP communication uses TLS |
| **Residual Risk** | SSH MITM that terminates the SSH session and proxies authentication to the real server in real-time. This is outside unix-oidc's control (SSH host key verification responsibility). |
| **Detection** | SSH host key verification warnings; anomalous DPoP proof targets |

### THREAT-006: Memory Forensics / Key Extraction

| Property | Value |
|----------|-------|
| **ID** | THREAT-006 |
| **Category** | Information Disclosure |
| **ATT&CK Technique** | T1003.007 (OS Credential Dumping: Proc Filesystem) |
| **Attack Surface** | TB-1: User machine (agent process) |
| **Description** | Attacker with elevated access dumps agent process memory to extract DPoP private key and/or access token. |
| **Likelihood** | Medium (requires elevated access) |
| **Impact** | High |
| **Risk Rating** | High |
| **Mitigation Status** | Partially Mitigated |
| **Mitigations** | (1) `mlock(2)` prevents swap-out of key pages (`protected_key.rs:190-197`); (2) `ZeroizeOnDrop` zeroes key bytes before deallocation; (3) Core dumps disabled via `prctl(PR_SET_DUMPABLE, 0)` / `ptrace(PT_DENY_ATTACH)` (`security.rs:28-70`); (4) Box-only constructors prevent stack copies (`protected_key.rs:174`); (5) `SecretString` wrapping for tokens prevents logging leaks; (6) `export_key()` returns `Zeroizing<Vec<u8>>` for automatic cleanup |
| **Residual Risk** | `mlock` is best-effort (may fail in containers). Root/kernel-level access can always read process memory. Volatile writes by `zeroize` cannot guarantee zeroing in all compiler/architecture combinations. Hardware-backed keys (YubiKey, TPM) eliminate software key extraction entirely. |
| **Detection** | Anomalous process access patterns; unexpected `ptrace` calls |

### THREAT-007: Storage Backend Compromise

| Property | Value |
|----------|-------|
| **ID** | THREAT-007 |
| **Category** | Information Disclosure |
| **ATT&CK Technique** | T1555.001 (Credentials from Password Stores: Keychain) |
| **Attack Surface** | TB-1: User machine credential storage |
| **Description** | Attacker extracts DPoP private key or refresh token from the credential storage backend (keyring or file). |
| **Likelihood** | Medium |
| **Impact** | High |
| **Risk Rating** | High |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) Probe-based backend detection with priority chain: Secret Service > keyutils > macOS Keychain > file fallback (`router.rs:130-136`); (2) File storage: mode 0600, path traversal prevention (`file_store.rs:57-61`, `file_store.rs:70-74`); (3) DoD 5220.22-M three-pass secure delete for file backend (`secure_delete.rs:84-111`); (4) Atomic migration with rollback when upgrading backends (`router.rs:178-264`); (5) Forced backend contract: `UNIX_OIDC_STORAGE_BACKEND` failures are hard errors, not fallback (`router.rs:332-442`); (6) CoW/SSD advisory logging (`secure_delete.rs:144-269`) |
| **Residual Risk** | File fallback in headless environments stores secrets in plaintext files (mode 0600). Keyring backends delegate security to OS keyring implementation. |
| **Detection** | Unusual keyring access patterns; file access audit (`auditd`) |

### THREAT-008: CIBA Channel Hijacking

| Property | Value |
|----------|-------|
| **ID** | THREAT-008 |
| **Category** | Spoofing, Elevation of Privilege |
| **ATT&CK Technique** | T1539 (Steal Web Session Cookie) |
| **Attack Surface** | CIBA backchannel authentication |
| **Description** | Attacker hijacks the CIBA authentication request to approve a step-up request intended for a different user or command, or replays the `auth_req_id` to obtain a token. |
| **Likelihood** | Low |
| **Impact** | High |
| **Risk Rating** | Medium |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) CIBA binding message includes command basename and hostname, visible in authenticator UI (`ciba/client.rs:118-134`); (2) Command arguments stripped from binding message to prevent sensitive data leakage; (3) `auth_req_id` is opaque to the PAM module and consumed by IdP's token endpoint only; (4) Step-up correlation ID tracked in agent with timeout (`daemon/socket.rs:85-92`); (5) CIBA token response validated with standard token validation pipeline |
| **Residual Risk** | Push notification fatigue (user approves without reading). Binding message is capped at 64 characters, which may truncate useful context on long hostnames. |
| **Detection** | Step-up initiation without corresponding user activity; `STEP_UP_FAILED` audit events |

### THREAT-009: Sudo Step-Up Bypass

| Property | Value |
|----------|-------|
| **ID** | THREAT-009 |
| **Category** | Elevation of Privilege |
| **ATT&CK Technique** | T1548.003 (Sudo and Sudo Caching) |
| **Attack Surface** | Sudo step-up authentication pipeline |
| **Description** | User bypasses step-up authentication to execute privileged commands: (a) by manipulating policy config, (b) by exploiting race conditions in the IPC poll loop, or (c) by authenticating as a different user during device flow. |
| **Likelihood** | Low |
| **Impact** | High |
| **Risk Rating** | Medium |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) Username mismatch check: token user must match sudo user (`sudo.rs:497-502`); (2) Group policy check runs BEFORE device flow to prevent wasted IdP interactions (`sudo.rs:140-159`); (3) IPC poll loop has a PAM-side deadline (`sudo.rs:290-291`); (4) Agent socket timeout of 2 seconds prevents indefinite blocking (`sudo.rs:385-390`); (5) Policy-based method selection (Push > FIDO2 > DeviceFlow, `sudo.rs:197-217`) |
| **Residual Risk** | If policy file is writable by the user, they can disable step-up. Policy file must be root-owned. |
| **Detection** | `STEP_UP_FAILED` audit events with `UserMismatch` reason; `GroupDenied` events |

### THREAT-010: Clock Skew Exploitation

| Property | Value |
|----------|-------|
| **ID** | THREAT-010 |
| **Category** | Spoofing, Elevation of Privilege |
| **ATT&CK Technique** | T1550.001 (Use Alternate Authentication Material) |
| **Attack Surface** | Token and proof time validation |
| **Description** | Attacker exploits clock skew between client, server, and IdP to extend token validity or use expired tokens. |
| **Likelihood** | Low |
| **Impact** | Medium |
| **Risk Rating** | Low |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) Token expiration checked with 60-second clock skew tolerance (`validation.rs:101`, `validation.rs:177-179`); (2) DPoP proof age checked with configurable `max_proof_age` (default 60s, `dpop.rs:300-305`); (3) Future-dated proofs rejected (5s tolerance, `dpop.rs:308-313`); (4) Auth_time validation with clock skew tolerance (`validation.rs:254-256`); (5) Severely misconfigured clocks (pre-1970) handled gracefully with `unwrap_or_default()` (`dpop.rs:295-298`) |
| **Residual Risk** | Clock skew tolerance windows are necessary for interoperability. NTP synchronization is an operational requirement. |
| **Detection** | `ProofExpired` errors with `iat` and `now` values logged; cluster-wide NTP monitoring |

### THREAT-011: JTI Cache Exhaustion DoS

| Property | Value |
|----------|-------|
| **ID** | THREAT-011 |
| **Category** | Denial of Service |
| **ATT&CK Technique** | T1499.003 (Application Exhaustion Flood) |
| **Attack Surface** | PAM module JTI and nonce caches |
| **Description** | Attacker sends a flood of unique authentication attempts to fill JTI caches, causing legitimate requests to be rejected when the cache is full. |
| **Likelihood** | Low |
| **Impact** | Medium |
| **Risk Rating** | Low |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) DPoP JTI cache: forced cleanup at capacity, then rejection if still full (`dpop.rs:73-87`); this causes a temporary DoS for new DPoP proofs but existing sessions are unaffected; (2) Token JTI cache: 100K limit with periodic cleanup (`jti_cache.rs:26`); (3) Rate limiting triggers before cache exhaustion (5 attempts per window, `rate_limit.rs:31-32`); (4) Nonce cache uses moka with LRU eviction (`nonce_cache.rs:82-88`), so old entries are evicted rather than new ones rejected |
| **Residual Risk** | Under sustained attack (100K+ concurrent legitimate users), the DPoP JTI cache could reject valid proofs. This scenario implies the server is already under extreme load. |
| **Detection** | "DPoP JTI cache at capacity" WARN log; rate limiter trigger counts; connection rate monitoring |

### THREAT-012: Race Conditions in Concurrent Auth

| Property | Value |
|----------|-------|
| **ID** | THREAT-012 |
| **Category** | Spoofing |
| **ATT&CK Technique** | T1550.001 (Use Alternate Authentication Material) |
| **Attack Surface** | JTI cache, nonce cache |
| **Description** | Two concurrent authentication requests race to check and record the same JTI or nonce, potentially allowing a replay. |
| **Likelihood** | Low |
| **Impact** | High |
| **Risk Rating** | Medium |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) DPoP JTI cache uses read-then-write-with-double-check pattern under `RwLock` (`dpop.rs:52-69`); write lock re-checks before insert; (2) Token JTI cache uses the same double-check locking (`jti_cache.rs:124-157`); (3) Nonce cache uses moka's `Cache::remove()` which is atomic test-and-delete, eliminating TOCTOU (`nonce_cache.rs:118-124`); (4) Concurrent nonce consumption tested (`nonce_cache.rs:316-349`): exactly one succeeds, one fails |
| **Residual Risk** | Negligible. The double-check locking pattern and atomic moka operations prevent known race conditions. |
| **Detection** | N/A (prevented at the code level) |

### THREAT-013: Supply Chain Attack

| Property | Value |
|----------|-------|
| **ID** | THREAT-013 |
| **Category** | Tampering |
| **ATT&CK Technique** | T1195.002 (Supply Chain Compromise: Software Supply Chain) |
| **Attack Surface** | Build dependencies, crates.io |
| **Description** | Malicious or compromised dependency introduces backdoor or vulnerability. |
| **Likelihood** | Low |
| **Impact** | Critical |
| **Risk Rating** | High |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) `cargo audit` in CI; (2) `dependency-review` GitHub Action for PRs; (3) `--locked` builds with checked-in `Cargo.lock`; (4) SBOM generation (CycloneDX); (5) SHA-256 checksums in releases; (6) Dependency evaluation criteria documented in CLAUDE.md; (7) Trusted core dependencies: `ring`/`rustls` (crypto), `jsonwebtoken` (JWT), `tokio` (async), `p256`/`ecdsa` (ECDSA) |
| **Residual Risk** | Zero-day in a trusted dependency before advisory publication. `cargo audit` can only detect known vulnerabilities. |
| **Detection** | `cargo audit` CI failures; Dependabot/Renovate alerts; GitHub security advisories |

### THREAT-014: Break-Glass Abuse

| Property | Value |
|----------|-------|
| **ID** | THREAT-014 |
| **Category** | Elevation of Privilege |
| **ATT&CK Technique** | T1078.003 (Valid Accounts: Local Accounts) |
| **Attack Surface** | Break-glass account |
| **Description** | Attacker obtains break-glass credentials and uses them for unauthorized access, bypassing all OIDC controls. |
| **Likelihood** | Low |
| **Impact** | Critical |
| **Risk Rating** | High |
| **Mitigation Status** | Partially Mitigated |
| **Mitigations** | (1) Break-glass credentials stored in secure vault (operational requirement); (2) Separate from IdP (survives IdP compromise); (3) Hardware tokens (YubiKey) recommended for break-glass; (4) Break-glass use should be monitored and alerted |
| **Residual Risk** | Break-glass accounts inherently bypass OIDC controls. This is by design for availability, but creates an attack vector. Vault compromise, credential sharing, or insider abuse are risks. |
| **Detection** | Local password authentication logs (break-glass use is anomalous); SIEM alerting on break-glass account login; quarterly DR exercises verify break-glass access and audit trail |

### THREAT-015: Path Traversal in File Storage

| Property | Value |
|----------|-------|
| **ID** | THREAT-015 |
| **Category** | Information Disclosure, Tampering |
| **ATT&CK Technique** | T1005 (Data from Local System) |
| **Attack Surface** | File storage backend |
| **Description** | Attacker injects path traversal characters (e.g., `../../../etc/passwd`) into storage key names to read or write arbitrary files. |
| **Likelihood** | Low (key names are internally controlled) |
| **Impact** | High |
| **Risk Rating** | Low |
| **Mitigation Status** | Mitigated |
| **Mitigations** | `FileStorage::key_path()` sanitizes key names by replacing `/`, `\`, and `.` with `_` (`file_store.rs:58-61`); result is verified to start with `base_dir` in tests (`file_store.rs:211-215`) |
| **Residual Risk** | None. Key names are hardcoded constants (`KEY_DPOP_PRIVATE`, `KEY_ACCESS_TOKEN`, etc.), not user-controlled. |
| **Detection** | N/A (prevented at the code level) |

### THREAT-016: DPoP Proof Pre-Computation

| Property | Value |
|----------|-------|
| **ID** | THREAT-016 |
| **Category** | Spoofing |
| **ATT&CK Technique** | T1550.001 (Use Alternate Authentication Material) |
| **Attack Surface** | DPoP proof validation |
| **Description** | Attacker with access to the DPoP private key pre-computes proofs for future use, bypassing the requirement for fresh proof generation. |
| **Likelihood** | Low (requires key access) |
| **Impact** | High |
| **Risk Rating** | Medium |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) Proof `iat` must be within `max_proof_age` of current time (`dpop.rs:300-305`); (2) Server nonce binding (when enabled) requires the server-issued nonce, which the attacker cannot predict (`nonce_cache.rs`); (3) JTI uniqueness prevents reuse of pre-computed proofs (`dpop.rs:344-349`) |
| **Residual Risk** | An attacker with the private key can generate proofs in real-time. Key theft is the root issue (see THREAT-006). |
| **Detection** | Unusual proof timing patterns; proofs with `iat` clustering |

### THREAT-017: Agent IPC Protocol Injection

| Property | Value |
|----------|-------|
| **ID** | THREAT-017 |
| **Category** | Tampering, Elevation of Privilege |
| **ATT&CK Technique** | T1559.001 (Inter-Process Communication: Component Object Model) |
| **Attack Surface** | TB-2: Agent Unix socket |
| **Description** | Malicious process sends crafted JSON messages to the agent socket to trigger unauthorized operations (Shutdown, StepUp, GetProof for attacker-controlled target). |
| **Likelihood** | Low (requires same-user access) |
| **Impact** | Medium |
| **Risk Rating** | Low |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) Socket in `XDG_RUNTIME_DIR` with owner-only permissions; (2) Typed serde deserialization (`AgentRequest` enum, `daemon/protocol.rs:8-70`) rejects unrecognized actions; (3) Socket read/write timeouts (2s) prevent hanging; (4) `StepUp` requests include username for verification against agent state |
| **Residual Risk** | A compromised process running as the same user has full access to the agent. Root processes can access any user's socket. |
| **Detection** | Unexpected agent operations in logs; `StepUp` for commands the user did not invoke |

### THREAT-018: Refresh Token Persistence Attack

| Property | Value |
|----------|-------|
| **ID** | THREAT-018 |
| **Category** | Persistence |
| **ATT&CK Technique** | T1078.004 (Valid Accounts: Cloud Accounts) |
| **Attack Surface** | Credential storage |
| **Description** | Attacker steals the refresh token to maintain persistent access, generating new access tokens even after password change. |
| **Likelihood** | Medium |
| **Impact** | High |
| **Risk Rating** | High |
| **Mitigation Status** | Mitigated |
| **Mitigations** | (1) Keyring storage preferred (OS-level protection); (2) Refresh tokens can be revoked at IdP (`revocation_endpoint` in OIDC discovery, `jwks.rs:73`); (3) Token revocation on session close (`protocol.rs:43-46`); (4) Secure delete on credential removal; (5) Atomic migration with rollback when changing storage backends (`router.rs:178-264`) |
| **Residual Risk** | Stolen refresh token is valid until IdP-side revocation or expiry. Detection depends on IdP monitoring for anomalous refresh patterns. |
| **Detection** | Refresh token use from unusual IP/device; IdP audit logs for token grants |

---

## 5. Specific Attack Scenarios

### 5.1 Scenario: Token Theft and Replay (End-to-End)

**Attacker Profile:** Network-positioned adversary or compromised intermediate host.

**Attack Steps:**
1. Attacker positions themselves on the network path between client and server (e.g., ARP spoofing, compromised switch).
2. SSH connection is observed; attacker extracts the access token and DPoP proof from the keyboard-interactive exchange.
3. Attacker attempts to use the stolen token + proof on the same server.
4. Attacker attempts to use the stolen token on a different server.

**Defense Chain:**
- Step 2: SSH encryption prevents extraction in most scenarios. If SSH MITM succeeds:
- Step 3: DPoP proof JTI is already consumed in the cache; `ReplayDetected` error returned.
- Step 4: DPoP proof `htu` claim binds to specific target; `TargetMismatch` error returned. Even if a new proof is crafted, the attacker does not possess the DPoP private key; `InvalidSignature` error.

**Verdict:** Attack fails at multiple layers. DPoP binding is the primary defense.

### 5.2 Scenario: Algorithm Confusion Attack

**Attacker Profile:** Cryptographic attacker with knowledge of JWT vulnerabilities.

**Attack Steps:**
1. Attacker crafts a DPoP proof with `alg: "none"` to bypass signature verification.
2. Alternatively, attacker crafts a proof with `alg: "HS256"` using the public key as the HMAC secret.
3. Attacker crafts an ID token with `alg: "HS256"`.

**Defense Chain:**
- Step 1: `dpop.rs:255-257` checks `alg != "ES256"` and returns `UnsupportedAlgorithm`.
- Step 2: Same check rejects HS256 for DPoP proofs.
- Step 3: ID token validation uses `jsonwebtoken` crate with `Validation::new(algorithm)` where `algorithm` is from the JWKS header. The server controls which key types are in the JWKS; HS256 keys are not published in JWKS.

**Verdict:** Attack fails. Algorithm enforcement is non-negotiable.

### 5.3 Scenario: IdP Compromise

**Attacker Profile:** Advanced persistent threat with access to IdP infrastructure.

**Attack Steps:**
1. Attacker compromises IdP and obtains the RS256/ES256 signing key.
2. Attacker forges tokens with arbitrary claims (any username, any audience, long expiry).
3. Attacker uses forged tokens to authenticate to all servers trusting this IdP.

**Defense Chain:**
- Steps 1-3: All succeed. The forged tokens pass all validation checks because the signing key is legitimate.
- **Detection:** Anomalous login patterns (time, geography, frequency); tokens with unusual `auth_time` values; JWKS key rotation events at the IdP.
- **Response:** (1) Disable PAM module (`sed -i 's/^auth.*pam_unix_oidc/#&/' /etc/pam.d/sshd`); (2) Activate break-glass account; (3) Wait for IdP key rotation; (4) Re-enable after confirmed remediation.

**Verdict:** IdP compromise is a catastrophic but accepted risk. Break-glass procedures are the primary control.

### 5.4 Scenario: Memory Forensics Key Extraction

**Attacker Profile:** Insider or attacker with root access to client machine.

**Attack Steps:**
1. Attacker runs `gcore <pid>` or reads `/proc/<pid>/mem` to dump agent memory.
2. Attacker scans memory dump for P-256 private key material (32 bytes).
3. Attacker extracts the DPoP private key and uses it to generate proofs.

**Defense Chain:**
- Step 1: `prctl(PR_SET_DUMPABLE, 0)` prevents `gcore` and restricts `/proc/PID/mem` on Linux. `ptrace(PT_DENY_ATTACH)` on macOS prevents debugger attach. Both are best-effort.
- Step 2: `mlock(2)` prevents key pages from being swapped to disk. `ZeroizeOnDrop` zeroes key material on struct drop.
- Step 3: If steps 1-2 fail and the key is extracted, attacker can generate valid proofs for the lifetime of the stolen access token.

**Stronger Alternatives:**
- YubiKey PIV (`crypto/yubikey_signer.rs`): Private key never leaves hardware.
- TPM (`crypto/tpm_signer.rs`): Key bound to platform hardware.

**Verdict:** Software-only key protection is defense-in-depth, not a guarantee against privileged attackers. Hardware-backed keys are recommended for high-security environments.

### 5.5 Scenario: CIBA Push Notification Fatigue

**Attacker Profile:** Attacker who has obtained valid credentials or session on the user's machine.

**Attack Steps:**
1. Attacker triggers repeated sudo step-up requests via CIBA push.
2. User receives multiple push notifications and eventually approves one without reading the binding message.
3. Attacker's privileged command executes with step-up authentication.

**Defense Chain:**
- Step 1: Rate limiting on the server side; group policy check (`sudo.rs:140-159`) rejects unauthorized users before CIBA is initiated.
- Step 2: Binding message shows command basename and hostname (`ciba/client.rs:118-134`), truncated to 64 characters per CIBA spec.
- Step 3: Username match verification (`sudo.rs:497-502`) ensures the authenticating user is the same as the sudo user.

**Verdict:** Push fatigue is a known risk with any push-based MFA. The binding message and username verification reduce (but do not eliminate) the risk. FIDO2 step-up requires physical interaction, making it resistant to fatigue attacks.

### 5.6 Scenario: PAM Module Crash Leading to Lockout

**Attacker Profile:** Network attacker sending malformed authentication data.

**Attack Steps:**
1. Attacker sends malformed tokens, DPoP proofs, or oversized payloads.
2. PAM module panics, causing sshd worker to crash.
3. Repeated crashes exhaust sshd's connection handling.

**Defense Chain:**
- Step 1: All parsing uses `Result`-based error handling, never `unwrap()` in PAM paths. `SystemTime` operations use `unwrap_or_default()`.
- Step 2: No panic paths in production PAM code. All errors return PAM error codes gracefully.
- Step 3: Rate limiting prevents rapid-fire attempts. Fuzz testing covers parser edge cases.
- Step 4: Break-glass account provides emergency access regardless of PAM module state.

**Verdict:** Rust's type system and deliberate `Result`-based design make panic-induced lockout extremely unlikely. Fuzz testing provides additional assurance.

---

## 6. Risk Matrix

### 6.1 Summary by Risk Level and Mitigation Status

| | Mitigated | Partially Mitigated | Accepted Risk |
|---|---|---|---|
| **Critical** | THREAT-003 (Algorithm Confusion), THREAT-013 (Supply Chain) | | THREAT-004 (IdP Compromise) |
| **High** | THREAT-001 (Token Replay), THREAT-002 (DPoP Replay), THREAT-007 (Storage Compromise), THREAT-018 (Refresh Persistence) | THREAT-006 (Memory Forensics), THREAT-014 (Break-Glass Abuse) | |
| **Medium** | THREAT-005 (MITM), THREAT-008 (CIBA Hijacking), THREAT-009 (Step-Up Bypass), THREAT-012 (Race Conditions), THREAT-016 (Proof Pre-Computation) | | |
| **Low** | THREAT-010 (Clock Skew), THREAT-011 (JTI Cache DoS), THREAT-015 (Path Traversal), THREAT-017 (IPC Injection) | THREAT-D3 (Rate Limiter Exhaustion) | |

### 6.2 STRIDE Coverage Summary

| STRIDE Category | Threats Identified | Mitigated | Partially Mitigated | Accepted |
|----------------|-------------------|-----------|--------------------|---------:|
| Spoofing | 7 | 5 | 1 | 1 |
| Tampering | 5 | 4 | 1 | 0 |
| Repudiation | 2 | 2 | 0 | 0 |
| Information Disclosure | 5 | 3 | 2 | 0 |
| Denial of Service | 5 | 4 | 1 | 0 |
| Elevation of Privilege | 4 | 3 | 1 | 0 |

### 6.3 ATT&CK Technique Coverage

| Tactic | Techniques Mapped | Mitigation Coverage |
|--------|-------------------|-------------------|
| Initial Access (TA0001) | 4 | 3 mitigated, 1 out-of-scope |
| Execution (TA0002) | 1 | 1 mitigated |
| Persistence (TA0003) | 3 | 2 mitigated, 1 partially |
| Privilege Escalation (TA0004) | 2 | 2 mitigated |
| Defense Evasion (TA0005) | 4 | 3 mitigated, 1 operational |
| Credential Access (TA0006) | 7 | 5 mitigated, 2 partially |
| Lateral Movement (TA0008) | 3 | 3 mitigated |
| Collection (TA0009) | 2 | 2 mitigated |

---

## 7. Recommendations

### 7.1 Priority 1: Critical (Address Before Production)

| # | Recommendation | Threat | Effort |
|---|---------------|--------|--------|
| R-1 | **Enforce `dpop_required: strict` in default policy template.** Current default is configurable/warn, which allows bearer token use. Production deployments should always require DPoP. | THREAT-001 | Low (config change) |
| R-2 | **Add hard upper bound to rate limiter HashMap.** Current implementation has no cap on unique user/IP entries. Add a max-entries limit with LRU eviction similar to the nonce cache. | THREAT-D3 | Medium (code change) |
| R-3 | **CI check: verify release builds exclude `test-mode` feature.** A misconfigured release pipeline could ship with signature bypass enabled. | THREAT-E2 | Low (CI config) |

### 7.2 Priority 2: High (Address Within 90 Days)

| # | Recommendation | Threat | Effort |
|---|---------------|--------|--------|
| R-4 | **Implement binary signing for PAM module releases.** SHA-256 checksums are provided but not cryptographically signed. Code signing (e.g., Sigstore/cosign) would detect tampering. | THREAT-T3 | Medium |
| R-5 | **Add server-side nonce as default-on for DPoP.** Currently optional; when enabled, reduces replay window from `max_proof_age` to single-use. | THREAT-002 | Medium (config + deployment) |
| R-6 | **Document and automate break-glass credential rotation.** Break-glass abuse (THREAT-014) is partially mitigated; automated rotation and monitoring would strengthen controls. | THREAT-014 | Medium (operational) |
| R-7 | **Add file integrity monitoring guidance for PAM module and policy file.** Recommend AIDE/OSSEC configuration in deployment guide. | THREAT-T3, THREAT-T4 | Low (docs) |

### 7.3 Priority 3: Medium (Address Within 180 Days)

| # | Recommendation | Threat | Effort |
|---|---------------|--------|--------|
| R-8 | **Implement distributed JTI cache.** In-memory caches are lost on process restart and are single-server. Redis or similar backend would survive restarts and support multi-server deployments. | THREAT-001, THREAT-002 | High |
| R-9 | **Add Prometheus metrics for security events.** Rate limiter triggers, replay detections, and cache capacity warnings should be exposed as Prometheus counters for SIEM integration. | Detection improvement | Medium |
| R-10 | **Evaluate FIPS-validated Rust crypto libraries.** Current P-256 implementation uses FIPS 186-4 approved curves but not a FIPS-validated module. FedRAMP environments may require this. | Compliance | High |
| R-11 | **Consider hardware key attestation.** When YubiKey/TPM signers are used, attestation certificates can prove to the server that the key is hardware-backed. | THREAT-006 | High |

### 7.4 Priority 4: Low (Track and Plan)

| # | Recommendation | Threat | Effort |
|---|---------------|--------|--------|
| R-12 | **Post-quantum algorithm agility.** ES256 (P-256) will need replacement when quantum computers become practical. Ensure algorithm selection is configuration-driven, not hardcoded. | Future-proofing | High |
| R-13 | **Agent socket authentication.** Add optional peer credential verification (`SO_PEERCRED`) for the Unix socket to detect cross-user access attempts. | THREAT-017 | Low |
| R-14 | **Implement token binding for non-DPoP scenarios.** For environments where DPoP is not feasible, alternative token binding mechanisms (mTLS, token binding over SSH) could provide similar protections. | THREAT-001 (alternative) | High |

---

## Appendix A: References

| Reference | Identifier | Relevance |
|-----------|-----------|-----------|
| DPoP Specification | RFC 9449 | Core token binding mechanism |
| OAuth 2.0 Security BCP | RFC 9700 | Security best practices for OAuth deployments |
| JWK Thumbprint | RFC 7638 | Key identification for DPoP binding |
| Device Authorization Grant | RFC 8628 | Sudo step-up device flow |
| CIBA Core | OpenID Connect CIBA Core 1.0 | Push-based step-up authentication |
| Digital Identity Guidelines | NIST SP 800-63B | Authentication assurance levels |
| Media Sanitization | NIST SP 800-88 Rev 1 | Secure deletion guidance (section 2.5) |
| STRIDE | Microsoft SDL Threat Modeling | Systematic threat categorization |
| ATT&CK | MITRE ATT&CK v16 | Adversary technique taxonomy |
| Digital Signature Standard | FIPS 186-4 | P-256 curve specification |

## Appendix B: Threat Model Scope Exclusions

The following are explicitly out of scope for this threat model:

1. **IdP internal security** -- Keycloak/Entra/Okta hardening is the IdP team's responsibility.
2. **SSSD/FreeIPA vulnerabilities** -- Standard Linux component; platform team responsibility.
3. **SSH protocol vulnerabilities** -- OpenSSH hardening is a separate concern.
4. **Endpoint security** -- Antivirus, EDR, device compliance are endpoint team responsibility.
5. **Physical security** -- Physical access to servers or client machines.
6. **Social engineering** -- Phishing for IdP credentials (mitigated by IdP MFA).
7. **Insider threat with root access** -- A root-level attacker can bypass any user-space control. Defense is host hardening, not application-layer auth.

## Appendix C: Review History

| Date | Reviewer | Changes |
|------|----------|---------|
| 2026-01-17 | Initial creation | Basic threat model |
| 2026-01-17 | Marcus Chen (adversarial review) | Security hardening items |
| 2026-01-18 | Supply chain review | cargo audit, SBOM, checksums |
| 2026-03-11 | Comprehensive rewrite | Full STRIDE + ATT&CK mapping; 18-threat catalog with file references; attack scenarios; risk matrix; prioritized recommendations |
