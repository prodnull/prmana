# Adversarial Design Review: prmana

> **Methodology**: Three independent expert personas each examined the prmana architecture from an adversarial angle. Each persona identified threats and gaps specific to their concern model. A cross-examination table consolidates findings, followed by prioritized recommendations. This review covers v2.0 (50/50 requirements complete) and is intended for iterative update as the system evolves.

---

## Persona 1: Red Team Attacker

*Concern model: exploit authentication bypass, credential theft, replay, denial of service, supply chain compromise.*

### IPC Socket Attacks

**SO_PEERCRED / getpeereid peer validation — MITIGATED**
The agent daemon validates the UID of every connecting process via `SO_PEERCRED` (Linux) or `getpeereid` (macOS) before processing any IPC request. An attacker running as a different UID cannot impersonate a legitimate session.

**Symlink race on socket path — LIMITED**
An attacker could attempt to swap the socket path for a symlink between daemon bind and client connect. However, exploiting this requires the attacker to already run as the same UID as the victim, at which point they have equivalent access to the agent state through other means. Residual risk is low.

**Connection exhaustion — MITIGATED**
Idle timeout enforcement on IPC connections prevents a malicious or buggy client from holding connections open indefinitely and starving legitimate callers.

---

### Token/DPoP Attacks

**Bearer token theft without DPoP key — MITIGATED**
When `dpop_required` is set to `Strict`, a stolen access token is cryptographically useless without the corresponding DPoP private key. The token's `cnf.jkt` claim binds it to an ephemeral key pair that never leaves the agent. An attacker who exfiltrates a token from network traffic or logs gains nothing.

**DPoP proof replay — MITIGATED**
Three independent controls prevent replay:
1. `jti` uniqueness enforced via bounded in-memory cache (moka, 10k entries with TTL).
2. Server-issued nonces (RFC 9449 §8) bind each proof to a server-controlled challenge.
3. `iat` freshness check rejects proofs older than the configured staleness window.

**Algorithm confusion (alg:none, HMAC confusion) — MITIGATED**
DPoP proofs are pinned to ES256. The validator explicitly rejects any proof header with a different `alg` value, including `none` and all symmetric algorithms. This prevents the well-documented algorithm confusion attack class (CVE-2015-9235 family).

**Key extraction from memory — MITIGATED with residual risk**
Multiple controls reduce key lifetime in memory:
- `mlock(2)` pins key pages to RAM, preventing swap-based recovery.
- `ZeroizeOnDrop` volatile-writes key material to zero on drop.
- Core dumps are disabled at daemon startup (`prctl(PR_SET_DUMPABLE, 0)` / `ptrace(PT_DENY_ATTACH)`).
- `ProtectedSigningKey` exposes no public stack constructors, preventing accidental stack copies.

Residual risk: a root-level attacker or kernel exploit can read process memory regardless of these controls. This is an accepted boundary per NIST SP 800-63B §5.1.9 and the project threat model. Full-disk encryption is the correct control for the at-rest analog.

---

### Break-Glass Abuse

**Break-glass returns PAM_IGNORE, not PAM_SUCCESS — MITIGATED**
A break-glass authentication event does not grant access by itself. It returns `PAM_IGNORE`, causing the PAM stack to fall through to the next module (typically password or key-based auth). An attacker who somehow triggers a break-glass path still must satisfy the downstream authenticator.

**No rate limiting on break-glass path — CONFIRMED**
Break-glass bypass events generate an audit log entry but are not subject to the OIDC rate limiter. A persistent attacker attempting to enumerate valid break-glass usernames would produce log entries but no automatic lockout or alerting. This is accepted as low priority given that break-glass accounts are intended for emergency use by known operators, and the rate of attempts is observable through the audit trail. A future improvement would apply a separate, permissive rate limit to the break-glass path to trigger anomaly detection.

---

### CIBA Phishing

**binding_message shows the command being authorized — MITIGATED**
The CIBA step-up flow presents a `binding_message` containing the command or resource being authorized, giving the user context to make an informed approval decision on their phone.

**User approval without reading — ACCEPTED**
Push-based authentication inherently relies on the user reading the approval prompt before tapping. Fatigue attacks (repeated push notifications until the user approves) are a known weakness of all push-based MFA systems, not specific to this implementation. Mitigations (push number matching, context display) are IdP-side controls. This risk is accepted as inherent to the CIBA interaction model.

---

### Clock Manipulation

**Configurable skew tolerance — MITIGATED**
Clock skew tolerance is configurable (default: 5 seconds future, 60 seconds staleness). Tokens and proofs outside this window are rejected. The values are intentionally conservative.

**NTP desync beyond tolerance — OPS CONCERN, NOT SECURITY**
An NTP desync exceeding the tolerance window causes legitimate authentication failures, not a security bypass. An attacker cannot exploit this to forge tokens; they can only cause a denial of service by disrupting the server's clock, which requires privileged network access or physical access — outside the threat model.

---

### Supply Chain

**cargo audit in CI — MITIGATED**
The CI pipeline runs `cargo audit` on every pull request, blocking merges when known-vulnerable crate versions are detected.

**Dependency evaluation criteria — MITIGATED**
CLAUDE.md documents explicit evaluation criteria for new dependencies: necessity, maintenance status, security track record, supply chain (crates.io authorship), transitive dependency surface, and complexity. New crypto-adjacent dependencies require heightened scrutiny.

**SBOM generation (CycloneDX + SPDX) — MITIGATED**
Software Bill of Materials artifacts are generated at build time, enabling downstream consumers to run their own vulnerability audits and satisfy supply-chain compliance requirements.

---

## Persona 2: Enterprise Security Architect

*Concern model: audit completeness, compliance evidence, key lifecycle hygiene, TLS posture, multi-tenancy.*

### Audit Trail

**AuditEvent coverage — MITIGATED**
Structured audit events are emitted for: login success, login failure (with reason code), break-glass activation, session open, session close, rate limit trigger. Each event carries a request ID for log correlation.

**Structured tracing spans — MITIGATED**
The `tracing` crate is used throughout the authentication path, producing structured spans that capture username, issuer, client IP, and outcome. These spans compose into a coherent audit trail for a single authentication flow.

**Centralized audit log shipping — CONFIRMED**
There is no built-in integration for shipping audit logs to a SIEM (syslog-ng, Fluentd, Splunk, etc.). The structured logs must be collected by an external agent. This is a planned capability (v2.1) and is not blocking for v2.0 deployments that use a log forwarder at the infrastructure layer. SOC2 Type II evidence collection requires this gap to be addressed before audit-period coverage begins.

---

### Key Lifecycle

**Ephemeral DPoP keys — MITIGATED by design**
DPoP keys are generated fresh per session and discarded on session close. There are no long-lived signing keys to rotate, escrow, or revoke. Key lifecycle management complexity is eliminated at the design level.

**Refresh token rotation — MITIGATED**
The agent's auto-refresh task rotates refresh tokens on each use, consistent with RFC 6749 §10.4 recommendations for public clients. Detected rotation violations (reuse of a rotated token) are treated as a compromise signal.

**Session close triggers revocation — MITIGATED**
On session close, the agent issues a token revocation request per RFC 7009. This is best-effort: revocation failure is logged but does not block session close. IdPs that do not implement a revocation endpoint are handled gracefully.

---

### TLS Validation

**reqwest with rustls-tls — MITIGATED**
All outbound HTTPS connections (JWKS fetch, token endpoint, introspection, CIBA) use `reqwest` backed by `rustls`, which validates certificates against the system trust store. There is no TLS-skip option exposed in configuration.

**No certificate pinning — CONFIRMED (ACCEPTED)**
Certificate pinning is not implemented. This is accepted: the IdP controls its own certificate lifecycle, and pinning would create operational burden on IdP certificate rotation (typically every 1-3 years). For environments with a heightened threat model (nation-state adversary with CA compromise capability), a pinning option could be added. See recommendation P3.

**JWKS fetched only from configured issuer URL — MITIGATED**
The JWKS endpoint URL is resolved from the OpenID Connect discovery document at the configured `issuer` URL, not from claims within the token itself. An attacker cannot direct the PAM module to fetch keys from an attacker-controlled endpoint by crafting a token with a modified `jku` or `x5u` header.

---

### Compliance Evidence

**No automated compliance report generation — CONFIRMED**
There is no tooling to generate a formatted compliance report (SOC2, FedRAMP, ISO 27001) from audit event data. Structured logs provide the raw evidence, but an auditor would need to query and format them manually.

**Audit events + structured logs as SOC2 evidence — PARTIAL**
The audit event schema covers the access control (CC6) and logical access (CC6.1, CC6.2) control domains. Change management, availability, and processing integrity controls require evidence from outside the prmana scope (CI/CD pipeline, deployment records). Evidence collection is achievable but requires operational tooling investment.

**Test coverage — EVIDENCE OF DUE DILIGENCE**
Approximately 460 unit tests plus integration tests against live IdP instances (Keycloak, Auth0, Google Cloud Identity) provide documented evidence of pre-release validation. Security-specific test cases cover replay protection, algorithm confusion rejection, and expiration enforcement.

---

### Multi-Tenancy

**Per-user Unix socket isolation — MITIGATED**
Each user's agent daemon binds to a path derived from their UID. Peer UID validation on every connection ensures users cannot access each other's agent state.

**Per-user keyring storage — MITIGATED**
Credentials are stored in the user's own keyring (Secret Service login keyring, user-session keyring, or macOS Keychain login keychain). Other users, including those with sudo access to specific commands, cannot access another user's stored credentials without authentication.

**No multi-tenant IdP isolation within a single PAM config — ACCEPTED**
A single PAM stack instance is configured for a single IdP issuer. Organizations with multiple IdPs must deploy separate PAM stack configurations per IdP. This is a deliberate design choice: supporting multiple simultaneous issuers would significantly complicate the issuer validation and JWKS caching logic, and the use case is adequately served by PAM stack composition.

---

## Persona 3: Ops Engineer

*Concern model: surviving failures at 3 AM, safe misconfiguration behavior, resource exhaustion, rollback path, monitoring.*

### IdP Outage at 3 AM

**Break-glass accounts bypass OIDC entirely — MITIGATED**
Accounts listed in the `break_glass` policy section bypass the OIDC path completely and return `PAM_IGNORE`, allowing the subsequent module (password, key-based) to authenticate. Break-glass does not depend on IdP availability, JWKS freshness, or agent daemon health.

**JWKS cache survives transient IdP failures — MITIGATED**
The JWKS cache has a TTL configured for resilience (not just for performance). Cached keys remain valid for authentication during IdP unavailability, as long as the IdP does not rotate keys during the outage window. This is the standard expectation: IdPs publish new keys before using them, providing a rotation overlap period.

**Introspection fail-open default — MITIGATED**
When the token introspection endpoint is unreachable, the PAM module proceeds with local validation only. This prevents an introspection endpoint outage from locking out all users. Operators who require introspection as a hard gate can set `introspection_required: true`.

**Clear error messages with request IDs — MITIGATED**
Authentication failures emit a request ID to the user-facing error channel and a corresponding structured log entry with full detail. Operators can correlate a user-reported failure to the exact log entry without guessing.

---

### Configuration Mistakes

**Missing policy.yaml — MITIGATED**
When `policy.yaml` is absent, the PAM module defaults to v1.0 behavior: OIDC validation required, no break-glass, default enforcement modes. This is a safe default — the system continues to enforce authentication rather than opening up.

**Invalid enforcement mode string — MITIGATED**
Enforcement mode values (`strict`, `warn`, `disabled`) are validated at configuration parse time. An unrecognized value produces a clear error message with the valid options and causes the daemon to refuse to start, rather than silently interpreting an unknown value as permissive.

**Username collision in break-glass config — MITIGATED**
If a break-glass account name collides with a valid OIDC-mapped username, the conflict is detected at configuration load time and the daemon refuses to start. This prevents an accidental policy that allows an OIDC-authenticated user to also be treated as a break-glass principal.

**Empty break-glass accounts list — MITIGATED**
An empty `break_glass` list is valid and means no break-glass accounts are configured. OIDC authentication proceeds normally. This is the correct default for new deployments.

---

### Disk Full / Memory Exhaustion

**JTI cache bounded — MITIGATED**
The JTI replay cache uses `moka` with a maximum of 10,000 entries and per-entry TTL expiration. Under sustained high-volume authentication, old entries expire before the cache reaches capacity. A targeted replay flood cannot grow the cache unboundedly.

**DPoP nonce cache bounded — MITIGATED**
Server-issued nonces are tracked with a TTL-based bounded cache. Nonce exhaustion attempts are rate-limited by the broader auth rate limiter.

**Session records on tmpfs — MITIGATED**
Active session state is written to `/run/` (tmpfs on systemd systems), which is separate from the data partition. A full data disk does not prevent session record writes. `/run/` is bounded by RAM, not disk.

**Introspection response cache bounded — MITIGATED**
The introspection cache is bounded with entry count and TTL limits, preventing unbounded growth under high login volume.

---

### Rollback Safety

**PAM module disabled by one-line edit — MITIGATED**
The PAM module is loaded via a single line in `/etc/pam.d/sshd`. Commenting out that line disables prmana entirely and restores the prior authentication behavior. No package removal or system restart is required.

**Documented rollback procedure — MITIGATED**
CLAUDE.md contains a step-by-step rollback procedure including the `sed` command for in-place disable, full uninstall steps, and a reminder that break-glass provides immediate access during rollback if OIDC is the only working auth path at the time of the incident.

**Break-glass provides access during rollback — MITIGATED**
As long as break-glass accounts are configured and tested before deployment, an operator can access the server via break-glass to perform the rollback without needing an already-functioning OIDC path. Pre-deployment checklist in CLAUDE.md makes break-glass setup explicit.

---

### Monitoring Blind Spots

**No built-in agent health check endpoint — CONFIRMED**
The agent daemon does not expose an HTTP health check endpoint (e.g., `GET /healthz`). Monitoring systems that scrape HTTP endpoints cannot determine whether the daemon is alive and processing requests. Partial coverage is provided by `sd_notify(WATCHDOG=1)` integration for systemd watchdog; systemd will restart a daemon that stops sending watchdog pings. However, a daemon that is alive but wedged (deadlocked, unable to process IPC) would not be detected by the watchdog alone.

**No Prometheus metrics endpoint — CONFIRMED**
A `Metrics` IPC command exists internally but there is no HTTP scrape endpoint. Operators cannot currently collect time-series data on JWKS cache hit rate, authentication latency distribution, DPoP proof validation rate, or session open/close counts. This limits capacity planning and anomaly detection.

**Log volume during brute force — MITIGATED**
The rate limiter significantly reduces authentication attempt rate under brute force conditions. Log volume is proportional to the rate limit bucket size, not the raw attack rate. Log rotation and size limits should be configured at the system level as standard practice.

---

## Cross-Examination Summary

| # | Finding | Persona | Verdict | Priority |
|---|---------|---------|---------|----------|
| 1 | No certificate pinning for IdP connections | Architect | ACCEPTED | Low |
| 2 | Break-glass path not rate-limited | Red Team | CONFIRMED | Low |
| 3 | No centralized audit log shipping (SIEM integration) | Architect | CONFIRMED | Medium |
| 4 | No agent health check endpoint (HTTP /healthz) | Ops | CONFIRMED | Medium |
| 5 | CIBA push approval without reading (fatigue attack) | Red Team | ACCEPTED | Low |
| 6 | No Prometheus metrics scrape endpoint | Ops | CONFIRMED | Low |
| 7 | Root-level attacker can read agent memory | Red Team | ACCEPTED | N/A — threat model boundary |
| 8 | CoW/SSD: three-pass overwrite may not reach original blocks | Red Team | ACCEPTED | N/A — FDE is the correct control |
| 9 | JTI cache is process-local; prefork sshd spawns multiple processes | Red Team | CONFIRMED | Medium |
| 10 | No compile-time guard preventing `test-mode` feature in release builds | Red Team | CONFIRMED | High |

---

## Prioritized Recommendations

### P0 — Blocking

**1. Compile-time guard for `test-mode` in release builds**
Add a `cfg` compile error that fires when both `test-mode` and `release` profile conditions are true. This prevents an accidental `cargo build --release --features test-mode` from producing a production binary with signature verification disabled. Recommended form:

```rust
// In lib.rs or a dedicated feature-guard module
#[cfg(all(feature = "test-mode", not(debug_assertions)))]
compile_error!(
    "The `test-mode` feature MUST NOT be enabled in release builds. \
     It disables all cryptographic verification. See CLAUDE.md."
);
```

---

### P1 — High

**2. Document `dpop_required: strict` as the production deployment default**
The current default is `warn` for DPoP binding. This is appropriate for initial rollout alongside legacy clients but should be explicitly documented as a migration target. Deployment guides should state that `strict` is the security-complete configuration, and provide a migration timeline recommendation (e.g., 90-day window to enforce after deploying the agent).

**3. Systemd watchdog integration (sd-notify WATCHDOG=1)**
Emit `sd_notify(WATCHDOG=1)` on each successful IPC processing cycle. Configure `WatchdogSec=30s` in the unit file. This allows systemd to detect and restart a wedged daemon without requiring a separate health check poller. This is a low-effort change with meaningful operational impact.

---

### P2 — Medium

**4. Shared JTI cache for prefork sshd (Redis/Valkey) — deferred**
The current JTI cache is process-local. In a prefork sshd model, each worker process has an independent cache. A DPoP proof that was seen by worker A could be replayed against worker B. For environments running stock OpenSSH (which does not prefork in the PAM-per-session model), this is not exploitable. For environments with custom sshd configurations or future sshd architectures, a shared external cache (Redis/Valkey) would provide strict inter-process deduplication. Track as `SCALE-01`.

**5. Rate limiting on break-glass path**
Apply a separate, permissive rate limiter (e.g., 10 attempts per minute per source IP) to the break-glass authentication path. This is distinct from the OIDC rate limiter and should not trigger the same lockout behavior. The goal is anomaly detection (trigger an alert after N break-glass attempts) rather than lockout.

**6. Prometheus metrics endpoint**
Expose a Prometheus scrape endpoint on a configurable local port (default: `127.0.0.1:9100/metrics`). Initial metrics to export: `auth_attempts_total{outcome}`, `dpop_proof_validations_total{outcome}`, `jwks_cache_hit_ratio`, `iat_validation_skew_seconds` (histogram), `session_duration_seconds` (histogram). This enables SLO definition and anomaly alerting without requiring log parsing.

---

### P3 — Low

**7. Certificate pinning option for high-security environments**
Add an optional `tls_pin_sha256: [<hex>]` configuration field accepting a list of SubjectPublicKeyInfo SHA-256 hashes. When set, TLS connections to the IdP are rejected if the presented certificate's SPKI hash does not match. This is an opt-in control for environments with a threat model that includes CA compromise.

**8. Centralized audit log shipping**
Add optional syslog output (RFC 5424 structured data format) alongside the existing `tracing` output. This allows standard log forwarders (syslog-ng, rsyslog, Fluentd) to ship audit events to a SIEM without requiring custom integration. The prmana side of this is a structured syslog formatter; the shipping infrastructure is out of scope.

---

*Reviewed: 2026-03-12*
*Methodology: Three-persona adversarial review — red team attacker, enterprise security architect, ops engineer*
*Codebase: prmana v2.0 — 50/50 requirements complete*
*Standards references: RFC 9449 (DPoP), RFC 7009 (Token Revocation), NIST SP 800-63B §5.1.9, NIST SP 800-88 Rev 1 §2.5*
