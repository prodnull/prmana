# unix-oidc Threat Model

> **Last Updated:** 2026-01-18 (Supply Chain Hardening)
> **Review Cycle:** Quarterly or after significant architecture changes
> **Status:** Active

## 1. System Overview

unix-oidc provides OIDC-based authentication for SSH and sudo step-up on Linux/Unix systems. The system consists of:

- **PAM Module** (`pam_unix_oidc.so`): Server-side component validating OIDC tokens
- **Client Agent** (`unix-oidc-agent`): User-side daemon managing tokens and DPoP proofs
- **IdP Integration**: Keycloak (primary), Entra ID, Okta (supported)
- **Directory Integration**: SSSD/FreeIPA for user resolution

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           TRUST BOUNDARY                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  User Laptop                    │  SSH Server                           │
│  ┌─────────────────┐            │  ┌─────────────────┐                  │
│  │ unix-oidc-agent │            │  │   PAM Module    │                  │
│  │ (user process)  │────────────┼──│   (root)        │                  │
│  └────────┬────────┘            │  └────────┬────────┘                  │
│           │                     │           │                           │
│           ▼                     │           ▼                           │
│  ┌─────────────────┐            │  ┌─────────────────┐                  │
│  │ Secure Storage  │            │  │ SSSD/NSS        │                  │
│  │ (Keychain)      │            │  │ (user lookup)   │                  │
│  └─────────────────┘            │  └─────────────────┘                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                    │                           │
                    ▼                           ▼
            ┌─────────────────┐         ┌─────────────────┐
            │   Keycloak      │         │   FreeIPA       │
            │   (IdP)         │         │   (Directory)   │
            └─────────────────┘         └─────────────────┘
```

---

## 2. Assets

### 2.1 Critical Assets (Compromise = Catastrophic)

| Asset | Description | Impact if Compromised |
|-------|-------------|----------------------|
| **DPoP Private Key** | Per-device cryptographic key | Attacker can generate valid proofs, impersonate user |
| **Refresh Token** | Long-lived credential for token renewal | Persistent access until revoked |
| **Root Access** | PAM module runs as root | Full system compromise |
| **JWKS Signing Key** | IdP's token signing key | Forge any token, impersonate any user |

### 2.2 High-Value Assets

| Asset | Description | Impact if Compromised |
|-------|-------------|----------------------|
| **Access Token** | Short-lived credential (5-60 min) | Temporary unauthorized access |
| **Session ID** | Authentication session identifier | Session hijacking, audit log tampering |
| **JTI Cache** | Token replay tracking | Replay attacks possible |
| **Rate Limit State** | Brute force protection | Brute force attacks enabled |

### 2.3 Sensitive Data

| Data | Classification | Storage |
|------|---------------|---------|
| Username/UPN | PII | Token claims, logs |
| IP Address | PII | Rate limiter, audit logs |
| ACR Level | Auth metadata | Token claims |
| Command (sudo) | Operational | Audit logs |

---

## 3. Threat Actors

### 3.1 External Attackers

| Actor | Capability | Motivation | Likelihood |
|-------|------------|------------|------------|
| **Nation State** | Advanced persistent threat, zero-days | Espionage, disruption | Medium (high-value targets) |
| **Organized Crime** | Exploit kits, social engineering | Financial gain, ransomware | High |
| **Script Kiddie** | Public exploits, credential stuffing | Notoriety | High |

### 3.2 Internal Threats

| Actor | Capability | Motivation | Likelihood |
|-------|------------|------------|------------|
| **Malicious Insider** | Legitimate access, knowledge of systems | Sabotage, theft | Low-Medium |
| **Compromised Insider** | Stolen credentials, phished user | Unwitting accomplice | Medium |
| **Rogue Admin** | Privileged access, can modify PAM | Cover tracks, escalate | Low |

### 3.3 Adjacent Threats

| Actor | Capability | Motivation | Likelihood |
|-------|------------|------------|------------|
| **Compromised IdP** | Token signing keys | Total authentication bypass | Low (catastrophic impact) |
| **MITM on Network** | Traffic interception | Token theft, session hijack | Medium |
| **Malware on Laptop** | Keychain access, process injection | Credential theft | Medium-High |

---

## 4. Attack Vectors

### 4.1 Token Theft and Replay

| ID | Attack | Mitigations | Status |
|----|--------|-------------|--------|
| **T1** | Steal access token from network | TLS required, short token lifetime | ✅ Mitigated |
| **T2** | Replay stolen token on same server | JTI tracking, token bound to server | ✅ Mitigated |
| **T3** | Replay stolen token on different server | **DPoP binding** (cnf.jkt claim verification) | ✅ Mitigated |
| **T4** | Steal token from client memory | Process isolation, short lifetime | ⚠️ Partial |
| **T5** | Steal refresh token | Keychain/secret service protection | ✅ Mitigated |

### 4.2 Credential Attacks

| ID | Attack | Mitigations | Status |
|----|--------|-------------|--------|
| **C1** | Brute force authentication | Rate limiting, exponential backoff | ✅ Mitigated |
| **C2** | Credential stuffing | Rate limiting per IP | ✅ Mitigated |
| **C3** | Phish OIDC credentials | Out of scope (IdP responsibility) | N/A |
| **C4** | Steal DPoP private key | Secure storage, hardware keys (future) | ✅ Mitigated |

### 4.3 Protocol Attacks

| ID | Attack | Mitigations | Status |
|----|--------|-------------|--------|
| **P1** | JWT signature bypass | Mandatory signature verification | ✅ Mitigated |
| **P2** | Algorithm confusion (none/HS256) | Explicit algorithm whitelist | ✅ Mitigated |
| **P3** | JWKS endpoint spoofing | TLS + issuer validation | ✅ Mitigated |
| **P4** | Token substitution (different user) | Username claim validation | ✅ Mitigated |
| **P5** | Expired token acceptance | exp claim validation with clock skew | ✅ Mitigated |
| **P6** | Wrong audience token | aud claim validation | ✅ Mitigated |
| **P7** | DPoP proof replay | Proof JTI tracking (65s TTL), constant-time comparison | ✅ Mitigated |
| **P8** | DPoP proof pre-computation | Server nonce binding (configurable) | ✅ Mitigated |
| **P9** | Timing attack on thumbprint | Constant-time string comparison (`subtle` crate) | ✅ Mitigated |
| **P10** | Malformed JWK parameters | Coordinate length validation (P-256: 32 bytes) | ✅ Mitigated |

### 4.4 Infrastructure Attacks

| ID | Attack | Mitigations | Status |
|----|--------|-------------|--------|
| **I1** | PAM module bypass | Correct PAM stack order, fail closed | ✅ Mitigated |
| **I2** | SSSD cache poisoning | Out of scope (SSSD hardening) | N/A |
| **I3** | IdP compromise | Federation limits blast radius | ⚠️ Partial |
| **I4** | Network partition (no IdP access) | JWKS caching, graceful degradation | ✅ Mitigated |

### 4.5 Denial of Service

| ID | Attack | Mitigations | Status |
|----|--------|-------------|--------|
| **D1** | Exhaust rate limiter memory | TTL-based cleanup, bounded structure | ✅ Mitigated |
| **D2** | Exhaust JTI cache memory | TTL-based cleanup, bounded structure | ✅ Mitigated |
| **D3** | JWKS endpoint unavailable | 5-minute cache, retry with backoff | ✅ Mitigated |
| **D4** | Lock out legitimate users | IP + username tracking, admin reset | ✅ Mitigated |

### 4.6 Supply Chain

| ID | Attack | Mitigations | Status |
|----|--------|-------------|--------|
| **S1** | Malicious dependency | `cargo audit` in CI, `dependency-review` for PRs, minimal deps | ✅ Mitigated |
| **S2** | Compromised build | `--locked` builds, SBOM generation (CycloneDX), pinned deps | ✅ Mitigated |
| **S3** | Binary tampering | SHA-256 checksums in releases, SBOM included | ✅ Mitigated |

---

## 5. Trust Boundaries

### 5.1 User Laptop ↔ Network

- **Assumption:** Network is hostile (MITM possible)
- **Control:** TLS for all connections
- **Residual Risk:** TLS interception proxies in enterprise environments

### 5.2 PAM Module ↔ SSH Daemon

- **Assumption:** sshd is trusted
- **Control:** PAM runs in sshd's process context
- **Residual Risk:** sshd vulnerabilities

### 5.3 PAM Module ↔ SSSD

- **Assumption:** SSSD is trusted for user resolution
- **Control:** NSS calls only, no secrets exchanged
- **Residual Risk:** SSSD cache poisoning

### 5.4 Client Agent ↔ Keychain

- **Assumption:** OS keychain provides secure storage
- **Control:** Use native APIs (Keychain, libsecret)
- **Residual Risk:** Malware with keychain access

### 5.5 Client Agent ↔ IdP

- **Assumption:** IdP is trusted for identity
- **Control:** TLS, issuer validation, signature verification
- **Residual Risk:** IdP compromise

---

## 6. Security Controls

### 6.1 Authentication Controls

| Control | Implementation | Test Coverage |
|---------|---------------|---------------|
| JWT signature verification | `jsonwebtoken` crate, JWKS fetching | ✅ Unit tests |
| Issuer validation | Exact string match | ✅ Unit tests |
| Audience validation | Contains check | ✅ Unit tests |
| Expiration validation | exp claim with 60s clock skew | ✅ Unit tests |
| ACR validation | Minimum level enforcement | ✅ Unit tests |
| auth_time validation | Maximum auth age check | ✅ Unit tests |
| DPoP proof validation | Signature + thumbprint + nonce + JTI | ✅ Unit tests |

### 6.2 Anti-Replay Controls

| Control | Implementation | Test Coverage |
|---------|---------------|---------------|
| Token JTI tracking | In-memory cache with TTL | ✅ Unit tests |
| Proof JTI tracking | In-memory cache, 65s TTL (max_proof_age + skew) | ✅ Unit tests |
| Server nonce | Optional, configurable via DPoPConfig | ✅ Unit tests |
| Constant-time comparison | `subtle::ConstantTimeEq` for thumbprint/nonce | ✅ Unit tests |

### 6.3 Rate Limiting Controls

| Control | Implementation | Test Coverage |
|---------|---------------|---------------|
| Per-user rate limit | Sliding window, 5 attempts | ✅ Unit tests |
| Per-IP rate limit | Sliding window, 10 attempts | ✅ Unit tests |
| Exponential backoff | 60s → 120s → ... → 3600s max | ✅ Unit tests |

### 6.4 Audit Controls

| Control | Implementation | Test Coverage |
|---------|---------------|---------------|
| Structured logging | JSON format to syslog | ✅ Unit tests |
| Session ID tracking | CSPRNG-based, 64-bit entropy | ✅ Unit tests |
| Event types | Login success/fail, step-up, replay | ✅ Unit tests |

---

## 7. DPoP-Specific Threats

### 7.1 New Attack Vectors with DPoP

| ID | Attack | Description | Mitigation |
|----|--------|-------------|------------|
| **DP1** | Key extraction from memory | Dump agent process memory | Short key residence time, memory protection |
| **DP2** | Proof theft mid-flight | Capture proof during SSH auth | Proofs are single-use, bound to target |
| **DP3** | Downgrade to non-DPoP | Strip DPoP header, use bearer token | Server policy enforcement |
| **DP4** | Weak key generation | Predictable keys | Use CSPRNG, proper entropy source |
| **DP5** | Key backup exfiltration | Steal from backup/sync services | Keys not synced, device-local only |
| **DP6** | Forward secrecy violation | Compromise key, decrypt past sessions | N/A - DPoP signs, doesn't encrypt |

### 7.2 Agent Forwarding Threats

| ID | Attack | Description | Mitigation |
|----|--------|-------------|------------|
| **AF1** | Proof request from malicious service | Hijacked session requests proofs for attacker's service | htu binding - proof only valid for specific target |
| **AF2** | Unlimited proof generation | Attacker generates proofs for many targets | Rate limiting on agent, audit logging |
| **AF3** | Agent socket hijacking | Another user on jump host accesses forwarded socket | Unix socket permissions (owner only) |

### 7.3 Post-Quantum Considerations

| Threat | Timeline | Mitigation |
|--------|----------|------------|
| Harvest now, decrypt later | Present | Hybrid ML-DSA-65 + ES256 |
| Quantum computer breaks ES256 | 10-20 years | ML-DSA-65 remains secure |
| ML-DSA-65 broken | Unknown | Algorithm agility, config-based switch |

---

## 8. Residual Risks

### 8.1 Accepted Risks

| Risk | Rationale | Owner |
|------|-----------|-------|
| IdP compromise | Out of scope; IdP security is IdP's responsibility | IdP team |
| SSSD vulnerabilities | Out of scope; standard Linux component | Platform team |
| TLS interception by enterprise proxy | Common in enterprise; users aware | Security team |
| Malware on user laptop | Defense in depth; not solvable at auth layer | Endpoint team |

### 8.2 Risks Requiring Monitoring

| Risk | Indicator | Response |
|------|-----------|----------|
| Token replay attempts | `stolen_token` audit events | Investigate, consider revocation |
| Brute force attempts | High rate limiter triggers | Block IP, investigate source |
| DPoP downgrade attempts | Non-DPoP auth when policy is `required` | Alert, investigate client |
| Key compromise indicators | Same key from multiple IPs | Force key rotation |

### 8.3 Honest Security Limitations

**DPoP does not eliminate key theft risks.** If an attacker can extract an SSH private key from memory, they can likely extract a DPoP signing key the same way. The security improvement is in *blast radius reduction*, not elimination:

| Scenario | SSH Key Stolen | DPoP Key + Token Stolen |
|----------|----------------|-------------------------|
| **What attacker has** | Permanent credential | Time-limited capability |
| **Usable indefinitely?** | Yes, until manually revoked | No - token expires (minutes) |
| **Can mint new credentials?** | Yes (key IS the credential) | No - requires IdP authentication |
| **Lateral movement** | Any server with authorized_keys | Only servers in token audience |
| **Detection** | Hard (legitimate-looking auth) | IdP logs, anomaly detection possible |
| **Revocation** | Hunt all authorized_keys files | Single IdP action, immediate effect |

**What DPoP actually provides:**

1. **Reduced damage window**: Stolen credentials expire automatically
2. **Centralized revocation**: Disable at IdP, all access stops
3. **Audit trail**: Token issuance logged at IdP
4. **No credential sprawl**: No keys scattered across authorized_keys files

**What DPoP does NOT provide:**

1. Protection against memory dump attacks (use hardware-backed keys for that)
2. Protection if attacker has persistent access to client machine
3. Magic - if the client is fully compromised, authentication is compromised

**Stronger alternatives for high-security environments:**

- Hardware security modules (HSM) for DPoP key storage
- Platform keychain with biometric unlock (macOS Secure Enclave, Windows TPM)
- FIDO2/WebAuthn hardware keys for step-up authentication

---

## 9. Security Testing Requirements

### 9.1 Unit Tests (Automated, CI)

- [x] Token validation edge cases (expired, wrong issuer, wrong audience)
- [x] JTI replay detection (both token and DPoP proof)
- [x] Rate limiter behavior
- [x] DPoP proof validation (signature, claims, timing, nonce)
- [x] Thumbprint computation (RFC 7638 compliant)
- [x] Constant-time comparison
- [x] JWK coordinate validation

### 9.2 Integration Tests (Automated, CI)

- [x] Full auth flow with real Keycloak (docker-compose.test.yaml)
- [x] Token validation with live IdP
- [ ] Token refresh flow (agent not yet complete)
- [ ] DPoP binding end-to-end (agent not yet complete)
- [ ] Agent forwarding through SSH (agent not yet complete)

### 9.3 Security Tests (Pre-release)

- [x] Fuzzing: Token parsing (`fuzz_token_parser`), policy parsing (`fuzz_policy_parser`), username mapping (`fuzz_username_mapper`)
- [x] DPoP proof fuzzing (`fuzz_dpop_proof`)
- [ ] Penetration test: Token manipulation, replay attacks
- [x] Code audit: Adversarial review (Marcus Chen, 2026-01-17)

### 9.4 Ongoing Monitoring

- [x] `cargo audit` in CI (dependency vulnerabilities)
- [x] `dependency-review` for PRs (GitHub Action)
- [ ] SIEM integration for `stolen_token` events (deployment-specific)
- [ ] Rate limiter metrics (Prometheus/Grafana) (deployment-specific)

---

## 10. Incident Response

### 10.1 Token Compromise

1. Revoke refresh token in Keycloak admin console
2. Rotate DPoP key: `unix-oidc-agent reset && unix-oidc-agent login`
3. Review audit logs for unauthorized access
4. Consider forced re-authentication for affected user

### 10.2 Key Compromise (DPoP Private Key)

1. User runs `unix-oidc-agent reset` (deletes key)
2. User runs `unix-oidc-agent login` (generates new key)
3. New key thumbprint automatically bound to new tokens
4. Old tokens become invalid (thumbprint mismatch)

### 10.3 IdP Compromise

1. Disable unix-oidc PAM module (emergency)
2. Fall back to SSH keys or password
3. Wait for IdP recovery and key rotation
4. Re-enable after IdP team confirms remediation

### 10.4 Widespread Attack

1. Set `dpop_policy: required` to block non-DPoP auth
2. Reduce token lifetime in Keycloak
3. Enable enhanced audit logging
4. Coordinate with IdP team on mass revocation if needed

---

## 11. Compliance Considerations

### 11.1 Relevant Standards

| Standard | Relevance | Status |
|----------|-----------|--------|
| SOC 2 Type II | Audit logging, access controls | ✅ Supported |
| PCI DSS | Strong auth for cardholder data access | ✅ Supported (ACR enforcement) |
| HIPAA | Access controls for PHI | ✅ Supported |
| FedRAMP | Federal systems auth requirements | 🔶 Requires FIPS crypto |

### 11.2 FIPS Considerations

- Current: ES256 uses P-256 (FIPS 186-4 approved)
- Future: ML-DSA-65 is FIPS 204 (approved August 2024)
- Gap: No FIPS-validated Rust crypto libraries yet
- Workaround: Use OpenSSL backend with FIPS module (planned)

---

## 12. Review History

| Date | Reviewer | Changes |
|------|----------|---------|
| 2026-01-17 | Initial creation | Full threat model |
| 2026-01-17 | Marcus Chen (adversarial review) | Security hardening: DPoP JTI replay protection, constant-time comparisons, JWK validation |
| 2026-01-18 | Supply chain review | Added: cargo audit, dependency-review, SBOM generation, checksums, locked builds |

---

## Appendix A: STRIDE Analysis

| Threat | Category | Examples | Mitigations |
|--------|----------|----------|-------------|
| **S**poofing | Identity | Fake token, impersonation | Signature verification, DPoP binding |
| **T**ampering | Data | Modified claims, altered proof | Signatures, integrity checks |
| **R**epudiation | Audit | Deny actions | Session ID tracking, audit logs |
| **I**nformation Disclosure | Confidentiality | Token theft, key exposure | TLS, secure storage, short lifetimes |
| **D**enial of Service | Availability | Rate limit exhaustion | Bounded caches, TTL cleanup |
| **E**levation of Privilege | Authorization | Low ACR to high, user to root | ACR validation, PAM fail-closed |

---

## Appendix B: NIST Cybersecurity Framework Mapping

unix-oidc controls mapped to NIST CSF 2.0 categories:

### IDENTIFY (ID)

| Subcategory | unix-oidc Implementation |
|-------------|--------------------------|
| ID.AM-1: Physical devices inventoried | N/A (out of scope) |
| ID.AM-2: Software platforms inventoried | Cargo.toml dependencies, SBOM generation |
| ID.AM-3: Data flows mapped | See Appendix C Data Flow Diagram |
| ID.RA-1: Vulnerabilities identified | cargo audit, dependency-review |

### PROTECT (PR)

| Subcategory | unix-oidc Implementation |
|-------------|--------------------------|
| PR.AA-1: Identities managed | OIDC integration, SSSD user resolution |
| PR.AA-2: Authentication | DPoP-bound tokens, MFA via IdP |
| PR.AA-3: Authorization | Policy engine, ACR enforcement |
| PR.AA-5: Access permissions | PAM integration, principle of least privilege |
| PR.DS-1: Data-at-rest protected | Keychain storage for tokens, file permissions |
| PR.DS-2: Data-in-transit protected | TLS 1.2+ required for all IdP communication |
| PR.DS-10: Secure development | Rust memory safety, clippy lints, security review |

### DETECT (DE)

| Subcategory | unix-oidc Implementation |
|-------------|--------------------------|
| DE.AE-2: Events analyzed | Structured JSON audit logs with session correlation |
| DE.AE-3: Correlation | Session ID links auth events across components |
| DE.CM-1: Network monitoring | Rate limiting, failed auth tracking |
| DE.CM-3: Personnel activity | User-level audit trail (oidc_sub, commands) |

### RESPOND (RS)

| Subcategory | unix-oidc Implementation |
|-------------|--------------------------|
| RS.AN-3: Forensics | Session ID enables incident correlation |
| RS.MI-1: Incident containment | Token revocation via IdP, key rotation |
| RS.MI-2: Incident mitigation | Fail-closed design, fallback to password |

### RECOVER (RC)

| Subcategory | unix-oidc Implementation |
|-------------|--------------------------|
| RC.RP-1: Recovery plan | Break-glass procedures, fallback auth |
| RC.CO-3: Lessons learned | Security review cycle, threat model updates |

---

## Appendix C: MITRE ATT&CK Mapping

Attack techniques relevant to unix-oidc and their mitigations:

### Initial Access

| Technique | ID | unix-oidc Mitigation |
|-----------|----|--------------------|
| Valid Accounts | T1078 | DPoP prevents stolen token reuse; MFA via IdP |
| Phishing | T1566 | Out of scope (IdP responsibility); device flow reduces exposure |
| External Remote Services | T1133 | PAM enforces OIDC auth for SSH |

### Credential Access

| Technique | ID | unix-oidc Mitigation |
|-----------|----|--------------------|
| Brute Force | T1110 | Rate limiting, exponential backoff |
| Credentials from Password Stores | T1555 | Keychain integration, OS-level protection |
| Steal Web Session Cookie | T1539 | DPoP binding makes stolen tokens unusable |
| Forge Web Credentials | T1606 | JWT signature verification, JWKS validation |
| OS Credential Dumping | T1003 | Short token lifetime, DPoP key rotation |

### Defense Evasion

| Technique | ID | unix-oidc Mitigation |
|-----------|----|--------------------|
| Access Token Manipulation | T1134.001 | Signature verification, DPoP binding |
| Modify Authentication Process | T1556 | PAM module integrity (binary signing planned) |
| Impair Defenses | T1562 | Audit logging, fail-closed design |

### Lateral Movement

| Technique | ID | unix-oidc Mitigation |
|-----------|----|--------------------|
| Use Alternate Authentication | T1550 | DPoP proof bound to specific target (htu claim) |
| SSH Hijacking | T1563.001 | Agent forwarding with rate limits, socket permissions |
| Remote Services: SSH | T1021.004 | OIDC step-up, MFA enforcement |

### Collection

| Technique | ID | unix-oidc Mitigation |
|-----------|----|--------------------|
| Input Capture | T1056 | Token-based auth (no password entry on server) |
| Data from Local System | T1005 | Audit logging of privileged access |

### Impact

| Technique | ID | unix-oidc Mitigation |
|-----------|----|--------------------|
| Account Access Removal | T1531 | IdP integration for centralized revocation |
| Inhibit System Recovery | T1490 | Break-glass procedures, fallback auth |

---

## Appendix D: Data Flow Diagram

```
                                    ┌─────────────────┐
                                    │    Keycloak     │
                                    │    (IdP)        │
                                    └────────┬────────┘
                                             │
                          ┌──────────────────┼──────────────────┐
                          │ (1) Device Flow  │ (4) JWKS Fetch   │
                          │     + DPoP       │                  │
                          ▼                  │                  ▼
┌─────────────────┐      ┌─────────────────┐ │ ┌─────────────────┐
│  User Browser   │◀────▶│ unix-oidc-agent │ │ │   PAM Module    │
│  (auth)         │      │ (client)        │ │ │   (server)      │
└─────────────────┘      └────────┬────────┘ │ └────────┬────────┘
                                  │          │          │
                    (2) Token +   │          │          │ (5) User
                        Proof     │          │          │     lookup
                                  ▼          │          ▼
                         ┌─────────────────┐ │ ┌─────────────────┐
                         │   SSH Client    │ │ │     SSSD        │
                         └────────┬────────┘ │ └────────┬────────┘
                                  │          │          │
                    (3) SSH +     │          │          │
                        Token +   │          │          ▼
                        Proof     │          │ ┌─────────────────┐
                                  ▼          │ │    FreeIPA      │
                         ┌─────────────────┐ │ │    (LDAP)       │
                         │   SSH Server    │◀┘ └─────────────────┘
                         │   (sshd)        │
                         └─────────────────┘

Data Classification:
(1) DPoP proof (signed), device_code, user_code
(2) Access token (signed, DPoP-bound), DPoP proof
(3) Access token, DPoP proof, SSH protocol data
(4) JWKS (public keys), OIDC discovery metadata
(5) Username, UID, GID (NSS query)
```
