# Standards Compliance Matrix

This document tracks every standards reference in the unix-oidc codebase -- RFCs, NIST publications, IETF drafts, industry frameworks, and compliance controls. It serves as a centralized index for auditors, security reviewers, conference submissions, and IETF working-group engagement.

**Scope:** Only standards actually referenced in implementation code (`*.rs`), documentation (`*.md`), configuration (`*.yaml`, `*.toml`), or test files are listed. Hypothetical or aspirational references are excluded.

**Last updated:** 2026-03-13

---

## 1. RFC Coverage Matrix

### Core Protocol RFCs (Normative -- We Implement These)

| RFC | Title | Sections Referenced | Implementation Files | Status | Notes |
|-----|-------|---------------------|----------------------|--------|-------|
| RFC 9449 | OAuth 2.0 Demonstrating Proof of Possession (DPoP) | SS4.2 (proof syntax), SS8 (server nonce), SS9.3 (pre-bound FD), SS11.1 (JTI replay) | `pam-unix-oidc/src/oidc/dpop.rs`, `unix-oidc-agent/src/crypto/dpop.rs`, `rust-oauth-dpop/src/server.rs`, `rust-oauth-dpop/src/lib.rs`, `go-oauth-dpop/dpop.go`, `python-oauth-dpop/oauth_dpop/server.py`, `java-oauth-dpop/src/.../DPoPValidator.java` | Full | Central security mechanism; four language implementations |
| RFC 7638 | JSON Web Key (JWK) Thumbprint | SS3.2 (canonical member order), SS3.3 (canonical JSON) | `unix-oidc-agent/src/crypto/thumbprint.rs`, `rust-oauth-dpop/src/thumbprint.rs`, `go-oauth-dpop/dpop.go:387`, `python-oauth-dpop/oauth_dpop/thumbprint.py`, `java-oauth-dpop/src/.../Thumbprint.java`, `unix-oidc-agent/src/crypto/pqc_signer.rs:145` | Full | Hardcoded canonical `kty`/`crv` values prevent thumbprint manipulation |
| RFC 7519 | JSON Web Token (JWT) | SS4.1.7 (jti claim) | `pam-unix-oidc/src/oidc/validation.rs` | Full | Token validation pipeline; `jti` enforcement configurable (Warn/Strict) |
| RFC 7517 | JSON Web Key (JWK) | SS4.5 (kid hint) | `pam-unix-oidc/src/oidc/validation.rs`, `pam-unix-oidc/src/oidc/dpop.rs` | Full | JWKS fetch and key selection |
| RFC 6749 | OAuth 2.0 Authorization Framework | SS5.2 (error response), SS6 (refresh) | `unix-oidc-agent/src/daemon/socket.rs:1017`, `pam-unix-oidc/src/ciba/types.rs:90` | Full | Token endpoint interactions, refresh flow |
| RFC 8628 | OAuth 2.0 Device Authorization Grant | SS3.2 (verification URI) | `unix-oidc-agent/src/askpass.rs`, `pam-unix-oidc/src/device_flow/client.rs`, `pam-unix-oidc/src/device_flow/types.rs` | Full | Step-up sudo authentication; `slow_down` backoff implemented |
| RFC 7009 | OAuth 2.0 Token Revocation | SS2.1 (revocation request) | `unix-oidc-agent/src/daemon/socket.rs:1154-1287`, `unix-oidc-agent/src/daemon/protocol.rs:44` | Full | Best-effort revocation on session close (5s timeout) |
| RFC 7662 | OAuth 2.0 Token Introspection | SS2.1 (authentication), SS4 | `pam-unix-oidc/src/policy/config.rs:271-305`, `pam-unix-oidc/src/oidc/introspection.rs` | Full | Opt-in with TTL-bounded caching; fail-open/fail-closed configurable |
| RFC 8414 | OAuth 2.0 Authorization Server Metadata | -- | `pam-unix-oidc/src/oidc/discovery.rs` | Full | OIDC discovery; issuer validation post-fetch |
| RFC 9700 | OAuth 2.0 Security Best Current Practice | SS2.2 (iat validation), SS2.4 (algorithm), SS2.5 (TLS), SS4.15.2 (replay) | `pam-unix-oidc/src/device_flow/client.rs:159`, `pam-unix-oidc/src/device_flow/types.rs:73`, `pam-unix-oidc/src/oidc/validation.rs` | Partial | HTTPS enforcement for issuer/verification URI in progress |
| RFC 7515 | JSON Web Signature (JWS) | SS4.1.1 (alg), SS4.1.4 (kid) | `pam-unix-oidc/src/oidc/validation.rs`, `pam-unix-oidc/src/oidc/dpop.rs` | Full | Algorithm validation, kid matching |
| RFC 7518 | JSON Web Algorithms (JWA) | SS3.4 (ES256 signature format), SS6.2.1.2 (EC key validation) | `go-oauth-dpop/dpop.go:410`, `unix-oidc-agent/src/crypto/dpop.rs:157` | Full | Raw r||s 64-byte signature format for P-256 |
| RFC 5424 | Syslog Protocol | PRIORITY codes | `unix-oidc-agent/src/main.rs:55` | Full | Tracing levels mapped to syslog priorities for journald |
| RFC 3339 | Date and Time on the Internet | Timestamp format | `pam-unix-oidc/src/audit.rs:593` | Full | All audit event timestamps |

### Protocol RFCs (Partial / Planned Implementation)

| RFC | Title | Sections Referenced | Implementation Files | Status | Notes |
|-----|-------|---------------------|----------------------|--------|-------|
| RFC 8693 | OAuth 2.0 Token Exchange | `act` claim format | `docs/adr/005-dpop-token-exchange.md`, `docs/adr/005-dpop-token-exchange-alignment.md`, `test/tests/test_token_exchange.sh`, `test/tests/test_token_exchange.py` | Referenced-Only | Deferred to v2.1; design documented in ADR-005; integration test scripts exist but not in CI |
| RFC 4648 | Base16/32/64 Encodings | SS5 (base64url) | `test/tests/test_token_exchange.sh:87` | Full | Base64URL encoding in DPoP proof construction |
| RFC 5480 | ECC SubjectPublicKeyInfo ASN.1 | P-256 curve OID `1.2.840.10045.3.1.7` | `docs/hardware-key-setup.md:82` | Full | PKCS#11 key generation uses this OID |
| RFC 5785 | Well-Known URIs | -- | `pam-unix-oidc/src/oidc/discovery.rs` | Full | `/.well-known/openid-configuration` endpoint |
| RFC 9126 | Pushed Authorization Requests (PAR) | -- | `.planning/research/STACK.md:341` | Referenced-Only | Noted as distinct from CIBA; not implemented |

### Referenced-Only RFCs (Informative Context)

| RFC | Title | Where Referenced | Notes |
|-----|-------|------------------|-------|
| RFC 8471 | Token Binding over HTTP/2 | `docs/adr/001-dpop-proof-of-possession.md:60` | Rejected alternative to DPoP (browser-focused, limited IdP support) |

---

## 2. OpenID Foundation Specifications

| Specification | Sections Referenced | Implementation Files | Normative/Informative | Status | Notes |
|---------------|---------------------|----------------------|----------------------|--------|-------|
| OpenID Connect Core 1.0 | SS3.1.3.7 (ID token validation), SS5.1 (preferred_username) | `pam-unix-oidc/src/oidc/validation.rs`, `pam-unix-oidc/src/oidc/claims.rs` | Normative | Full | Core identity layer; `preferred_username` made optional per SS5.1 |
| OpenID Connect Discovery 1.0 | SS4 (issuer identifier) | `pam-unix-oidc/src/oidc/discovery.rs` | Normative | Full | HTTPS issuer requirement; auto-configuration |
| OpenID CIBA Core 1.0 | SS2 (grant type URN), SS7.1 (binding_message), SS7.3 (poll mode), SS10.1 (token request), SS10.2 (token response), SS11 (slow_down) | `pam-unix-oidc/src/ciba/client.rs`, `pam-unix-oidc/src/ciba/types.rs`, `unix-oidc-agent/src/daemon/socket.rs:1684-1780` | Normative | Full | Push step-up for sudo; poll mode with `slow_down` backoff; `binding_message` security |
| OpenID Connect EAP ACR Values 1.0 | `phr`/`phrh` URIs | `pam-unix-oidc/src/ciba/acr.rs`, `docs/diagrams/ciba-step-up-flow.svg` | Normative | Full | Phishing-resistant ACR validation for FIDO2 step-up |

---

## 3. IETF Drafts

| Draft | Title | Implementation Files | Status | Notes |
|-------|-------|----------------------|--------|-------|
| draft-ietf-jose-pq-composite-sigs-01 | Use of Post-Quantum Algorithms with JOSE | `unix-oidc-agent/src/crypto/pqc_signer.rs`, `pam-unix-oidc/src/oidc/dpop.rs:446` | Partial | ML-DSA-65+ES256 hybrid DPoP; composite signature format; pre-RFC, may change |
| draft-ietf-oauth-identity-chaining-08 | OAuth 2.0 Identity Chaining | `docs/adr/005-dpop-token-exchange-alignment.md:94` | Referenced-Only | Cited for token exchange delegation patterns |

---

## 4. NIST / Government Standards

### NIST Special Publications

| Publication | Title | Sections Referenced | Implementation Files | Normative/Informative | Status | Notes |
|-------------|-------|---------------------|----------------------|----------------------|--------|-------|
| SP 800-63B Rev 3 | Digital Identity Guidelines: Authentication | SS4.3.3 (session lifetime), SS5.1.9 (trusted OS), SS7.1 (replay) | `pam-unix-oidc/src/oidc/validation.rs`, `docs/security-guide.md`, `docs/threat-model.md` | Normative | Partial | AAL enforcement via ACR claims; clock skew tolerance exceeds recommended limits (finding F-01) |
| SP 800-88 Rev 1 | Guidelines for Media Sanitization | SS2.4 (Clear), SS2.5 (CoW/FDE), SS4.7 | `unix-oidc-agent/src/storage/secure_delete.rs`, `unix-oidc-agent/src/storage/file_store.rs:20` | Normative | Full | Three-pass overwrite with documented CoW/SSD limitations; FDE advisory |
| SP 800-53 Rev 5 | Security and Privacy Controls | AC-2 (account mgmt), AU-2/3/9/10/11 (audit), IA-2(12) (replay-resistant), IA-7/8 (crypto), SC-8/12/13 (comms/keys) | `pam-unix-oidc/src/audit.rs`, `pam-unix-oidc/src/oidc/dpop.rs` | Informative | Partial | Break-glass (AC-2), audit events (AU-*), replay protection (IA-2(12)); tamper-evidence gap (AU-9) |
| SP 800-131A Rev 2 | Transitioning Cryptographic Algorithms | SS3 (time-validity), Table 1/2 (approved algorithms, key lengths) | `pam-unix-oidc/src/oidc/validation.rs` | Informative | Partial | Algorithm allowlist added; RSA minimum key length check gap noted |
| SP 800-57 Part 1 Rev 5 | Recommendation for Key Management | SS5.3 (cryptoperiod), SS5.3.6 (expiration), SS6.2 Table 1 (key lifetime), SS8.2 (key lifecycle audit) | `unix-oidc-agent/src/crypto/protected_key.rs` | Informative | Partial | Key rotation lifecycle not yet codified; key lifecycle audit events planned |
| SP 800-123 | Guide to General Server Security | Least-privilege baseline | `deploy/systemd/unix-oidc-agent.service` | Normative | Full | systemd hardening directives (NoNewPrivileges, ProtectSystem, etc.) |
| SP 800-115 | Technical Guide to Information Security Testing | -- | `docs/security-testing-roadmap.md:178` | Informative | Referenced-Only | Testing methodology reference |

### FIPS Standards

| Standard | Title | Sections Referenced | Implementation Files | Status | Notes |
|----------|-------|---------------------|----------------------|--------|-------|
| FIPS 186-4/5 | Digital Signature Standard | SS6 (approved curves: P-256, P-384, P-521) | `pam-unix-oidc/src/oidc/dpop.rs`, all DPoP signing code | Full | ES256 (P-256 ECDSA) is the primary algorithm |
| FIPS 204 | ML-DSA (Module-Lattice-Based Digital Signature) | SS3.2 (implementation security) | `unix-oidc-agent/src/crypto/pqc_signer.rs` | Full | ML-DSA-65 (NIST level 3, 192-bit classical); `mlock` gap noted (finding F-07) |
| FIPS 203 | ML-KEM (Module-Lattice-Based Key Encapsulation) | -- | -- | Referenced-Only | Cited in NIST audit for completeness; not implemented (KEM not needed for DPoP) |
| FIPS 140-3 | Security Requirements for Cryptographic Modules | AS05.10 (zeroization) | `docs/research/libcrux-zeroize-contribution.md` | Referenced-Only | No FIPS-validated Rust crypto libraries yet; OpenSSL FIPS backend planned |

### Other Government Standards

| Standard | Sections Referenced | Implementation Files | Status | Notes |
|----------|---------------------|----------------------|--------|-------|
| NIST CSF 2.0 | ID.AM, PR.AA, PR.DS, DE.AE, DE.CM, RS.AN, RS.MI, RC.RP | `docs/THREAT_MODEL.md` (Appendix B) | Informative | Full mapping across Identify, Protect, Detect, Respond, Recover |

---

## 5. Industry Standards and Compliance Frameworks

### SOC 2 Type II

| Control | Description | Implementation | Files |
|---------|-------------|----------------|-------|
| CC6.1 | Logical access controls | Policy-based authorization | `pam-unix-oidc/src/policy/` |
| CC6.2 | Authentication mechanisms | MFA via OIDC + DPoP | `pam-unix-oidc/src/oidc/` |
| CC6.3 | Access removal | Token expiration, IdP revocation | `unix-oidc-agent/src/daemon/socket.rs` |
| CC6.7 | Anomalous activity detection | Lockout events | `pam-unix-oidc/src/audit.rs` |
| CC7.1 | Log integrity | Gap: no tamper-evidence (hash chain/HMAC) | -- |
| CC7.2 | System monitoring | Structured audit logs with session correlation | `pam-unix-oidc/src/audit.rs` |
| CC7.3 | Severity classification | Break-glass severity gap noted | `pam-unix-oidc/src/audit.rs` |
| CC7.4 | Security event response | Gap: alerting not yet automated | -- |
| A1.2 | Log retention | Gap: no retention policy controls | -- |

### PCI DSS v4.0

| Requirement | Description | Status | Notes |
|-------------|-------------|--------|-------|
| 10.2.1 | Log all authentication events | Partial | PAM audit events structured; agent daemon audit events gap |
| 10.2.1.3 | Log privilege escalations | Partial | Sudo step-up logged; session linkage gap |
| 10.2.1.6 | Log lockout status changes | Partial | -- |
| 10.3.3 | Audit log integrity | Gap | No file integrity mechanism |
| 10.5.1 | 12-month retention | Gap | No logrotate config shipped |
| 3.7.6 | Key lifecycle audit trails | Gap | Key events are tracing-only |

### ISO/IEC Standards

| Standard | Title | Where Referenced | Notes |
|----------|-------|------------------|-------|
| ISO/IEC 29147:2018 | Vulnerability Disclosure | `SECURITY.md:281` | Referenced for vulnerability disclosure process |
| ISO 27001 | ISMS | `docs/sub-agents/observability-audit.md` | Controls A.10.1.2, A.12.4.1, A.12.4.2 mapped |
| ISO 27002 | Security Controls | `docs/sub-agents/observability-audit.md` | -- |

### HIPAA Security Rule

| Section | Description | Status | Notes |
|---------|-------------|--------|-------|
| SS164.312(a)(2)(iv) | Encryption and decryption | Supported | TLS, DPoP binding |
| SS164.312(b) | Audit controls | Partial | Structured logs present; retention gap |

### FedRAMP Moderate

| Control Family | Controls Referenced | Status | Notes |
|----------------|---------------------|--------|-------|
| AU (Audit) | AU-2, AU-3, AU-6, AU-9, AU-10, AU-11, AU-14 | Partial | Audit events present; tamper-evidence and retention gaps |
| AC (Access Control) | AC-17 | Partial | Privileged access logging needs auth-strength field |
| IA (Identification) | IA-2(12), IA-7, IA-8(1) | Partial | Replay protection via JTI; timing enforcement gap |
| SC (System/Comms) | SC-8, SC-12, SC-13 | Partial | TLS enforced; key management audit gap |
| SI (System Integrity) | SI-4, SI-7 | Gap | No file integrity monitoring for audit logs |

### CIS Controls

| Control | Description | Implementation | Files |
|---------|-------------|----------------|-------|
| 5.2 | Use MFA | ACR enforcement via OIDC | `pam-unix-oidc/src/policy/` |
| 6.3 | Require MFA for admin access | Step-up for sudo via CIBA | `pam-unix-oidc/src/ciba/` |
| 8.5 | Centralized log collection | JSON structured audit logs | `pam-unix-oidc/src/audit.rs` |

### OWASP

| Reference | Where Used | Notes |
|-----------|-----------|-------|
| OWASP Authentication Cheat Sheet | `docs/security-guide.md:457` | Referenced as external resource |
| OWASP Testing Guide v4 | `docs/security-testing-roadmap.md:177` | Testing methodology |
| OWASP Top 10 | `.github/PULL_REQUEST_TEMPLATE.md:34` | PR checklist item |

### MITRE ATT&CK v16

Referenced in `docs/THREAT_MODEL.md` (Appendix C) and `docs/threat-model.md` (Section 3).

| Technique ID | Name | Mitigation |
|-------------|------|------------|
| T1078 | Valid Accounts | DPoP prevents stolen token reuse; MFA via IdP |
| T1078.003 | Valid Accounts: Local Accounts | Break-glass access audited |
| T1078.004 | Valid Accounts: Cloud Accounts | OIDC token validation |
| T1110 | Brute Force | Rate limiting, exponential backoff |
| T1133 | External Remote Services | PAM enforces OIDC auth for SSH |
| T1134.001 | Access Token Manipulation | Signature verification, DPoP binding |
| T1195.002 | Supply Chain: Software | cargo audit, dependency-review, SBOM |
| T1199 | Trusted Relationship | IdP trust chain validation |
| T1003.007 | OS Credential Dumping: Proc Filesystem | `mlock`, `ZeroizeOnDrop`, core dump suppression |
| T1005 | Data from Local System | Keychain storage, file permissions |
| T1499.003 | Application Exhaustion Flood | Bounded JTI cache (100k), TTL cleanup |
| T1539 | Steal Web Session Cookie | DPoP binding makes stolen tokens unusable |
| T1548.003 | Sudo and Sudo Caching | CIBA step-up, ACR enforcement |
| T1550.001 | Use Alternate Auth Material | DPoP proof-of-possession |
| T1555.001 | Credentials from Password Stores: Keychain | OS keychain integration, `mlock` |
| T1557 | Adversary-in-the-Middle | TLS required, DPoP binding |
| T1559.001 | IPC: Component Object Model | Unix socket permissions |
| T1606.001 | Forge Web Credentials | JWT signature verification, JWKS pinning |

### STRIDE (Microsoft SDL)

Referenced in `docs/THREAT_MODEL.md` (Appendix A) and `docs/threat-model.md` (Section 2). Full categorization: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.

### Other Standards

| Standard | Where Referenced | Notes |
|----------|------------------|-------|
| PKCS#11 v2.40 | `docs/hardware-key-setup.md:82`, `unix-oidc-agent/src/crypto/yubikey_signer.rs` | SS2.3.6 (key generation), SS11.3.1 (ECDSA signature format); YubiKey PIV interface |
| TCG TPM 2.0 Part 2 | `docs/hardware-key-setup.md:301`, `unix-oidc-agent/src/crypto/tpm_signer.rs` | Hardware-backed DPoP signing via tss-esapi |
| DoD 5220.22-M | `CLAUDE.md:198` | Historical reference for three-pass overwrite; superseded by NIST SP 800-88 Rev 1 |

---

## 6. Implementation Status Summary

| Category | Full | Partial | Referenced-Only | Total |
|----------|------|---------|-----------------|-------|
| RFCs (Normative) | 13 | 1 | 0 | 14 |
| RFCs (Informative/Planned) | 1 | 0 | 3 | 4 |
| OpenID Specs | 4 | 0 | 0 | 4 |
| IETF Drafts | 0 | 1 | 1 | 2 |
| NIST SP | 2 | 4 | 1 | 7 |
| FIPS | 2 | 0 | 2 | 4 |
| SOC 2 Controls | 4 | 1 | 0 | 5 mapped (4 gaps) |
| PCI DSS Requirements | 0 | 3 | 0 | 3 mapped (3 gaps) |
| MITRE ATT&CK Techniques | 18 mapped | -- | -- | 18 |
| **Totals** | **44** | **10** | **7** | **61** |

---

## 7. Cross-Reference Index

For each source file that references standards, the standards it cites.

### Rust Implementation Files

| File | Standards Referenced |
|------|---------------------|
| `pam-unix-oidc/src/oidc/dpop.rs` | RFC 9449, RFC 7638, RFC 7518, FIPS 186-5, draft-ietf-jose-pq-composite-sigs-01 |
| `pam-unix-oidc/src/oidc/validation.rs` | RFC 7519, RFC 7517, RFC 7515, RFC 9700, SP 800-63B, SP 800-131A |
| `pam-unix-oidc/src/audit.rs` | RFC 3339, SP 800-53 (AU-*) |
| `pam-unix-oidc/src/policy/config.rs` | RFC 7662, RFC 9449 SS8 |
| `pam-unix-oidc/src/ciba/client.rs` | CIBA Core 1.0 SS7.1/SS10.1, OpenID EAP ACR Values 1.0 |
| `pam-unix-oidc/src/ciba/types.rs` | RFC 6749 SS5.1, CIBA Core 1.0 SS10.2 |
| `pam-unix-oidc/src/device_flow/client.rs` | RFC 9700 SS2.5 |
| `pam-unix-oidc/src/device_flow/types.rs` | RFC 9700 SS2.5 |
| `unix-oidc-agent/src/main.rs` | RFC 5424, RFC 7009 |
| `unix-oidc-agent/src/daemon/socket.rs` | RFC 6749 SS5.2, RFC 7009 SS2.1, CIBA Core 1.0 SS11 |
| `unix-oidc-agent/src/daemon/protocol.rs` | RFC 7009 |
| `unix-oidc-agent/src/crypto/dpop.rs` | RFC 9449 SS4.2 |
| `unix-oidc-agent/src/crypto/thumbprint.rs` | RFC 7638 |
| `unix-oidc-agent/src/crypto/protected_key.rs` | RFC 7638, SP 800-57 |
| `unix-oidc-agent/src/crypto/pqc_signer.rs` | draft-ietf-jose-pq-composite-sigs-01, RFC 7638, FIPS 204 |
| `unix-oidc-agent/src/crypto/tpm_signer.rs` | RFC 9449 SS4.2, RFC 7638 SS3.3, TCG TPM 2.0 |
| `unix-oidc-agent/src/crypto/yubikey_signer.rs` | RFC 7638 SS3.3, PKCS#11 v2.40 |
| `unix-oidc-agent/src/storage/secure_delete.rs` | NIST SP 800-88 Rev 1 SS2.4/SS2.5 |
| `unix-oidc-agent/src/storage/file_store.rs` | NIST SP 800-88 Rev 1 SS2.4 |
| `unix-oidc-agent/src/storage/router.rs` | NIST SP 800-88 |
| `unix-oidc-agent/src/askpass.rs` | RFC 9449 SS4 |
| `rust-oauth-dpop/src/server.rs` | RFC 9449 SS11.1, RFC 7638 |
| `rust-oauth-dpop/src/thumbprint.rs` | RFC 7638 |
| `rust-oauth-dpop/src/lib.rs` | RFC 9449 SS4.2 |
| `rust-oauth-dpop/src/jwk.rs` | RFC 7638 |

### Cross-Language DPoP Libraries

| File | Standards Referenced |
|------|---------------------|
| `go-oauth-dpop/dpop.go` | RFC 9449, RFC 7638 SS3.3, RFC 7518 SS6.2.1.2 |
| `python-oauth-dpop/oauth_dpop/thumbprint.py` | RFC 7638 |
| `python-oauth-dpop/oauth_dpop/server.py` | RFC 9449 |
| `java-oauth-dpop/src/.../Thumbprint.java` | RFC 7638 |
| `java-oauth-dpop/src/.../DPoPValidator.java` | RFC 9449 |

### Test Files

| File | Standards Referenced |
|------|---------------------|
| `test/tests/test_token_exchange.py` | RFC 9449, RFC 8693, RFC 7638 SS3.2 |
| `test/tests/test_token_exchange.sh` | RFC 9449 SS4.2, RFC 8693, RFC 7638 SS3.2, RFC 7517, RFC 7518, RFC 4648 SS5 |
| `test/tests/test_dpop_binding.sh` | RFC 9449, RFC 7638 |

### Documentation Files

| File | Standards Referenced |
|------|---------------------|
| `SECURITY.md` | RFC 9449, NIST SP 800-63B, NIST CSF, ISO/IEC 29147:2018, MITRE ATT&CK, STRIDE |
| `README.md` | RFC 9449, RFC 8628, RFC 7519, RFC 7517, NIST SP 800-63, NIST SP 800-88, MITRE ATT&CK, NIST CSF |
| `CLAUDE.md` | RFC 9449, NIST SP 800-88 Rev 1 SS2.5 |
| `docs/security-guide.md` | NIST SP 800-63 (AAL), SOC 2 (CC6/CC7), CIS Controls (5.2/6.3/8.5), OWASP, RFC 9449 |
| `docs/THREAT_MODEL.md` | NIST CSF 2.0 (full mapping), MITRE ATT&CK, STRIDE, SOC 2, PCI DSS, HIPAA, FedRAMP, FIPS 186-4/204 |
| `docs/threat-model.md` | RFC 9449, RFC 7638, RFC 7519, RFC 6749, NIST SP 800-63B, NIST SP 800-88, MITRE ATT&CK v16, STRIDE |
| `docs/hardware-key-setup.md` | RFC 9449, RFC 5480, PKCS#11 v2.40, TCG TPM 2.0 |
| `docs/storage-architecture.md` | NIST SP 800-88 Rev 1 |
| `docs/security-testing-roadmap.md` | RFC 9449, NIST SP 800-115, OWASP Testing Guide v4 |
| `docs/adversarial-review.md` | RFC 9449, RFC 7009, NIST SP 800-63B SS5.1.9, NIST SP 800-88, SOC 2, FedRAMP, ISO 27001 |
| `docs/adr/001-dpop-proof-of-possession.md` | RFC 9449, RFC 8471 |
| `docs/adr/002-pam-agent-architecture.md` | RFC 7662, CIBA Core 1.0 |
| `docs/adr/003-token-validation-strategy.md` | RFC 7519, RFC 7517, OpenID Connect Core 1.0 |
| `docs/adr/004-device-authorization-grant.md` | RFC 8628 |
| `docs/adr/005-dpop-token-exchange.md` | RFC 8693, RFC 9449 |
| `docs/adr/005-dpop-token-exchange-alignment.md` | RFC 8693, RFC 9449, draft-ietf-oauth-identity-chaining-08 |
| `docs/adr/007-pqc-hybrid-dpop.md` | FIPS 204, RFC 9449, RFC 7638, draft-ietf-jose-pq-composite-sigs-01 |

### Audit Reports (Internal -- gitignored)

| File | Standards Referenced |
|------|---------------------|
| `docs/sub-agents/oidc-audit.md` | RFC 6749, RFC 7517, RFC 7519, RFC 8414, RFC 9449, RFC 9700, RFC 7515, RFC 7662, RFC 8628, OpenID Connect Core 1.0, OpenID Connect Discovery 1.0 |
| `docs/sub-agents/nist-audit.md` | NIST SP 800-63B, SP 800-88, SP 800-131A, SP 800-57, SP 800-53, FIPS 186-5, FIPS 203, FIPS 204, NIST CSF 2.0, RFC 9449, RFC 7638, RFC 7517 |
| `docs/sub-agents/crypto-audit.md` | RFC 9449, RFC 7638, FIPS 204, NIST SP 800-88, draft-ietf-jose-pq-composite-sigs-01 |
| `docs/sub-agents/observability-audit.md` | SOC 2 (CC6/CC7/A1), PCI DSS v4.0 (Req 3/10), HIPAA SS164.312, FedRAMP (AU/AC/IA/SC/SI), ISO 27001/27002, GDPR, NIST SP 800-57, RFC 3339, RFC 5424 |
| `docs/sub-agents/consolidated-audit-report.md` | RFC 7517, NIST SP 800-88, SOC 2, PCI DSS, HIPAA, FedRAMP |

---

## 8. Known Gaps

Standards referenced in audit reports where compliance is incomplete.

| Gap ID | Standard | Control/Section | Description | Priority |
|--------|----------|-----------------|-------------|----------|
| F-01 | SP 800-63B SS4.3.3 | Session lifetime | Configurable clock skew exceeds recommended tolerances | HIGH |
| F-02 | SP 800-53 IA-2(12) | Replay protection | JTI cache is process-local; cross-instance replay window | HIGH |
| F-03 | SP 800-131A Table 1 | Algorithm validation | No RSA minimum key length check on JWKS keys | MEDIUM |
| F-04 | SP 800-88 Rev 1 SS2.4 | Media sanitization | DoD 5220.22-M citation should be SP 800-88 | MEDIUM |
| F-05 | SP 800-57 SS5.3 | Key management | DPoP key rotation lifecycle not codified | LOW |
| F-06 | SP 800-131A | Algorithm agility | Config does not enforce approved algorithm set | LOW |
| ~~F-07~~ | ~~FIPS 204 SS3.2~~ | ~~Key protection~~ | ~~ML-DSA signing key lacks `mlock` equivalent~~ | ~~CLOSED (Phase 17, MEM-07)~~ |
| F-08 | SP 800-53 AU-9/10 | Audit integrity | No tamper-evidence on audit logs | INFORMATIONAL |
| ~~OBS-1~~ | ~~SOC 2 CC7.2, PCI 10.2.1~~ | ~~Agent audit events~~ | ~~Agent daemon lacks structured audit events~~ | ~~CLOSED (Phase 17, OBS-1)~~ |
| ~~OBS-3~~ | ~~SOC 2 CC7.2~~ | ~~Session linkage~~ | ~~Sudo step-up not linked to parent SSH session~~ | ~~CLOSED (Phase 17, OBS-3)~~ |
| OBS-4 | PCI 3.7.6 | Key lifecycle | Key events are tracing-only, not audit events | P2 |
| F-09 | RFC 9700 SS2.5 | URI scheme | Device flow verification URI scheme not validated | MEDIUM |
| F-12 | RFC 9700 SS2.5 | Issuer HTTPS | Issuer URL HTTPS scheme not enforced in code | MEDIUM |
