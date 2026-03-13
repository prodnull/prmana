# Security Guide

This guide covers security best practices for deploying and operating unix-oidc in production environments. It aligns with NIST SP 800-63 Digital Identity Guidelines and industry security standards.

## Table of Contents

- [Security Architecture](#security-architecture)
- [Authentication Assurance Levels](#authentication-assurance-levels)
- [Token Security](#token-security)
- [DPoP Protection](#dpop-protection)
- [Deployment Hardening](#deployment-hardening)
- [Audit and Monitoring](#audit-and-monitoring)
- [Incident Response](#incident-response)
- [Compliance Mapping](#compliance-mapping)

---

## Security Architecture

### Defense in Depth

unix-oidc implements multiple layers of security:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Layer 1: Network                            │
│  • TLS 1.3 for IdP communication                               │
│  • Network segmentation                                         │
│  • Firewall rules                                               │
├─────────────────────────────────────────────────────────────────┤
│                     Layer 2: Authentication                     │
│  • OIDC token validation                                        │
│  • DPoP proof-of-possession                                     │
│  • Step-up MFA for privileged actions                          │
├─────────────────────────────────────────────────────────────────┤
│                     Layer 3: Authorization                      │
│  • Policy-based access control                                  │
│  • ACR (Authentication Context Class Reference)                 │
│  • Host classification                                          │
├─────────────────────────────────────────────────────────────────┤
│                     Layer 4: Audit                              │
│  • Structured JSON audit logs                                   │
│  • Session correlation                                          │
│  • Tamper-evident logging                                       │
└─────────────────────────────────────────────────────────────────┘
```

### Trust Boundaries

| Boundary | Trust Level | Controls |
|----------|-------------|----------|
| User ↔ PAM | Untrusted | Input validation, rate limiting |
| PAM ↔ IdP | Semi-trusted | TLS, token validation, DPoP |
| PAM ↔ SSSD | Trusted | Local Unix socket |
| PAM ↔ Policy | Trusted | File permissions (root:root 600) |

---

## Authentication Assurance Levels

unix-oidc supports NIST SP 800-63B Authentication Assurance Levels through ACR claims.

### AAL Mapping

| NIST AAL | Description | Typical ACR Values | Use Case |
|----------|-------------|-------------------|----------|
| AAL1 | Single-factor | `urn:*:acr:1`, `password` | Low-risk access |
| AAL2 | Multi-factor | `urn:*:acr:loa2`, `mfa` | Standard access |
| AAL3 | Hardware MFA | `phr`, `phrh` | High-security access |

### Configuring ACR Requirements

```yaml
# /etc/unix-oidc/policy.yaml
defaults:
  # Minimum AAL2 for all access
  required_acr: urn:ietf:params:acr:aal2

hosts:
  production-*:
    classification: critical
    # AAL3 for production systems
    required_acr: urn:ietf:params:acr:aal3

commands:
  /usr/bin/sudo:
    # Step-up to AAL2 for sudo
    step_up_required: true
    required_acr: urn:ietf:params:acr:aal2
```

### Provider-Specific ACR Values

| Provider | AAL1 | AAL2 | AAL3 |
|----------|------|------|------|
| Azure AD | `pwd` | `mfa` | `windowsHello` |
| Auth0 | (none) | `http://schemas.openid.net/pape/policies/2007/06/multi-factor` | - |
| Keycloak | `urn:keycloak:acr:0` | `urn:keycloak:acr:loa2` | - |
| Okta | `pwd` | `mfa` | `phr` |

---

## Token Security

### Token Validation

unix-oidc performs comprehensive token validation:

1. **Signature verification** - JWKS-based, supports RS256/ES256/EdDSA
2. **Issuer validation** - Must match configured OIDC_ISSUER
3. **Audience validation** - Must include OIDC_CLIENT_ID
4. **Expiration check** - Rejects expired tokens
5. **Not-before check** - Rejects tokens used before nbf
6. **DPoP binding** - When enabled, validates proof-of-possession

### Token Lifetime Recommendations

| Token Type | Recommended Lifetime | Rationale |
|------------|---------------------|-----------|
| Access Token | 5-15 minutes | Limits exposure window |
| Refresh Token | 8-24 hours | Balance security/usability |
| DPoP Proof | 60 seconds | Replay protection |

### Configuring in IdP

**Azure AD:**
```json
{
  "accessTokenAcceptedVersion": 2,
  "accessTokenLifetime": "00:15:00"
}
```

**Keycloak:**
- Realm Settings → Tokens → Access Token Lifespan: 15 minutes
- Realm Settings → Tokens → SSO Session Max: 8 hours

---

## DPoP Protection

DPoP (Demonstrating Proof of Possession) binds tokens to cryptographic keys, preventing token theft attacks.

### How DPoP Works

```
┌──────────┐    ┌──────────┐    ┌──────────┐
│  Client  │    │   IdP    │    │  Server  │
└────┬─────┘    └────┬─────┘    └────┬─────┘
     │               │               │
     │ Generate keypair              │
     │──────────────>│               │
     │               │               │
     │ DPoP proof + auth request     │
     │──────────────>│               │
     │               │               │
     │ DPoP-bound access token       │
     │<──────────────│               │
     │               │               │
     │ Token + fresh DPoP proof      │
     │──────────────────────────────>│
     │               │               │
     │               │ Validate:     │
     │               │ - Token sig   │
     │               │ - DPoP proof  │
     │               │ - cnf.jkt     │
     │               │               │
```

### Security Properties

| Property | Protection |
|----------|------------|
| Token theft | Stolen tokens unusable without private key; if both stolen, damage is time-limited |
| Replay attack | jti + iat validation with time window |
| Key confusion | cnf.jkt binding in token |

> **Honest limitation:** DPoP reduces blast radius, not eliminates risk. If an attacker can extract tokens from memory, they can likely extract the DPoP key too. The value is time-limited damage (tokens expire), centralized revocation (IdP controls access), and audit trails. For maximum protection, use hardware-backed key storage (TPM, Secure Enclave).

### Enabling DPoP

```yaml
# /etc/unix-oidc/policy.yaml — DPoP is controlled via security_modes
security_modes:
  dpop_required: strict  # strict (default) | warn | disabled
```

DPoP uses ES256 (P-256 ECDSA) exclusively. The algorithm is enforced at the code level — there is no configuration to change it, preventing algorithm downgrade attacks. Max proof age defaults to 60 seconds.

### Post-Quantum Readiness

> **Status: Planned (not yet implemented).** The configuration schema includes an `enable_pqc` flag for forward compatibility, but ML-DSA-65 support is not yet available. ES256 (P-256 ECDSA) is the only supported DPoP algorithm today. Post-quantum algorithm support will be added when mature Rust PQC libraries are available and OIDC ecosystem support emerges. See NIST FIPS 204 for the ML-DSA specification.

---

## Deployment Hardening

### DPoP Enforcement (CRITICAL)

> **Production deployments MUST set `dpop_required: strict` in policy.yaml.**

DPoP (proof-of-possession) is the primary defense against token theft. Without it, stolen bearer tokens grant full access. The default is `strict`, but operators who set `warn` or `disabled` during migration MUST re-enable strict enforcement before production use.

```yaml
# /etc/unix-oidc/policy.yaml
security_modes:
  dpop_required: strict   # REQUIRED for production — rejects non-DPoP tokens
```

Running with `dpop_required: warn` or `disabled` in production is a **documented residual risk** (R-6 in the threat model) and leaves the deployment vulnerable to bearer token replay.

### File Permissions

```bash
# PAM module
chmod 755 /lib/security/pam_unix_oidc.so
chown root:root /lib/security/pam_unix_oidc.so

# Configuration
chmod 600 /etc/unix-oidc/policy.yaml
chown root:root /etc/unix-oidc/policy.yaml

# Audit logs
chmod 640 /var/log/unix-oidc/audit.log
chown root:adm /var/log/unix-oidc/audit.log
```

### SELinux Policy

```
# /etc/selinux/local/unix-oidc.te
module unix_oidc 1.0;

require {
    type pam_t;
    type http_port_t;
    class tcp_socket { connect };
}

# Allow PAM to connect to IdP
allow pam_t http_port_t:tcp_socket connect;
```

### Network Security

```bash
# Firewall rules (allow only IdP egress)
iptables -A OUTPUT -p tcp -d <idp-ip> --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j DROP

# Or with security groups / network policies
# Only allow egress to IdP endpoints
```

### Environment Variables

```bash
# Secure environment configuration
# Set in /etc/unix-oidc/env (chmod 600, root:root)

# Required
OIDC_ISSUER="https://auth.example.com/realms/production"
OIDC_CLIENT_ID="unix-oidc"

# Optional: Override policy file location (default: /etc/unix-oidc/policy.yaml)
# UNIX_OIDC_POLICY_FILE="/etc/unix-oidc/policy.yaml"

# Optional: Audit log file path
# UNIX_OIDC_AUDIT_LOG="/var/log/unix-oidc/audit.log"
```

> **Note:** TLS verification is always enabled and cannot be disabled via configuration. This is by design — all IdP communication must use HTTPS with proper certificate validation.

---

## Audit and Monitoring

### Audit Log Format

unix-oidc produces structured JSON audit logs:

```json
{
  "timestamp": "2026-01-18T10:30:45.123Z",
  "event": "AUTH_SUCCESS",
  "session_id": "sess-abc123",
  "user": "alice",
  "host": "prod-web-01",
  "source_ip": "10.1.2.3",
  "oidc_sub": "auth0|abc123",
  "oidc_iss": "https://auth.example.com/",
  "oidc_acr": "mfa",
  "dpop_jkt": "sha256-xyz...",
  "service": "sshd",
  "result": "success"
}
```

### Event Types

| Event | Description | Severity |
|-------|-------------|----------|
| `AUTH_SUCCESS` | Successful authentication | Info |
| `AUTH_FAILURE` | Failed authentication | Warning |
| `TOKEN_EXPIRED` | Token validation failed (expired) | Warning |
| `TOKEN_INVALID` | Token validation failed (signature) | Alert |
| `DPOP_REPLAY` | DPoP replay attack detected | Critical |
| `STEP_UP_REQUIRED` | Step-up authentication triggered | Info |
| `STEP_UP_SUCCESS` | Step-up completed | Info |
| `STEP_UP_FAILURE` | Step-up failed | Warning |

### SIEM Integration

```yaml
# Fluent Bit configuration
[INPUT]
    Name tail
    Path /var/log/unix-oidc/audit.log
    Parser json
    Tag unix-oidc.audit

[OUTPUT]
    Name splunk
    Match unix-oidc.*
    Host splunk.example.com
    Port 8088
    TLS On
```

### Alerting Rules

```yaml
# Example Prometheus alerting rules
groups:
  - name: unix-oidc
    rules:
      - alert: DPoPReplayDetected
        expr: increase(unix_oidc_dpop_replay_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "DPoP replay attack detected"

      - alert: AuthFailureSpike
        expr: rate(unix_oidc_auth_failures_total[5m]) > 10
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
```

---

## Incident Response

### Token Compromise

If you suspect token compromise:

1. **Immediate**: Revoke refresh tokens in IdP
2. **Short-term**: Reduce token lifetime
3. **Investigation**: Correlate audit logs by session_id
4. **Remediation**: Rotate client secrets if applicable

```bash
# Keycloak: Revoke all sessions for user
kcadm.sh delete users/<user-id>/sessions -r production

# Azure AD: Revoke refresh tokens
az ad user update --id <user-id> --force-change-password-next-sign-in
```

### DPoP Key Compromise

If a client's DPoP key is compromised:

1. The key only works for that specific client
2. Token theft is still prevented (attacker needs both)
3. Rotate the key via agent restart or key rotation API

### Break-Glass Procedure

For emergency access when IdP is unavailable:

```yaml
# /etc/unix-oidc/policy.yaml
break_glass:
  enabled: true
  accounts:
    - breakglass       # Pre-authorized emergency accounts
    - emergency-admin
  requires: yubikey_otp  # Optional: require hardware token for break-glass
  alert_on_use: true     # Log alert when break-glass is used
```

> **Note:** Break-glass accounts must exist as local Unix accounts with password authentication configured. See the [installation guide](installation.md) for setup instructions.

---

## Compliance Mapping

### NIST SP 800-63 Alignment

| Requirement | unix-oidc Implementation |
|-------------|-------------------------|
| 800-63A: Identity Proofing | Delegated to IdP |
| 800-63B: Authentication | ACR-based AAL enforcement |
| 800-63C: Federation | OIDC with DPoP binding |

### SOC 2 Controls

| Control | Implementation |
|---------|----------------|
| CC6.1: Logical Access | Policy-based authorization |
| CC6.2: Auth Mechanisms | MFA via OIDC, DPoP |
| CC6.3: Access Removal | Token expiration, IdP revocation |
| CC7.2: System Monitoring | Structured audit logs |

### CIS Controls

| Control | Implementation |
|---------|----------------|
| 5.2: Use MFA | ACR enforcement |
| 6.3: Require MFA for Admin | Step-up for sudo |
| 8.5: Centralized Log Collection | JSON audit logs |

---

## Security Checklist

### Pre-Deployment

- [ ] TLS certificates valid and trusted
- [ ] Token lifetimes configured appropriately
- [ ] DPoP enabled if available
- [ ] ACR requirements match security policy
- [ ] File permissions hardened
- [ ] Audit logging configured and tested
- [ ] SIEM integration verified
- [ ] Break-glass procedure documented and tested

### Ongoing Operations

- [ ] Regular security updates applied
- [ ] JWKS cache functioning (check TTL)
- [ ] Audit logs reviewed
- [ ] Token lifetime appropriate for threat model
- [ ] IdP health monitored
- [ ] Incident response procedures current

---

## D-Bus and Secret Service Transport Security

### Advisory: D-Bus Session Bus Snooping

The Linux agent uses the [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/) (via the `keyring` crate and `libdbus-sys`) to store DPoP keys and OAuth tokens in GNOME Keyring or KDE Wallet.

**D-Bus itself provides no wire encryption.** The session bus uses Unix domain sockets with `SCM_CREDENTIALS` (peer UID verification) for authentication, but message payloads are plaintext. Any process running as the same UID can call `dbus-monitor` or `busctl monitor` to observe all session bus traffic.

**The Secret Service API mitigates this** by negotiating an encrypted session (`dh-ietf1024-sha256-aes128-cbc-pkcs7`) via `org.freedesktop.secrets.Session.OpenSession`. When an encrypted session is active, credential values are encrypted in transit over D-Bus even though D-Bus itself is unencrypted.

### Residual Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Same-user D-Bus snooping | Medium | Secret Service session encryption protects credential payloads |
| Root-level bus interception | High | Root access is a complete compromise regardless; out of scope |
| Secret Service `plain` session fallback | Medium | If the daemon negotiates `plain` instead of `dh-ietf1024-*`, credentials transit D-Bus unencrypted. The `keyring` crate delegates session negotiation to the daemon — there is no application-level control to reject `plain` sessions |
| `libdbus-sys` supply chain | Low | Well-maintained, mirrors the C `libdbus` API; pinned in `Cargo.lock` |

### Recommendations for Operators

1. **Ensure a Secret Service daemon is running** (GNOME Keyring, KDE Wallet, or `keepassxc`). Without one, the agent falls back to file-based storage.
2. **Prefer keyring backends over file storage** — the keyring provides memory protection, access control, and (with encrypted sessions) transport encryption that file storage cannot.
3. **Restrict D-Bus monitor access** in hardened environments: remove `dbus-monitor` from production images, or apply AppArmor/SELinux policy to restrict `org.freedesktop.DBus.Monitoring` interface access.
4. **Full-disk encryption** remains the primary defense for at-rest credential material on CoW filesystems and SSDs (NIST SP 800-88 Rev 1, §2.5).

---

## Additional Resources

- [NIST SP 800-63 Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CIS Controls](https://www.cisecurity.org/controls)
