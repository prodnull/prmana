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
# /etc/unix-oidc/policy.yaml
defaults:
  dpop:
    enabled: true
    required: true  # Reject non-DPoP tokens
    algorithms:
      - ES256       # ECDSA P-256 (recommended)
      - ML-DSA-65   # Post-quantum (if supported)
    max_age: 60     # Maximum proof age in seconds
    replay_cache_size: 10000
```

### Post-Quantum Readiness

unix-oidc supports ML-DSA-65 (FIPS 204) for post-quantum security:

```yaml
dpop:
  algorithms:
    - ML-DSA-65   # Post-quantum (primary)
    - ES256       # Fallback for compatibility
```

---

## Deployment Hardening

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
# In /etc/environment or PAM environment

# Required
OIDC_ISSUER="https://auth.example.com/realms/production"
OIDC_CLIENT_ID="unix-oidc"

# Optional security settings
OIDC_VERIFY_TLS="true"          # Never disable in production
OIDC_JWKS_CACHE_TTL="3600"      # Cache JWKS for 1 hour
OIDC_CONNECT_TIMEOUT="5"         # 5 second timeout
```

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
  users:
    - alice  # Pre-authorized emergency users
  method: totp
  secret_file: /etc/unix-oidc/break-glass.key  # chmod 400
  audit: always
```

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

## Additional Resources

- [NIST SP 800-63 Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CIS Controls](https://www.cisecurity.org/controls)
