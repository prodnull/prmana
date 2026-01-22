# Security Policy

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

unix-oidc takes security seriously. As authentication infrastructure, vulnerabilities in this
project could have significant impact. We appreciate your efforts to responsibly disclose
your findings.

### How to Report

Send vulnerability reports to: **security@unix-oidc.dev** (or create a private security
advisory on GitHub)

Include as much of the following information as possible:

- **Type of vulnerability** (e.g., token bypass, privilege escalation, injection, cryptographic weakness)
- **Affected component** (PAM module, agent daemon, IPC, DPoP implementation)
- **Full paths of source files** related to the vulnerability
- **Step-by-step reproduction instructions**
- **Proof-of-concept or exploit code** (if possible)
- **Impact assessment** - what an attacker could achieve
- **CVSS score** (if you have calculated one)
- **Any suggested remediation**

### What to Expect

| Timeframe | Action |
|-----------|--------|
| 24 hours | Initial acknowledgment of your report |
| 72 hours | Preliminary assessment and severity determination |
| 7 days | Detailed response with remediation plan |
| 90 days | Target for fix release (may vary based on complexity) |

We will keep you informed throughout the process and credit you in the security advisory
(unless you prefer to remain anonymous).

## Scope

### In Scope

The following are considered security vulnerabilities:

- **Authentication bypass** - Any method to authenticate without valid credentials
- **Token security** - JWT validation bypasses, replay attacks, token theft
- **DPoP implementation** - Proof-of-possession bypasses, key binding issues
- **Cryptographic weaknesses** - Weak algorithms, timing attacks, key exposure
- **Privilege escalation** - Gaining elevated privileges through the PAM module
- **Unix socket security** - IPC vulnerabilities, unauthorized agent access
- **Configuration security** - Insecure defaults, dangerous configurations
- **Information disclosure** - Leaking tokens, keys, or sensitive user data
- **Denial of service** - Crashes, resource exhaustion affecting authentication
- **Supply chain** - Compromised dependencies, build process issues

### Out of Scope

- Issues in dependencies (report to upstream maintainers)
- Social engineering attacks on users
- Physical attacks requiring local access
- Issues requiring misconfiguration by administrators
- Theoretical attacks without proof of concept

## Security Design Principles

unix-oidc follows these security principles aligned with NIST guidelines:

### NIST SP 800-63B Compliance

- **Authenticator Assurance Level (AAL)**: Designed to support AAL2 and AAL3
- **Proof of Possession**: DPoP implementation per RFC 9449
- **Replay Resistance**: JTI tracking for tokens and DPoP proofs
- **Cryptographic Standards**: ES256 (P-256 ECDSA) per NIST recommendations

### Defense in Depth

1. **Token Validation**: Multiple validation layers (signature, claims, binding)
2. **Replay Protection**: Time-based and nonce-based replay prevention
3. **Constant-Time Operations**: Timing attack resistant comparisons
4. **Minimal Privileges**: PAM module runs with least required privileges
5. **Secure Defaults**: Conservative defaults requiring explicit opt-in for features

### Threat Model

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for comprehensive threat analysis including:
- STRIDE threat categorization
- MITRE ATT&CK technique mapping
- Attack surface analysis
- Mitigation strategies

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Security updates will be backported to supported versions when feasible.

## Security Updates

Security advisories are published through:

1. **GitHub Security Advisories** - Primary disclosure channel
2. **CHANGELOG.md** - Security fixes noted in release notes
3. **GitHub Releases** - Security releases clearly marked

### Subscribing to Updates

- Watch this repository for releases
- Enable GitHub security alerts for your fork
- Monitor the GitHub Security Advisories page

## Hardening Guidelines

### Pre-Deployment Security Checklist

Complete this checklist before deploying unix-oidc to production:

#### Binary Verification
- [ ] Downloaded binaries from official GitHub releases
- [ ] Verified Sigstore signatures on all binaries:
  ```bash
  cosign verify-blob --certificate unix-oidc-*.pem \
    --signature unix-oidc-*.sig \
    --certificate-identity-regexp 'https://github.com/prodnull/unix-oidc' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    unix-oidc-*
  ```
- [ ] Verified SHA256 checksums match release notes

#### Identity Provider Configuration
- [ ] Using HTTPS for all IdP communication (no HTTP)
- [ ] Configured dedicated OIDC client for unix-oidc (not shared with other apps)
- [ ] Client configured as confidential (not public) if supported
- [ ] Enabled PKCE for authorization code flow
- [ ] Restricted redirect URIs to localhost only
- [ ] Set appropriate token lifetimes:
  - Access token: 5-15 minutes recommended
  - Refresh token: 8-24 hours max for interactive sessions
- [ ] Enabled DPoP if IdP supports it

#### File Permissions
- [ ] Configuration file restricted: `chmod 600 /etc/unix-oidc/config.toml`
- [ ] Configuration owned by root: `chown root:root /etc/unix-oidc/config.toml`
- [ ] PAM module permissions: `chmod 755 /usr/lib/security/pam_unix_oidc.so`
- [ ] Agent socket directory: `chmod 750 /run/unix-oidc`
- [ ] Log directory permissions: `chmod 750 /var/log/unix-oidc`

#### Secret Management
- [ ] Client secrets not stored in version control
- [ ] Client secrets sourced from:
  - [ ] Environment variables, OR
  - [ ] Secrets manager (HashiCorp Vault, AWS Secrets Manager), OR
  - [ ] Encrypted configuration
- [ ] No secrets in command-line arguments (visible in `ps`)
- [ ] No secrets in systemd unit files (use `LoadCredential=` instead)

#### Network Security
- [ ] Firewall allows outbound HTTPS (443) to IdP only
- [ ] No inbound ports required for PAM module
- [ ] Agent Unix socket not exposed over network
- [ ] mTLS configured if IdP requires it

#### Token Security
- [ ] DPoP enabled (strongly recommended)
- [ ] JTI replay protection enabled (default)
- [ ] Token cache TTL appropriate for use case
- [ ] Offline access disabled unless specifically needed

#### PAM Configuration
- [ ] PAM stack order correct (unix-oidc after local auth for fallback)
- [ ] Tested with non-privileged user first
- [ ] Emergency local account configured (break-glass)
- [ ] `pam_faillock` or equivalent configured for brute-force protection

#### Logging and Monitoring
- [ ] Audit logging enabled:
  ```toml
  [logging]
  level = "info"
  format = "json"
  destination = "syslog"
  ```
- [ ] Log forwarding to SIEM configured
- [ ] Alerts configured for:
  - [ ] Authentication failures > threshold
  - [ ] Token validation errors
  - [ ] DPoP validation failures
  - [ ] Agent crashes/restarts
- [ ] Log retention meets compliance requirements

#### Backup and Recovery
- [ ] Configuration backed up (encrypted)
- [ ] Recovery procedure documented and tested
- [ ] Break-glass local account credentials secured
- [ ] Rollback procedure documented

#### Testing
- [ ] Tested authentication flow end-to-end
- [ ] Tested IdP unavailability scenario (graceful degradation)
- [ ] Tested token expiration handling
- [ ] Tested sudo step-up flow if enabled
- [ ] Tested with all target user accounts

#### Documentation
- [ ] Runbook created for common operations
- [ ] Incident response procedure documented
- [ ] On-call team trained on unix-oidc
- [ ] User documentation distributed

### Quick Hardening Commands

```bash
# Verify binary signatures before deployment
cosign verify-blob --certificate unix-oidc-agent.pem \
  --signature unix-oidc-agent.sig \
  --certificate-identity-regexp 'https://github.com/prodnull/unix-oidc' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  unix-oidc-agent

# Set strict file permissions
chmod 600 /etc/unix-oidc/config.toml
chown root:root /etc/unix-oidc/config.toml
chmod 755 /usr/lib/security/pam_unix_oidc.so

# Enable audit logging (in config.toml)
cat >> /etc/unix-oidc/config.toml << 'EOF'
[logging]
level = "info"
format = "json"
destination = "syslog"
EOF

# Verify PAM configuration
pamtester sshd testuser authenticate
```

### Configuration Security

- **Never** commit client secrets to version control
- **Always** use HTTPS for OIDC provider communication
- **Enable** DPoP for enhanced token security
- **Configure** appropriate token lifetimes
- **Restrict** Unix socket permissions

### Monitoring

Monitor for:
- Authentication failures (potential brute force)
- Token validation errors (potential replay attacks)
- DPoP validation failures (potential token theft)
- Unusual access patterns

## Vulnerability Disclosure Policy

We follow coordinated disclosure:

1. **Reporter** submits vulnerability privately
2. **Maintainers** acknowledge and assess
3. **Collaboration** on fix and timeline
4. **Fix** developed and tested
5. **Advisory** prepared with reporter credit
6. **Release** with security fix
7. **Public disclosure** after users have time to update

We request a 90-day disclosure window for complex vulnerabilities. We will not take
legal action against security researchers who:

- Make good faith efforts to avoid privacy violations and service disruptions
- Provide sufficient detail for reproduction
- Allow reasonable time for remediation before disclosure
- Do not exploit vulnerabilities beyond proof of concept

## Security Contacts

- **Primary**: security@unix-oidc.dev
- **GitHub**: [Create private security advisory](https://github.com/prodnull/unix-oidc/security/advisories/new)

## Acknowledgments

We gratefully acknowledge security researchers who help improve unix-oidc:

<!-- Security researchers will be acknowledged here after coordinated disclosure -->

*No vulnerabilities have been reported yet. Be the first to help secure unix-oidc!*

---

This security policy is aligned with:
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NIST SP 800-63 Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [ISO/IEC 29147:2018 Vulnerability Disclosure](https://www.iso.org/standard/72311.html)
