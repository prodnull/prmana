<p align="center">
  <img src="assets/logo.svg" alt="unix-oidc logo" width="120" height="120">
</p>

<h1 align="center">unix-oidc</h1>

<p align="center">
  <strong>Step-up authentication layer for Linux SSH and sudo with OIDC</strong>
</p>

> **⚠️ EDUCATIONAL USE ONLY ⚠️**
>
> This project is provided for **educational and discussion purposes only**. It demonstrates concepts related to OIDC authentication, DPoP token binding, and PAM module development. **It is NOT intended for production use.**
>
> Licensed under [CC BY-NC-SA 4.0](LICENSE) (Non-Commercial).

<p align="center">
  <a href="https://github.com/prodnull/unix-oidc/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-CC%20BY--NC--SA%204.0-lightgrey.svg" alt="License"></a>
</p>

<p align="center">
  <a href="#why-unix-oidc">Why?</a> •
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#deployment">Deployment</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#learn-more">Learn More</a>
</p>

---

## Why unix-oidc?

A senior engineer leaves. They had SSH keys on dozens of servers — production, staging, internal tools. Nobody knows where all the keys are. Finding them is archaeology: grepping `authorized_keys` files across every host, hoping you don't miss one. Meanwhile, those keys still work.

This isn't a hypothetical. It's the norm. SSH keys get copied, shared, never rotated, and rarely audited. When someone leaves, their access doesn't leave with them — it lingers until someone finds it. unix-oidc fixes this: authentication flows through your IdP (Okta, Entra, Keycloak). Disable the user in your IdP, and their server access dies instantly. No key hunting.

**[OpenID Connect (OIDC)](https://openid.net/specs/openid-connect-core-1_0.html)** solves identity, but existing tools have significant limitations:

### Open Source Alternatives

| Tool | Limitation |
|------|------------|
| [pam_oidc](https://github.com/salesforce/pam_oidc) (Salesforce) | Bearer tokens only—if stolen, attacker has full access. No sudo step-up. |
| [pam_oauth2_device](https://github.com/ICS-MU/pam_oauth2_device) | Device flow support, but still bearer tokens. No cryptographic binding. |
| [pam-keycloak-oidc](https://github.com/zhaow-de/pam-keycloak-oidc) | Keycloak-specific. Embeds OTP in password field (hacky UX). |
| [ssh-oidc](https://github.com/EOSC-synergy/ssh-oidc) | Token passed as password—limited to 1023 bytes by OpenSSH. |

### "Why not Teleport / StrongDM / CyberArk?"

Good question. These are serious products. Here's the honest answer.

**The SSH identity market has three architectures:**

| Architecture | How it works | Players |
|---|---|---|
| **Gateway/Proxy** | All SSH routes through a central proxy that issues short-lived certs from its own CA | Teleport, StrongDM, Boundary |
| **Vault/Broker** | A privileged access manager brokers and records SSH sessions, manages credential rotation | CyberArk, BeyondTrust, Delinea |
| **PAM drop-in** | A module on the server validates OIDC tokens directly against the IdP. No proxy, no CA, no new infra | **unix-oidc** |

**When to use them instead of us:**
- You want session recording, RBAC policies, and a managed gateway → **Teleport**
- You need credential vaulting, rotation, and compliance reporting across SSH/RDP/databases → **CyberArk/Delinea**
- Budget is not a constraint and you want a turnkey platform → **StrongDM**

**When to use us:**
- You already have an IdP (Okta, Entra, Keycloak) and don't want another identity silo
- You want to cover servers where a proxy is impractical — edge nodes, CI runners, legacy boxes, air-gapped environments, the staging server someone set up "temporarily" three years ago
- You need DPoP token binding (RFC 9449) — intercepted tokens are cryptographically useless without the private key. Teleport/StrongDM use short-lived bearer certs that are replayable during their validity window
- You want sudo step-up MFA via CIBA (phone push approval for `sudo`)
- You want to drop in alongside existing sshd with zero infrastructure changes

**The key security difference: token binding.**

Teleport and StrongDM issue short-lived x509 certificates. These are bearer credentials — if exfiltrated from `/tmp` or memory during their 5-15 minute validity window, an attacker can use them from any machine. DPoP (RFC 9449) binds every token to the client's ephemeral private key. The token is useless without the key, even during its validity window. This is the same proof-of-possession model used by banking APIs.

**Complementary at worst, sufficient at best.** If you have Teleport on your managed fleet, unix-oidc covers the long tail. If you don't want gateway architecture, unix-oidc is the lightweight path to IdP-backed SSH.

### Feature Comparison

| Feature | unix-oidc | Teleport | StrongDM | CyberArk |
|---------|-----------|----------|----------|----------|
| SSH OIDC auth | ✅ | Enterprise | ✅ | Via proxy |
| DPoP token binding (RFC 9449) | ✅ | ❌ (bearer certs) | API only | ❌ |
| Sudo step-up (CIBA) | ✅ | ❌ | ❌ | ❌ |
| SPIFFE workload identity | ✅ | ✅ | ✅ | ❌ |
| No proxy required | ✅ | ❌ | ❌ | ❌ |
| Session recording | ❌ | ✅ | ✅ | ✅ |
| Credential vaulting | ❌ | ❌ | ❌ | ✅ |
| Works with existing sshd | ✅ | ❌ (own client) | ❌ (own client) | Via proxy |
| IdP failover (Phase 41) | ✅ | Via HA proxy | Via HA proxy | Via HA proxy |
| Open source | ✅ | Partial | ❌ | ❌ |
| Deployment | PAM module | Gateway cluster | SaaS + relay | On-prem vault |

### Sudo step-up: sudo as a fresh trust boundary

Most SSH identity solutions — gateways (Teleport, StrongDM), vaults (CyberArk, Delinea), and MFA-for-SSH tools (Duo Unix, Okta PAM) — challenge at login or session start. Once you're in, `sudo` either just works, relies on a proprietary agent command (`dzdo`), or requires a separate MFA product bolted onto PAM.

unix-oidc treats `sudo` as a fresh trust boundary, not an extension of the login session. Via [CIBA](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) (Client-Initiated Backchannel Authentication), your phone receives a push notification with the **specific command** — "Approve `sudo apt install nginx` on server-01" — and the command only executes after you confirm. This is OIDC-native: the step-up challenge flows through your existing IdP as a fresh, locally validated token — not a separate MFA integration, not a proprietary agent, not a session-level blanket approval.

### Why This Matters Now

Recent attacks prove that static credentials and bearer tokens are no longer defensible:

| Attack | CVE | What happened | What unix-oidc changes |
|--------|-----|---------------|----------------------|
| **xz/liblzma backdoor** | [CVE-2024-3094](https://nvd.nist.gov/vuln/detail/cve-2024-3094) | Supply chain backdoor in a compression library hijacked OpenSSH's `RSA_public_decrypt`, enabling remote auth bypass. Static SSH keys meant the backdoor granted persistent access to any server the key was authorized for. | DPoP-bound tokens expire. Even a backdoored sshd that intercepts a token cannot reuse it — the attacker lacks the DPoP private key. Blast radius is bounded by token lifetime, not key lifetime. |
| **GitHub Actions secret leak** | [CVE-2025-30066](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3) | Compromised GitHub Action exfiltrated SSH keys and access tokens from 23,000+ repo CI pipelines to workflow logs. Any bearer token in those logs was immediately usable. | DPoP-bound tokens leaked to logs are inert — they require a corresponding private key to use. The key never appears in logs. |
| **PuTTY key recovery** | [CVE-2024-31497](https://nvd.nist.gov/vuln/detail/cve-2024-31497) | Biased ECDSA nonces in PuTTY allowed private key recovery from ~60 signatures. A rogue SSH server could harvest enough signatures during normal logins to steal the key permanently. | unix-oidc tokens are short-lived — stolen credentials have a bounded window. TPM-backed DPoP keys (hardware non-exportable) cannot be recovered even with full nonce bias exploitation. |
| **JWT algorithm confusion** | [CVE-2023-48223](https://github.com/advisories/GHSA-c2ff-88x2-x9pg) | JWT libraries accepted HMAC signatures verified with RSA public keys, enabling token forgery with zero knowledge of private keys. | unix-oidc enforces an asymmetric-only algorithm allowlist and pins the token's algorithm to the JWKS-advertised algorithm. HMAC algorithms are rejected at every verification point. |

**What we honestly cannot prevent:** If the PAM module binary itself is backdoored (analogous to xz targeting our `.so`), the attacker controls verification. DPoP cannot help if the verifier is compromised. Mitigations: code signing, SLSA provenance, reproducible builds. These are tracked in our [security roadmap](docs/security-guide.md).

**unix-oidc** was built to address these gaps:

- **[DPoP token binding](https://datatracker.ietf.org/doc/html/rfc9449)** (RFC 9449): Tokens are cryptographically bound to a key pair. Even if an attacker intercepts a token, they can't use it without the private key. This is the same security model used by modern banking APIs.

- **Sudo step-up authentication**: SSH login is just the beginning. Sensitive commands like `systemctl restart` or `kubectl delete` can require fresh MFA via [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628) (RFC 8628)—bringing web-grade security to the terminal.

- **Provider-agnostic**: Works with Azure AD, Auth0, Google, Okta, Keycloak, or any OIDC-compliant provider. No vendor lock-in.

- **Memory-safe implementation**: Written in Rust. No buffer overflows, no use-after-free, no memory corruption vulnerabilities that plague C-based [PAM modules](https://www.man7.org/linux/man-pages/man8/pam.8.html).

- **Production-ready security**: Rate limiting, [JTI](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7) replay protection, structured audit logging, and alignment with [NIST SP 800-63](https://pages.nist.gov/800-63-3/) digital identity guidelines.

### Developer & User Experience

Enterprise MFA solutions often create friction that developers actively work around. unix-oidc was designed with usability as a core requirement:

| Pain Point | Traditional MFA | unix-oidc |
|------------|----------------|-----------|
| Password fatigue | Yet another password to remember | **No passwords**—use your existing IdP (Google, Azure AD, Okta) |
| Token management | Hardware tokens to carry, batteries that die | **Phone-based**—device flow works with authenticator apps you already have |
| SSH workflow disruption | Copy-paste tokens, time-sensitive OTPs | **Transparent**—token passed via SSH auth, cached for session |
| Sudo interruptions | MFA prompt for every privileged command | **Context-aware**—step-up only for sensitive commands, configurable grace periods |
| Learning curve | New tools, new interfaces, training required | **Familiar flows**—same "scan QR, tap approve" as consumer apps |
| Network dependencies | VPN required, proxy servers to configure | **Direct to IdP**—works from anywhere your IdP is reachable |
| Emergency access | Locked out when MFA fails | **Break-glass auth**—configurable fallback for emergencies |

**What developers actually experience:**

```
$ ssh prod-server.example.com
→ Browser opens: "Sign in with Google" (or your IdP)
→ Approve on phone if MFA required
→ You're in. Session token cached.

$ sudo systemctl restart critical-service
→ Phone notification: "Approve sudo on prod-server?"
→ Tap approve
→ Command runs
```

No new passwords. No hardware tokens. No copy-pasting OTPs. Just your existing identity, extended to the terminal.

### A Human-AI Collaboration

This project was developed collaboratively with [Claude](https://claude.ai) (Anthropic's AI assistant).

The human contributors brought domain expertise in enterprise identity systems, security architecture, and real-world operational requirements from experience with PAM, LDAP, and SSO at scale. They defined the security requirements, threat model, and ensured the design would work in production environments.

**Claude** contributed rapid prototyping, comprehensive documentation, security analysis (including [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) and [MITRE ATT&CK](https://attack.mitre.org/) mappings), and systematic implementation of the Rust codebase. The AI's ability to maintain consistency across a large codebase and generate thorough test coverage accelerated development significantly.

This collaboration demonstrates that human expertise and AI capabilities can complement each other effectively—humans providing judgment, context, and real-world grounding; AI providing speed, consistency, and tireless attention to detail.

## Features

- **OIDC Authentication for SSH**: Authenticate SSH sessions using [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) tokens
- **Step-up MFA for Sudo**: Require additional authentication for privileged commands
  - [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628) (RFC 8628)
  - Custom webhook approval workflows
  - Future: Push notifications, [FIDO2/WebAuthn](https://fidoalliance.org/fido2/)
- **[DPoP Token Binding](https://datatracker.ietf.org/doc/html/rfc9449)** (RFC 9449): Cryptographically bind tokens to prevent theft
  - [ES256](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4) (P-256 ECDSA); ML-DSA-65 post-quantum support planned
  - Replay attack protection
  - Cross-language libraries: [Rust](rust-oauth-dpop/), [Go](go-oauth-dpop/), [Python](python-oauth-dpop/), [Java](java-oauth-dpop/)
- **[JWT](https://datatracker.ietf.org/doc/html/rfc7519) Signature Verification**: Cryptographically validates tokens using [JWKS](https://datatracker.ietf.org/doc/html/rfc7517) from OIDC discovery
- **[SSSD](https://sssd.io/) Integration**: Maps to existing LDAP/AD users via SSSD
- **Policy-Based Control**: Configure requirements per host classification and command
- **Audit Logging**: Structured JSON audit events for security monitoring
- **Multi-Provider Support**: Works with Azure AD, Auth0, Google, Okta, Keycloak, and any OIDC provider

## Quick Start

### Prerequisites

- Linux with PAM support
- SSSD configured for user directory
- OIDC-compliant Identity Provider (Keycloak, Azure AD, Okta, etc.)

### Installation

```bash
# Build the PAM module
cargo build --release

# Install the PAM module
sudo cp target/release/libpam_unix_oidc.so /lib/security/pam_unix_oidc.so

# Create configuration directory
sudo mkdir -p /etc/unix-oidc

# Copy example policy
sudo cp examples/policy.yaml /etc/unix-oidc/policy.yaml
```

### Configuration

Set environment variables:

```bash
export OIDC_ISSUER="https://your-idp.example.com/realms/your-realm"
export OIDC_CLIENT_ID="unix-oidc"
```

Configure PAM for SSH (`/etc/pam.d/sshd`):

```
auth    sufficient    pam_unix_oidc.so
auth    required      pam_unix.so try_first_pass
```

Configure PAM for sudo (`/etc/pam.d/sudo`):

```
auth    required    pam_unix_oidc.so
auth    required    pam_unix.so try_first_pass
```

## Deployment

Ready to deploy? We provide multiple paths from quick demos to production infrastructure.

### Quick Start Options

| Path | Time | Description |
|------|------|-------------|
| [5-Minute Demo](deploy/quickstart/5-minute-demo.md) | 5 min | Docker-based, zero setup required |
| [15-Minute Production](deploy/quickstart/15-minute-production.md) | 15 min | Real server with your IdP |

### One-Line Installer

```bash
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh | bash
```

### Infrastructure as Code

| Tool | Directory | Description |
|------|-----------|-------------|
| **Terraform** | [deploy/terraform/](deploy/terraform/) | AWS, GCP, Azure modules |
| **Ansible** | [deploy/ansible/](deploy/ansible/) | Configuration management role |
| **Chef** | [deploy/chef/](deploy/chef/) | Cookbook for Chef users |
| **Puppet** | [deploy/puppet/](deploy/puppet/) | Puppet module |

### IdP Setup Guides

Pre-built configurations for popular identity providers:

| Provider | Guide |
|----------|-------|
| Keycloak | [deploy/idp-templates/keycloak/](deploy/idp-templates/keycloak/) |
| Okta | [deploy/idp-templates/okta/](deploy/idp-templates/okta/) |
| Azure AD | [deploy/idp-templates/azure-ad/](deploy/idp-templates/azure-ad/) |
| Auth0 | [deploy/idp-templates/auth0/](deploy/idp-templates/auth0/) |

See [deploy/README.md](deploy/README.md) for comprehensive deployment documentation.

## Development

```bash
# Start test environment (Keycloak, LDAP, test host)
make dev-up

# Run unit tests
cargo test

# Run integration tests
make test-integration

# Stop test environment
make dev-down
```

## Documentation

### User Documentation
- [Installation Guide](docs/installation.md) - Installing and configuring unix-oidc
- [Community Testing Guide](docs/community-testing-guide.md) - Help us test on different platforms
- [User Guide](docs/user-guide.md) - Day-to-day usage for end users
- [Sudo Step-Up Authentication](docs/sudo-step-up.md) - Step-up configuration reference
- [Deployment Patterns](docs/deployment-patterns.md) - Choose the right deployment for your environment

### Security Documentation
- [Security Guide](docs/security-guide.md) - Hardening, compliance, and best practices
- [Threat Model](docs/threat-model.md) - STRIDE analysis, residual risks, and prioritized recommendations
- [Security Policy](SECURITY.md) - Vulnerability reporting

### Developer Documentation
- [Testing Guide](docs/testing.md) - Running tests at all levels
- [Extensibility Guide](docs/extensibility-guide.md) - Webhooks, custom mappers, and plugins
- [Architecture Decision Records](docs/adr/) - Design decisions and rationale
- [Contributing](CONTRIBUTING.md) - How to contribute

## Architecture

unix-oidc works with **any OIDC-compliant Identity Provider**:

| Provider | Status | Notes |
|----------|--------|-------|
| Azure AD (Entra ID) | Tested | Enterprise SSO, Conditional Access |
| Auth0 | Tested | Developer-friendly, free tier |
| Google Cloud Identity | Tested | Google Workspace integration |
| Okta | Supported | Enterprise IdP |
| Keycloak | Tested | Self-hosted, used in our CI |
| Any OIDC Provider | Supported | Must support Device Authorization Grant |

### Basic Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   SSH/Sudo   │────>│  PAM Module  │────>│   OIDC IdP   │
│   Client     │     │  (unix-oidc) │     │  (Your IdP)  │
└──────────────┘     └──────┬───────┘     └──────────────┘
                           │
                           v
                     ┌──────────────┐
                     │     SSSD     │
                     │  (user dir)  │
                     └──────────────┘
```

### Deployment Patterns

**Pattern A: Direct to Cloud IdP** (Simplest)
- Point unix-oidc directly at Azure AD, Auth0, Google, or Okta
- Users authenticate with their existing cloud identity
- Best for: Organizations already using a cloud IdP

**Pattern B: Self-hosted IdP** (Full Control)
- Deploy Keycloak or similar on your infrastructure
- Full control over authentication policies
- Best for: Air-gapped environments, compliance requirements

**Pattern C: Federated via Keycloak** (Hybrid)
- Keycloak brokers to upstream IdPs (Azure AD, Google, etc.)
- Centralized policy enforcement
- Best for: Multi-IdP environments, complex mapping requirements

See [docs/deployment-patterns.md](docs/deployment-patterns.md) for detailed guidance.

## Testing Status

### What We've Tested

| Component | Environment | Status |
|-----------|-------------|--------|
| **Identity Providers** | | |
| Keycloak | CI (automated) | ✅ Fully tested |
| Auth0 | CI (automated) | ✅ Fully tested |
| Google Cloud Identity | CI (automated) | ✅ Fully tested |
| Azure AD (Entra ID) | Manual testing | ⚠️ Basic flows tested |
| Okta | Not yet tested | 🔄 Community reports welcome |
| **Operating Systems** | | |
| Ubuntu 22.04 LTS | CI (automated) | ✅ Fully tested |
| Ubuntu 24.04 LTS | Manual testing | ✅ Tested |
| RHEL 9 | CI (automated) | ✅ Fully tested |
| Amazon Linux 2023 | CI (automated) | ✅ Fully tested |
| Amazon Linux 2 | CI (automated) | ✅ Fully tested |
| Rocky 9 | Not yet tested | 🔄 Marketplace subscription required |
| Debian 12 | Not yet tested | 🔄 SSM Agent compatibility issues |

### Enterprise Readiness

This is a **beta release**. While the core security mechanisms (DPoP binding, token validation, rate limiting) are thoroughly tested, enterprise deployments should consider:

- **Additional IdP testing**: If you're using Azure AD, Okta, or another IdP in production, please test and report your experience
- **OS compatibility**: Test on your target OS and report any issues
- **Scale testing**: We haven't yet tested with hundreds of concurrent authentications
- **HA/failover**: Document your high-availability setup if you deploy one

**We welcome contributions!** If you test unix-oidc with an IdP or OS not listed above, please:
1. Open an issue with your test results
2. Submit a PR to update this table
3. Share your deployment configuration (sanitized) to help others

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute.

### CI Infrastructure

Our CI includes:
- **Unit tests**: Rust test suite runs on every PR
- **Integration tests**: Keycloak in Docker for OIDC flow testing
- **AWS Platform Tests**: Real EC2 instances testing Ubuntu 22.04, RHEL 9, Amazon Linux 2, and Amazon Linux 2023
- **Security scanning**: Dependabot, cargo-audit, cargo-deny, Snyk, TruffleHog, OSSF Scorecard

This testing infrastructure is **not** a requirement for production—use whatever OIDC provider your organization already has.

## Security Design

unix-oidc is designed with defense in depth for key material. This section summarizes the memory and storage protection model for operators and contributors.

### Memory protection

| Mechanism | What it protects | Limitation |
|-----------|-----------------|------------|
| `zeroize` on drop (`ecdsa-0.16`) | DPoP private key bytes zeroed when struct is dropped | Compiler may not guarantee zeroing in all conditions; zeroize uses volatile writes as best effort |
| `mlock(2)` / `PR_SET_DUMPABLE` | Key pages pinned to RAM; core dumps disabled | Does not protect against root or kernel access; `mlock` failure is non-fatal |
| `secrecy::SecretString` for tokens | OAuth tokens show `[REDACTED]` in all logs/traces | Raw value accessible via `.expose_secret()` — audit boundary is grep-searchable |
| `Box`-only `ProtectedSigningKey` | No stack copies of key material | Only protects within process; memory forensics by root can still access |

### Secure deletion

`FileStorage::delete()` performs a three-pass DoD 5220.22-M overwrite before unlinking:
- Pass 1: random bytes, `fsync`
- Pass 2: complement (XOR 0xFF), `fsync`
- Pass 3: new random bytes, `fsync`, then `unlink`

**CoW filesystem warning**: On btrfs (Linux) and APFS (macOS), copy-on-write semantics mean overwrites may not modify the original data blocks. The agent logs a `WARN` advisory if CoW storage is detected at startup and before each key deletion.

**SSD wear leveling warning**: Flash storage firmware may redirect writes to spare blocks. The agent logs a `WARN` advisory on Linux when non-rotational storage is detected.

**Recommendation**: Use full-disk encryption (LUKS on Linux, FileVault on macOS) when deploying on CoW filesystems or SSDs. Secure overwrite is complementary, not a substitute, for FDE on those platforms. See [NIST SP 800-88 Rev 1](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final) §2.5 for background.

### For contributors

See `CLAUDE.md` — **Memory Protection Invariants** section — for the complete set of invariants, rationale, and known limitations. Security-critical files:

| File | What it protects |
|------|-----------------|
| `unix-oidc-agent/src/crypto/protected_key.rs` | DPoP key lifecycle (zeroize, mlock, Box-only) |
| `unix-oidc-agent/src/storage/secure_delete.rs` | Three-pass overwrite, CoW/SSD detection |
| `unix-oidc-agent/src/security.rs` | Core dump disabling (`prctl`/`ptrace`) |

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and security design principles.

## Learn More

This project implements several important security standards. Here are resources to learn more:

### Standards & RFCs
- **[RFC 9449 - DPoP](https://datatracker.ietf.org/doc/html/rfc9449)**: Demonstrating Proof of Possession—how we bind tokens to keys
- **[RFC 8628 - Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)**: OAuth 2.0 flow for devices without browsers
- **[RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)**: The token format we validate
- **[RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)**: How public keys are published
- **[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)**: The identity layer on OAuth 2.0

### Security Frameworks
- **[NIST SP 800-63](https://pages.nist.gov/800-63-3/)**: Digital Identity Guidelines—our authentication assurance levels align with these
- **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)**: Risk management framework we map our controls to
- **[MITRE ATT&CK](https://attack.mitre.org/)**: Threat modeling framework we use for attack analysis

### Linux Security
- **[Linux-PAM](https://www.man7.org/linux/man-pages/man8/pam.8.html)**: Pluggable Authentication Modules documentation
- **[SSSD](https://sssd.io/)**: System Security Services Daemon for identity management

## License

This work is licensed under the [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC BY-NC-SA 4.0)](LICENSE).

**This project is for educational and discussion purposes only. It is NOT intended for production use.**

See [LICENSE](LICENSE) for details.
