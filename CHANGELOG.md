# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Cross-platform client support (Windows experimental)
- Hardware security key integration (YubiKey) - planned

## [0.1.0-beta.1] - 2026-01-18

### Added

#### PAM Module (`pam_unix_oidc.so`)
- OIDC token validation with JWKS support
- DPoP token binding (RFC 9449) for proof-of-possession security
- SSSD user resolution and verification
- Rate limiting per user and per IP (PAM_RHOST)
- JTI replay protection with TTL-based cache
- Structured JSON audit logging for SIEM integration
- Policy-based access control with YAML configuration
- ACR enforcement (AAL1/AAL2/AAL3 authentication assurance levels)
- Test mode for CI/CD integration testing

#### Sudo Step-Up Authentication
- OAuth 2.0 Device Authorization Grant (RFC 8628)
- Browser-based authentication with automatic redirect
- Terminal UI with QR code display for mobile authentication
- Configurable step-up policies by command pattern and host

#### Client Agent (`unix-oidc-agent`)
- ES256 (P-256) DPoP proof generation
- JWK thumbprint computation (RFC 7638)
- Unix socket IPC daemon for SSH integration
- Secure storage abstraction (keyring/file backends)
- CLI commands: `login`, `status`, `logout`, `reset`, `serve`, `get-proof`

#### Security Features
- Constant-time comparison for cryptographic values (`subtle` crate)
- JWK coordinate validation (P-256: exactly 32 bytes)
- Exponential backoff for rate limiting (60s → 3600s max)
- DPoP proof JTI tracking with 65s TTL (max_proof_age + clock_skew)
- Optional server nonce support for enhanced replay protection

#### Multi-Provider Support
- Keycloak (primary, comprehensive test coverage)
- Microsoft Entra ID (Azure AD)
- Okta
- Auth0
- Google Cloud Identity
- Any OIDC-compliant provider

#### Documentation
- Installation guide with step-by-step instructions
- User guide with workflow examples
- Security guide with defense-in-depth recommendations
- Threat model (STRIDE, NIST CSF 2.0, MITRE ATT&CK mappings)
- Deployment patterns (standalone, enterprise, multi-region)
- Extensibility guide for custom integrations

#### CI/CD & Supply Chain Security
- GitHub Actions workflows for all stages
- Multi-OS build matrix (Ubuntu 22.04, macOS)
- Multi-architecture support (x86_64, aarch64)
- Fuzz testing with 4 targets (nightly)
- Security audit (`cargo audit` on every push)
- Dependency review for PRs (fail on high severity)
- SBOM generation (CycloneDX format)
- SHA-256 checksums for all release artifacts
- Reproducible builds with `--locked`

### Security
- Supply chain hardening complete (S1, S2, S3 mitigated)
- Adversarial security review by Marcus Chen (2026-01-17)
- Comprehensive threat model with 10 attack categories
- All DPoP-specific threats (DP1-DP6) addressed
- Agent forwarding threats (AF1-AF3) mitigated

### Fixed
- PAM_RHOST extraction for IP-based rate limiting

### Known Limitations
- Windows client support is experimental
- Hardware security key (YubiKey) integration planned for v0.2.0
- Post-quantum (ML-DSA-65) algorithms planned for v0.3.0

## [0.0.1] - 2026-01-16

### Added
- Initial project structure
- Basic OIDC token validation prototype
- PAM module skeleton
- Docker Compose test environment with Keycloak

[Unreleased]: https://github.com/prodnull/unix-oidc/compare/v0.1.0-beta.1...HEAD
[0.1.0-beta.1]: https://github.com/prodnull/unix-oidc/compare/v0.0.1...v0.1.0-beta.1
[0.0.1]: https://github.com/prodnull/unix-oidc/releases/tag/v0.0.1
