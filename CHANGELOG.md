# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Resolved RUSTSEC-2026-0387 (`crypto-bigint` timing variability) by moving to `p256` 0.14 and the
  matching RustCrypto releases (`sha2`/`sha1` 0.11, `hmac` 0.13) across all Rust crates.
- Removed `chrono` (RUSTSEC-2026-0543, unmaintained). Audit log timestamps keep the same format.
- Token expiry validation now rejects tokens when the system clock reads before the Unix epoch,
  instead of treating every token as unexpired.
- `jsonwebtoken` 10 → 12 (claim type-confusion fixes, unknown critical header rejection).
- `ml-dsa` release candidate → stable 0.1.2 for the experimental `pqc` feature; the ML-DSA key's
  heap allocations are now `mlock`ed explicitly.

### Changed
- **Java DPoP library now requires Java 17** (was declared as 11). The previous target could not
  work at runtime: Eclipse Collections 13 ships Java 17 bytecode.
- Crates declare `rust-version = 1.88`; dependency resolution is MSRV-aware (resolver 3).
- Dependency refresh: `base64` 0.23, `dirs` 7, `directories` 6, `gethostname` 1.1, `syslog` 7,
  `thiserror` 2, `getrandom` 0.4.

### Fixed
- Java DPoP library unit tests compile and run again (broken since the JUnit 6 upgrade).

## [1.0.0] - 2026-04-XX — prmana rename

### Changed
- **Product rename**: All crates, binaries, env vars, and paths renamed from `unix-oidc` to `prmana`
  - `pam-unix-oidc` crate → `pam-prmana`; PAM .so is now `libpam_prmana.so`
  - `unix-oidc-agent` crate/binary → `prmana-agent`; `unix-oidc-jti-helper` → `prmana-jti-helper`
  - `unix-oidc-scim` crate/binary → `prmana-scim`
  - `unix-oidc-audit-verify` → `prmana-audit-verify`; `unix-oidc-evidence-export` → `prmana-evidence-export`
  - All `UNIX_OIDC_*` environment variables renamed to `PRMANA_*`
  - Config directory `/etc/unix-oidc/` → `/etc/prmana/`; runtime dir `/run/unix-oidc/` → `/run/prmana/`
  - Socket path `unix-oidc-agent.sock` → `prmana-agent.sock`
  - Audit log `/var/log/unix-oidc-audit.log` → `/var/log/prmana-audit.log`
  - Systemd units renamed: `prmana-agent.service`, `prmana-agent.socket`, `prmana.tmpfiles.conf`
  - Keycloak test realm `unix-oidc-test` → `prmana-test`
- **Keyring key-name migration**: New `migrate_legacy_key_names()` function in `prmana-agent` reads
  `unix-oidc-*` keyring entries and writes them under `prmana-*` names on first startup, preserving
  credentials across the rename. Migration is idempotent and runs at daemon startup and login.
- **Version**: Clean-slate v1.0.0 — independent of unix-oidc version history.

### Migration guide
See `docs/migration/unix-oidc-to-prmana.md` for step-by-step upgrade instructions.
Users must update PAM config (`pam_unix_oidc.so` → `pam_prmana.so`), config paths,
and environment variable names. Agent credentials are migrated automatically.

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

[Unreleased]: https://github.com/prodnull/prmana/compare/v0.1.0-beta.1...HEAD
[0.1.0-beta.1]: https://github.com/prodnull/prmana/compare/v0.0.1...v0.1.0-beta.1
[0.0.1]: https://github.com/prodnull/prmana/releases/tag/v0.0.1
