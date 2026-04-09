# Release Verification Guide

How to verify the integrity and provenance of unix-oidc release artifacts.

## Overview

Every unix-oidc release includes three layers of supply chain verification:

| Layer | What it proves | Tool |
|-------|---------------|------|
| SHA-256 checksums | Artifact integrity (no corruption/tampering in transit) | `sha256sum` |
| Sigstore keyless signatures | Artifact was produced by the unix-oidc GitHub Actions CI | `cosign` |
| SLSA build provenance | Artifact was built from a specific commit via a specific workflow | `gh attestation` |

## Prerequisites

```bash
# cosign (Sigstore CLI) — https://docs.sigstore.dev/cosign/system_config/installation/
# Available via brew, apt, dnf, or direct download
brew install cosign          # macOS
apt install cosign           # Debian/Ubuntu (if packaged)

# GitHub CLI (for SLSA verification)
brew install gh              # macOS
apt install gh               # Debian/Ubuntu
```

## 1. Verify Checksums

Download `SHA256SUMS` alongside the release tarball:

```bash
# Download the release and checksums
VERSION="v3.0.0"  # replace with actual version
gh release download "$VERSION" --repo prodnull/unix-oidc

# Verify
sha256sum -c SHA256SUMS
```

Expected output:
```
unix-oidc-v3.0.0-linux-x86_64.tar.gz: OK
unix-oidc-v3.0.0-linux-aarch64.tar.gz: OK
unix-oidc-v3.0.0-macos-x86_64.tar.gz: OK
unix-oidc-v3.0.0-macos-aarch64.tar.gz: OK
```

On macOS (BSD `shasum`):
```bash
shasum -a 256 -c SHA256SUMS
```

## 2. Verify Sigstore Signature

The `SHA256SUMS` file is signed with Sigstore keyless signing. The signing identity is
the GitHub Actions OIDC token for the `prodnull/unix-oidc` repository.

```bash
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github.com/prodnull/unix-oidc' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

Individual tarballs also have their own `.sig` and `.pem` files:

```bash
cosign verify-blob \
  --certificate unix-oidc-v3.0.0-linux-x86_64.tar.gz.pem \
  --signature unix-oidc-v3.0.0-linux-x86_64.tar.gz.sig \
  --certificate-identity-regexp 'https://github.com/prodnull/unix-oidc' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  unix-oidc-v3.0.0-linux-x86_64.tar.gz
```

### What this proves

- The artifact was signed by a GitHub Actions workflow in the `prodnull/unix-oidc` repository.
- No private key exists — signing uses ephemeral keys backed by GitHub's OIDC identity.
- Signatures are logged in the [Rekor](https://rekor.sigstore.dev) transparency log.

## 3. Verify SLSA Build Provenance

SLSA (Supply-chain Levels for Software Artifacts) provenance proves the artifact
was built from a specific source commit by a specific CI workflow.

```bash
gh attestation verify unix-oidc-v3.0.0-linux-x86_64.tar.gz \
  --repo prodnull/unix-oidc
```

This verifies:
- The artifact was built by the `release.yml` workflow in `prodnull/unix-oidc`.
- The build used a specific git commit (shown in the attestation output).
- The build environment was GitHub-hosted runners (not a compromised local machine).

## Installer Verification

The `deploy/installer/install.sh` script automatically verifies checksums and
Sigstore signatures (when `cosign` is available):

```bash
# Automatic verification during install
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh | \
  sudo bash -s -- --issuer https://your-idp.example.com

# The installer will:
# 1. Download the release tarball
# 2. Verify SHA-256 checksum (mandatory)
# 3. Verify Sigstore signature (if cosign is installed)
```

## Security Guarantees

### What is verified

| Threat | Mitigation |
|--------|-----------|
| CDN/mirror tampering | SHA-256 checksum detects any modification |
| Compromised GitHub release UI | Sigstore signature ties artifact to CI OIDC identity |
| Compromised CI workflow | SLSA provenance records the exact workflow and commit |
| Replay of old release | Rekor transparency log records signing timestamp |

### What is NOT verified

- **Source code integrity**: Verification proves the binary matches what CI built,
  not that the source code is correct. Audit the source separately.
- **Dependency integrity**: SBOM files (CycloneDX, SPDX) are included in releases
  for dependency auditing, but are not cryptographically tied to the binary.

### Test-mode exclusion

Release binaries include a compile-time gate (`compile_error!`) that prevents
building with `--features test-mode`. The release workflow additionally runs a
`strings` check on the binary to verify no test-mode sentinels are present.
Test-mode bypasses all JWT signature verification and must never ship in production.

## Reporting Issues

If you find a verification failure for a release published by this project, please
report it via the security advisory process described in [SECURITY.md](../SECURITY.md).
