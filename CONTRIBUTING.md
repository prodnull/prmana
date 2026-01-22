# Contributing to unix-oidc

Thank you for your interest in contributing to unix-oidc! This document provides guidelines
and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Contributions](#making-contributions)
- [Security Contributions](#security-contributions)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)
- [License](#license)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report unacceptable
behavior to conduct@unix-oidc.dev.

## Getting Started

### Prerequisites

- Rust 1.70+ (stable)
- Linux development environment (or Docker)
- PAM development headers (`libpam0g-dev` on Debian/Ubuntu)
- OpenSSL development headers

### Quick Start

```bash
# Clone the repository
git clone https://github.com/prodnull/unix-oidc.git
cd unix-oidc

# Build all components
cargo build

# Run tests
cargo test

# Run with all checks (recommended before submitting)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test
```

## Development Setup

### Linux (Native)

```bash
# Debian/Ubuntu
sudo apt-get install libpam0g-dev libssl-dev pkg-config

# RHEL/CentOS/Fedora
sudo dnf install pam-devel openssl-devel pkg-config

# Build
cargo build
```

### macOS (Cross-compilation)

The PAM module requires Linux. For macOS development:

```bash
# Use Docker for PAM module development
docker-compose -f docker-compose.dev.yaml up -d

# Or use the devcontainer
code --folder-uri vscode-remote://dev-container+$(pwd)
```

### Docker Development Environment

```bash
# Start development environment
docker-compose -f docker-compose.dev.yaml up -d

# Enter the container
docker exec -it unix-oidc-dev bash

# Build and test inside container
cargo build && cargo test
```

## Making Contributions

### Workflow

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```
3. **Make your changes** following our coding standards
4. **Test thoroughly** (see Testing Requirements)
5. **Commit** with clear messages (see Commit Guidelines)
6. **Push** to your fork
7. **Open a Pull Request**

### Commit Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `security`: Security fix (triggers security review)
- `docs`: Documentation only
- `test`: Adding or updating tests
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `chore`: Build process or auxiliary tool changes

**Examples:**
```
feat(pam): add DPoP proof validation

Implement RFC 9449 DPoP validation in the PAM module.
Includes JWK thumbprint verification and replay protection.

Closes #42
```

```
security(dpop): add constant-time comparison for JWK thumbprints

Prevents timing attacks when validating DPoP proof bindings.

Security: Timing attack mitigation
```

### Commit Signing (Required)

All commits must be cryptographically signed. We use **Gitsign** for keyless signing via Sigstore, which aligns with our project's security philosophy (same infrastructure we use for release signing).

#### Install Gitsign

**macOS:**
```bash
brew install sigstore/tap/gitsign
```

**Linux:**
```bash
# Download from https://github.com/sigstore/gitsign/releases
# Or use go install:
go install github.com/sigstore/gitsign@latest
```

**Windows:**
```powershell
winget install sigstore.gitsign
# Or: scoop install gitsign
```

#### Configure Git to Use Gitsign

```bash
# Configure for this repository only
cd unix-oidc
git config gpg.x509.program gitsign
git config gpg.format x509
git config commit.gpgsign true

# Or configure globally
git config --global gpg.x509.program gitsign
git config --global gpg.format x509
git config --global commit.gpgsign true
```

#### Making Signed Commits

When you commit, Gitsign will open your browser to authenticate via OIDC (GitHub, Google, or Microsoft):

```bash
git commit -m "feat: add new feature"
# Browser opens for authentication
# After auth, commit is signed with your verified identity
```

#### Verify Your Setup

```bash
# Make a test commit
echo "test" >> test.txt
git add test.txt
git commit -m "test: verify signing works"

# Check it's signed
git log --show-signature -1

# Clean up
git reset --hard HEAD~1
rm test.txt
```

#### Why Gitsign?

- **Keyless**: No GPG keys to generate, store, or rotate
- **Identity-based**: Uses your existing GitHub/Google/Microsoft identity
- **Transparent**: All signatures recorded in Sigstore's public transparency log
- **Verifiable provenance**: Same infrastructure we use for release artifact signing

## Security Contributions

### Reporting Vulnerabilities

**Do NOT open public issues for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure process.

### Security-Sensitive Changes

Changes touching these areas require additional review:

- **Cryptographic operations** (signing, verification, key handling)
- **Token validation** (JWT parsing, claim verification)
- **Authentication flows** (PAM callbacks, credential handling)
- **DPoP implementation** (proof generation/validation)
- **Unix socket IPC** (agent communication)
- **File permissions** (configuration, sockets, keys)

For security-sensitive changes:

1. Add `security:` prefix to commit type
2. Include security impact in PR description
3. Request review from a maintainer with security focus
4. Ensure comprehensive test coverage for security paths

### Security Testing Checklist

Before submitting security-related changes:

- [ ] No secrets or credentials in code
- [ ] Constant-time comparison for sensitive values
- [ ] Input validation on all external data
- [ ] Proper error handling (no information leakage)
- [ ] Replay protection where applicable
- [ ] Comprehensive test coverage
- [ ] Updated threat model if applicable

## Coding Standards

### Rust Style

- Follow `rustfmt` defaults (run `cargo fmt`)
- Follow `clippy` recommendations (run `cargo clippy -- -D warnings`)
- Use meaningful variable and function names
- Document public APIs with doc comments
- Prefer explicit error handling over `.unwrap()`

### Error Handling

```rust
// Good: Explicit error handling with context
fn validate_token(token: &str) -> Result<Claims, ValidationError> {
    let header = decode_header(token)
        .map_err(|e| ValidationError::InvalidHeader(e.to_string()))?;
    // ...
}

// Avoid: Panicking in library code
fn validate_token(token: &str) -> Claims {
    decode_header(token).unwrap() // Don't do this!
}
```

### Security-Sensitive Code

```rust
// Good: Constant-time comparison for secrets
use subtle::ConstantTimeEq;

fn verify_thumbprint(expected: &str, actual: &str) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    expected.as_bytes().ct_eq(actual.as_bytes()).into()
}

// Avoid: Direct comparison (timing attack vulnerable)
fn verify_thumbprint(expected: &str, actual: &str) -> bool {
    expected == actual // Don't do this for secrets!
}
```

### Documentation

- All public functions must have doc comments
- Include examples for complex APIs
- Document security considerations
- Update relevant guides for user-facing changes

## Testing Requirements

### Minimum Coverage

All contributions must:

1. **Pass existing tests**: `cargo test`
2. **Add tests for new functionality**
3. **Add tests for bug fixes** (regression tests)
4. **Pass CI checks** (formatting, linting, security audit)

### Test Categories

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test '*'

# With test-mode feature (for mock IdP testing)
cargo test --features test-mode

# Run specific test
cargo test test_dpop_validation

# Run with output
cargo test -- --nocapture
```

### Security Testing

For security-related changes, also run:

```bash
# Security audit
cargo audit

# Fuzz testing (if applicable)
cargo +nightly fuzz run fuzz_target

# Clippy with all warnings
cargo clippy --all-targets --all-features -- -D warnings
```

### Multi-Provider Testing

We test against multiple OIDC providers. For local testing:

```bash
# Start local Keycloak
docker-compose -f docker-compose.test.yaml up -d keycloak

# Run integration tests
cargo test --features integration-tests
```

## Documentation

### What to Document

- **API changes**: Update rustdoc comments
- **Configuration changes**: Update example configs and guides
- **New features**: Add to relevant guides
- **Security changes**: Update threat model and security guide

### Documentation Style

- Use clear, concise language
- Include code examples
- Document security implications
- Keep guides up to date

## Pull Request Process

1. **Ensure CI passes** - All checks must be green
2. **Update documentation** - If your change affects docs
3. **Add changelog entry** - For user-facing changes
4. **Request review** - Tag appropriate reviewers
5. **Address feedback** - Respond to review comments
6. **Squash if requested** - Keep history clean

### PR Title Format

Follow the same format as commits:

```
feat(pam): add DPoP proof validation
fix(agent): resolve token refresh race condition
docs: update installation guide for Ubuntu 24.04
```

## Getting Help

- **Questions**: Open a [Discussion](https://github.com/prodnull/unix-oidc/discussions)
- **Bugs**: Open an [Issue](https://github.com/prodnull/unix-oidc/issues)
- **Security**: See [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be licensed under the same
terms as the project: Apache-2.0 OR MIT (at the user's option).

See [LICENSE](LICENSE) for details.

---

Thank you for contributing to unix-oidc! Your efforts help make Unix/Linux authentication
more secure and modern.
