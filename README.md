<p align="center">
  <img src="assets/logo.svg" alt="prmana logo" width="120" height="120">
</p>

<h1 align="center">prmana</h1>

<p align="center">
  <strong>OIDC SSH login for Linux, without the gateway</strong>
</p>

<p align="center">
  Replace static SSH keys with short-lived IdP-issued tokens, validated directly at the host through PAM, without requiring a gateway or SSH certificate authority.
</p>

<p align="center">
  <a href="https://github.com/prodnull/unix-oidc/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
</p>

<p align="center">
  <a href="#why-prmana">Why?</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#documentation">Documentation</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

---

## Why prmana?

SSH keys get copied, shared, and never rotated. When someone leaves, finding all their access is archaeology. Enterprise MFA stops at the browser — you need it for email but not for root on production.

`prmana` bridges this gap by bringing OIDC (the same protocol behind "Sign in with Google/Microsoft/Okta") to Linux PAM, with DPoP token binding to prevent token theft.

### Why teams try it

- **Kill static SSH keys** without forcing a full access platform rollout
- **Keep direct-to-host SSH** instead of routing everything through a proxy
- **Reuse your existing IdP** (Keycloak, Okta, Azure AD, Auth0, Google) for Linux login
- **Get proof-of-possession** with DPoP — not just bearer-token login
- **Stay Linux-native** with PAM at the host boundary
- **Start small** on a few hosts before deciding whether you need more

### What makes it different

Most alternatives fall into one of three buckets:

- **Access platforms** that introduce a proxy, gateway, or managed control plane
- **SSH certificate systems** that add a CA and cert lifecycle layer
- **Simpler PAM/OIDC modules** that provide SSO but not strong proof-of-possession

`prmana` takes a different path: OIDC-backed login directly at the Linux host, with DPoP-bound authentication for stronger token handling. No gateway. No SSH CA. No static keys.

### What it is not

`prmana` is not a session recording platform, a universal infrastructure access proxy, or a full privileged-access management suite. It is a focused tool for SSH login.

---

## How It Works

```
  User's Machine                              Linux Server
  ┌─────────────────────┐                    ┌─────────────────────┐
  │  prmana-agent       │     SSH            │  sshd               │
  │  ┌───────────────┐  │ ──────────────▶    │  ┌───────────────┐  │
  │  │ OIDC token    │  │                    │  │ PAM module     │  │
  │  │ + DPoP proof  │  │                    │  │ (pam_prmana)   │  │
  │  └───────────────┘  │                    │  └───────────────┘  │
  └─────────────────────┘                    └─────────────────────┘
          │                                           │
          ▼                                           ▼
  ┌─────────────────────┐                    ┌─────────────────────┐
  │  Identity Provider  │                    │  Token validation   │
  │  (Keycloak/Okta/    │                    │  + DPoP verify      │
  │   Azure AD/Auth0)   │                    │  + JWKS cache       │
  └─────────────────────┘                    └─────────────────────┘
```

1. **`prmana-agent`** on the user's machine acquires an OIDC token from your IdP (device flow or auth code + PKCE)
2. The agent generates a DPoP proof binding the token to an ephemeral key pair
3. On SSH connection, the server's **PAM module** validates the token signature, issuer, audience, expiration, and DPoP binding
4. If validation passes and the username maps to a local account (via SSSD), authentication succeeds

### Key Components

| Component | Purpose |
|-----------|---------|
| `prmana-core` | Shared OIDC discovery and JWKS primitives |
| `pam-prmana` | PAM module — token validation, DPoP verification, break-glass |
| `prmana-agent` | Client-side agent — token acquisition, DPoP proof generation |

### Hardware Key Support

DPoP proofs can be bound to hardware security keys for stronger assurance:

- **Software signer** — ephemeral P-256 key pair (default)
- **YubiKey** — PKCS#11 via `--features yubikey`
- **TPM 2.0** — platform TPM via `--features tpm` (Linux)

---

## Quick Start

### Prerequisites

- A Linux server with OpenSSH and PAM
- An OIDC identity provider (Keycloak, Okta, Azure AD, Auth0, Google)
- Rust toolchain for building from source

### Build

```bash
cargo build --workspace
```

### Install

```bash
# Install the PAM module
sudo cp target/release/libpam_prmana.so /lib/security/pam_prmana.so

# Install the agent
cp target/release/prmana-agent ~/.local/bin/

# Configure
sudo cp examples/policy.yaml /etc/prmana/policy.yaml
# Edit policy.yaml with your issuer URL and client ID
```

### Login

```bash
# On the client machine
prmana-agent login

# Then SSH normally
ssh user@server
```

See the [installation guide](docs/installation.md) for detailed setup including IdP configuration, SSSD integration, and break-glass access.

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](docs/installation.md) | Full setup guide |
| [PAM Integration](docs/pam-integration.md) | PAM module configuration |
| [Security Guide](docs/security-guide.md) | Hardening and threat model |
| [Hardware Key Setup](docs/hardware-key-setup.md) | YubiKey and TPM configuration |
| [Break-Glass](docs/break-glass-validation.md) | Emergency access procedures |
| [Keycloak Reference](docs/keycloak-dpop-reference.md) | Keycloak DPoP setup |
| [Entra ID Setup](docs/entra-setup-guide.md) | Azure Entra ID configuration |
| [Community Testing](docs/community-testing-guide.md) | Testing on various platforms |

### Architecture Decision Records

Design decisions are documented in [docs/adr/](docs/adr/).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

```bash
# Run tests
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all
```

---

## Community

We'd love your feedback — questions, ideas, bug reports, or just sharing how you're using prmana.

- [GitHub Discussions](https://github.com/prodnull/prmana/discussions) — ask questions, share ideas
- [Issues](https://github.com/prodnull/prmana/issues) — bug reports and feature requests

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

**Important**: Always configure [break-glass access](docs/break-glass-validation.md) before deploying to production. Getting locked out of servers because your IdP is down is a catastrophic failure mode.

---

## The Name

**Pramana** (Sanskrit: प्रमाण, *pramāṇa*) means "proof" and "means of knowledge" — the classical Indian epistemological framework for how you know something is true. The six pramanas are the valid means by which accurate knowledge is acquired: direct perception, inference, testimony, comparison, postulation, and proof by absence.

For this project, the connection is literal: DPoP is a pramana — cryptographic proof-of-possession, not just a bearer token asserting identity.

---

## License

Apache-2.0. See [LICENSE](LICENSE).
