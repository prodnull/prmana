# prmana-agent

Client-side agent for DPoP-bound OIDC authentication.

> **Status: In Development** - Core crypto and IPC infrastructure complete. CLI commands are stubs awaiting device flow integration.

## Overview

The prmana-agent manages OIDC tokens and DPoP proofs on the client machine, enabling passwordless SSH authentication with cryptographic proof-of-possession.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    prmana-agent                           │
├─────────────────┬─────────────────┬─────────────────────────┤
│   CLI Interface │  Daemon (IPC)   │   Crypto Module         │
│   - login       │  - Unix socket  │   - DPoP signing (ES256)│
│   - status      │  - JSON protocol│   - JWK thumbprints     │
│   - logout      │  - Token cache  │   - Secure key storage  │
│   - get-proof   │                 │                         │
└─────────────────┴─────────────────┴─────────────────────────┘
```

## Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| **Crypto** | ✅ Complete | ES256 signing, DPoP proofs, JWK thumbprints |
| **IPC Protocol** | ✅ Complete | JSON over Unix socket, request/response |
| **Daemon Server** | ✅ Complete | Connection handling, state management |
| **Key Storage** | 🔄 Partial | In-memory working, keyring integration planned |
| **CLI: login** | ⏳ Stub | Needs device flow integration |
| **CLI: status** | ⏳ Stub | Needs daemon connection |
| **CLI: logout** | ⏳ Stub | Needs token revocation |
| **CLI: get-proof** | ⏳ Stub | Needs daemon connection |
| **CLI: serve** | ⏳ Stub | Needs startup logic |
| **Device Flow** | ⏳ Planned | OAuth 2.0 device authorization |

## Usage (Planned)

```bash
# Authenticate with your IdP
prmana-agent login --issuer https://login.example.com

# Check authentication status
prmana-agent status

# SSH uses the agent automatically (via PAM integration)
ssh server.example.com

# Revoke tokens (keeps DPoP keypair)
prmana-agent logout

# Delete everything including keypair
prmana-agent reset
```

## Development

```bash
# Build
cargo build -p prmana-agent

# Run tests
cargo test -p prmana-agent

# Run with debug logging
RUST_LOG=prmana_agent=debug cargo run -p prmana-agent -- status
```

## Security Design

- **DPoP Binding (RFC 9449)**: Tokens are cryptographically bound to a keypair
- **ES256 Signatures**: ECDSA with P-256 curve
- **Secure Storage**: Platform keychain integration (planned)
- **Socket Permissions**: Unix socket with 0600 permissions
- **No Secrets in CLI**: Keypair never leaves secure storage

## Related

- [DPoP Proof-of-Possession ADR](../docs/adr/001-dpop-proof-of-possession.md)
- [PAM/Agent Architecture ADR](../docs/adr/002-pam-agent-architecture.md)
- [Security Roadmap](../docs/security-roadmap.md)
