# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for prmana.

ADRs document significant architectural decisions made during the project's development, including the context, decision, and consequences.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [001](./001-dpop-proof-of-possession.md) | DPoP Proof-of-Possession for Token Binding | Accepted | 2026-01-16 |
| [002](./002-pam-agent-architecture.md) | PAM Module and Agent Daemon Separation | Accepted | 2026-01-16 |
| [003](./003-token-validation-strategy.md) | Local Token Validation Strategy | Accepted | 2026-01-16 |
| [004](./004-device-authorization-grant.md) | Device Authorization Grant for Headless Auth | Accepted | 2026-01-17 |
| [006](./006-agent-ssh-introspection.md) | Agent SSH Config Introspection for Automatic Audience Discovery | Proposed | 2026-01-18 |
| [007](./007-pqc-hybrid-dpop.md) | Post-Quantum Hybrid DPoP Signatures (ML-DSA-65+ES256) | Accepted (experimental, behind `pqc` feature flag) | 2026-03-12 |
| [008](./008-sssd-group-resolution.md) | SSSD-Only Group Resolution | Accepted | 2026-04-09 |
| [009](./009-stat-based-config-hot-reload.md) | Stat-Based Config Hot-Reload | Accepted | 2026-04-09 |
| [010](./010-hmac-audit-chain-composition.md) | HMAC Audit Chain Composition | Accepted | 2026-04-09 |
| [011](./011-per-issuer-jwks-configuration.md) | Per-Issuer JWKS Configuration | Accepted | 2026-04-09 |
| [012](./012-acr-enforcement-hard-fail.md) | ACR Enforcement as Hard-Fail | Accepted | 2026-04-09 |
| [013](./013-same-uid-ipc-trust-model.md) | Same-UID IPC Trust Model | Accepted | 2026-04-09 |
| [014](./014-tpm-object-attributes.md) | TPM 2.0 Object Attributes | Accepted | 2026-04-09 |
| [018](./018-hardware-attestation.md) | TPM 2.0 Key Attestation via TPM2_CC_Certify | Accepted | 2026-04-09 |

## ADR Format

Each ADR follows this template:

```markdown
# ADR-NNN: Title

## Status
[Proposed | Accepted | Deprecated | Superseded by ADR-XXX]

## Context
What is the issue that we're seeing that is motivating this decision?

## Decision
What is the change that we're proposing and/or doing?

## Consequences
What becomes easier or more difficult because of this decision?
```

## Contributing

When making significant architectural changes:

1. Create a new ADR with the next available number
2. Follow the template format
3. Link to relevant issues or PRs
4. Update this index
