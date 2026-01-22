# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for unix-oidc.

ADRs document significant architectural decisions made during the project's development, including the context, decision, and consequences.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [001](./001-dpop-proof-of-possession.md) | DPoP Proof-of-Possession for Token Binding | Accepted | 2026-01-16 |
| [002](./002-pam-agent-architecture.md) | PAM Module and Agent Daemon Separation | Accepted | 2026-01-16 |
| [003](./003-token-validation-strategy.md) | Local Token Validation Strategy | Accepted | 2026-01-16 |
| [004](./004-device-authorization-grant.md) | Device Authorization Grant for Headless Auth | Accepted | 2026-01-17 |

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
