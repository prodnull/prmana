# ADR-013: Same-UID IPC Trust Model

## Status

Accepted

## Context

The prmana agent daemon serves per-user credentials over local IPC. It must decide
which local clients are trusted to request proofs and token operations.

Two approaches were considered:

- Trust same-UID clients authenticated via `SO_PEERCRED`/`getpeereid`
- Require stronger cross-process isolation immediately, such as per-client ACLs or a
  dedicated broker boundary

Credential agents such as `ssh-agent` and `gpg-agent` use same-UID trust as the local
security boundary. The agent holds user-scoped credentials, not system-wide secrets.
Stronger isolation remains desirable, but it is a later architectural step.

## Decision

The agent daemon trusts IPC connections from the same UID, authenticated with
`SO_PEERCRED` on Linux or `getpeereid` on BSD/macOS. This is the current trust model
for local agent access.

## Consequences

### Positive

- Matches established Unix credential-agent practice
- Keeps IPC authorization simple, fast, and portable
- Avoids premature complexity in the user-scoped agent path

### Negative

- Processes running as the same UID can access the agent
- Does not provide defense between mutually untrusted applications of one user
- Stronger cross-UID or per-client isolation must be added separately in a future ADR
