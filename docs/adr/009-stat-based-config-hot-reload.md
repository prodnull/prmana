# ADR-009: Stat-Based Config Hot-Reload

## Status

Accepted

## Context

prmana needs to detect policy changes without restarting critical services.
Two approaches were considered:

- Trigger reload with `SIGHUP`
- Detect changes by polling file metadata with `stat(2)` and reloading on mtime change

`SIGHUP` requires process supervision integration, is awkward in containers, and
adds signal-handling complexity to code running in or adjacent to a PAM module.
Signal safety is especially important in authentication paths. Stat-based polling is
stateless and works in systemd, containers, and ad hoc deployments without relying
on external orchestration.

## Decision

Policy hot-reload is driven by `stat(2)` mtime polling, not `SIGHUP`. The
multi-issuer policy path checks file metadata and reloads when the policy mtime
changes. Legacy single-issuer environment-based loading does not gain hot-reload.

## Consequences

### Positive

- Works uniformly across bare metal, containers, and minimal process managers
- Avoids signal handler complexity in security-critical code
- No external reload orchestration is required
- Stateless approach is easier to test and reason about

### Negative

- Reload is not instantaneous; it occurs on the next poll interval
- Adds a small amount of periodic filesystem I/O
- mtime-based detection depends on correct file replacement/update behavior
