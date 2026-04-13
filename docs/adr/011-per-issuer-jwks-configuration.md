# ADR-011: Per-Issuer JWKS Configuration

## Status

Accepted

## Context

prmana validates tokens from multiple issuers. Those issuers have different JWKS
rotation schedules, uptime characteristics, and latency profiles.

Two approaches were considered:

- Use one global JWKS cache TTL and HTTP timeout for every issuer
- Make JWKS cache TTL and HTTP timeout configurable per issuer

A single global value forces a lowest-common-denominator policy. Conservative global
settings over-fetch stable issuers; relaxed settings increase stale-key risk for
fast-rotating issuers.

## Decision

JWKS cache TTL and HTTP timeout are configurable per issuer. Hardcoded shared
constants are replaced by issuer-specific settings in policy configuration.

## Consequences

### Positive

- Better fit for heterogeneous IdP behavior and rotation schedules
- Reduces unnecessary fetches for stable issuers
- Lowers stale-key risk for issuers with aggressive rotation
- Keeps validation policy aligned with multi-issuer architecture

### Negative

- More operator-visible tuning knobs
- Misconfiguration can create issuer-specific availability or freshness problems
- Documentation and defaults must be maintained carefully

