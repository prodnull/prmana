# ADR-008: SSSD-Only Group Resolution

## Status

Accepted

## Context

unix-oidc must decide where authorization group membership comes from during PAM
authentication. Two approaches were considered:

- Resolve groups from SSSD/NSS, with FreeIPA or the directory as the source of truth
- Trust group membership claims carried in the OIDC token

Token claims are asserted by the IdP and can be stale, omitted, or transformed by
issuer-side mapping. Directory-backed NSS lookups reflect the current host-visible
authorization state used by the rest of the Unix system. Mixing token claims with
SSSD creates split-brain authorization, where login decisions may differ from local
system policy.

## Decision

Group membership is resolved from SSSD/NSS only. FreeIPA or the configured
directory remains the authoritative source of truth for Unix authorization.
`GroupSource::TokenClaim` is removed as an active source; compatibility fields in
group-mapping config remain reserved but are not used for authorization.

OIDC tokens remain the source of authentication identity, but not group-based
authorization.

## Consequences

### Positive

- Authorization matches the host's authoritative directory view
- Group changes take effect consistently across SSH, sudo, and other NSS consumers
- Removes trust in potentially stale or manipulated JWT claims (RFC 7519)
- Simplifies reasoning about access control by using one source of truth

### Negative

- Authentication depends on SSSD/NSS group resolution being healthy
- IdP-side group mapping cannot be used as an authorization shortcut
- Some deployments may need extra directory synchronization to expose expected groups
