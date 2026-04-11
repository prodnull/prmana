# ADR-015: SPIFFE Trust via OIDC Discovery

## Status

Accepted

## Context

Phase 35 adds support for SPIRE-issued JWT-SVIDs so workloads can authenticate to
Unix hosts. prmana had to choose between:

- Adding SPIFFE-specific trust bundle validation logic to the PAM module
- Registering SPIRE trust domains as standard OIDC issuers through the SPIRE OIDC
  Discovery Provider and reusing existing JWT validation

The PAM module is a security-critical component and should keep its trusted computing
base small. JWT-SVIDs are still JWTs (RFC 7519), so signature, issuer, audience, and
expiry validation can reuse the existing token path if SPIRE is surfaced as OIDC.

## Decision

SPIRE trust domains are integrated as standard OIDC issuers via the SPIRE OIDC
Discovery Provider. PAM reuses the existing `TokenValidator` and JWKS infrastructure.
No SPIFFE-specific trust bundle logic is added to PAM.

## Consequences

### Positive

- Keeps the PAM trusted computing base lean
- Avoids maintaining two parallel trust validation paths
- Reuses existing JWT validation semantics and issuer configuration
- SPIRE integration fits naturally into the multi-issuer architecture

### Negative

- Depends on the SPIRE OIDC Discovery Provider being deployed and reachable
- PAM does not directly consume native SPIFFE trust bundles
- SPIFFE-specific features outside the OIDC/JWKS model remain out of scope for PAM

