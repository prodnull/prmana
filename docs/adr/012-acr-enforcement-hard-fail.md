# ADR-012: ACR Enforcement as Hard-Fail

## Status

Accepted

## Context

Some issuers attach an Authentication Context Class Reference (ACR) claim describing
the assurance level of the authentication event. When an operator configures
`required_acr`, prmana must choose whether non-matching tokens are rejected or
merely logged.

Two approaches were considered:

- Warn and allow on ACR mismatch
- Reject the token on ACR mismatch

ACR expresses assurance policy. If an operator requires MFA or another elevated
authentication context, accepting a weaker token defeats the purpose of the policy.
NIST SP 800-63B treats authentication assurance as a security property, not a soft
hint.

## Decision

When `required_acr` is configured for an issuer, ACR validation is a hard fail.
Tokens with missing or non-matching ACR are rejected. This decision supersedes any
earlier warn-style interpretation for explicit `required_acr` checks.

## Consequences

### Positive

- Enforces explicit assurance requirements consistently
- Prevents silent downgrade from MFA or stronger authentication contexts
- Keeps issuer policy aligned with operator intent and NIST SP 800-63B

### Negative

- Misconfigured issuer ACR mappings will cause authentication failures
- Less tolerant of IdPs that emit inconsistent or sparse ACR values
- Operators must understand issuer-specific ACR semantics before enabling checks
- Legacy configuration fields suggesting softer ACR enforcement become effectively
  advisory once `required_acr` is set
