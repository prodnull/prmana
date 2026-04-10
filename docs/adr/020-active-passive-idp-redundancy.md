# ADR-020: Active-Passive IdP Redundancy

## Status

Accepted

## Context

Enterprise environments require high availability for authentication infrastructure.
When a single OIDC IdP goes down (maintenance, outage, DNS failure), all SSH
authentication stops. This is unacceptable for production server access where even
brief outages can cascade into incident response failures.

unix-oidc already supports multi-issuer configuration (Phase 21, MIDP-01..05) and
per-issuer JWKS cache isolation (MIDP-07). However, there is no mechanism to
automatically route authentication attempts to a backup IdP when the primary is
unreachable.

### Design constraints

- **Failover must be availability-only.** Failing over on policy errors (4xx,
  signature failures, ACR rejections) would convert security rejections into
  bypasses. An attacker who cannot pass the primary's policy checks should not
  be routed to a more permissive secondary.

- **JWKS caches must remain issuer-scoped.** A JWKS key from issuer A must never
  validate tokens from issuer B (MIDP-07 invariant, unchanged).

- **PAM does not perform network failover.** PAM validates whatever token it
  receives against the token's own `iss` claim. The agent owns all outbound
  network logic and failover decisions.

- **In-flight requests must not switch issuers.** Mid-stream endpoint switching
  creates split-brain session states. A failed in-flight request stays failed;
  the next request uses the failover target.

### Alternatives considered

| Option | Pros | Cons |
|--------|------|------|
| **Active-passive pair (chosen for v1)** | Simple to reason about, audit, and debug. No split-brain. | Max one issuer active per pair. |
| Active-active load balancing | Better throughput utilization | Split-brain token sessions, complex audit correlation, harder to debug |
| N-issuer priority chain | More flexible for multi-region | Extension of active-passive; planned for post-v1 |
| DNS-level failover (e.g., Route53/CloudFlare) | Transparent to application; failover responsibility moves to enterprise networking team | Cannot distinguish availability vs policy failures at application layer; DNS TTL delays; unix-oidc still gets a single `iss` claim regardless |

### Planned evolution: DNS-level failover, then N-issuer chain

**DNS-level failover** is the natural enterprise deployment pattern. When the
issuer URL resolves via DNS health-checked endpoints (Route53 failover routing,
CloudFlare load balancer, F5 GTM), the enterprise networking team owns failover
logic entirely. This is elegant for unix-oidc because:

1. The agent sees a single issuer URL — no application-level failover needed.
2. PAM validates against the single `iss` claim as usual.
3. JWKS caching works normally since the logical issuer URL is stable.
4. Failover latency is DNS TTL (typically 30-60s), acceptable for SSH.

DNS failover does not replace application-level failover — it complements it.
DNS cannot classify *why* a request failed (policy vs availability), so
unix-oidc's application-level failover remains valuable when:
- The enterprise does not control IdP DNS (SaaS IdPs like Auth0, Okta)
- Different issuers have different `iss` claim values (multi-tenant)
- Sub-second failover is required (DNS TTL is too slow)

**N-issuer priority chain** extends active-passive to ordered lists:

```yaml
failover_chain:
  - issuer_url: "https://idp-primary.example.com"
    priority: 1
  - issuer_url: "https://idp-secondary.example.com"
    priority: 2
  - issuer_url: "https://idp-dr.example.com"
    priority: 3
```

This builds naturally on the Phase 41 state machine — each issuer gets a
state slot, and the chain walks from highest to lowest priority on availability
failures. Planned for a future phase after DNS failover documentation.

## Decision

### 1. Active-passive primary/secondary failover

Each failover pair explicitly names a primary and secondary issuer URL. All new
requests go to primary. On availability failure, the agent switches to secondary.
Recovery is lazy and cooldown-based: after `cooldown_secs` expire, the next
request retries primary.

### 2. Three-state machine: Primary / Secondary / Exhausted

- **Primary**: all requests go to primary issuer.
- **Secondary**: primary failed, all requests go to secondary until cooldown expires.
- **Exhausted**: both issuers unavailable. Authentication fails closed.

No intermediate "suspect" state. A single availability failure immediately triggers
failover. The 10-second request timeout already absorbs transient jitter.

### 3. Failure classification is the security boundary

**Availability failures (trigger failover):**
- DNS/connect failure, TCP timeout, TLS handshake failure
- HTTP client timeout, OIDC discovery unreachable
- 5xx responses from discovery or token endpoints

**Non-failover failures (hard fail, no retry):**
- 400 `invalid_grant`, 401 `invalid_client`, 403 `access_denied`
- Malformed token/discovery response from a reachable issuer
- Signature validation failure, DPoP proof rejection
- Token replay, ACR failure, policy/authz denial

This classification prevents the failover mechanism from becoming a security
bypass vector.

### 4. Configuration via explicit failover pairs

```yaml
# Agent config
failover_pairs:
  - primary_issuer_url: "https://idp-primary.example.com/realms/corp"
    secondary_issuer_url: "https://idp-secondary.example.com/realms/corp"
    request_timeout_secs: 10
    cooldown_secs: 60
```

Both URLs must reference issuers already in the `issuers` array (PAM config) or
be known to the agent. An issuer can be primary in at most one pair. Secondaries
can be shared across pairs (shared standby pattern).

### 5. Agent owns failover; PAM accepts from the redundant set

- **Agent**: resolves which issuer to use, performs discovery, runs login/exchange/CIBA
  flows, records failover state transitions.
- **PAM**: lists both issuers in its `issuers` array, validates tokens against the
  token's own `iss` claim. PAM does not perform failover — it simply accepts tokens
  from any configured issuer.

### 6. OCSF audit events for failover lifecycle

| Event | Severity | Trigger |
|-------|----------|---------|
| `IDP_FAILOVER_ACTIVATED` | High | Primary failed, switched to secondary |
| `IDP_FAILOVER_RECOVERED` | Info | Primary healthy again after cooldown retry |
| `IDP_FAILOVER_EXHAUSTED` | Critical | Both issuers down, fail closed |

Existing `SSH_LOGIN_SUCCESS` events gain `serving_issuer` and `failover_active`
fields for SIEM correlation.

### 7. Lazy cooldown-based recovery (no background probing)

After failover to secondary, the agent remains on secondary for `cooldown_secs`.
After expiry, the next new request retries primary. No background timer or health
check endpoint is required. This keeps daemon complexity minimal and avoids
creating traffic to a potentially overwhelmed primary.

## Consequences

### Positive

- Automatic HA for OIDC authentication with zero user-visible impact during IdP outages
- Clear audit trail of failover events for SIEM and incident response
- No split-brain: at most one issuer is active per pair at any time
- Zero overhead when no failover pairs are configured (no runtime cost)
- Security invariants preserved: policy/crypto failures are never masked by failover

### Negative

- Configuration complexity: operators must configure both primary and secondary issuers
- Secondary issuer must be pre-provisioned with matching client registration
- Lazy recovery adds up to `cooldown_secs` delay before returning to primary
- No active-active for throughput; dedicated to single-active model

### Risks

- If both issuers share infrastructure (same cloud region, same DNS), failover
  provides no benefit. Operators should ensure issuers are in different failure domains.
- Secondary issuer with different policy configuration could be more permissive.
  Operators must ensure policy parity across the pair.

## References

- Phase 41 implementation plan: `docs/plans/2026-04-10-phase-41-multi-idp-redundancy.md`
- MIDP-07: Per-issuer JWKS cache isolation invariant
- ADR-011: Per-issuer JWKS configuration
- ADR-012: ACR enforcement hard-fail (preserved across failover)
