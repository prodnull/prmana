# DNS-Level IdP Failover Guide

This guide covers DNS-based failover for OIDC identity providers — the simplest high-availability pattern for enterprise deployments where the networking team owns routing.

## When to Use DNS Failover

DNS failover is the right choice when:

- You control the IdP infrastructure (self-hosted Keycloak, PingFederate, ADFS)
- Multiple IdP instances share the same `iss` claim value (same logical issuer)
- Your networking team already manages health-checked DNS (Route53, CloudFlare, F5 GTM)
- Failover latency of 30-60s (DNS TTL) is acceptable

Use application-level failover (Phase 41 `failover_pairs`) when:

- Different IdP instances have different `iss` claim values
- You use SaaS IdPs (Auth0, Okta) where you don't control DNS
- Sub-second failover is required
- You need availability vs policy failure classification (DNS can't distinguish these)

The two approaches are complementary. DNS handles infrastructure-level routing; application-level failover handles issuer-level redundancy.

## Architecture

```
                           DNS Health Check
                          ┌───────────────┐
                          │ Route53 / CF  │
                          │ Health Check  │
                          └──────┬────────┘
                                 │
                    ┌────────────┴────────────┐
                    │  idp.example.com        │
                    │  (health-checked CNAME)  │
                    └────────────┬────────────┘
                          ┌──────┴──────┐
                          ▼             ▼
                   ┌─────────────┐ ┌─────────────┐
                   │ IdP Primary │ │ IdP Standby  │
                   │ us-east-1   │ │ eu-west-1    │
                   └─────────────┘ └─────────────┘

    Agent config:
      issuer: https://idp.example.com/realms/corp

    PAM config:
      issuers:
        - issuer_url: https://idp.example.com/realms/corp
```

The agent and PAM both see a single issuer URL. DNS resolves it to whichever instance is healthy. No application-level failover config needed.

## Pattern 1: AWS Route53 Failover Routing

### Prerequisites

- Two IdP instances in different regions/AZs
- Both configured with the same realm, client registration, and signing keys
- Route53 hosted zone for `idp.example.com`

### Setup

1. **Create health checks** for each IdP instance:

```
# Health check on the OIDC discovery endpoint
Resource: https://idp-primary.internal.example.com/.well-known/openid-configuration
Type: HTTPS
Interval: 30 seconds
Failure threshold: 3
```

2. **Create failover DNS records:**

```
# Primary record
Name: idp.example.com
Type: A (or CNAME)
Routing policy: Failover
Failover type: Primary
Health check: primary-idp-health
TTL: 60

# Secondary record
Name: idp.example.com
Type: A (or CNAME)
Routing policy: Failover
Failover type: Secondary
Health check: secondary-idp-health (optional)
TTL: 60
```

3. **Set TTL to 60 seconds or less.** This controls failover speed. Lower TTL = faster failover but more DNS queries.

### What happens during failover

1. Primary IdP becomes unreachable
2. Route53 health check fails after 3 consecutive checks (~90s)
3. DNS resolves `idp.example.com` to secondary
4. New SSH logins use secondary within TTL window (60s)
5. In-flight device flow polls may fail once (agent retries automatically)
6. Primary recovers → Route53 switches back after health check passes

### JWKS considerations

Both IdP instances must serve the same signing keys, or both sets of keys must be in the JWKS endpoint. If the instances have separate key material, token validation will fail after failover because the PAM module's cached JWKS won't include the secondary's keys.

**Recommended:** Shared key material across instances (Keycloak supports this via database replication or shared keystore).

**Alternative:** Short JWKS cache TTL (60-120s) so the PAM module refreshes keys quickly after failover.

## Pattern 2: CloudFlare Load Balancer

### Setup

1. **Create an origin pool** with both IdP endpoints:

```
Pool: idp-pool
Origins:
  - idp-primary.internal.example.com (weight: 1)
  - idp-secondary.internal.example.com (weight: 0, failover only)
Health check: HTTPS GET /.well-known/openid-configuration
Interval: 60s
```

2. **Create a load balancer:**

```
Hostname: idp.example.com
Default pool: idp-pool
Fallback pool: (none — handled by pool weights)
Steering: failover
Session affinity: none (stateless OIDC discovery)
```

3. **Proxy mode:** Full proxy (orange cloud) for TLS termination, or DNS-only (grey cloud) for pass-through. DNS-only is simpler for OIDC since the IdP handles its own TLS.

## Pattern 3: F5 GTM (BIG-IP DNS)

### Setup

1. **Create a wide IP** for `idp.example.com`
2. **Add two pools** (primary and secondary data centers)
3. **Health monitor:** HTTPS monitor on `/.well-known/openid-configuration` expecting HTTP 200
4. **Load balancing method:** Global Availability (active-passive)
5. **TTL:** 60 seconds

## Prmana Configuration for DNS Failover

When using DNS failover, the Prmana config is simple — single issuer, no `failover_pairs`:

### Agent config (`~/.config/prmana/config.yaml`)

```yaml
issuer: https://idp.example.com/realms/corp
client_id: prmana
# No failover_pairs needed — DNS handles routing
```

### PAM policy (`/etc/prmana/policy.yaml`)

```yaml
issuers:
  - issuer_url: https://idp.example.com/realms/corp
    client_id: prmana
    dpop_enforcement: strict

# Break-glass: always configure regardless of failover strategy
break_glass:
  enabled: true
  users:
    - username: breakglass
      password_hash: "$6$..."
  alert_on_use: true
```

### Combining DNS and application-level failover

For defense in depth, you can layer both:

```yaml
# Agent config: DNS-failovered primary + separate secondary
issuer: https://idp.example.com/realms/corp  # DNS-failovered
failover_pairs:
  - primary_issuer_url: https://idp.example.com/realms/corp
    secondary_issuer_url: https://idp-dr.example.com/realms/corp
    cooldown_secs: 120
```

This gives you: DNS failover between primary instances (fast, networking-owned) + application-level failover to a completely separate DR issuer (different `iss`, different infrastructure).

## Monitoring

### Health check endpoints to monitor

| Endpoint | Expected | Failure means |
|---|---|---|
| `/.well-known/openid-configuration` | HTTP 200 + valid JSON | Discovery broken |
| JWKS URI from discovery | HTTP 200 + valid JWKS | Token validation will fail |
| Token endpoint | HTTP 200 on POST (with valid grant) | Login flows will fail |

### DNS failover events to alert on

- Route53: CloudWatch `HealthCheckStatusMetric` transitions
- CloudFlare: Health check notifications via webhook/email
- F5: SNMP traps or iHealth alerts on pool member status changes

### Prmana audit events

When DNS failover occurs transparently, Prmana won't emit `IDP_FAILOVER_ACTIVATED` events (since the issuer URL didn't change). Monitor at the DNS/LB layer instead. If you also use application-level `failover_pairs`, those events will fire when the app-level failover triggers.

## Troubleshooting

### "Token not valid for this issuer" after failover

**Cause:** Primary and secondary IdP instances have different signing keys. The PAM module's JWKS cache has only the primary's keys.

**Fix:** Either share key material across instances, or reduce `jwks_cache_ttl_secs` to force a JWKS refresh:

```yaml
issuers:
  - issuer_url: https://idp.example.com/realms/corp
    jwks_cache_ttl_secs: 60  # Refresh every minute during failover
```

### "Connection refused" during failover window

**Cause:** DNS TTL hasn't expired on the client. The agent is still connecting to the failed primary's IP.

**Fix:** Lower DNS TTL to 30-60s. Check that no intermediate DNS caches (corporate resolvers, nscd) are caching longer than the TTL.

### Break-glass access during total IdP outage

If both DNS-failovered IdP instances and the DR issuer are all down, break-glass accounts are the last line of defense:

```bash
ssh breakglass@server  # Uses local password auth, bypasses OIDC
```

See `docs/break-glass-validation.md` for testing procedures.

---

*DNS failover is the simplest path to IdP HA for organizations that control their IdP infrastructure. For SaaS IdPs or multi-issuer scenarios, use Prmana's application-level failover pairs (Phase 41, ADR-020).*
