# ADR-005: DPoP-Chained Token Exchange for Multi-Hop SSH

## Status

Proposed

## Context

Users often need to SSH through jump hosts (bastions) to reach internal servers. The current prmana architecture supports two approaches:

1. **Socket forwarding**: Forward the prmana-agent socket through SSH, allowing the jump host to request DPoP proofs from the user's machine
2. **Direct authentication**: Authenticate independently to each hop

Socket forwarding has security concerns (see THREAT_MODEL.md AF1-AF3): a compromised jump host can use the forwarded socket to generate proofs for any target.

RFC 8693 (Token Exchange) provides a standard mechanism for a service to exchange a token for a new token scoped to a different audience. However, RFC 9449 (DPoP) does not specify how proof-of-possession should work across token exchanges.

## Decision

We will implement **DPoP-chained token exchange** where:

1. Each hop in the SSH chain has its own DPoP keypair
2. Token exchange binds the new token to the exchanging party's DPoP key
3. The original user's identity is preserved in delegation claims (`act`)
4. **Cryptographic lineage** is embedded in tokens and propagated to telemetry
5. No private keys or agent sockets are forwarded between hosts

### Architecture

```
User's Machine                    Jump Host A                      Target Host B
┌──────────────┐                 ┌──────────────┐                 ┌──────────────┐
│ DPoP key: U  │                 │ DPoP key: J  │                 │              │
│              │  Token(cnf=U)   │              │  Token(cnf=J)   │              │
│ prmana    │────────────────▶│ PAM validates│────────────────▶│ PAM validates│
│ agent        │  + DPoP proof U │ + exchanges  │  + DPoP proof J │ lineage claim│
└──────────────┘                 │ for Token(J) │                 └──────────────┘
                                 └──────────────┘
                                        │
                                        │ Token Exchange + Lineage
                                        ▼
                                 ┌──────────────┐
                                 │     IdP      │
                                 │ (Keycloak)   │
                                 └──────────────┘
```

### Trust Model

```
Alice ──DPoP proof──▶ Jump Host A ──attestation──▶ IdP ──signed token──▶ Target Host B
        (verified)                   (recorded)          (trusted)
```

- **Jump Host A verifies** Alice's DPoP proof against `cnf.jkt` in her token
- **Jump Host A attests** to IdP: "I verified alice, here's her thumbprint"
- **IdP records** the attestation in `x-prmana-lineage` claim
- **IdP signs** the entire token (including lineage)
- **Target Host B trusts** the IdP signature - no need to re-verify Alice's proof

### Token Exchange Request

Jump host requests token exchange from IdP, including lineage attestation:

```http
POST /realms/example/protocol/openid-connect/token HTTP/1.1
Host: idp.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: <proof signed by jump_key, with htu=token endpoint>

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<user's original access token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=target-host-b
&client_id=jump-host-a
&client_secret=<jump host's client secret>
&x_lineage_attestation=<base64-encoded attestation, see below>
```

### Lineage Attestation (Jump Host → IdP)

When requesting token exchange, jump host includes attestation of what it verified:

```json
{
  "version": 1,
  "trace_id": "otel-trace-abc123",
  "attester": "jump-host-a",
  "attester_dpop_jkt": "jump-host-dpop-thumbprint",
  "subject_verification": {
    "sub": "alice@example.com",
    "dpop_jkt": "alice-original-dpop-thumbprint",
    "dpop_proof_verified": true,
    "cnf_matched": true,
    "verified_at": 1699996300
  },
  "request": {
    "target_audience": "target-host-b",
    "requested_at": 1699996399
  }
}
```

### Exchanged Token Structure

The IdP embeds the verified lineage in the exchanged token:

```json
{
  "iss": "https://idp.example.com/realms/example",
  "sub": "jump-host-a",
  "aud": "target-host-b",
  "exp": 1699999999,
  "iat": 1699996399,
  "jti": "exchange-uuid-here",

  "act": {
    "sub": "alice@example.com",
    "client_id": "prmana-agent"
  },
  "cnf": {
    "jkt": "jump-host-dpop-thumbprint"
  },
  "scope": "ssh:login",

  "x-prmana-lineage": {
    "version": 1,
    "trace_id": "otel-trace-abc123",
    "origin": {
      "sub": "alice@example.com",
      "dpop_jkt": "alice-original-dpop-thumbprint",
      "auth_time": 1699996000,
      "acr": "urn:example:mfa",
      "session_id": "sess-xyz789",
      "verified_by": "jump-host-a",
      "verified_at": 1699996300
    },
    "path": [
      {
        "hop": 1,
        "actor": "jump-host-a",
        "actor_dpop_jkt": "jump-host-dpop-thumbprint",
        "exchange_time": 1699996399,
        "target_audience": "target-host-b",
        "subject_token_jti": "original-token-jti",
        "subject_cnf_verified": true
      }
    ]
  }
}
```

### Lineage Claim Fields

| Field | Purpose |
|-------|---------|
| `trace_id` | OpenTelemetry trace ID for distributed tracing |
| `origin.sub` | Original authenticated user |
| `origin.dpop_jkt` | Alice's original DPoP key thumbprint |
| `origin.acr` | Authentication strength (MFA level) |
| `origin.verified_by` | Which hop verified the origin's DPoP proof |
| `path[].actor` | Service that performed this exchange |
| `path[].actor_dpop_jkt` | That service's DPoP key thumbprint |
| `path[].subject_cnf_verified` | Attestation that inbound DPoP was verified |
| `path[].subject_token_jti` | JTI of token that was exchanged (audit link) |

### Why Lineage Is Tamper-Proof

1. The `x-prmana-lineage` claim is inside the JWT payload
2. The JWT is signed by the IdP
3. Modifying any field invalidates the IdP's signature
4. Target host only verifies IdP signature (standard JWT validation)
5. No need to re-verify previous hops - trust the IdP's attestation

### Multi-Hop Lineage (3+ Hops)

For deeper chains, lineage accumulates:

```json
{
  "x-prmana-lineage": {
    "trace_id": "otel-trace-abc123",
    "origin": {
      "sub": "alice@example.com",
      "dpop_jkt": "alice-thumbprint",
      "verified_by": "jump-host-a"
    },
    "path": [
      {
        "hop": 1,
        "actor": "jump-host-a",
        "actor_dpop_jkt": "jump-a-thumbprint",
        "target_audience": "jump-host-b",
        "subject_cnf_verified": true
      },
      {
        "hop": 2,
        "actor": "jump-host-b",
        "actor_dpop_jkt": "jump-b-thumbprint",
        "target_audience": "target-host-c",
        "subject_cnf_verified": true
      }
    ]
  }
}
```

Each hop adds to `path[]`, origin stays constant.

### Security Properties

| Property | Mechanism |
|----------|-----------|
| **No key forwarding** | Each hop has its own DPoP keypair |
| **Proof-of-possession at every hop** | DPoP proof required, verified, attested |
| **Tamper-proof lineage** | IdP signature covers lineage claim |
| **Verifiable chain** | Each hop attests it verified the previous |
| **Traceable** | OpenTelemetry trace_id links all hops |
| **Scoped tokens** | Each exchanged token is audience-restricted |
| **Time-limited blast radius** | Exchanged tokens have short expiry |

### Hardening: Require DPoP on Original Session

To prevent token theft enabling exchanges, we require:

1. **Subject token MUST have `cnf.jkt`** - Only DPoP-bound tokens can be exchanged
2. **Jump host validates original DPoP proof** - Before initiating exchange
3. **Jump host attests verification** - IdP records the attestation
4. **IdP policy enforces DPoP** - Token exchange endpoint rejects bearer tokens

```yaml
# IdP client policy (Keycloak)
policies:
  - name: "require-dpop-for-exchange"
    conditions:
      - grant_type: "token-exchange"
    requirements:
      - subject_token_must_be_dpop_bound: true
      - dpop_proof_required: true
      - lineage_attestation_required: true
```

## OpenTelemetry Integration

### Trace Propagation

The `trace_id` in lineage connects to OpenTelemetry distributed tracing:

```
Trace: otel-trace-abc123
├── Span: user-auth (alice@user-machine)
│   ├── dpop_jkt: alice-thumbprint
│   ├── auth_method: oidc+dpop
│   └── acr: urn:example:mfa
├── Span: ssh-session (jump-host-a)
│   ├── parent: user-auth
│   ├── dpop_verified: true
│   ├── token_exchange: initiated
│   └── target: target-host-b
└── Span: ssh-session (target-host-b)
    ├── parent: ssh-session (jump-host-a)
    ├── lineage_verified: true
    ├── origin_sub: alice@example.com
    └── hop_count: 1
```

### PAM Module Telemetry

Each PAM authentication emits OpenTelemetry spans:

```rust
// In PAM module
let span = tracer.span_builder("prmana.auth")
    .with_kind(SpanKind::Server)
    .start(&tracer);

span.set_attribute(KeyValue::new("prmana.trace_id", lineage.trace_id));
span.set_attribute(KeyValue::new("prmana.origin.sub", lineage.origin.sub));
span.set_attribute(KeyValue::new("prmana.origin.dpop_jkt", lineage.origin.dpop_jkt));
span.set_attribute(KeyValue::new("prmana.hop_count", lineage.path.len()));
span.set_attribute(KeyValue::new("prmana.current_actor", token.sub));
span.set_attribute(KeyValue::new("prmana.lineage_valid", true));
```

### Telemetry Export

Structured log event for SIEM integration:

```json
{
  "timestamp": "2024-01-15T10:05:00Z",
  "level": "INFO",
  "target": "prmana::pam",
  "event": "AUTH_SUCCESS",
  
  "trace_id": "otel-trace-abc123",
  "span_id": "span-def456",
  
  "auth": {
    "user": "alice",
    "unix_uid": 1001,
    "method": "oidc_delegation"
  },
  
  "lineage": {
    "origin_sub": "alice@example.com",
    "origin_dpop_jkt": "alice-thumbprint",
    "origin_acr": "urn:example:mfa",
    "origin_verified_by": "jump-host-a",
    "hop_count": 1,
    "path": ["jump-host-a"],
    "current_actor": "jump-host-a",
    "current_dpop_jkt": "jump-thumbprint"
  },
  
  "request": {
    "target_host": "target-host-b",
    "source_ip": "10.0.0.5",
    "service": "sshd"
  }
}
```

## Comparison with Socket Forwarding

| Aspect | Socket Forwarding | DPoP Token Exchange |
|--------|-------------------|---------------------|
| Key location | User's machine only | Each hop has own key |
| Compromised jump host impact | Can request proofs for ANY target | Can only use already-exchanged token |
| IdP dependency per hop | No | Yes |
| Audit trail | Limited | Full lineage in token + telemetry |
| Lineage provenance | None | Cryptographically attested |
| Offline operation | Yes | No |
| OpenTelemetry integration | Manual | Built-in trace_id |

## Policy Configuration

```yaml
# /etc/prmana/policy.yaml

delegation:
  # Mode: "exchange" (token exchange) or "forward" (socket forwarding)
  mode: exchange

  # Allow token exchange from these jump hosts
  allowed_exchangers:
    - client_id: "jump-host-a"
      allowed_targets:
        - "*.internal.example.com"
      max_chain_depth: 2

    - client_id: "jump-host-b"
      allowed_targets:
        - "db-*.example.com"
      require_mfa_on_original: true

  # Security requirements
  require_original_dpop: true      # Subject token must be DPoP-bound
  require_lineage_claim: true      # Exchanged tokens must have lineage
  require_cnf_attestation: true    # Exchanger must attest DPoP verification
  max_delegation_depth: 3          # Maximum hops
  exchanged_token_lifetime: 300    # 5 minutes (short!)

telemetry:
  # OpenTelemetry configuration
  otlp_endpoint: "http://otel-collector:4317"
  service_name: "prmana-pam"
  
  # Include lineage in all spans
  include_lineage: true
  
  # Emit structured logs
  structured_logs: true
```

## Consequences

### Positive

1. **Tamper-proof lineage**: IdP signature ensures lineage can't be spoofed
2. **Full observability**: OpenTelemetry traces link all hops
3. **Trust delegation**: Target trusts IdP attestation, not previous hops directly
4. **No key forwarding**: Each hop has isolated credentials
5. **Audit-ready**: Every authentication has verifiable provenance
6. **Art of the possible**: Sets high bar for multi-hop SSH security

### Negative

1. **IdP dependency**: Each hop needs network access to IdP
2. **Latency**: Token exchange adds round-trip per hop
3. **IdP customization**: Requires custom claim mapper in Keycloak
4. **Complexity**: More moving parts than socket forwarding

### IdP Support Matrix

| IdP | Token Exchange | DPoP | Custom Claims | Status |
|-----|---------------|------|---------------|--------|
| Keycloak 26.2+ | Yes | Yes | Protocol Mapper | Primary target |
| Azure AD/Entra | Yes (OBO) | Yes | Claims Mapping | Likely works |
| Auth0 | Yes | Yes | Actions/Rules | Needs testing |
| Okta | Limited | Preview | Hooks | Not ready |

## Implementation Plan

### Phase 1: Keycloak Validation (PoC)

1. Configure test realm:
   - Token exchange enabled on jump-host client
   - DPoP required on both clients
   - Custom protocol mapper for `x-prmana-lineage`

2. Test flow:
   - User gets DPoP-bound token
   - Jump host exchanges with attestation
   - Verify lineage claim in exchanged token

3. Document Keycloak configuration

### Phase 2: Core Implementation

1. Add `LineageAttestation` struct and builder
2. Add `TokenExchanger` trait with lineage support
3. Add lineage claim parsing to token validation
4. Extend audit logging with lineage fields

### Phase 3: OpenTelemetry Integration

1. Add `opentelemetry` dependency
2. Emit spans with lineage attributes
3. Propagate trace_id through token exchange
4. Structured log exporter for SIEM

### Phase 4: Jump Host Agent

1. Create `prmana-jump` daemon
2. DPoP key management for jump hosts
3. Automatic exchange on session establishment
4. PAM integration

## References

- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 9449 - DPoP](https://www.rfc-editor.org/rfc/rfc9449.html)
- [Keycloak 26.2 Token Exchange](https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2)
- [OpenTelemetry Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/)
- [THREAT_MODEL.md - Agent Forwarding Threats](../THREAT_MODEL.md)
