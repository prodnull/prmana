# ADR-005 Alignment with IETF OAuth WG Direction

## Summary

After due diligence research, we need to modify our DPoP token exchange design
to align with emerging IETF patterns. This avoids:
1. Inventing incompatible mechanisms
2. Using custom claims that duplicate RFC 8693 `act`
3. Missing the `subject_token_dpop` parameter from WG discussions

## Changes Required

### 1. Remove `x-unix-oidc-lineage` Custom Claim

**Problem**: Our custom `x-unix-oidc-lineage` claim duplicates RFC 8693's `act` claim.

**Before (non-standard)**:
```json
{
  "act": { "sub": "alice@example.com" },
  "x-unix-oidc-lineage": {
    "origin": { "sub": "alice@example.com", "dpop_jkt": "..." },
    "path": [{ "actor": "jump-host-a", "actor_dpop_jkt": "..." }]
  }
}
```

**After (RFC 8693 compliant)**:
```json
{
  "sub": "alice@example.com",
  "act": {
    "sub": "service-account-jump-host-a",
    "client_id": "jump-host-a"
  },
  "cnf": {
    "jkt": "jump-host-dpop-thumbprint"
  }
}
```

The `act` claim already provides delegation chain via nesting:
```json
{
  "sub": "alice@example.com",
  "act": {
    "sub": "jump-host-b",
    "act": {
      "sub": "jump-host-a"
    }
  }
}
```

### 2. Add `subject_token_dpop` Parameter

**Problem**: Our design only uses the `DPoP` header for binding the NEW token.
We have no mechanism to prove possession of the SUBJECT token being exchanged.

**WG Proposed Solution** (Vladimir Dzhuvinov, Oct 2025):

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
DPoP: <proof for NEW token, bound to jump host's key>

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<alice's DPoP-bound token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&subject_token_dpop=<DPoP proof for subject_token, proving alice's key>
&client_id=jump-host-a
&client_secret=...
```

**Note**: The jump host would need Alice's DPoP proof that she sent when
authenticating. This proof should be forwarded (not generated) since the
jump host doesn't have Alice's private key.

### 3. Remove `x_lineage_attestation` Parameter

**Problem**: Our custom `x_lineage_attestation` parameter is not in any WG
discussion and adds unnecessary complexity.

**Solution**: The IdP can derive all necessary information from:
1. `subject_token` - contains original user identity
2. `subject_token_dpop` - proves possession was verified (by forwarding)
3. `client_id` - identifies the exchanger (jump host)
4. `DPoP` header - binds new token to exchanger's key

No additional attestation parameter needed.

### 4. Use `requested_cnf` from Identity Chaining

**From draft-ietf-oauth-identity-chaining-08**:

When crossing trust domains, include `requested_cnf` to carry the key binding:

```json
{
  "iss": "https://domain-a.example.com",
  "sub": "alice@example.com",
  "aud": "https://domain-b.example.com/as",
  "requested_cnf": {
    "jkt": "target-service-dpop-thumbprint"
  }
}
```

### 5. Keep: Core Architecture

These parts of our design remain valid:
- Each hop has its own DPoP keypair ✓
- Token exchange rebinds `cnf.jkt` to exchanger's key ✓
- RFC 8693 `act` claim for delegation ✓
- Short-lived exchanged tokens ✓
- OpenTelemetry trace correlation (via standard tracing, not custom claims) ✓

## Updated Token Exchange Flow

```http
POST /realms/example/protocol/openid-connect/token HTTP/1.1
Host: idp.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imp1bXAtaG9zdC1rZXkifX0...

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImNuZiI6eyJqa3QiOiJhbGljZS1rZXktdGh1bWJwcmludCJ9fQ...
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&subject_token_dpop=eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7ImFsaWNlLWtleSJ9fQ...
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=target-host-b
&client_id=jump-host-a
&client_secret=jump-host-secret
```

**Headers**:
- `DPoP`: Proof signed by jump-host's key (for binding new token)

**Parameters**:
- `subject_token_dpop`: Alice's original DPoP proof (forwarded, proves she authenticated)

## Keycloak Configuration Changes

### Remove Custom Protocol Mappers

**Delete**:
- `x-unix-oidc-lineage-mapper` (hardcoded claim mapper)

**Keep**:
- `act-claim-mapper` - but verify it uses RFC 8693 format

### Enable Standard Token Exchange

Keycloak 26.2+ V2 token exchange should handle:
1. Preserving `sub` from subject token (original user)
2. Adding `act` claim with exchanger identity
3. Rebinding `cnf.jkt` to DPoP key from request header

### Future: subject_token_dpop Support

Keycloak doesn't currently support `subject_token_dpop`. Options:
1. File feature request with Keycloak
2. Implement via custom SPI
3. Wait for IETF standardization to drive adoption

## Audit Trail Without Custom Claims

Instead of `x-unix-oidc-lineage`, use:

1. **Structured Logging** (server-side):
```json
{
  "event": "TOKEN_EXCHANGE",
  "trace_id": "otel-abc123",
  "subject": "alice@example.com",
  "subject_cnf_jkt": "alice-thumbprint",
  "exchanger": "jump-host-a",
  "exchanger_cnf_jkt": "jump-thumbprint",
  "target_audience": "target-host-b",
  "subject_token_jti": "original-jti",
  "exchanged_token_jti": "new-jti"
}
```

2. **OpenTelemetry Spans** (distributed tracing):
```
Trace: otel-abc123
├── Span: user-auth (alice)
│   └── dpop_jkt: alice-thumbprint
├── Span: token-exchange (jump-host-a)
│   ├── subject_jkt: alice-thumbprint
│   └── new_jkt: jump-thumbprint
└── Span: target-auth (target-host-b)
    └── actor_chain: [jump-host-a, alice]
```

The audit trail is in the observability system, not the token itself.

## Summary of Changes

| Component | Before | After |
|-----------|--------|-------|
| Delegation chain | `x-unix-oidc-lineage` | RFC 8693 `act` (nested) |
| Attestation param | `x_lineage_attestation` | Remove (not needed) |
| Subject proof | None | `subject_token_dpop` (when IdPs support) |
| Audit trail | Custom claims | OpenTelemetry + structured logs |
| Keycloak mappers | Custom lineage | Standard `act` only |

## References

- [RFC 8693 - Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 9449 - DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [draft-ietf-oauth-identity-chaining-08](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/)
- [OAuth WG: DPoP for token exchange](https://www.mail-archive.com/oauth@ietf.org/msg24953.html)
