# ADR-003: Local Token Validation Strategy

## Status

Accepted

## Context

OIDC token validation can be performed in two ways:

1. **Introspection**: Send token to IdP's introspection endpoint
2. **Local validation**: Validate JWT signature and claims locally

For SSH authentication, we needed to choose a validation strategy considering:

- **Availability**: SSH must work even during IdP outages
- **Latency**: Authentication should be fast
- **Security**: Validation must be cryptographically sound
- **Privacy**: Minimize data sent to IdP

Traditional web applications often use introspection because:
- Tokens can be revoked server-side
- Claims can be updated dynamically
- No need to manage JWKS locally

However, SSH authentication has different requirements.

## Decision

We use **local JWT validation** with cached JWKS (JSON Web Key Set).

### Validation steps:

1. **Parse JWT**: Extract header, payload, signature
2. **Fetch JWKS** (cached): Retrieve IdP's public keys
3. **Verify signature**: Validate JWT signature against JWKS
4. **Validate claims**:
   - `iss`: Must match configured issuer
   - `aud`: Must match configured audience
   - `exp`: Must not be expired
   - `iat`: Must not be in the future
   - `nbf`: Must be valid (if present)
5. **Validate DPoP binding**: If DPoP enabled, verify `cnf.jkt` matches proof thumbprint
6. **Check JTI cache**: Detect replay attempts

### JWKS Caching

```
┌─────────────┐
│ PAM Module  │
└──────┬──────┘
       │
       │ 1. Check local cache
       ↓
┌─────────────┐     Cache miss      ┌─────────────┐
│ JWKS Cache  │ ─────────────────→  │     IdP     │
│ (file-based)│ ←─────────────────  │ /.well-known│
└─────────────┘     Fetch & cache   └─────────────┘
```

- **Cache location**: `/var/cache/unix-oidc/jwks.json`
- **TTL**: Configurable, default 1 hour
- **Refresh**: Background refresh before expiry
- **Fallback**: Use stale cache if IdP unreachable

## Consequences

### Positive

- **Offline capability**: Auth works during IdP outages (with cached JWKS)
- **Low latency**: No network round-trip per authentication
- **Privacy**: Token contents not sent to IdP
- **Scalability**: No IdP load per authentication
- **Auditability**: All validation logic is local and verifiable

### Negative

- **Revocation lag**: Revoked tokens valid until expiry
- **Key rotation**: Must detect and handle JWKS updates
- **Clock drift**: Requires synchronized clocks
- **Complexity**: More validation code to maintain

### Mitigations for negatives

#### Revocation lag

- Use short-lived tokens (5-15 min recommended)
- DPoP binding prevents stolen token use
- Rate limiting detects brute force

#### Key rotation

- Automatic JWKS refresh on unknown `kid`
- Background refresh before cache expiry
- Support for multiple concurrent keys

#### Clock drift

- Configurable clock skew tolerance (default 30s)
- NTP recommended in deployment guide
- Warnings for significant drift

## Security considerations

### What we validate

| Claim | Validation | Purpose |
|-------|------------|---------|
| `iss` | Exact match | Prevent token from wrong IdP |
| `aud` | Contains expected | Prevent token for wrong app |
| `exp` | Not expired | Limit token lifetime |
| `iat` | Not future | Detect clock issues |
| `nbf` | Currently valid | Honor IdP restrictions |
| `sub` | Present | Identify user |
| `cnf.jkt` | Matches proof | DPoP binding |

### What we DON'T validate (and why)

| Check | Why skipped |
|-------|-------------|
| `azp` | Not universally present |
| `nonce` | Session-based, not applicable |
| `acr`/`amr` | Policy decision, not security |

## Alternatives considered

### Introspection (rejected for primary validation)

- Network dependency unacceptable for SSH
- Latency too high for interactive login
- IdP becomes single point of failure
- Privacy concerns (IdP sees all auth attempts)

### Hybrid approach (possible future)

- Local validation for normal auth
- Introspection for high-security operations
- Not implemented due to complexity

## References

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [OpenID Connect Core 1.0 - ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
- [Implementation: pam-unix-oidc/src/oidc/validation.rs](../../pam-unix-oidc/src/oidc/validation.rs)
