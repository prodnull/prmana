# ADR-004: Device Authorization Grant for Headless Authentication

## Status

Accepted

## Context

SSH servers are often headless - no browser, no GUI. Traditional OIDC flows require:

- **Authorization Code**: Redirect to IdP login page (needs browser)
- **Implicit**: Also browser-based (deprecated anyway)
- **Resource Owner Password**: Anti-pattern, often disabled

Users connecting to headless servers need a way to authenticate with their IdP.

### Requirements

1. Work without browser on the server
2. Support MFA (not just password)
3. User-friendly flow
4. Secure against phishing
5. Compatible with major IdPs

## Decision

We implemented **OAuth 2.0 Device Authorization Grant** (RFC 8628).

### Flow

```
┌────────────┐                              ┌─────────────┐
│   Server   │                              │   User's    │
│ (headless) │                              │   Device    │
└─────┬──────┘                              └──────┬──────┘
      │                                            │
      │ 1. Request device code                     │
      │ ─────────────────────────→                 │
      │                           ┌───────────┐    │
      │ 2. Display URL + code     │    IdP    │    │
      │ ←─────────────────────────┴───────────┘    │
      │                                            │
      │ 3. Show: "Visit https://idp/device"        │
      │    "Enter code: ABCD-1234"                 │
      │ ─────────────────────────────────────────→ │
      │                                            │
      │                            4. User visits  │
      │                               URL on phone │
      │                               enters code  │
      │                               logs in+MFA  │
      │                                            │
      │ 5. Poll for token                          │
      │ ─────────────────────────→                 │
      │                           ┌───────────┐    │
      │ 6. Return access token    │    IdP    │    │
      │ ←─────────────────────────┴───────────┘    │
      │                                            │
```

### Why Device Authorization Grant

| Alternative | Why Not |
|-------------|---------|
| Authorization Code | Requires browser on server |
| Password Grant | Often disabled, no MFA support |
| Client Credentials | Machine auth, not user auth |
| Copy-paste token | Poor UX, error-prone |
| SSH agent forwarding | Security risks, not OIDC |

### Implementation details

```rust
// Simplified flow
let device_response = request_device_code(&config).await?;

println!("Visit: {}", device_response.verification_uri);
println!("Code: {}", device_response.user_code);

// Poll until user completes auth
let token = poll_for_token(
    &device_response.device_code,
    device_response.interval,
).await?;
```

### User code format

We use IdP-provided codes, typically:
- 8 characters with dash: `ABCD-1234`
- Easy to read and type
- Case-insensitive

### Verification URI display

We display both:
- Full URI: `https://idp.example.com/device`
- QR code (when terminal supports it): Scan to open on phone

## Consequences

### Positive

- **Works headless**: No browser needed on server
- **Full IdP auth**: Supports MFA, SSO, conditional access
- **User-friendly**: Familiar "enter code" pattern
- **Secure**: Code displayed server-side, auth on trusted device
- **Standard protocol**: RFC 8628, wide IdP support

### Negative

- **Requires second device**: User needs phone/laptop
- **Polling overhead**: Server polls IdP during auth
- **Timeout risk**: User must complete within time limit
- **IdP support required**: Not all IdPs support device flow

### Mitigations

#### Second device requirement

- Document the flow clearly
- Support both device flow and direct token paste
- Consider hardware token support (future)

#### Polling overhead

- Honor IdP-provided interval
- Exponential backoff on errors
- Timeout after reasonable period (5 min default)

#### IdP compatibility

- Detect device flow support via discovery
- Fall back to token paste if unsupported
- Document IdP-specific configuration

## Security considerations

### Threats mitigated

| Threat | Mitigation |
|--------|------------|
| Phishing | User enters code on IdP site, not attacker site |
| MITM | TLS to IdP, code only works once |
| Brute force | Rate limiting, short code lifetime |
| Session hijacking | DPoP binding after auth |

### User education

The device flow is unfamiliar to some users. We provide:
- Clear instructions during flow
- Timeout countdown
- Error messages explaining failures
- Documentation with screenshots

## Alternatives considered

### Browser-based with port forwarding (rejected)

- Complex setup
- Security implications of port forwarding
- Not always possible (firewalls)

### Pre-provisioned tokens (rejected)

- Operational complexity
- Token distribution challenges
- Short lifetimes problematic

### SSH certificate authority (future consideration)

- Could integrate with OIDC for cert issuance
- More complex infrastructure
- May complement device flow, not replace

## References

- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628)
- [Implementation: unix-oidc-agent device flow](../../unix-oidc-agent/src/main.rs)
- [User Guide: Device Flow section](../user-guide.md#device-flow-headless)
