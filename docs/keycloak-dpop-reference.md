# Keycloak DPoP + Device Authorization Grant: Reference Implementation

## Overview

Keycloak 26.0+ is the reference implementation for DPoP-bound token issuance on the
Device Authorization Grant flow. This is the only commercially deployable IdP that
supports full proof-of-possession (PoP) for Device Auth Grant as of Keycloak 26.x.
This document covers the configuration required and how to verify it works with unix-oidc.

The canonical runnable example is `docker-compose.e2e.yaml`. The configuration
documented here is extracted directly from `test/fixtures/keycloak/e2e/unix-oidc-realm.json`
and verified against Keycloak 26.5.5.

## What This Proves

- Keycloak issues access tokens with a `cnf.jkt` claim (RFC 9449 §4.3) when a DPoP proof
  is presented during token acquisition via the Device Authorization Grant (RFC 8628)
- The PAM module validates the DPoP proof header against the token's `cnf.jkt` JWK thumbprint
  (RFC 7638) — a stolen token without the DPoP private key is useless
- Token requests without a DPoP proof are rejected (HTTP 400) when
  `dpop.bound.access.tokens` is enabled on the client

## Quick Start: Run the Reference Stack

```bash
# Start Keycloak 26.5.5 with realm auto-import + OpenLDAP + test SSH host
docker compose -f docker-compose.e2e.yaml up -d

# Wait for Keycloak health (uses /health/ready on port 9000)
until curl -sf http://localhost:9000/health/ready | grep -q '"status":"UP"'; do sleep 3; done

# Run DPoP binding verification (positive + negative tests)
bash test/tests/test_dpop_binding.sh
```

Expected output from `test_dpop_binding.sh`:

```
=== DPoP Binding E2E Test ===
Computed JWK thumbprint: <base64url-string>

--- Positive test: token request with DPoP proof ---
PASS: Token request with DPoP returned 200
PASS: cnf.jkt matches computed JWK thumbprint

--- Negative test: token request without DPoP proof ---
PASS: Token request without DPoP correctly rejected (400)

=== Results: 3 passed, 0 failed ===
```

## Required Keycloak Configuration

### Realm-Level: Enable DPoP

In `unix-oidc-realm.json`, the realm `attributes` section enables DPoP globally:

```json
{
  "realm": "unix-oidc",
  "enabled": true,
  "attributes": {
    "dpopEnabled": "true"
  }
}
```

**Admin Console path:** Realm Settings → Sessions → DPoP (toggle on).

### Client Configuration

The `unix-oidc` client requires three settings in its `attributes` block:

```json
{
  "clientId": "unix-oidc",
  "publicClient": true,
  "directAccessGrantsEnabled": true,
  "attributes": {
    "oauth2.device.authorization.grant.enabled": "true",
    "oauth2.device.code.lifespan": "600",
    "oauth2.device.polling.interval": "5",
    "dpop.bound.access.tokens": "true"
  }
}
```

| Attribute | Value | Purpose |
|-----------|-------|---------|
| `oauth2.device.authorization.grant.enabled` | `"true"` | Enables Device Authorization Grant (RFC 8628) |
| `oauth2.device.code.lifespan` | `"600"` | Device code valid for 600 seconds |
| `oauth2.device.polling.interval` | `"5"` | Client polls every 5 seconds |
| `dpop.bound.access.tokens` | `"true"` | Requires DPoP proof; rejects bearer-only requests |

**Admin Console path:** Clients → [client] → Settings → Advanced Settings → DPoP Bound Access Tokens (toggle on).

**Public client note:** The unix-oidc client is `publicClient: true` (no `client_secret`
required). This matches how `unix-oidc-agent` acquires tokens — it presents the DPoP proof
as the binding mechanism rather than a shared secret.

### Token Lifetime

The realm sets access token lifetime to 300 seconds (5 minutes):

```json
{
  "accessTokenLifespan": 300
}
```

The agent daemon's refresh cycle should be configured below this value.

## Verification: Inspect cnf.jkt in a Token

To manually inspect the `cnf.jkt` claim in an access token:

```bash
# Acquire a token (requires DPoP proof — see test_dpop_binding.sh for full proof generation)
ACCESS_TOKEN="<your.access.token.here>"

# Decode JWT payload and extract cnf.jkt
echo "$ACCESS_TOKEN" | cut -d. -f2 | \
  (input=$(cat); padding=$((4 - ${#input} % 4)); \
   [ "$padding" -ne 4 ] && printf '%s%*s' "$input" "$padding" '' | tr ' ' '=' || echo "$input") | \
  tr '_-' '/+' | base64 -d 2>/dev/null | jq '{cnf, iss, exp}'
```

Expected output structure:

```json
{
  "cnf": {
    "jkt": "<base64url-encoded-SHA-256-thumbprint>"
  },
  "iss": "http://localhost:8080/realms/unix-oidc",
  "exp": 1712345678
}
```

The `cnf.jkt` value is the SHA-256 hash of the canonical JWK representation of the
DPoP proof's public key (RFC 7638 §3):

```json
{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}
```

Members in lexicographic order. See `test/tests/test_dpop_binding.sh` for the full
thumbprint computation procedure used in the test suite.

## Test Script Reference

`test/tests/test_dpop_binding.sh` performs three checks:

1. **Positive test** — Token request with a valid DPoP proof returns HTTP 200 and includes
   `cnf.jkt` in the access token payload
2. **Thumbprint match** — The `cnf.jkt` value equals the SHA-256 thumbprint (RFC 7638) of
   the DPoP proof's public key
3. **Negative test** — Token request without a DPoP proof is rejected with HTTP 400
   (Keycloak enforces binding when `dpop.bound.access.tokens` is enabled)

The test uses the Resource Owner Password Credentials grant (`grant_type=password`) for
simplicity. The Device Authorization Grant produces identical `cnf.jkt` binding — see
`test/e2e/run-device-flow-e2e.sh` for the full Playwright-coordinated device flow test.

## Scope

This document covers the Keycloak reference implementation (full DPoP PoP on Device
Authorization Grant). Commercial IdP configurations are covered in subsequent phases.

## Standards References

- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
  — `cnf.jkt` claim definition (§4.3), thumbprint computation (§6)
- RFC 7638 — JSON Web Key (JWK) Thumbprint
  — Canonical serialization, SHA-256 hash procedure
- RFC 8628 — OAuth 2.0 Device Authorization Grant
  — Device code flow that unix-oidc uses for interactive login
