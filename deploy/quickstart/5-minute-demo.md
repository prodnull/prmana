# 5-Minute Demo: OIDC Authentication in Action

**Time to complete:** 5 minutes
**Prerequisites:** Docker with Docker Compose

This demo launches a complete OIDC environment locally so you can see token-based authentication in action before deploying to production.

## What You'll Get

| Component | URL/Address | Credentials |
|-----------|-------------|-------------|
| Keycloak Admin | http://localhost:8080/admin | admin / admin |
| OIDC Issuer | http://localhost:8080/realms/unix-oidc-test | - |
| OpenLDAP | ldap://localhost:389 | admin / admin |

### Test Users

| Username | Password | Email |
|----------|----------|-------|
| testuser | testpass | testuser@test.local |
| adminuser | adminpass | adminuser@test.local |

### OIDC Client

| Setting | Value |
|---------|-------|
| Client ID | unix-oidc |
| Client Secret | unix-oidc-test-secret |
| Grant Types | password, device_code |

## Quick Start

### Option 1: One-liner (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/demo.sh | bash
```

### Option 2: Manual Setup

If you prefer to inspect the script first:

```bash
# Download the script
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/demo.sh -o demo.sh

# Review it
less demo.sh

# Run it
bash demo.sh
```

## Step-by-Step Walkthrough

### Step 1: Get an Access Token

Once the demo is running, request a token using the password grant:

```bash
TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/unix-oidc-test/protocol/openid-connect/token \
  -d 'grant_type=password' \
  -d 'client_id=unix-oidc' \
  -d 'client_secret=unix-oidc-test-secret' \
  -d 'username=testuser' \
  -d 'password=testpass' | jq -r '.access_token')

echo "$TOKEN"
```

**Expected output:** A long JWT string (three base64-encoded parts separated by dots).

### Step 2: Inspect the Token

Decode and examine the token payload:

```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

**Expected output:**
```json
{
  "exp": 1234567890,
  "iat": 1234567590,
  "iss": "http://localhost:8080/realms/unix-oidc-test",
  "sub": "...",
  "preferred_username": "testuser",
  "email": "testuser@test.local",
  "acr": "1"
}
```

Key claims used by unix-oidc:
- `iss` - Issuer URL (must match PAM configuration)
- `sub` - Subject identifier (unique user ID)
- `preferred_username` - Maps to Unix username
- `exp` - Token expiration (enforced by PAM module)
- `acr` - Authentication Context Class Reference (for MFA validation)

### Step 3: View OIDC Discovery Document

See the full OIDC configuration:

```bash
curl -s http://localhost:8080/realms/unix-oidc-test/.well-known/openid-configuration | jq
```

This document tells clients (like unix-oidc) where to find:
- Token endpoint
- Authorization endpoint
- JWKS endpoint (public keys for token validation)
- Supported grant types and scopes

### Step 4: Verify Token Signature (Optional)

Fetch the JWKS and verify the token is properly signed:

```bash
# Get the JWKS
curl -s http://localhost:8080/realms/unix-oidc-test/protocol/openid-connect/certs | jq

# The PAM module uses this to cryptographically verify tokens
```

## Using Device Code Flow (Headless Auth)

For servers without browsers, use the device authorization grant:

```bash
# Step 1: Request device code
DEVICE_RESPONSE=$(curl -s -X POST \
  http://localhost:8080/realms/unix-oidc-test/protocol/openid-connect/auth/device \
  -d 'client_id=unix-oidc')

echo "$DEVICE_RESPONSE" | jq

# Step 2: Open the verification URL in a browser and enter the code
# verification_uri_complete contains the full URL with code

# Step 3: Poll for token (after user authorizes)
DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.device_code')
curl -s -X POST \
  http://localhost:8080/realms/unix-oidc-test/protocol/openid-connect/token \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  -d 'client_id=unix-oidc' \
  -d "device_code=$DEVICE_CODE" | jq
```

## Managing the Demo

### View Logs

```bash
cd ~/.unix-oidc-demo && docker compose logs -f
```

### Stop the Demo

```bash
cd ~/.unix-oidc-demo && docker compose down
```

### Restart the Demo

```bash
cd ~/.unix-oidc-demo && docker compose up -d
```

### Clean Up Completely

```bash
cd ~/.unix-oidc-demo && docker compose down -v
rm -rf ~/.unix-oidc-demo
```

## Troubleshooting

### "Docker is not installed"

Install Docker Desktop:
- **macOS/Windows:** https://docs.docker.com/desktop/
- **Linux:** https://docs.docker.com/engine/install/

### "Docker daemon is not running"

Start Docker Desktop or the Docker service:
```bash
# Linux
sudo systemctl start docker

# macOS/Windows
# Open Docker Desktop application
```

### "Port 8080 already in use"

Another service is using port 8080. Either stop that service or modify the demo:

```bash
cd ~/.unix-oidc-demo
# Edit docker-compose.yaml to change the port mapping
# e.g., change "8080:8080" to "8081:8080"
docker compose up -d
```

### "Keycloak failed to start within 2 minutes"

Check the logs for errors:
```bash
cd ~/.unix-oidc-demo && docker compose logs keycloak
```

Common issues:
- Insufficient memory (Keycloak needs ~512MB)
- Port conflict on 8080
- Docker resource limits too restrictive

### Token request returns error

Verify Keycloak is healthy:
```bash
curl -s http://localhost:8080/health/ready
```

Check the realm was imported correctly:
```bash
curl -s http://localhost:8080/realms/unix-oidc-test | jq .realm
# Should output: "unix-oidc-test"
```

## Next Steps

Now that you've seen OIDC authentication in action:

1. **[15-Minute Production Setup](./15-minute-production.md)**
   Deploy unix-oidc on a real server with your identity provider

2. **[Architecture Decisions](../../docs/adr/)**
   Understand the design decisions behind unix-oidc

3. **[Threat Model](../../docs/THREAT_MODEL.md)**
   Learn about the threat model and security guarantees

4. **[IdP Integration Guides](../idp-templates/)**
   Configuration examples for Okta, Azure AD, Google, and more

## How This Relates to Production

In production, the flow is similar but with important differences:

| Demo | Production |
|------|------------|
| Password grant (direct credentials) | Device code or authorization code flow |
| HTTP (localhost) | HTTPS (required) |
| Test realm with sample users | Your organization's IdP |
| Local token validation | unix-oidc PAM module validation |
| Manual curl commands | unix-oidc-agent handles token lifecycle |

The PAM module (`pam_oidc.so`) validates tokens the same way you did manually:
1. Fetches JWKS from issuer's discovery document
2. Verifies token signature
3. Validates claims (issuer, audience, expiration)
4. Maps `preferred_username` to Unix user
5. Grants or denies access

---

*Questions? Issues? [Open a GitHub issue](https://github.com/prodnull/unix-oidc/issues)*
