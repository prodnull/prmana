# unix-oidc E2E Demo Guide

This guide walks through a complete demonstration of OIDC-based Unix authentication, including:
- Device flow authentication
- SSH login with OIDC tokens
- Sudo step-up authentication
- Audit event visibility

## Prerequisites

- Docker and Docker Compose
- Built PAM module (`make build`)
- Terminal with curl, jq installed

## Quick Start

```bash
# 1. Build the PAM module
make build

# 2. Start test environment
make dev-up

# 3. Wait for services (Keycloak takes ~30s)
./test/scripts/wait-for-healthy.sh

# 4. Run the demo
./demo/run-demo.sh
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Demo Environment                               │
├─────────────────┬─────────────────┬──────────────────────────────────┤
│    Keycloak     │    OpenLDAP     │         Test Host                │
│    (OIDC IdP)   │   (Directory)   │    (SSH + PAM + unix-oidc)       │
│    :8080        │    :389         │         :2222                    │
└─────────────────┴─────────────────┴──────────────────────────────────┘

Authentication Flow:
1. User initiates device flow → Keycloak returns verification URL
2. User authenticates in browser → Keycloak issues token
3. Token used for SSH login → PAM validates via JWKS
4. Sudo command → Step-up via device flow if ACR insufficient
```

## Manual Step-by-Step Demo

### Step 1: Start the Environment

```bash
# Start all services
docker compose -f docker-compose.test.yaml up -d

# Verify services are healthy
docker compose -f docker-compose.test.yaml ps
```

Expected output: All three services (keycloak, openldap, test-host) should show "healthy".

### Step 2: Initiate Device Flow

```bash
# Request device authorization
DEVICE_RESPONSE=$(curl -s -X POST \
  "http://localhost:8080/realms/unix-oidc-test/protocol/openid-connect/auth/device" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=unix-oidc" \
  -d "client_secret=unix-oidc-test-secret" \
  -d "scope=openid")

echo "$DEVICE_RESPONSE" | jq .
```

Note the `verification_uri_complete` and `device_code` from the response.

### Step 3: Complete Authentication in Browser

1. Open the `verification_uri_complete` URL in your browser
2. Log in with credentials:
   - Username: `testuser`
   - Password: `testpass`
3. Grant consent when prompted

### Step 4: Poll for Token

```bash
# Extract device code
DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.device_code')

# Poll for token (run after completing browser auth)
TOKEN_RESPONSE=$(curl -s -X POST \
  "http://localhost:8080/realms/unix-oidc-test/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=unix-oidc" \
  -d "client_secret=unix-oidc-test-secret" \
  -d "device_code=$DEVICE_CODE")

# Extract access token
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
echo "Token acquired (length: ${#ACCESS_TOKEN})"
```

### Step 5: Verify Token Claims

```bash
# Decode and display token claims
echo "$ACCESS_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '{iss, aud, sub, preferred_username, acr, exp}'
```

Expected claims:
- `iss`: `http://keycloak:8080/realms/unix-oidc-test`
- `aud`: includes `unix-oidc`
- `preferred_username`: `testuser`
- `acr`: `1` (basic authentication level)

### Step 6: Test PAM Authentication

```bash
# Test PAM authentication with the token
# Note: UNIX_OIDC_TEST_MODE enables reading tokens from environment variables
docker compose -f docker-compose.test.yaml exec -e OIDC_TOKEN="$ACCESS_TOKEN" -e UNIX_OIDC_TEST_MODE="true" test-host bash -c "
export OIDC_ISSUER='http://keycloak:8080/realms/unix-oidc-test'
export OIDC_CLIENT_ID='unix-oidc'
pamtester -v sshd testuser authenticate
"
```

Expected output:
```
pamtester: invoking pam_start(sshd, testuser, ...)
pamtester: performing operation - authenticate
unix-oidc-audit: {"event":"SSH_LOGIN_SUCCESS",...}
pamtester: successfully authenticated
```

### Step 7: Test Sudo Authentication

```bash
# Test sudo PAM authentication
docker compose -f docker-compose.test.yaml exec -e OIDC_TOKEN="$ACCESS_TOKEN" -e UNIX_OIDC_TEST_MODE="true" test-host bash -c "
export OIDC_ISSUER='http://keycloak:8080/realms/unix-oidc-test'
export OIDC_CLIENT_ID='unix-oidc'
pamtester -v sudo testuser authenticate
"
```

### Step 8: View Audit Events

The PAM module emits audit events in JSON format to syslog/stderr:

```json
{
  "event": "SSH_LOGIN_SUCCESS",
  "timestamp": "2026-01-20T00:04:04.887238250+00:00",
  "session_id": "unix-oidc-188c4791bb41a389-6784f12565e5dcb1",
  "user": "testuser",
  "uid": 1000,
  "source_ip": null,
  "host": "725f1773510f",
  "oidc_jti": "a34f6c65-b1df-4563-94f2-95f4ff2a1141",
  "oidc_acr": "1",
  "oidc_auth_time": null
}
```

## Automated Demo Script

For a fully automated demo, use the provided script:

```bash
./demo/run-demo.sh
```

This script:
1. Starts the test environment
2. Initiates device flow
3. Opens browser for authentication (or uses Playwright if available)
4. Polls for token completion
5. Demonstrates SSH and sudo authentication
6. Shows audit events

## Security Features Demonstrated

### 1. Token Validation
- JWT signature verified against Keycloak's JWKS
- Issuer (`iss`) must match configured OIDC issuer
- Audience (`aud`) must include the client ID
- Expiration (`exp`) is enforced with clock skew tolerance

### 2. User Mapping
- Token's `preferred_username` mapped to Unix user
- User must exist in SSSD/LDAP directory
- UID verified against directory service

### 3. Step-Up Authentication
Policy in `/etc/unix-oidc/policy.yaml`:
```yaml
sudo:
  step_up_required: true
  allowed_methods:
    - device_flow
  required_acr: urn:keycloak:acr:loa2
  commands:
    - pattern: "/usr/bin/apt*"
      step_up_required: true
```

Commands matching elevated patterns require fresh authentication with higher ACR level.

### 4. Audit Trail
Every authentication attempt (success or failure) is logged with:
- Timestamp
- Session ID (for correlation)
- User and UID
- Source IP (if available)
- Token JTI (for replay detection)
- ACR level achieved

## Test Credentials

| User | Password | Description |
|------|----------|-------------|
| testuser | testpass | Standard test user |
| adminuser | adminpass | Admin test user |
| admin | admin | Keycloak admin console |

## Token Passing Methods

The PAM module supports several methods for receiving OIDC tokens:

### 1. Environment Variable (Recommended for Automation)
```bash
# Set the token in the environment before authentication
export OIDC_TOKEN="eyJ..."
export UNIX_OIDC_TEST_MODE="true"  # Enable env var reading

# Then authenticate
pamtester sshd testuser authenticate
```

This is the recommended method for automated/scripted authentication and the demo.

### 2. PAM Environment Variable
```bash
# Set via pam_env.so or programmatically
# The PAM module reads OIDC_TOKEN from the PAM environment
```

### 3. Keyboard-Interactive (Limited)
The PAM conversation prompt has a ~512 byte buffer limit, which is insufficient for JWT tokens (~1400+ bytes). This method is not suitable for OIDC tokens.

For SSH interactive authentication, consider using:
- SSH certificates issued via OIDC-authenticated CLI
- SSH keys registered through OIDC flows
- SSH_ASKPASS with a local token agent

## Troubleshooting

### Keycloak not responding
```bash
docker compose -f docker-compose.test.yaml logs keycloak
curl http://localhost:8080/health/ready
```

### Token validation fails
```bash
# Check token issuer matches
echo "$ACCESS_TOKEN" | cut -d'.' -f2 | base64 -d | jq '.iss'
# Should be: http://keycloak:8080/realms/unix-oidc-test
```

### PAM module not found
```bash
docker compose -f docker-compose.test.yaml exec test-host ls -la /lib/security/pam_unix_oidc.so
```

### SSSD user resolution fails
```bash
docker compose -f docker-compose.test.yaml exec test-host id testuser
```

## Cleanup

```bash
# Stop and remove containers
make dev-down

# Or manually
docker compose -f docker-compose.test.yaml down -v
```
