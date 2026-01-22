# Keycloak Configuration for unix-oidc

This guide covers configuring Keycloak as an Identity Provider (IdP) for unix-oidc.

## Prerequisites

- Keycloak 24.0+ (tested with 24.0, 25.0, 26.0)
- Admin access to Keycloak
- Network connectivity between Unix hosts and Keycloak server
- HTTPS recommended for production (required for Device Authorization Grant in browsers)

## Quick Setup (Recommended)

### Option 1: Import Realm via Admin Console

1. Log in to Keycloak Admin Console
2. Click the realm dropdown (top-left) and select "Create Realm"
3. Click "Browse" and select `realm-export.json` from this directory
4. Click "Create"
5. Navigate to Clients > unix-oidc > Credentials and regenerate the client secret
6. Note the new client secret for your unix-oidc configuration

### Option 2: Import via CLI

```bash
# Using kcadm.sh (Keycloak Admin CLI)
# First, authenticate
/opt/keycloak/bin/kcadm.sh config credentials \
    --server https://keycloak.example.com \
    --realm master \
    --user admin \
    --password <admin-password>

# Import the realm
/opt/keycloak/bin/kcadm.sh create realms \
    -f realm-export.json

# Regenerate client secret (recommended)
/opt/keycloak/bin/kcadm.sh create clients/<client-uuid>/client-secret \
    -r unix-oidc
```

### Option 3: Import via REST API

```bash
# Get admin token
ACCESS_TOKEN=$(curl -s -X POST \
    "https://keycloak.example.com/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin" \
    -d "password=<admin-password>" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    | jq -r '.access_token')

# Import realm
curl -X POST \
    "https://keycloak.example.com/admin/realms" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d @realm-export.json
```

## Manual Setup

If you prefer to configure Keycloak manually or need to integrate with an existing realm.

### Step 1: Create Realm (Skip if using existing realm)

1. Log in to Keycloak Admin Console
2. Click the realm dropdown (top-left)
3. Click "Create Realm"
4. Enter realm name: `unix-oidc` (or your preferred name)
5. Click "Create"

### Step 2: Create Client

1. Navigate to Clients > Create client
2. Configure General Settings:
   - **Client type**: OpenID Connect
   - **Client ID**: `unix-oidc`
   - **Name**: Unix OIDC Client
   - Click "Next"

3. Configure Capability Config:
   - **Client authentication**: ON (confidential client)
   - **Authorization**: OFF
   - **Authentication flow**:
     - [x] Standard flow (for testing)
     - [x] Direct access grants (for testing)
     - [x] **OAuth 2.0 Device Authorization Grant** (REQUIRED for unix-oidc)
   - Click "Next"

4. Configure Login Settings:
   - **Valid redirect URIs**:
     - `http://localhost:*` (for testing)
     - `urn:ietf:wg:oauth:2.0:oob` (for device flow)
   - **Web origins**: `*` (or restrict as needed)
   - Click "Save"

5. Get Client Secret:
   - Go to the Credentials tab
   - Copy the "Client secret" value

### Step 3: Configure Client Scopes

The `preferred_username` claim must be included in tokens for unix-oidc to map IdP users to Unix users.

1. Navigate to Client scopes > Create client scope
2. Or modify the existing `profile` scope

**To ensure preferred_username is always included:**

1. Go to Clients > unix-oidc > Client scopes
2. Click "Add client scope" > "profile" (if not already added)
3. Alternatively, create a dedicated mapper:
   - Go to Clients > unix-oidc > Client scopes > Dedicated scopes
   - Click "Configure a new mapper" > "User Property"
   - Configure:
     - **Name**: preferred_username
     - **Property**: username
     - **Token Claim Name**: preferred_username
     - **Claim JSON Type**: String
     - **Add to ID token**: ON
     - **Add to access token**: ON
     - **Add to userinfo**: ON

**Verify the mapper exists:**

1. Go to Client scopes > profile > Mappers
2. Confirm "username" mapper exists with claim name `preferred_username`

### Step 4: Add Users

Users must exist in Keycloak with usernames that **exactly match** Unix usernames.

1. Navigate to Users > Add user
2. Configure:
   - **Username**: Must match the Unix username exactly (e.g., `jsmith`)
   - **Email**: User's email (optional but recommended)
   - **First name**: User's first name
   - **Last name**: User's last name
   - **Email verified**: ON (recommended)
   - Click "Create"

3. Set password:
   - Go to Credentials tab
   - Click "Set password"
   - Enter password and confirm
   - **Temporary**: OFF (unless you want forced password change)
   - Click "Save"

**Important**: The username in Keycloak becomes the `preferred_username` claim, which unix-oidc uses to identify the Unix user. These must match exactly.

### Step 5: Get Configuration Values

Gather these values for unix-oidc configuration:

1. **Issuer URL**: `https://keycloak.example.com/realms/unix-oidc`
   - This is your realm's base URL

2. **Client ID**: `unix-oidc` (or whatever you named your client)

3. **Client Secret**: Found in Clients > unix-oidc > Credentials

4. **Discovery URL**: `https://keycloak.example.com/realms/unix-oidc/.well-known/openid-configuration`

Example unix-oidc configuration (`/etc/unix-oidc/config.toml`):

```toml
[oidc]
issuer = "https://keycloak.example.com/realms/unix-oidc"
client_id = "unix-oidc"
client_secret = "your-client-secret-here"

[claims]
username_claim = "preferred_username"
```

## Testing

### Verify OpenID Configuration

```bash
curl -s https://keycloak.example.com/realms/unix-oidc/.well-known/openid-configuration | jq .
```

Confirm these endpoints exist:
- `device_authorization_endpoint`
- `token_endpoint`
- `userinfo_endpoint`

### Test Device Authorization Flow

```bash
# Step 1: Request device code
DEVICE_RESPONSE=$(curl -s -X POST \
    "https://keycloak.example.com/realms/unix-oidc/protocol/openid-connect/auth/device" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=unix-oidc" \
    -d "client_secret=YOUR_CLIENT_SECRET" \
    -d "scope=openid profile")

echo "$DEVICE_RESPONSE" | jq .

# Extract values
DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.device_code')
USER_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.user_code')
VERIFICATION_URI=$(echo "$DEVICE_RESPONSE" | jq -r '.verification_uri_complete')

echo "Go to: $VERIFICATION_URI"
echo "Or enter code: $USER_CODE at $(echo "$DEVICE_RESPONSE" | jq -r '.verification_uri')"

# Step 2: Poll for token (run after user authenticates)
curl -s -X POST \
    "https://keycloak.example.com/realms/unix-oidc/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=unix-oidc" \
    -d "client_secret=YOUR_CLIENT_SECRET" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    -d "device_code=$DEVICE_CODE" | jq .
```

### Verify Token Claims

```bash
# Decode the access token (paste your token)
echo "YOUR_ACCESS_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

Verify the token contains:
- `preferred_username`: matches your Unix username
- `aud`: includes your client ID

### Test Direct Grant (Development Only)

```bash
curl -s -X POST \
    "https://keycloak.example.com/realms/unix-oidc/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=unix-oidc" \
    -d "client_secret=YOUR_CLIENT_SECRET" \
    -d "grant_type=password" \
    -d "username=testuser" \
    -d "password=testpass" \
    -d "scope=openid profile" | jq .
```

**Note**: Direct access grants should be disabled in production. Use Device Authorization Grant instead.

## Troubleshooting

### "Device authorization not enabled"

**Symptom**: Error when requesting device code

**Solution**:
1. Go to Clients > unix-oidc > Settings
2. Scroll to "Capability config"
3. Enable "OAuth 2.0 Device Authorization Grant"
4. Click Save

### "Invalid client credentials"

**Symptom**: 401 error with "invalid_client"

**Solution**:
1. Verify client secret in Clients > unix-oidc > Credentials
2. Ensure Client authentication is ON (confidential client)
3. Regenerate secret if needed

### "User not found" or username mismatch

**Symptom**: unix-oidc authentication succeeds but user mapping fails

**Solution**:
1. Verify Keycloak username exactly matches Unix username
2. Check the `preferred_username` claim in the token
3. Ensure the username mapper is configured correctly

### Token missing preferred_username claim

**Symptom**: Token doesn't contain preferred_username

**Solution**:
1. Go to Client scopes > profile > Mappers
2. Verify "username" mapper exists
3. Ensure "Add to access token" is ON
4. If using dedicated scope, ensure it's assigned to the client

### "Invalid redirect URI"

**Symptom**: Error during device flow completion

**Solution**:
1. Go to Clients > unix-oidc > Settings
2. Add `urn:ietf:wg:oauth:2.0:oob` to Valid redirect URIs
3. Click Save

### HTTPS/SSL Certificate Issues

**Symptom**: Connection refused or certificate errors

**Solution**:
1. Ensure Keycloak is accessible via HTTPS
2. For self-signed certificates, configure unix-oidc to trust the CA:
   ```toml
   [tls]
   ca_cert = "/etc/unix-oidc/keycloak-ca.pem"
   ```
3. For development, you can disable verification (NOT for production):
   ```toml
   [tls]
   insecure_skip_verify = true  # DANGER: Development only!
   ```

### Device code expired

**Symptom**: "expired_token" error when polling

**Solution**:
1. The default device code lifetime is 300 seconds (5 minutes)
2. User must complete authentication within this window
3. To extend, modify client settings:
   - Clients > unix-oidc > Advanced > Advanced settings
   - Adjust "OAuth 2.0 Device Code Lifespan"

## Security Recommendations

1. **Use HTTPS**: Always use TLS in production
2. **Disable direct access grants**: Use Device Authorization Grant only
3. **Rotate client secrets**: Regenerate periodically
4. **Enable brute force protection**: Realm Settings > Security Defenses
5. **Configure appropriate token lifespans**: Keep access tokens short-lived
6. **Use strong password policies**: Realm Settings > Authentication > Password Policy

## Additional Resources

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OAuth 2.0 Device Authorization Grant](https://www.keycloak.org/docs/latest/server_admin/#device-authorization-grant)
- [OpenID Connect](https://www.keycloak.org/docs/latest/server_admin/#assembly-oidc-clients_server_administration_guide)
