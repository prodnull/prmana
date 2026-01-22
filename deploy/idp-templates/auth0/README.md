# Auth0 Configuration for unix-oidc

This guide walks you through configuring Auth0 as an Identity Provider for unix-oidc.

## Prerequisites

- An Auth0 tenant (free tier works for testing)
- Admin access to your Auth0 dashboard
- unix-oidc installed on your Linux server(s)

## Quick Setup

| Step | Action | Time |
|------|--------|------|
| 1 | Create Native Application | 2 min |
| 2 | Enable Device Authorization Grant | 1 min |
| 3 | Configure Scopes | 1 min |
| 4 | Add Username Claim Action | 3 min |
| 5 | Create Test User | 2 min |
| 6 | Get Configuration Values | 1 min |

**Total time: ~10 minutes**

## Manual Setup

### Step 1: Create Application

1. Log in to your [Auth0 Dashboard](https://manage.auth0.com/)

2. Navigate to **Applications** > **Applications** in the left sidebar

3. Click **+ Create Application**

4. Configure the application:
   - **Name**: `unix-oidc` (or your preferred name)
   - **Application Type**: Select **Native**

   > **Important**: You must select "Native" for Device Authorization Grant support. Regular Web Application and SPA types do not support this flow.

5. Click **Create**

6. Note your **Client ID** from the Settings tab (you'll need this later)

### Step 2: Enable Device Authorization Grant

1. In your application settings, scroll down to **Advanced Settings** (click to expand)

2. Select the **Grant Types** tab

3. Ensure these grants are enabled:
   - [x] **Device Code** (required for unix-oidc)
   - [x] **Refresh Token** (recommended for token refresh)

4. Click **Save Changes**

### Step 3: Configure Scopes

Auth0 includes standard OIDC scopes by default. Verify your API settings:

1. Navigate to **Applications** > **APIs**

2. Click on **Auth0 Management API** (or your custom API if using one)

3. Verify these scopes are available:
   - `openid` - Required for OIDC
   - `profile` - User profile information
   - `email` - User email address
   - `offline_access` - For refresh tokens

For unix-oidc, the default Auth0 configuration typically works. If you need custom scopes:

1. Navigate to **Applications** > **APIs**
2. Click **+ Create API**
3. Configure:
   - **Name**: `unix-oidc-api`
   - **Identifier**: `https://unix-oidc.example.com` (your choice)
4. Add custom scopes in the **Permissions** tab if needed

### Step 4: Configure Username Claim

Auth0 does not include `preferred_username` in tokens by default. unix-oidc needs this claim to map OIDC identity to Unix usernames.

#### Option A: Auth0 Action (Recommended)

Actions are the modern way to customize Auth0 behavior.

1. Navigate to **Actions** > **Library** in the left sidebar

2. Click **+ Create Action** > **Build from scratch**

3. Configure the action:
   - **Name**: `Add Unix Username Claim`
   - **Trigger**: Select **Login / Post Login**
   - **Runtime**: Node 18 (recommended)

4. Replace the code with:

```javascript
/**
 * Add preferred_username claim for unix-oidc compatibility
 *
 * This action adds the preferred_username claim to both the ID token
 * and access token, which unix-oidc uses to map OIDC identity to
 * Unix usernames.
 */
exports.onExecutePostLogin = async (event, api) => {
  // Option 1: Use email prefix as username
  // Good for: Organizations where email prefix matches Unix username
  const emailUsername = event.user.email?.split('@')[0];

  // Option 2: Use a custom user_metadata field
  // Good for: When Unix usernames differ from email
  const customUsername = event.user.user_metadata?.unix_username;

  // Option 3: Use nickname (set during registration)
  const nickname = event.user.nickname;

  // Choose your preferred source (customize as needed)
  const username = customUsername || nickname || emailUsername;

  if (username) {
    // Add to ID token (used by unix-oidc)
    api.idToken.setCustomClaim('preferred_username', username);

    // Add to access token (useful for APIs)
    api.accessToken.setCustomClaim('preferred_username', username);
  }
};
```

5. Click **Deploy**

6. Navigate to **Actions** > **Flows** > **Login**

7. Drag your new action from the right panel into the flow, between **Start** and **Complete**

8. Click **Apply**

#### Option B: Auth0 Rules (Legacy)

If you're using the legacy Rules feature:

1. Navigate to **Auth Pipeline** > **Rules**

2. Click **+ Create Rule**

3. Select **Empty Rule**

4. Name it `Add Unix Username Claim`

5. Replace the code with:

```javascript
function addUnixUsernameClaim(user, context, callback) {
  // Use email prefix as username (customize as needed)
  const username = user.user_metadata?.unix_username ||
                   user.nickname ||
                   user.email?.split('@')[0];

  if (username) {
    context.idToken['preferred_username'] = username;
    context.accessToken['preferred_username'] = username;
  }

  callback(null, user, context);
}
```

6. Click **Save Changes**

> **Note**: Auth0 recommends migrating from Rules to Actions. Rules are considered legacy and may be deprecated in the future.

### Step 5: Add Users

Create users whose usernames match their Unix accounts:

1. Navigate to **User Management** > **Users**

2. Click **+ Create User**

3. Configure the user:
   - **Email**: `alice@example.com`
   - **Password**: Set a secure password
   - **Connection**: Username-Password-Authentication (default)

4. After creation, click on the user to edit

5. Scroll to **user_metadata** and click **Edit**

6. Add the Unix username mapping:

```json
{
  "unix_username": "alice"
}
```

7. Click **Save**

> **Important**: The `unix_username` value must exactly match the Unix username on your Linux server(s). This is case-sensitive.

#### Bulk User Import

For importing many users, use Auth0's bulk import:

1. Navigate to **User Management** > **Users**
2. Click **Import Users**
3. Use this JSON format:

```json
[
  {
    "email": "alice@example.com",
    "email_verified": true,
    "user_metadata": {
      "unix_username": "alice"
    },
    "password_hash": "$2b$10$..."
  },
  {
    "email": "bob@example.com",
    "email_verified": true,
    "user_metadata": {
      "unix_username": "bob"
    },
    "password_hash": "$2b$10$..."
  }
]
```

### Step 6: Get Configuration Values

Gather the values needed for unix-oidc configuration:

1. **Issuer URL**: `https://YOUR-TENANT.auth0.com/`
   - Find your tenant name in the top-left of the dashboard
   - Or check **Settings** > **General** > **Tenant Domain**

2. **Client ID**: Found in **Applications** > **Your App** > **Settings**

3. **Device Authorization Endpoint**: `https://YOUR-TENANT.auth0.com/oauth/device/code`

Configure unix-oidc:

```bash
# /etc/unix-oidc/config.yaml
oidc:
  issuer: "https://YOUR-TENANT.auth0.com/"
  client_id: "YOUR_CLIENT_ID"

# Or via environment variables
export OIDC_ISSUER="https://YOUR-TENANT.auth0.com/"
export OIDC_CLIENT_ID="YOUR_CLIENT_ID"
```

## Testing

### Test Device Flow

Verify the device authorization flow works:

```bash
# Request device code
curl -X POST "https://YOUR-TENANT.auth0.com/oauth/device/code" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "scope=openid profile email"
```

Expected response:

```json
{
  "device_code": "XXXX-XXXX",
  "user_code": "XXXX-XXXX",
  "verification_uri": "https://YOUR-TENANT.auth0.com/activate",
  "verification_uri_complete": "https://YOUR-TENANT.auth0.com/activate?user_code=XXXX-XXXX",
  "expires_in": 900,
  "interval": 5
}
```

### Complete Authentication

1. Open the `verification_uri_complete` URL in a browser
2. Log in with your test user credentials
3. Authorize the application

### Poll for Token

```bash
# Poll for token (repeat until success)
curl -X POST "https://YOUR-TENANT.auth0.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "device_code=DEVICE_CODE_FROM_ABOVE"
```

### Verify Token Contents

Decode the ID token to verify the `preferred_username` claim:

```bash
# Extract and decode the ID token (requires jq)
TOKEN_RESPONSE=$(curl -s -X POST "https://YOUR-TENANT.auth0.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "device_code=DEVICE_CODE")

# Decode the ID token payload
echo $TOKEN_RESPONSE | jq -r '.id_token' | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

Verify the output includes:

```json
{
  "preferred_username": "alice",
  "email": "alice@example.com",
  "sub": "auth0|...",
  ...
}
```

### Test OIDC Discovery

Verify Auth0's OIDC configuration is accessible:

```bash
curl -s "https://YOUR-TENANT.auth0.com/.well-known/openid-configuration" | jq .
```

### Test SSH Authentication

Once configured, test SSH login:

```bash
# From a client machine
ssh alice@your-server.example.com

# You should see a device flow prompt with Auth0's activation URL
```

## Troubleshooting

### "Grant type 'device_code' not allowed"

**Cause**: Device Authorization Grant is not enabled for your application.

**Solution**:
1. Go to **Applications** > **Your App** > **Settings**
2. Expand **Advanced Settings**
3. Click **Grant Types** tab
4. Enable **Device Code**
5. Save changes

### "Invalid client" error

**Cause**: Client ID is incorrect or application doesn't exist.

**Solution**:
1. Verify the Client ID in **Applications** > **Your App** > **Settings**
2. Ensure you're using the correct tenant domain
3. Check there are no extra spaces in your configuration

### "preferred_username" claim missing

**Cause**: The Auth0 Action or Rule isn't configured or deployed correctly.

**Solution**:
1. Verify the Action is deployed (green checkmark)
2. Check it's added to the Login flow
3. Test the Action using Auth0's built-in testing
4. Check the Action logs for errors: **Monitoring** > **Logs**

### "User not found" in unix-oidc

**Cause**: The `preferred_username` doesn't match a local Unix user.

**Solution**:
1. Verify the user exists on the Linux server: `id alice`
2. Check the `unix_username` in Auth0 user_metadata matches exactly
3. Verify case sensitivity (Unix usernames are case-sensitive)
4. Check SSSD is properly configured if using directory integration

### Device code expired

**Cause**: The user didn't complete authentication within the timeout (default 900 seconds).

**Solution**:
1. Start a new device flow
2. Complete authentication promptly
3. Consider extending the timeout in Auth0 settings if needed

### Rate limiting errors

**Cause**: Too many requests to Auth0 endpoints.

**Solution**:
1. Auth0 has rate limits on all endpoints
2. Implement exponential backoff in polling
3. Check **Monitoring** > **Logs** for rate limit events
4. Consider upgrading your Auth0 plan for higher limits

### Token validation fails

**Cause**: Token signature verification failed or token is expired.

**Solution**:
1. Verify the issuer URL matches exactly (including trailing slash)
2. Check server time is synchronized (NTP)
3. Verify JWKS endpoint is accessible from your server:
   ```bash
   curl -s "https://YOUR-TENANT.auth0.com/.well-known/jwks.json" | jq .
   ```

## Auth0-Specific Considerations

### Multi-Factor Authentication

Auth0 supports MFA which integrates well with unix-oidc's step-up authentication:

1. Navigate to **Security** > **Multi-factor Auth**
2. Enable your preferred factors (Push, OTP, WebAuthn)
3. Configure **Policies** to require MFA for all users or specific conditions

### Custom Domains

If using a custom domain with Auth0:

1. Your issuer URL will be `https://auth.yourdomain.com/`
2. Update unix-oidc configuration accordingly
3. All endpoints use the custom domain

### Enterprise Connections

Auth0 can federate to enterprise IdPs:

1. Navigate to **Authentication** > **Enterprise**
2. Add connections for SAML, Azure AD, Google Workspace, etc.
3. Users from these connections can authenticate to unix-oidc

### Tenant Regions

Auth0 has region-specific endpoints:

| Region | Domain Format |
|--------|---------------|
| US | `your-tenant.us.auth0.com` |
| EU | `your-tenant.eu.auth0.com` |
| AU | `your-tenant.au.auth0.com` |
| JP | `your-tenant.jp.auth0.com` |

Use the correct regional domain in your configuration.

## Additional Resources

- [Auth0 Device Authorization Flow Documentation](https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow)
- [Auth0 Actions Documentation](https://auth0.com/docs/customize/actions)
- [Auth0 Token Customization](https://auth0.com/docs/secure/tokens/json-web-tokens/create-custom-claims)
- [unix-oidc Documentation](../../../docs/)
