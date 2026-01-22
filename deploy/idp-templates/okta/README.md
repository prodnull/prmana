# Okta Configuration for unix-oidc

This guide walks you through configuring Okta as your Identity Provider (IdP) for unix-oidc.

## Prerequisites

- Okta account with admin access
- unix-oidc installed on your target server(s)
- Unix users created that match Okta usernames

## Quick Setup Overview

1. Create a Native Application in Okta
2. Enable Device Authorization Grant
3. Configure required scopes (openid, profile, email)
4. Map the `preferred_username` claim
5. Assign users (usernames must match Unix usernames)
6. Get configuration values for unix-oidc

**Estimated time: 15-20 minutes**

---

## Manual Setup Steps

### Step 1: Create Application

1. Log in to your Okta Admin Console
2. Navigate to **Applications** > **Applications**
3. Click **Create App Integration**

![Create App Integration](screenshots/create-app-integration.png)

4. Select **OIDC - OpenID Connect** as the Sign-in method
5. Select **Native Application** as the Application type (required for Device Flow)
6. Click **Next**

![Select Native Application](screenshots/select-native-application.png)

7. Configure the application:
   - **App integration name**: `unix-oidc` (or your preferred name)
   - **Grant type**:
     - Check **Device Authorization** (this is critical)
     - Check **Refresh Token** (recommended)
   - **Controlled access**: Select who can access (e.g., "Allow everyone in your organization")

![Configure Application](screenshots/configure-application.png)

8. Click **Save**

### Step 2: Enable Device Authorization Grant

If you didn't enable Device Authorization during creation, or need to verify:

1. Go to **Applications** > **Applications**
2. Click on your `unix-oidc` application
3. Go to the **General** tab
4. Scroll to **General Settings** and click **Edit**
5. Under **Grant type**, ensure **Device Authorization** is checked
6. Click **Save**

![Enable Device Authorization](screenshots/enable-device-authorization.png)

> **Note**: Device Authorization Grant is supported on Okta's Org Authorization Server and custom Authorization Servers. If using the Org Authorization Server, the issuer URL is `https://your-org.okta.com`. For custom servers, it's `https://your-org.okta.com/oauth2/{authServerId}` or `https://your-org.okta.com/oauth2/default`.

### Step 3: Configure Scopes

The default scopes should already be available, but verify:

1. In your application settings, go to the **Sign On** tab (or **Okta API Scopes** for API access)
2. Ensure these scopes are enabled:
   - `openid` - Required for OIDC
   - `profile` - Access to user profile information
   - `email` - Access to user email

For custom Authorization Servers:
1. Navigate to **Security** > **API** > **Authorization Servers**
2. Select your Authorization Server (e.g., "default")
3. Go to **Scopes** tab
4. Verify `openid`, `profile`, and `email` scopes exist

![Configure Scopes](screenshots/configure-scopes.png)

### Step 4: Map preferred_username Claim

unix-oidc uses the `preferred_username` claim to match OIDC identities to Unix usernames.

#### For Custom Authorization Servers (Recommended):

1. Navigate to **Security** > **API** > **Authorization Servers**
2. Select your Authorization Server
3. Go to the **Claims** tab
4. Click **Add Claim**
5. Configure:
   - **Name**: `preferred_username`
   - **Include in token type**: ID Token (Always)
   - **Value type**: Expression
   - **Value**: `user.login` or `user.email` (depending on your Unix username convention)
   - **Include in**: Any scope (or limit to `profile`)
6. Click **Create**

![Add Claim](screenshots/add-claim.png)

#### For Org Authorization Server:

The Org Authorization Server includes `preferred_username` by default using the user's login. If you need to customize it, you'll need to use a custom Authorization Server.

### Step 5: Add Users

Users must exist in both Okta and on your Unix systems with matching usernames.

1. Navigate to **Directory** > **People**
2. For each user that needs unix-oidc access:
   - Verify their **Username** matches their Unix username
   - OR ensure the mapped claim value matches their Unix username

![Verify Username](screenshots/verify-username.png)

3. Assign users to the application:
   - Go to **Applications** > **unix-oidc**
   - Go to the **Assignments** tab
   - Click **Assign** > **Assign to People** (or **Assign to Groups**)
   - Select the users/groups that should have access
   - Click **Assign** for each, then **Done**

![Assign Users](screenshots/assign-users.png)

> **Important**: The `preferred_username` claim value MUST exactly match the Unix username. For example, if the Unix user is `jsmith`, the Okta username (or mapped claim) must also be `jsmith`.

### Step 6: Get Configuration Values

Gather these values for unix-oidc configuration:

1. **Client ID**:
   - Go to **Applications** > **unix-oidc** > **General** tab
   - Copy the **Client ID** from the Client Credentials section

2. **Issuer URL**:
   - For Org Authorization Server: `https://your-org.okta.com`
   - For custom Authorization Server: `https://your-org.okta.com/oauth2/default` or `https://your-org.okta.com/oauth2/{authServerId}`

3. **Device Authorization Endpoint** (for reference):
   - `https://your-org.okta.com/oauth2/v1/device/authorize` (Org AS)
   - `https://your-org.okta.com/oauth2/default/v1/device/authorize` (default custom AS)

![Get Client ID](screenshots/get-client-id.png)

Configure unix-oidc with these values:

```bash
export OIDC_ISSUER="https://your-org.okta.com/oauth2/default"
export OIDC_CLIENT_ID="0oaxxxxxxxxxxxxxxxxx"
```

Or in `/etc/unix-oidc/config.yaml`:

```yaml
oidc:
  issuer: "https://your-org.okta.com/oauth2/default"
  client_id: "0oaxxxxxxxxxxxxxxxxx"
```

---

## Testing

### Test Device Authorization Flow

1. **Initiate Device Flow**:

```bash
# Using the default Authorization Server
curl -X POST "https://your-org.okta.com/oauth2/default/v1/device/authorize" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "scope=openid profile email"
```

Expected response:

```json
{
  "device_code": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://your-org.okta.com/activate",
  "verification_uri_complete": "https://your-org.okta.com/activate?user_code=ABCD-EFGH",
  "expires_in": 600,
  "interval": 5
}
```

2. **Authenticate**:
   - Open the `verification_uri_complete` URL in a browser
   - Sign in with your Okta credentials
   - Approve the device authorization request

3. **Poll for Token**:

```bash
curl -X POST "https://your-org.okta.com/oauth2/default/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=DEVICE_CODE_FROM_STEP_1"
```

While waiting for user authentication, you'll get:

```json
{
  "error": "authorization_pending",
  "error_description": "The authorization request is still pending."
}
```

After successful authentication:

```json
{
  "access_token": "eyJraWQi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email",
  "id_token": "eyJraWQi..."
}
```

4. **Verify ID Token Claims**:

```bash
# Decode the ID token (middle part between the dots)
echo "ID_TOKEN_HERE" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Verify the output includes:
- `preferred_username` matching your Unix username
- `sub` (subject identifier)
- `iss` matching your issuer URL

### Test OIDC Discovery

```bash
curl -s "https://your-org.okta.com/oauth2/default/.well-known/openid-configuration" | jq .
```

Verify the response includes:
- `device_authorization_endpoint`
- `token_endpoint`
- `jwks_uri`

---

## Troubleshooting

### Error: "The client is not authorized for device authorization flow"

**Cause**: Device Authorization grant type is not enabled for the application.

**Solution**:
1. Go to **Applications** > your app > **General** > **Edit**
2. Enable **Device Authorization** under Grant type
3. Click **Save**

### Error: "User not assigned to this application"

**Cause**: The user trying to authenticate isn't assigned to the application.

**Solution**:
1. Go to **Applications** > your app > **Assignments**
2. Assign the user directly or via a group

### Error: "Invalid scope requested"

**Cause**: The requested scope isn't configured on the Authorization Server.

**Solution**:
1. Go to **Security** > **API** > **Authorization Servers**
2. Select your Authorization Server > **Scopes**
3. Ensure `openid`, `profile`, and `email` scopes exist

### Username mismatch / User not found

**Cause**: The `preferred_username` claim doesn't match the Unix username.

**Solution**:
1. Check what value is being returned in the `preferred_username` claim:
   ```bash
   # Decode the ID token
   echo "ID_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .preferred_username
   ```
2. Either:
   - Update the Unix username to match Okta, OR
   - Update the Okta claim mapping to return the Unix username

### "access_denied" during device activation

**Cause**: User doesn't have permission or consent was denied.

**Solution**:
1. Verify the user is assigned to the application
2. Check if any access policies are blocking the user
3. Navigate to **Security** > **Authentication Policies** to review rules

### Org Authorization Server vs Custom Authorization Server

| Feature | Org AS | Custom AS |
|---------|--------|-----------|
| URL | `https://your-org.okta.com` | `https://your-org.okta.com/oauth2/{id}` |
| Custom claims | No | Yes |
| Custom scopes | No | Yes |
| Access policies | Limited | Full control |
| Okta plan | All | API Access Management add-on |

If you need custom claims or scopes, you must use a custom Authorization Server (requires Okta API Access Management add-on).

### Token expiration issues

**Cause**: Short-lived tokens may expire before authentication completes.

**Solution**:
1. Go to **Security** > **API** > **Authorization Servers**
2. Select your Authorization Server > **Access Policies**
3. Edit the relevant rule and adjust token lifetimes:
   - Access Token Lifetime: 1 hour (recommended minimum)
   - Refresh Token Lifetime: Configure based on security requirements

### Testing tips

1. **Use Okta's Token Preview**:
   - Go to **Security** > **API** > **Authorization Servers**
   - Select your Authorization Server > **Token Preview**
   - Test token generation and inspect claims

2. **Check System Log for errors**:
   - Navigate to **Reports** > **System Log**
   - Filter by recent authentication events
   - Look for failed authentication attempts and their error codes

3. **Verify OIDC Discovery**:
   ```bash
   # Check the discovery document
   curl -s "https://your-org.okta.com/oauth2/default/.well-known/openid-configuration" | jq .
   ```

---

## Additional Resources

- [Okta Device Authorization Grant Documentation](https://developer.okta.com/docs/guides/device-authorization-grant/main/)
- [Okta Custom Claims](https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/main/)
- [Okta Authorization Servers](https://developer.okta.com/docs/concepts/auth-servers/)
- [unix-oidc Documentation](../../../docs/)
