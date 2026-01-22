# Azure AD (Microsoft Entra ID) Setup for unix-oidc

**Difficulty:** Medium
**Time to complete:** 10-15 minutes
**Last verified:** January 2026

This guide walks you through configuring Azure AD (now Microsoft Entra ID) as an identity provider for unix-oidc. Azure AD provides enterprise-grade identity management with built-in MFA, conditional access, and seamless integration with Microsoft 365.

---

## Prerequisites

Before starting, ensure you have:

| Requirement | Details | How to Verify |
|-------------|---------|---------------|
| **Azure AD Tenant** | Any Azure AD tenant (free or premium) | [Azure Portal](https://portal.azure.com) access |
| **Admin Access** | Application Administrator or Global Administrator role | Can create App Registrations |
| **User Accounts** | Users with UPNs that can map to Unix usernames | `user@yourdomain.com` format |

### Important Azure AD Concepts

- **Tenant ID**: Your Azure AD directory identifier (a GUID)
- **Application (Client) ID**: The identifier for the app registration
- **UPN (User Principal Name)**: The user's sign-in name (e.g., `alice@contoso.com`)

---

## Quick Setup Overview

1. Register an application in Azure AD
2. Enable Device Code Flow (public client)
3. Configure API permissions (openid, profile, email)
4. Configure token claims for username mapping
5. Test the configuration

---

## Manual Setup Steps

### Step 1: Register Application

1. Navigate to the [Azure Portal](https://portal.azure.com)

2. Go to **Azure Active Directory** (or **Microsoft Entra ID**)
   - In the left sidebar, click "Azure Active Directory"
   - Or search for "Entra" in the top search bar

3. Select **App registrations** from the left menu

4. Click **+ New registration**

5. Configure the application:

   | Field | Value |
   |-------|-------|
   | **Name** | `unix-oidc` |
   | **Supported account types** | "Accounts in this organizational directory only" |
   | **Redirect URI** | Leave empty (we'll use device code flow) |

6. Click **Register**

7. **Note these values** from the Overview page:

   | Value | Where to Find | Example |
   |-------|---------------|---------|
   | **Application (client) ID** | Overview page | `12345678-abcd-1234-efgh-123456789abc` |
   | **Directory (tenant) ID** | Overview page | `87654321-dcba-4321-hgfe-987654321cba` |

---

### Step 2: Configure Authentication (Enable Device Code Flow)

1. In your app registration, select **Authentication** from the left menu

2. Scroll down to **Advanced settings**

3. Set **Allow public client flows** to **Yes**

   > **Why?** Device Code Flow requires the application to be configured as a public client. This is because the flow is used on devices that cannot securely store a client secret.

4. Click **Save**

5. **Optional: Add a platform for testing**
   - Click **+ Add a platform**
   - Select **Mobile and desktop applications**
   - Check the box for `https://login.microsoftonline.com/common/oauth2/nativeclient`
   - Click **Configure**

---

### Step 3: Configure API Permissions

1. Select **API permissions** from the left menu

2. Verify the default permissions include:
   - `Microsoft Graph` > `User.Read` (usually added by default)

3. Click **+ Add a permission**

4. Select **Microsoft Graph** > **Delegated permissions**

5. Add these permissions:

   | Permission | Category | Purpose |
   |------------|----------|---------|
   | `openid` | OpenId permissions | Required for OIDC authentication |
   | `profile` | OpenId permissions | Access to user profile claims |
   | `email` | OpenId permissions | Access to user email address |

6. Click **Add permissions**

7. **Optional but recommended:** Click **Grant admin consent for [Your Organization]**
   - This pre-approves the permissions for all users
   - Without this, users will be prompted to consent on first login

Your permissions should look like:

| API | Permission | Type | Status |
|-----|------------|------|--------|
| Microsoft Graph | email | Delegated | Granted |
| Microsoft Graph | openid | Delegated | Granted |
| Microsoft Graph | profile | Delegated | Granted |
| Microsoft Graph | User.Read | Delegated | Granted |

---

### Step 4: Configure Token Claims

By default, Azure AD includes `preferred_username` in ID tokens, which contains the user's UPN (e.g., `alice@contoso.com`). For unix-oidc, you may need to configure claims to match your Unix usernames.

#### Option A: Use UPN Prefix (Recommended for Most Cases)

If your Unix usernames match the prefix of the UPN (e.g., UPN `alice@contoso.com` maps to Unix user `alice`):

1. Go to **Token configuration** in the left menu

2. Click **+ Add optional claim**

3. Select **ID** token type

4. Check the following claims:
   - `preferred_username` (should already be included)
   - `upn` (User Principal Name)

5. Click **Add**

6. Configure unix-oidc to extract the username prefix:
   ```bash
   # In /etc/unix-oidc/config.env
   OIDC_USERNAME_CLAIM=preferred_username
   OIDC_USERNAME_TRANSFORM=prefix  # Strips @domain.com
   ```

#### Option B: Use Custom Claim with On-Premises sAMAccountName

If you have Azure AD Connect syncing from on-premises AD and want to use sAMAccountName:

1. Go to **Token configuration**

2. Click **+ Add optional claim**

3. Select **ID** token type

4. Check: `onprem_sid` (if available) or configure a custom claim

5. For sAMAccountName, you may need to use a custom claims policy or directory extension

#### Option C: Configure Username Mapping in unix-oidc

If your UPNs don't directly map to Unix usernames:

```bash
# In /etc/unix-oidc/config.env
OIDC_USERNAME_CLAIM=preferred_username
OIDC_USERNAME_MAPPING=/etc/unix-oidc/username-map.json
```

Create `/etc/unix-oidc/username-map.json`:
```json
{
  "alice@contoso.com": "alice",
  "bob.smith@contoso.com": "bsmith",
  "charlie@contoso.com": "cjones"
}
```

---

### Step 5: Add Users

Ensure the users who will authenticate via unix-oidc:

1. **Exist in Azure AD** with appropriate licenses

2. **Have UPNs that can map to Unix usernames**

3. **Are not blocked from sign-in**

To verify a user:

1. Go to **Azure Active Directory** > **Users**

2. Search for and select a user

3. Verify:
   - **User principal name**: e.g., `alice@contoso.com`
   - **Account enabled**: Yes
   - **Block sign in**: No

#### Verify Unix Username Mapping

```bash
# On your Linux server, verify the user exists
getent passwd alice

# Expected output:
# alice:x:1001:1001:Alice Smith:/home/alice:/bin/bash
```

---

### Step 6: Get Configuration Values

Collect these values for unix-oidc configuration:

| Setting | How to Find | Your Value |
|---------|-------------|------------|
| **Issuer URL** | `https://login.microsoftonline.com/{tenant-id}/v2.0` | _____________ |
| **Client ID** | App Registration > Overview > Application (client) ID | _____________ |
| **Tenant ID** | App Registration > Overview > Directory (tenant) ID | _____________ |

#### Construct the Issuer URL

```bash
# Format:
https://login.microsoftonline.com/{tenant-id}/v2.0

# Example:
https://login.microsoftonline.com/87654321-dcba-4321-hgfe-987654321cba/v2.0
```

#### Verify the OIDC Discovery Endpoint

```bash
# Replace {tenant-id} with your actual tenant ID
TENANT_ID="your-tenant-id"

curl -s "https://login.microsoftonline.com/${TENANT_ID}/v2.0/.well-known/openid-configuration" | jq '{
  issuer,
  device_authorization_endpoint,
  token_endpoint,
  jwks_uri
}'
```

**Expected output:**
```json
{
  "issuer": "https://login.microsoftonline.com/{tenant-id}/v2.0",
  "device_authorization_endpoint": "https://login.microsoftonline.com/{tenant-id}/v2.0/devicecode",
  "token_endpoint": "https://login.microsoftonline.com/{tenant-id}/v2.0/token",
  "jwks_uri": "https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys"
}
```

---

## Configure unix-oidc

Create or update `/etc/unix-oidc/config.env`:

```bash
# Azure AD Configuration
OIDC_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
OIDC_CLIENT_ID={client-id}

# Username claim (Azure AD uses preferred_username by default)
OIDC_USERNAME_CLAIM=preferred_username

# Optional: Strip domain from UPN (alice@contoso.com -> alice)
# OIDC_USERNAME_TRANSFORM=prefix

# Optional: Require specific tenant
# OIDC_ALLOWED_TENANTS={tenant-id}
```

---

## Testing

### Test 1: Verify OIDC Discovery

```bash
ISSUER="https://login.microsoftonline.com/{tenant-id}/v2.0"

curl -s "${ISSUER}/.well-known/openid-configuration" | jq '.issuer'
```

**Expected:** Your issuer URL

### Test 2: Start Device Code Flow

```bash
TENANT_ID="your-tenant-id"
CLIENT_ID="your-client-id"

# Request device code
curl -s -X POST "https://login.microsoftonline.com/${TENANT_ID}/v2.0/devicecode" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}" \
  -d "scope=openid profile email" | jq
```

**Expected output:**
```json
{
  "user_code": "ABCD1234",
  "device_code": "...",
  "verification_uri": "https://microsoft.com/devicelogin",
  "expires_in": 900,
  "interval": 5,
  "message": "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code ABCD1234 to authenticate."
}
```

### Test 3: Complete Authentication

1. Open https://microsoft.com/devicelogin in a browser

2. Enter the `user_code` shown above

3. Sign in with your Azure AD credentials

4. Poll for the token:

```bash
# Use the device_code from the previous response
DEVICE_CODE="your-device-code"

curl -s -X POST "https://login.microsoftonline.com/${TENANT_ID}/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=${CLIENT_ID}" \
  -d "device_code=${DEVICE_CODE}" | jq
```

**Expected output (after successful authentication):**
```json
{
  "token_type": "Bearer",
  "scope": "openid profile email",
  "expires_in": 3600,
  "access_token": "eyJ...",
  "id_token": "eyJ...",
  "refresh_token": "0.AT..."
}
```

### Test 4: Verify Token Claims

```bash
# Decode the ID token (middle part between dots)
ID_TOKEN="your-id-token"

echo "$ID_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{
  iss,
  sub,
  preferred_username,
  name,
  email
}'
```

**Expected output:**
```json
{
  "iss": "https://login.microsoftonline.com/{tenant-id}/v2.0",
  "sub": "abc123...",
  "preferred_username": "alice@contoso.com",
  "name": "Alice Smith",
  "email": "alice@contoso.com"
}
```

### Test 5: Test PAM Authentication

```bash
# Store the access token
export OIDC_TOKEN="your-access-token"

# Test with pamtester
sudo pamtester sshd alice authenticate <<< "$OIDC_TOKEN"
```

---

## Troubleshooting

### "AADSTS700016: Application not found"

**Cause:** The client ID is incorrect or the app registration was deleted.

**Solution:**
1. Verify the Application (client) ID in Azure Portal
2. Ensure you're using the correct tenant ID in the issuer URL
3. Check that the app registration still exists

### "AADSTS7000218: Public client flow is not allowed"

**Cause:** Device Code Flow is not enabled for the application.

**Solution:**
1. Go to App Registration > Authentication
2. Under "Advanced settings", set "Allow public client flows" to **Yes**
3. Click Save

### "AADSTS50034: User account does not exist"

**Cause:** The user doesn't exist in your Azure AD tenant.

**Solution:**
1. Verify the user exists in Azure AD > Users
2. Check that the user's account is enabled
3. Ensure "Block sign in" is set to No

### "AADSTS65001: User has not consented"

**Cause:** The user hasn't consented to the requested permissions.

**Solution:**
1. Have an admin grant consent for the organization:
   - App Registration > API permissions > Grant admin consent
2. Or have the user complete the device code flow once to consent

### "Token validation failed: issuer mismatch"

**Cause:** The issuer in the token doesn't match the configured issuer.

**Solution:**
1. Verify you're using the v2.0 endpoint:
   ```
   https://login.microsoftonline.com/{tenant-id}/v2.0
   ```
2. Not the v1.0 endpoint (which has a different issuer format)
3. Check the token's `iss` claim matches exactly

### "preferred_username contains full UPN"

**Cause:** Azure AD returns the full UPN (e.g., `alice@contoso.com`) but your Unix user is just `alice`.

**Solution:**
Configure username transformation in unix-oidc:
```bash
# In /etc/unix-oidc/config.env
OIDC_USERNAME_TRANSFORM=prefix
```

Or use a username mapping file as described in Step 4.

### Device Code expires before user completes authentication

**Cause:** Default expiration is 15 minutes; user took too long.

**Solution:**
1. Request a new device code
2. Have users authenticate more quickly
3. Consider using Conditional Access policies to streamline the sign-in experience

### MFA not being triggered

**Cause:** Conditional Access policies may not be configured for device code flow.

**Solution:**
1. Review Conditional Access policies in Azure AD
2. Ensure policies apply to "All cloud apps" or specifically include your app
3. Verify policies don't exclude device code flow grant type

---

## Security Considerations

### Conditional Access

Azure AD Conditional Access can enforce additional security requirements:

1. Go to **Azure AD** > **Security** > **Conditional Access**

2. Create a policy for the unix-oidc app:
   - **Users**: All users (or specific groups)
   - **Cloud apps**: Select your unix-oidc app
   - **Conditions**: Configure as needed (location, device state, etc.)
   - **Grant**: Require MFA, compliant device, etc.

### Token Lifetime

Configure token lifetime policies to balance security and usability:

1. Use short-lived access tokens (default: 1 hour)
2. Configure refresh token policies based on your security requirements

### Audit Logging

Azure AD logs all authentication events:

1. Go to **Azure AD** > **Sign-in logs**
2. Filter by Application: `unix-oidc`
3. Export logs to SIEM for correlation with unix-oidc audit logs

---

## Next Steps

- [15-Minute Production Setup](../../quickstart/15-minute-production.md) - Complete the server-side installation
- [Security Guide](../../../docs/security-guide.md) - Configure DPoP and other security features
- [Sudo Step-Up](../../../docs/sudo-step-up.md) - Enable MFA step-up for sudo commands

---

## Reference Links

- [Azure AD Device Code Flow Documentation](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)
- [Microsoft Identity Platform Token Claims](https://learn.microsoft.com/en-us/azure/active-directory/develop/id-tokens)
- [Azure AD App Registration](https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- [Conditional Access Policies](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview)

---

*This guide is part of the [unix-oidc deployment documentation](../../README.md).*
