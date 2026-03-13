# Entra ID App Registration Setup Guide

This guide walks through the complete setup of an Azure Entra ID (formerly Azure AD) application
registration for use with unix-oidc. Follow each step in order before running integration tests
or deploying to production.

**Why Entra requires additional setup:** Entra access tokens use RS256 (RSA signatures), tenant-specific
issuer URLs, UPN-based username claims, and do not implement RFC 9449 DPoP. The unix-oidc configuration
for Entra differs from Keycloak in several important ways documented in this guide.

---

## Prerequisites

- An Azure subscription with an active Entra ID tenant
- **Global Administrator** or **Application Administrator** role in the tenant
- The Azure CLI (`az`) or access to the Azure Portal (https://portal.azure.com)
- Basic familiarity with OAuth 2.0 / OIDC concepts

## Information to Collect

After completing setup, you will have:

| Item | Where to find it |
|------|-----------------|
| Tenant ID | Azure Portal → Entra ID → Overview → Tenant ID |
| Client ID | Azure Portal → App registrations → your app → Overview → Application (client) ID |
| Test user UPN | Azure Portal → Entra ID → Users → your test user → User principal name |

---

## Step 1: Register the Application

1. Open the [Azure Portal](https://portal.azure.com) and navigate to **Entra ID → App registrations**.
2. Click **New registration**.
3. Fill in the registration form:
   - **Name:** `unix-oidc-integration` (or a site-specific name)
   - **Supported account types:** Select **"Accounts in this organizational directory only
     (Single tenant)"** — this is the critical setting that makes the single-tenant security
     model work. Multi-tenant would allow tokens from any Entra tenant, bypassing your
     domain constraint. [Checklist item 2]
   - **Redirect URI:** Leave blank for now — we add it in Step 3.
4. Click **Register**.
5. On the app's **Overview** page, copy the **Application (client) ID** and **Directory (tenant) ID**.
   Store these; you will need them for the unix-oidc policy configuration and CI secrets.

---

## Step 2: Enable Public Client Flows

Unix-oidc uses the Resource Owner Password Credentials (ROPC) grant in CI and the Device Code flow
in production. Both require the app to be a **public client** (no client secret required for token
exchange).

1. In your registered app, navigate to **Authentication**.
2. Under **Advanced settings**, find **"Allow public client flows"** and set it to **Yes**. [Checklist item 4]
3. Click **Save**.

**Security note:** Public client means the client secret is not required to exchange credentials for
tokens. This is appropriate for PAM authentication where the secret cannot be stored securely on
every server. The security boundary is the token itself (validated via JWKS signature verification).

---

## Step 3: Add Redirect URI for Device Code Flow

The device code flow requires a redirect URI even though the browser navigation does not complete
to that URI. A standard localhost URI is used.

1. Still in **Authentication**, click **Add a platform**.
2. Select **Mobile and desktop applications**.
3. Under **Custom redirect URIs**, enter: `http://localhost` [Checklist item 3]
4. Click **Configure**, then **Save**.

**Note for CI (ROPC):** ROPC token acquisition does not use the redirect URI. The URI is required
only for device code and authorization code flows. The CI bootstrap uses ROPC to avoid browser
automation against Entra login pages.

---

## Step 4: Configure API Permissions

Add the OIDC scopes required for unix-oidc to validate tokens and extract username claims.

1. Navigate to **API permissions** in your app.
2. Click **Add a permission → Microsoft Graph → Delegated permissions**.
3. Add the following scopes:
   - `openid` — required for OIDC token issuance
   - `profile` — provides `preferred_username` and `name` claims
   - `email` — provides the `email` claim used for username extraction
4. If your organization uses `User.Read` for other purposes, you may add it as an API permission
   here. **However, do NOT include `User.Read` in ROPC or device code token request scope strings
   used for PAM validation.** See the critical note below. [Checklist item 5]
5. Click **Grant admin consent for [Your Tenant]** and confirm. Admin consent is required because
   delegated permissions need tenant-wide approval before tokens can be issued.

### CRITICAL: User.Read and Audience

Including `User.Read` in a token request changes the token's audience (`aud` claim) to
`https://graph.microsoft.com` instead of your client ID. A token with Graph audience will fail
PAM audience validation. The scope string for PAM tokens must be:

```
openid profile email
```

Not:

```
openid profile email User.Read   ← WRONG for PAM tokens
```

`User.Read` may be configured as an API permission in the portal (for other token use cases) but
must be excluded from the scope parameter of any token request intended for PAM validation.
See [22-RESEARCH.md Pitfall 3] for the full analysis.

---

## Step 5: Verify Optional Claims

Entra ID does not always include `preferred_username` in access tokens by default. Verify or
configure it. [Checklist item 6]

1. Navigate to **Token configuration**.
2. Click **Add optional claim → Access token**.
3. Check that `preferred_username` is listed. If it is not, add it:
   - Select `Access` token type
   - Check `preferred_username`
   - Click **Add**
4. Verify that `email` is also included (it should be present when the `email` scope is requested,
   but check here if you encounter missing claim errors).

**Username claim mapping in policy.yaml:**

The default unix-oidc Entra fixture uses `username_claim: email` with `strip_domain` + `lowercase`
transforms. For example:

```
email claim: Alice@Corp.onmicrosoft.com
→ strip_domain: Alice
→ lowercase: alice
→ Unix username: alice
```

If you prefer `preferred_username`, replace `username_claim: email` with
`username_claim: preferred_username` in `policy.yaml`. The same transforms apply.

---

## Step 6: Create a CI Test User

ROPC requires a real Entra user with username + password. Create a dedicated test user.

1. Navigate to **Entra ID → Users → New user → Create new user**.
2. Fill in the form:
   - **User principal name:** `unix-oidc-ci@yourtenant.onmicrosoft.com` (or similar)
   - **Display name:** `unix-oidc CI Test User`
   - **Password:** Generate or set a strong password — store it in your CI secrets vault immediately
3. Click **Create**.

### MFA and Conditional Access

ROPC fails silently when MFA is required for a user. Before relying on this test user in CI, ensure
it is excluded from MFA requirements.

**Option A — Named Location exclusion (preferred for CI users):**
1. Navigate to **Protection → Conditional Access → Named locations**.
2. Create a named location for your CI runner IP range (or "trusted IPs").
3. Edit any MFA Conditional Access policy and add the CI named location to the **Exclude** list.

**Option B — Policy exclusion by user or group:**
1. Navigate to **Protection → Conditional Access**.
2. Edit the MFA policy and under **Assignments → Users**, add the test user (or a "CI users" group)
   to the **Exclude** list.

**Verify before relying on CI:** Manually test ROPC with the test user credentials (Step 8 below)
to confirm MFA is not blocking token acquisition before encoding credentials in CI secrets.

---

## Step 7: Configure GitHub Actions Secrets

Add these repository secrets in **Settings → Secrets and variables → Actions**:

| Secret | Value |
|--------|-------|
| `ENTRA_TENANT_ID` | Directory (tenant) ID from Entra ID Overview |
| `ENTRA_CLIENT_ID` | Application (client) ID from App registrations |
| `ENTRA_TEST_USER` | Full UPN of CI test user (e.g. `unix-oidc-ci@tenant.onmicrosoft.com`) |
| `ENTRA_TEST_PASSWORD` | CI test user password |

These secrets are used by the CI workflow to acquire tokens for integration tests. Rotate the
test user password periodically and update the secret. Never use a production user account for CI.

---

## Step 8: Verify Token Acquisition (ROPC Test)

Test the token acquisition flow from your local machine before running CI. This confirms the app
registration is correct and the test user has no MFA blocks.

```bash
# Substitute your actual values
TENANT_ID="your-tenant-id"
CLIENT_ID="your-client-id"
USERNAME="unix-oidc-ci@yourtenant.onmicrosoft.com"
PASSWORD="your-test-password"

curl -s -X POST \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}" \
  -d "scope=openid profile email" \
  | jq .
```

A successful response contains `access_token`, `id_token`, and `token_type: "Bearer"`. An error
response will include `error` and `error_description` fields — see Troubleshooting below.

---

## Step 9: Verify Token Claims

Decode the access token and verify the claims look correct before writing assertions.

```bash
# Decode the access token payload (no verification — decode only)
ACCESS_TOKEN="eyJ..."   # paste access_token from Step 8

echo "${ACCESS_TOKEN}" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Expected claims for unix-oidc:

| Claim | Expected value | Notes |
|-------|---------------|-------|
| `iss` | `https://login.microsoftonline.com/{tenant-id}/v2.0` | Must match `issuer_url` in policy.yaml |
| `aud` | Your client ID GUID | If `api://` URI is set, see expected_audience note below |
| `preferred_username` | UPN of test user | e.g. `alice@tenant.onmicrosoft.com` |
| `email` | Email of test user | May require Step 5 optional claim config |
| `sub` | Stable subject identifier | Opaque GUID |
| `uti` | Unique token identifier | Entra uses `uti`, not standard `jti` |

**If aud is an api:// URI:** If you configured an Application ID URI (e.g. `api://unix-oidc`) in
**Expose an API**, the `aud` claim will be `api://unix-oidc` instead of the GUID client ID.
Uncomment and set `expected_audience: "api://unix-oidc"` in `policy-entra.yaml` to match.

---

## Configuring unix-oidc Policy

Use `test/fixtures/policy/policy-entra.yaml` as a reference. For production, substitute the
placeholder values:

```yaml
security_modes:
  jti_enforcement: warn  # Entra uses uti not jti (see Pitfall 5 / Research)

issuers:
  - issuer_url: "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0"
    client_id: "YOUR_CLIENT_ID"
    dpop_enforcement: disabled  # Entra uses SHR not RFC 9449 DPoP
    allow_unsafe_identity_pipeline: true  # strip_domain is safe for single-tenant Entra
    # expected_audience: "api://unix-oidc"  # uncomment if Application ID URI is set
    claim_mapping:
      username_claim: email
      transforms:
        - strip_domain
        - lowercase
    acr_mapping:
      enforcement: warn
    group_mapping:
      source: nss_only
```

---

## Known Limitations

### uti vs jti

Entra ID emits a `uti` claim (unique token identifier — proprietary) rather than the standard `jti`
claim from RFC 7519. The unix-oidc replay prevention cache checks `jti`; because `uti` is not
recognized as `jti`, replay prevention falls back to warn mode. Set `jti_enforcement: warn` in
`security_modes` (as shown in the fixture). Strict replay protection for Entra tokens requires
a future enhancement to map `uti` to the JTI cache.

### ROPC Deprecation

ROPC (Resource Owner Password Credentials) is deprecated in OAuth 2.1 (draft) and Microsoft
recommends against it for new applications. It is used in unix-oidc CI only because it avoids
browser automation against Entra login pages. The risk is bounded: ROPC is used only with a
dedicated CI test user account, not with production accounts. If your organization's Conditional
Access policies block ROPC entirely, consider the device code flow as an alternative (requires
storing a refresh token in CI secrets instead of a password).

### SHR vs RFC 9449 DPoP

Entra ID implements Signed HTTP Requests (SHR, also known as PoP — Proof of Possession) as its
token binding mechanism, not RFC 9449 DPoP. The two protocols are not interoperable. Set
`dpop_enforcement: disabled` for all Entra issuers. RFC 9449 DPoP with Entra may be possible in
future via Entra's preview DPoP support, but is not recommended for production use.

---

## Troubleshooting

### ROPC returns AADSTS65001 (user consent required)

Admin consent was not granted for the required scopes. Return to Step 4, verify you clicked
"Grant admin consent", and confirm the status shows "Granted for [tenant]".

### ROPC returns AADSTS50076 (MFA required)

The test user has MFA required by a Conditional Access policy. See Step 6 for exclusion options.

### ROPC returns AADSTS90014 (missing required field)

Check your scope string. Common mistake: using `profile openid email` instead of
`openid profile email` (order does not matter) or accidentally including `User.Read` which
changes the audience to Graph and may trigger additional requirements.

### Token aud is https://graph.microsoft.com

You included `User.Read` in the scope parameter. Remove it — use `openid profile email` only.
See Step 4, CRITICAL note.

### preferred_username or email claim is missing

Add the optional claim in Step 5. If `email` is absent even after adding the optional claim,
check that the test user has an email address set in Entra ID (Users → your user → Contact info).

### Token iss does not match issuer_url

Entra v2.0 issuers are tenant-specific:
`https://login.microsoftonline.com/{tenant-id}/v2.0`. Replace `{tenant-id}` with your actual
tenant GUID (not your tenant domain name like `contoso.onmicrosoft.com`). The `/v2.0` suffix
is required.

### Authentication fails with "unknown issuer"

The `issuer_url` in `policy.yaml` must exactly match the `iss` claim in the token (after
trailing-slash normalization). Decode your token (Step 9) and compare `iss` character-for-character
with `issuer_url`.

### Authentication fails with audience mismatch

The `aud` claim in your token does not match `client_id` in policy.yaml. Either:
- The token `aud` is the GUID client ID → ensure `client_id` in policy.yaml matches exactly
- The token `aud` is an `api://` URI → uncomment `expected_audience` in policy.yaml and set it
  to match the token `aud` value

---

*This guide covers Phase 22 (Entra ID integration) App Registration Checklist items:*
*(1) public client flag, (2) single-tenant account type, (3) platform redirect URI http://localhost,*
*(4) Allow public client flows enabled, (5) API permissions (openid, profile, email) with admin*
*consent, (6) optional claims verification for preferred_username.*
