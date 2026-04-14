# Entra ID E2E Test Setup Guide

Step-by-step setup for running prmana integration tests against a live Entra ID (Azure AD) tenant. This covers tenant creation through passing CI tests.

For production deployment configuration, see `docs/entra-setup-guide.md`.

---

## 1. Create a Free Entra ID Test Tenant

You need an Azure Entra ID tenant where you are a **Global Administrator** or **Application Administrator**. A personal Azure subscription will not work if your organization's Conditional Access policies lock down ROPC.

**Option A -- New free tenant (recommended for testing):**

1. Sign up at <https://azure.microsoft.com/en-us/free/>.
2. Once the subscription is active, navigate to **Entra ID** in the Azure Portal.
3. If your subscription was created under an existing organization, create a separate tenant:
   **Entra ID -> Manage tenants -> + Create** -> **Entra ID** (not Entra ID B2C).
4. Name it something recognizable (e.g., `prmana-test`). The default domain will be
   `prmana-test.onmicrosoft.com`.

**Option B -- Existing tenant you control:**

Works fine as long as you can exclude a test user from MFA Conditional Access policies (Step 4).

**What you need from the tenant:**

| Item | Where to find it |
|------|-----------------|
| Tenant ID (GUID) | Azure Portal -> Entra ID -> Overview -> Tenant ID |

---

## 2. Register the Application

1. Navigate to **Entra ID -> App registrations -> New registration**.
2. Fill in the form:
   - **Name:** `prmana-test`
   - **Supported account types:** **Accounts in this organizational directory only (Single tenant)**. Multi-tenant would accept tokens from any Entra tenant -- a security violation for PAM auth.
   - **Redirect URI:** Select **Mobile and desktop applications** -> `http://localhost`
3. Click **Register**.
4. On the app's **Overview** page, copy:
   - **Application (client) ID** -- this is `ENTRA_CLIENT_ID`
   - **Directory (tenant) ID** -- this is `ENTRA_TENANT_ID`
5. Navigate to **Authentication -> Advanced settings**.
6. Set **Allow public client flows** to **Yes** and click **Save**.

This enables both ROPC (used in CI) and Device Code flow (used in production). ROPC requires a public client because there is no secure location to store a client secret on every PAM-authenticated server.

---

## 3. Configure API Permissions

1. Navigate to **API permissions** in your app registration.
2. Click **Add a permission -> Microsoft Graph -> Delegated permissions**.
3. Add exactly these scopes:
   - `openid`
   - `profile`
   - `email`
4. **Do NOT add `User.Read`.** This is the most common setup mistake. Adding `User.Read` changes the token audience (`aud` claim) from your client ID to `00000003-0000-0000-c000-000000000000` (Microsoft Graph), which fails PAM audience validation.
5. Click **Grant admin consent for [Your Tenant]** and confirm. Verify each permission shows status **Granted**.

### Optional: Configure Token Claims

Entra may not include `preferred_username` in access tokens by default.

1. Navigate to **Token configuration -> Add optional claim**.
2. Select **Access** token type.
3. Add `preferred_username` and `email`.
4. Click **Add**.

---

## 4. Create a Test User

1. Navigate to **Entra ID -> Users -> New user -> Create new user**.
2. Fill in:
   - **User principal name:** `prmana-ci@yourtenant.onmicrosoft.com`
   - **Display name:** `prmana CI Test`
   - **Password:** Set a strong password. Record it immediately.
3. Click **Create**.
4. After creation, navigate to the user's profile and set an **Email** under Contact info (the `email` claim depends on this).

### Exclude from MFA (Required)

ROPC is incompatible with MFA. If your tenant has Conditional Access policies requiring MFA, the test user must be excluded.

**Option A -- User/group exclusion (simpler):**

1. Navigate to **Protection -> Conditional Access**.
2. Edit each MFA policy.
3. Under **Assignments -> Users -> Exclude**, add the test user or a `CI-Users` group.

**Option B -- Named Location exclusion (for CI runners):**

1. Navigate to **Protection -> Conditional Access -> Named locations**.
2. Create a named location for your CI runner IP range.
3. Edit the MFA policy and add the named location to the **Exclude** list.

Verify the exclusion works before proceeding to Step 6.

---

## 5. Configure Local Credentials

Create a `.entra` file in the project root (already gitignored):

```
ENTRA_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ENTRA_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ENTRA_TEST_USER=prmana-ci@yourtenant.onmicrosoft.com
ENTRA_TEST_PASSWORD=YourStrongPassword123!
```

This file uses `KEY=VALUE` format, one per line. The token acquisition script and test runner source it automatically.

---

## 6. Verify Token Acquisition

Run the token acquisition script manually:

```bash
source .entra
./test/scripts/get-entra-token.sh
```

On success, it prints a JWT access token (a long base64url string with two dots). On failure, it prints an error code and description to stderr.

Decode and inspect the token claims:

```bash
TOKEN=$(./test/scripts/get-entra-token.sh)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

Verify these claims:

| Claim | Expected Value |
|-------|---------------|
| `iss` | `https://login.microsoftonline.com/{your-tenant-id}/v2.0` |
| `aud` | Your client ID GUID (NOT `00000003-...` or `https://graph.microsoft.com`) |
| `preferred_username` | `prmana-ci@yourtenant.onmicrosoft.com` |
| `email` | The email set on the test user's profile |
| `sub` | An opaque GUID (stable per user per app) |

If `aud` is the Graph API GUID, you added `User.Read` to the scopes -- go back to Step 3.

---

## 7. Run E2E Tests

### Rust Integration Tests

These tests validate token signature verification, claim mapping, and the multi-issuer auth pipeline against live Entra JWKS:

```bash
source .entra

# Acquire a token for the test suite
export ENTRA_TOKEN=$(./test/scripts/get-entra-token.sh)

# Run the Entra integration tests
cargo test -p pam-prmana --test entra_integration -- --include-ignored
```

The test suite (`pam-prmana/tests/entra_integration.rs`) includes:

| Test | What it validates |
|------|-------------------|
| `test_entra_discovery_returns_valid_jwks_uri` | OIDC discovery + JWKS fetch with RS256 keys |
| `test_entra_rs256_token_validates` | Real signature verification against live JWKS |
| `test_entra_token_has_expected_claims` | `preferred_username`, `email`, `sub` present |
| `test_entra_upn_strip_domain_maps_to_bare_username` | `email` -> `strip_domain` -> `lowercase` pipeline |
| `test_entra_raw_preferred_username_preserves_domain` | UPN format preserved without transforms |
| `test_entra_bearer_auth_completes_without_dpop_error` | Bearer-only auth (no DPoP) works with Entra |
| `test_entra_wrong_tenant_rejected` | Wrong tenant ID -> rejected |
| `test_entra_tampered_token_rejected` | Modified payload -> signature verification fails |
| `test_entra_unknown_issuer_rejected_by_multi_issuer` | Entra token rejected when issuer not in policy |

The `test_policy_entra_yaml_deserializes` test runs without secrets in every CI build to catch YAML schema regressions.

### Policy Fixture

The test policy fixture is at `test/fixtures/policy/policy-entra.yaml`. Key settings:

- `dpop_enforcement: disabled` -- Entra uses SHR, not RFC 9449 DPoP
- `jti_enforcement: warn` -- Entra emits `uti`, not standard `jti`
- `username_claim: email` with `strip_domain` + `lowercase` transforms
- `allow_unsafe_identity_pipeline: true` -- safe for single-tenant Entra (IdP enforces domain)

---

## 8. Configure CI Secrets

Add these secrets in **GitHub repo -> Settings -> Secrets and variables -> Actions**:

| Secret | Value |
|--------|-------|
| `ENTRA_TENANT_ID` | Directory (tenant) ID |
| `ENTRA_CLIENT_ID` | Application (client) ID |
| `ENTRA_TEST_USER` | Full UPN (e.g., `prmana-ci@yourtenant.onmicrosoft.com`) |
| `ENTRA_TEST_PASSWORD` | Test user password |

The CI workflow (`.github/workflows/provider-tests.yml`, `entra` job) auto-detects whether secrets are configured. When present, it:

1. Verifies OIDC discovery and JWKS availability
2. Acquires a token via ROPC (masked in logs with `::add-mask::`)
3. Runs `cargo test -p pam-prmana --test entra_integration -- --ignored --test-threads=1`

When secrets are absent, the job skips gracefully.

---

## 9. Troubleshooting

### ROPC Errors

| Error Code | Meaning | Fix |
|-----------|---------|-----|
| `AADSTS50126` | Invalid username or password | Check `ENTRA_TEST_USER` and `ENTRA_TEST_PASSWORD`. UPN must include the full `@domain`. |
| `AADSTS50076` | MFA required | Exclude the test user from Conditional Access MFA policies (Step 4). |
| `AADSTS700016` | Application not found in the directory | Verify `ENTRA_TENANT_ID` and `ENTRA_CLIENT_ID` match. Ensure the app was created in the correct tenant. |
| `AADSTS65001` | User or admin has not consented | Return to Step 3 and click **Grant admin consent**. |
| `AADSTS53003` | Access blocked by Conditional Access | A CA policy beyond MFA is blocking ROPC. Check all policies that apply to the test user. |
| `AADSTS50079` | User needs to register for MFA | The user was created but hasn't completed MFA registration. Exclude from MFA instead. |

### Token Claim Issues

**`aud` is `00000003-0000-0000-c000-000000000000` (Graph API):**
`User.Read` was included in the scope string or API permissions are misconfigured. Remove `User.Read` from the scope parameter. The scope must be exactly `openid profile email`.

**`preferred_username` or `email` is missing from the access token:**
Add the optional claims in **Token configuration** (Step 3). For `email`, also verify the test user has an email address set in their profile under Contact info.

**`iss` does not match `issuer_url`:**
The Entra v2.0 issuer is `https://login.microsoftonline.com/{tenant-id}/v2.0` where `{tenant-id}` is the GUID, not the domain name. The `/v2.0` suffix is required.

### Test Failures

**`test_entra_bearer_auth_completes_without_dpop_error` returns `UnknownIssuer`:**
The `ENTRA_TENANT_ID` in the environment does not match the `iss` claim in the token. Decode the token and compare.

**`test_entra_rs256_token_validates` fails with signature error:**
Token may have expired. Entra access tokens typically expire after 60-90 minutes. Re-acquire via `./test/scripts/get-entra-token.sh`.

**CI job is skipped:**
The `ENTRA_TENANT_ID` secret is not set. Verify it was added to the correct scope (repository secrets, not environment secrets) and that the workflow has access.

### Entra-Specific Quirks

- **`uti` vs `jti`:** Entra emits `uti` (unique token identifier) instead of standard `jti`. The prmana replay cache checks `jti`, so `jti_enforcement` must be set to `warn` for Entra issuers. Strict mode rejects all Entra tokens.
- **SHR vs DPoP:** Entra implements Signed HTTP Requests (SHR/PoP), not RFC 9449 DPoP. The two are not interoperable. `dpop_enforcement` must be `disabled`.
- **ROPC deprecation:** ROPC is deprecated in OAuth 2.1 and Microsoft discourages its use. It is used here strictly for CI automation with a dedicated test user. Device Code flow is the production path.
- **Token lifetime:** Entra access tokens are valid for 60-90 minutes by default. CI acquires a fresh token per run. For local testing, re-run `get-entra-token.sh` if tests fail with expiration errors.

---

## References

- [Microsoft Learn: ROPC grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc)
- [Microsoft Learn: Optional claims](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims)
- [Microsoft Learn: Conditional Access exclusions](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups)
- `docs/entra-setup-guide.md` -- Full Entra app registration and production configuration
- `test/fixtures/policy/policy-entra.yaml` -- Test policy fixture
- `test/scripts/get-entra-token.sh` -- Token acquisition script
- `pam-prmana/tests/entra_integration.rs` -- Rust integration test suite
- `.github/workflows/provider-tests.yml` -- CI workflow (Entra job)
