#!/usr/bin/env bash
# Acquire an Entra ID access token via ROPC (Resource Owner Password Credentials).
#
# Usage: ./get-entra-token.sh
#
# Required environment variables:
#   ENTRA_TENANT_ID     -- Azure AD tenant ID (GUID)
#   ENTRA_CLIENT_ID     -- Application (client) ID (GUID)
#   ENTRA_TEST_USER     -- UPN of test user (e.g. ci-test@corp.example)
#   ENTRA_TEST_PASSWORD -- Password for test user
#
# Outputs the access token on stdout. Exits non-zero on failure.
#
# Security notes:
#   - ROPC is incompatible with MFA. The test user MUST have MFA disabled
#     or be excluded from Conditional Access MFA policies.
#   - Scopes are `openid profile email` only -- NOT User.Read.
#     User.Read is a Graph permission that changes the token audience to
#     https://graph.microsoft.com, breaking PAM audience validation.
#     See 22-RESEARCH.md Pitfall 3 and 22-CONTEXT.md revision note.
#   - Tokens are masked in CI via `::add-mask::`.
#
# References:
#   - Microsoft Learn: OAuth 2.0 ROPC (https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc)
set -euo pipefail

: "${ENTRA_TENANT_ID:?ENTRA_TENANT_ID is required}"
: "${ENTRA_CLIENT_ID:?ENTRA_CLIENT_ID is required}"
: "${ENTRA_TEST_USER:?ENTRA_TEST_USER is required}"
: "${ENTRA_TEST_PASSWORD:?ENTRA_TEST_PASSWORD is required}"

TOKEN_ENDPOINT="https://login.microsoftonline.com/${ENTRA_TENANT_ID}/oauth2/v2.0/token"

# Request scopes: openid + profile + email for user claims.
# Do NOT add User.Read -- it changes aud to Graph (see 22-RESEARCH.md Pitfall 3).
SCOPE="openid profile email"

RESPONSE=$(curl -sf -X POST "${TOKEN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ENTRA_CLIENT_ID}" \
  -d "username=${ENTRA_TEST_USER}" \
  -d "password=${ENTRA_TEST_PASSWORD}" \
  -d "scope=${SCOPE}")

# Extract access_token from JSON response.
ACCESS_TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token // empty')

if [ -z "${ACCESS_TOKEN}" ]; then
  ERROR=$(echo "${RESPONSE}" | jq -r '.error_description // .error // "unknown error"')
  echo "ERROR: Failed to acquire Entra token: ${ERROR}" >&2
  exit 1
fi

echo "${ACCESS_TOKEN}"
