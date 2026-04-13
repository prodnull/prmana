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

# Conditional Access diagnostic function.
# Checks whether an Entra error response indicates a Conditional Access policy
# blocking ROPC. Emits actionable diagnostic to stderr if detected.
#
# Arguments:
#   $1 -- JSON error response from Entra token endpoint
#
# Returns:
#   0 if Conditional Access error detected (diagnostic emitted)
#   1 if not a Conditional Access error
check_conditional_access_error() {
  local response="$1"
  local error_code error_desc

  error_code=$(echo "${response}" | jq -r '.error // empty' 2>/dev/null)
  error_desc=$(echo "${response}" | jq -r '.error_description // empty' 2>/dev/null)

  # Check for known Conditional Access error patterns:
  #   AADSTS50076 -- MFA required but not provided
  #   AADSTS53003 -- Access blocked by Conditional Access policy
  #   AADSTS50079 -- User needs to register for MFA
  #   interaction_required -- Generic interactive auth needed (ROPC cannot handle)
  local ca_pattern="AADSTS50076|AADSTS53003|AADSTS50079|interaction_required"

  if echo "${error_code} ${error_desc}" | grep -qE "${ca_pattern}"; then
    echo "DIAGNOSTIC: Entra ROPC failed due to Conditional Access policy." >&2
    echo "  Possible causes:" >&2
    echo "  - MFA required for test user (exclude from Conditional Access or use MFA-exempt user)" >&2
    echo "  - Conditional Access blocks ROPC grant type (add Named Location exclusion for CI IP range)" >&2
    echo "  - Consider switching to client_credentials grant if user context is not required" >&2
    echo "  Error code: ${error_code}" >&2
    echo "  Error description: ${error_desc}" >&2
    return 0
  fi

  return 1
}

# Guard: when sourced for testing, do not execute main body.
# Set _ENTRA_TOKEN_SOURCED=1 before sourcing to import functions only.
if [ "${_ENTRA_TOKEN_SOURCED:-0}" = "1" ]; then
  return 0 2>/dev/null || true
fi

set -euo pipefail

: "${ENTRA_TENANT_ID:?ENTRA_TENANT_ID is required}"
: "${ENTRA_CLIENT_ID:?ENTRA_CLIENT_ID is required}"
: "${ENTRA_TEST_USER:?ENTRA_TEST_USER is required}"
: "${ENTRA_TEST_PASSWORD:?ENTRA_TEST_PASSWORD is required}"

TOKEN_ENDPOINT="https://login.microsoftonline.com/${ENTRA_TENANT_ID}/oauth2/v2.0/token"

# Request scopes: openid + profile + email for user claims.
# Do NOT add User.Read -- it changes aud to Graph (see 22-RESEARCH.md Pitfall 3).
#
# IMPORTANT: Plain "openid profile email" scopes default to Graph audience on Entra.
# To get a token with aud=client_id, request the app's own exposed API scope.
# This requires "Expose an API" with an Application ID URI and at least one scope.
SCOPE="api://${ENTRA_CLIENT_ID}/access openid profile email"

# Use -s (not -sf) so we get the error response body for diagnostic parsing.
RESPONSE=$(curl -s -X POST "${TOKEN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ENTRA_CLIENT_ID}" \
  -d "username=${ENTRA_TEST_USER}" \
  -d "password=${ENTRA_TEST_PASSWORD}" \
  -d "scope=${SCOPE}")

# Extract access_token from JSON response.
ACCESS_TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token // empty')

if [ -z "${ACCESS_TOKEN}" ]; then
  # Check for Conditional Access errors first (actionable diagnostic).
  check_conditional_access_error "${RESPONSE}" || true

  ERROR=$(echo "${RESPONSE}" | jq -r '.error_description // .error // "unknown error"')
  echo "ERROR: Failed to acquire Entra token: ${ERROR}" >&2
  exit 1
fi

echo "${ACCESS_TOKEN}"
