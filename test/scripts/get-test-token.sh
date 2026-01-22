#!/bin/bash
# test/scripts/get-test-token.sh
# Get a valid OIDC token from Keycloak for testing
set -e

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="unix-oidc-test"
CLIENT_ID="unix-oidc"
CLIENT_SECRET="unix-oidc-test-secret"
USERNAME="${1:-testuser}"
PASSWORD="${2:-testpass}"

# Request token using Resource Owner Password Credentials flow
RESPONSE=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}" \
  -d "scope=openid")

# Extract access token
TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "Error: Failed to get token" >&2
    echo "Response: $RESPONSE" >&2
    exit 1
fi

echo "$TOKEN"
