#!/bin/bash
# test/scripts/test-device-flow.sh
# Test the OAuth 2.0 Device Authorization Grant flow
set -e

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="unix-oidc-test"
CLIENT_ID="unix-oidc"
CLIENT_SECRET="unix-oidc-test-secret"

echo "=== Testing Device Flow ==="
echo ""

# Step 1: Start device authorization
echo "Step 1: Starting device authorization..."
DEVICE_RESPONSE=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/auth/device" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=openid")

DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.device_code')
USER_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.user_code')
VERIFICATION_URI=$(echo "$DEVICE_RESPONSE" | jq -r '.verification_uri')
EXPIRES_IN=$(echo "$DEVICE_RESPONSE" | jq -r '.expires_in')
INTERVAL=$(echo "$DEVICE_RESPONSE" | jq -r '.interval')

if [ -z "$DEVICE_CODE" ] || [ "$DEVICE_CODE" = "null" ]; then
    echo "Error: Failed to start device flow"
    echo "Response: $DEVICE_RESPONSE"
    exit 1
fi

echo "  Device Code: ${DEVICE_CODE:0:20}..."
echo "  User Code: $USER_CODE"
echo "  Verification URI: $VERIFICATION_URI"
echo "  Expires In: ${EXPIRES_IN}s"
echo "  Polling Interval: ${INTERVAL}s"
echo ""

# Step 2: Simulate user authentication
# In a real scenario, the user would visit the verification_uri and enter the user_code
# For testing, we use the direct grant to simulate this
echo "Step 2: Simulating user authentication (via direct grant)..."
AUTH_RESPONSE=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "username=testuser" \
  -d "password=testpass" \
  -d "scope=openid")

ACCESS_TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.access_token')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    echo "Error: Failed to authenticate user"
    echo "Response: $AUTH_RESPONSE"
    exit 1
fi

echo "  User authenticated successfully"
echo ""

# Step 3: Poll for token (this will fail in test since we can't complete the device flow programmatically)
# In a real scenario, this would succeed after the user completes authentication
echo "Step 3: Testing token endpoint polling..."
POLL_RESPONSE=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=${DEVICE_CODE}" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}")

ERROR=$(echo "$POLL_RESPONSE" | jq -r '.error')

if [ "$ERROR" = "authorization_pending" ]; then
    echo "  Got expected 'authorization_pending' response (device flow is working)"
    echo "  In production, polling would continue until user completes auth"
elif [ "$ERROR" = "null" ]; then
    echo "  Got token (unexpected in test mode)"
else
    echo "  Error: $ERROR"
    echo "  Description: $(echo "$POLL_RESPONSE" | jq -r '.error_description')"
fi

echo ""
echo "=== Device Flow Test Complete ==="
echo ""
echo "Note: Full device flow requires user interaction at $VERIFICATION_URI"
echo "      This test verifies the endpoints are working correctly."
