#!/bin/bash
# test/e2e/test-device-flow-e2e.sh
# End-to-end test for device flow using Playwright for browser automation
#
# This test:
# 1. Starts device authorization flow
# 2. Uses Playwright to complete the Keycloak login
# 3. Verifies token is returned
#
# Prerequisites:
# - Test environment running (make dev-up)
# - Playwright available via Claude Code MCP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="unix-oidc-test"
CLIENT_ID="unix-oidc"
CLIENT_SECRET="unix-oidc-test-secret"
SCREENSHOTS_DIR="${SCRIPT_DIR}/screenshots"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Device Flow E2E Test ==="
echo ""

# Create screenshots directory
mkdir -p "$SCREENSHOTS_DIR"

# Step 1: Start device authorization
echo -e "${YELLOW}Step 1: Starting device authorization...${NC}"
DEVICE_RESPONSE=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/auth/device" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=openid")

DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.device_code')
USER_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.user_code')
VERIFICATION_URI=$(echo "$DEVICE_RESPONSE" | jq -r '.verification_uri')
VERIFICATION_URI_COMPLETE=$(echo "$DEVICE_RESPONSE" | jq -r '.verification_uri_complete')
EXPIRES_IN=$(echo "$DEVICE_RESPONSE" | jq -r '.expires_in')
INTERVAL=$(echo "$DEVICE_RESPONSE" | jq -r '.interval')

if [ -z "$DEVICE_CODE" ] || [ "$DEVICE_CODE" = "null" ]; then
    echo -e "${RED}Error: Failed to start device flow${NC}"
    echo "Response: $DEVICE_RESPONSE"
    exit 1
fi

echo -e "${GREEN}  Device Code: ${DEVICE_CODE:0:20}...${NC}"
echo -e "${GREEN}  User Code: $USER_CODE${NC}"
echo -e "${GREEN}  Verification URI: $VERIFICATION_URI${NC}"
echo -e "${GREEN}  Verification URI Complete: $VERIFICATION_URI_COMPLETE${NC}"
echo ""

# Export for Playwright test
export DEVICE_CODE
export USER_CODE
export VERIFICATION_URI
export VERIFICATION_URI_COMPLETE

# Step 2: Output Playwright instructions
echo -e "${YELLOW}Step 2: Browser automation required${NC}"
echo ""
echo "To complete this test, use Playwright to:"
echo "  1. Navigate to: $VERIFICATION_URI_COMPLETE"
echo "     (or $VERIFICATION_URI and enter code: $USER_CODE)"
echo "  2. Login as: testuser / testpass"
echo "  3. Grant consent if prompted"
echo ""
echo "Playwright commands:"
echo "  browser_navigate: $VERIFICATION_URI_COMPLETE"
echo "  browser_snapshot (to see the page)"
echo "  browser_type: username field -> testuser"
echo "  browser_type: password field -> testpass"
echo "  browser_click: login button"
echo ""

# Step 3: Poll for token in background
echo -e "${YELLOW}Step 3: Polling for token (waiting for browser auth)...${NC}"
echo "  Polling every ${INTERVAL}s, timeout in ${EXPIRES_IN}s"
echo ""

MAX_ATTEMPTS=$((EXPIRES_IN / INTERVAL))
ATTEMPT=0

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    ATTEMPT=$((ATTEMPT + 1))

    POLL_RESPONSE=$(curl -s -X POST \
      "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
      -d "device_code=${DEVICE_CODE}" \
      -d "client_id=${CLIENT_ID}" \
      -d "client_secret=${CLIENT_SECRET}")

    ERROR=$(echo "$POLL_RESPONSE" | jq -r '.error // empty')
    ACCESS_TOKEN=$(echo "$POLL_RESPONSE" | jq -r '.access_token // empty')

    if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
        echo ""
        echo -e "${GREEN}=== SUCCESS ===${NC}"
        echo -e "${GREEN}Token received after $ATTEMPT attempts${NC}"
        echo ""

        # Decode and display token info
        echo "Token claims:"
        echo "$ACCESS_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.' || echo "(could not decode)"
        echo ""

        # Save token for verification
        echo "$ACCESS_TOKEN" > "$SCREENSHOTS_DIR/token.txt"
        echo "Token saved to: $SCREENSHOTS_DIR/token.txt"

        exit 0
    elif [ "$ERROR" = "authorization_pending" ]; then
        echo -n "."
    elif [ "$ERROR" = "slow_down" ]; then
        echo -n "S"
        INTERVAL=$((INTERVAL + 5))
    elif [ "$ERROR" = "access_denied" ]; then
        echo ""
        echo -e "${RED}=== FAILED ===${NC}"
        echo -e "${RED}Access denied by user${NC}"
        exit 1
    elif [ "$ERROR" = "expired_token" ]; then
        echo ""
        echo -e "${RED}=== FAILED ===${NC}"
        echo -e "${RED}Device code expired${NC}"
        exit 1
    else
        echo ""
        echo -e "${RED}Unexpected error: $ERROR${NC}"
        echo "Response: $POLL_RESPONSE"
        exit 1
    fi

    sleep "$INTERVAL"
done

echo ""
echo -e "${RED}=== TIMEOUT ===${NC}"
echo -e "${RED}No authentication completed within ${EXPIRES_IN}s${NC}"
exit 1
