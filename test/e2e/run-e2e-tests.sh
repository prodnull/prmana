#!/bin/bash
# test/e2e/run-e2e-tests.sh
# Automated E2E tests using Playwright MCP for browser automation
#
# This script is designed to be called by Claude Code with Playwright MCP available.
# It outputs structured commands that Claude Code can interpret.
#
# Usage:
#   ./run-e2e-tests.sh              # Run all E2E tests
#   ./run-e2e-tests.sh device-flow  # Run specific test

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="unix-oidc-test"
CLIENT_ID="unix-oidc"
CLIENT_SECRET="unix-oidc-test-secret"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

test_device_flow() {
    echo -e "${YELLOW}=== E2E Test: Device Flow ===${NC}"
    echo ""

    # Step 1: Start device authorization
    echo "Step 1: Starting device authorization..."
    DEVICE_RESPONSE=$(curl -sf -X POST \
      "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/auth/device" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&scope=openid")

    DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.device_code')
    USER_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.user_code')
    VERIFICATION_URI_COMPLETE=$(echo "$DEVICE_RESPONSE" | jq -r '.verification_uri_complete')

    if [ -z "$DEVICE_CODE" ] || [ "$DEVICE_CODE" = "null" ]; then
        echo -e "${RED}FAIL: Could not start device flow${NC}"
        echo "Response: $DEVICE_RESPONSE"
        return 1
    fi

    echo "  Device Code: ${DEVICE_CODE:0:20}..."
    echo "  User Code: $USER_CODE"
    echo "  Verification URL: $VERIFICATION_URI_COMPLETE"
    echo ""

    # Step 2: Output Playwright automation instructions
    # These are structured for Claude Code to interpret
    echo "PLAYWRIGHT_AUTOMATION_START"
    echo "NAVIGATE: $VERIFICATION_URI_COMPLETE"
    echo "FILL: username -> testuser"
    echo "FILL: password -> testpass"
    echo "CLICK: Sign In"
    echo "WAIT: consent page"
    echo "CLICK: Yes"
    echo "WAIT: success page"
    echo "PLAYWRIGHT_AUTOMATION_END"
    echo ""

    # Step 3: Poll for token
    echo "Step 3: Polling for token..."
    MAX_ATTEMPTS=30
    INTERVAL=2

    for i in $(seq 1 $MAX_ATTEMPTS); do
        POLL_RESPONSE=$(curl -sf -X POST \
          "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=${DEVICE_CODE}&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}" 2>/dev/null || echo '{"error":"request_failed"}')

        ACCESS_TOKEN=$(echo "$POLL_RESPONSE" | jq -r '.access_token // empty')
        ERROR=$(echo "$POLL_RESPONSE" | jq -r '.error // empty')

        if [ -n "$ACCESS_TOKEN" ]; then
            echo ""
            echo -e "${GREEN}SUCCESS: Token received${NC}"
            echo "  Token length: ${#ACCESS_TOKEN}"
            return 0
        elif [ "$ERROR" = "authorization_pending" ]; then
            echo -n "."
        elif [ "$ERROR" = "expired_token" ]; then
            echo ""
            echo -e "${RED}FAIL: Device code expired${NC}"
            return 1
        elif [ "$ERROR" = "access_denied" ]; then
            echo ""
            echo -e "${RED}FAIL: Access denied${NC}"
            return 1
        fi

        sleep $INTERVAL
    done

    echo ""
    echo -e "${RED}FAIL: Timeout waiting for token${NC}"
    return 1
}

# Main
case "${1:-all}" in
    device-flow)
        test_device_flow
        ;;
    all)
        test_device_flow
        ;;
    *)
        echo "Unknown test: $1"
        echo "Available tests: device-flow"
        exit 1
        ;;
esac
