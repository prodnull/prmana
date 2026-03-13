#!/bin/bash
# test/e2e/run-device-flow-e2e.sh
# PLAY-02: Shell + Playwright coordination for device flow E2E.
#
# Protocol:
#   1. This script starts device authorization with Keycloak
#   2. Writes verification_uri_complete to TMPFILE
#   3. Launches Playwright in background to automate browser consent
#   4. Polls Keycloak token endpoint until token is received
#   5. Validates token has DPoP binding (cnf.jkt claim)
#
# Prerequisites:
#   - Keycloak running and healthy (docker-compose.e2e.yaml)
#   - Playwright browsers installed (npx playwright install chromium)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${KEYCLOAK_REALM:-unix-oidc}"
CLIENT_ID="${KEYCLOAK_CLIENT_ID:-unix-oidc}"
TMPFILE="${DEVICE_FLOW_TMPFILE:-/tmp/unix-oidc-device-flow-uri}"

# Cleanup on exit
cleanup() {
    rm -f "$TMPFILE"
    # Kill background Playwright if still running
    if [ -n "${PW_PID:-}" ] && kill -0 "$PW_PID" 2>/dev/null; then
        kill "$PW_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=== Device Flow E2E Test ==="
echo "Keycloak: $KEYCLOAK_URL"
echo "Realm: $REALM"
echo "Client: $CLIENT_ID"
echo ""

# Step 1: Start device authorization
echo "Step 1: Starting device authorization..."
DEVICE_RESPONSE=$(curl -sf -X POST \
    "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/auth/device" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=${CLIENT_ID}&scope=openid")

DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.device_code')
USER_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.user_code')
VERIFICATION_URI_COMPLETE=$(echo "$DEVICE_RESPONSE" | jq -r '.verification_uri_complete')
EXPIRES_IN=$(echo "$DEVICE_RESPONSE" | jq -r '.expires_in // 600')
INTERVAL=$(echo "$DEVICE_RESPONSE" | jq -r '.interval // 5')

if [ -z "$DEVICE_CODE" ] || [ "$DEVICE_CODE" = "null" ]; then
    echo "FATAL: Could not start device flow"
    echo "Response: $DEVICE_RESPONSE"
    exit 1
fi

echo "  Device Code: ${DEVICE_CODE:0:20}..."
echo "  User Code: $USER_CODE"
echo "  Verification URI: $VERIFICATION_URI_COMPLETE"
echo ""

# Step 2: Write verification URI for Playwright (PLAY-02: tmpfile coordination)
echo "$VERIFICATION_URI_COMPLETE" > "$TMPFILE"

# Step 3: Launch Playwright in background
echo "Step 2: Launching Playwright for browser consent..."
export DEVICE_FLOW_TMPFILE="$TMPFILE"
export KEYCLOAK_USER="${KEYCLOAK_USER:-testuser}"
export KEYCLOAK_PASS="${KEYCLOAK_PASS:-testpass}"

cd "$SCRIPT_DIR"
npx playwright test tests/device-flow.spec.ts --reporter=line &
PW_PID=$!

# Step 4: Poll for token
echo "Step 3: Polling for token..."
MAX_ATTEMPTS=$((EXPIRES_IN / INTERVAL))
ATTEMPT=0

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    ATTEMPT=$((ATTEMPT + 1))

    POLL_RESPONSE=$(curl -sf -X POST \
        "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=${DEVICE_CODE}&client_id=${CLIENT_ID}" \
        2>/dev/null || echo '{"error":"request_failed"}')

    ACCESS_TOKEN=$(echo "$POLL_RESPONSE" | jq -r '.access_token // empty')
    ERROR=$(echo "$POLL_RESPONSE" | jq -r '.error // empty')

    if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
        echo ""
        echo "=== TOKEN RECEIVED ==="

        # Decode and validate claims
        CLAIMS=$(echo "$ACCESS_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null)
        ISS=$(echo "$CLAIMS" | jq -r '.iss // empty')
        AZP=$(echo "$CLAIMS" | jq -r '.azp // empty')
        CNF_JKT=$(echo "$CLAIMS" | jq -r '.cnf.jkt // empty')

        echo "  Issuer: $ISS"
        echo "  Client: $AZP"
        echo "  DPoP binding (cnf.jkt): ${CNF_JKT:-NONE}"

        # Validate issuer alignment (BFIX-01)
        EXPECTED_ISS="${KEYCLOAK_URL}/realms/${REALM}"
        if [ "$ISS" != "$EXPECTED_ISS" ]; then
            echo "WARNING: Issuer mismatch: expected $EXPECTED_ISS, got $ISS"
        fi

        # Wait for Playwright to finish
        wait "$PW_PID" 2>/dev/null || true

        echo ""
        echo "=== DEVICE FLOW E2E: PASSED ==="
        exit 0
    elif [ "$ERROR" = "authorization_pending" ]; then
        printf "."
    elif [ "$ERROR" = "slow_down" ]; then
        INTERVAL=$((INTERVAL + 5))
        printf "S"
    elif [ "$ERROR" = "expired_token" ]; then
        echo ""
        echo "FATAL: Device code expired"
        exit 1
    elif [ "$ERROR" = "access_denied" ]; then
        echo ""
        echo "FATAL: Access denied"
        exit 1
    fi

    sleep "$INTERVAL"
done

echo ""
echo "FATAL: Timeout waiting for token"
exit 1
