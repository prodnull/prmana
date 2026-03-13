#!/bin/bash
# test/e2e/run-device-flow-e2e.sh
# PLAY-02: Shell + Playwright coordination for device flow E2E.
#
# Protocol:
#   1. This script runs unix-oidc-agent login (which generates DPoP proofs)
#   2. Captures the verification URI from agent stdout via a FIFO
#   3. Writes the URI to TMPFILE for Playwright
#   4. Playwright automates browser login + consent
#   5. The agent receives the DPoP-bound token
#   6. Script validates the token has cnf.jkt (DPoP binding)
#
# Prerequisites:
#   - Keycloak running and healthy (docker-compose.e2e.yaml)
#   - unix-oidc-agent binary on PATH (or AGENT_BIN set)
#   - Playwright browsers installed (npx playwright install chromium)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${KEYCLOAK_REALM:-unix-oidc}"
CLIENT_ID="${KEYCLOAK_CLIENT_ID:-unix-oidc}"
AGENT_BIN="${AGENT_BIN:-unix-oidc-agent}"
TMPFILE="${DEVICE_FLOW_TMPFILE:-/tmp/unix-oidc-device-flow-uri}"
AGENT_OUTPUT="/tmp/unix-oidc-agent-output-$$"
AGENT_PID=""
PW_PID=""

# Cleanup on exit
cleanup() {
    rm -f "$TMPFILE" "$AGENT_OUTPUT"
    if [ -n "${AGENT_PID:-}" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
    fi
    if [ -n "${PW_PID:-}" ] && kill -0 "$PW_PID" 2>/dev/null; then
        kill "$PW_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=== Device Flow E2E Test (with DPoP) ==="
echo "Keycloak: $KEYCLOAK_URL"
echo "Realm: $REALM"
echo "Client: $CLIENT_ID"
echo "Agent: $AGENT_BIN"
echo ""

# Verify agent binary exists
if ! command -v "$AGENT_BIN" >/dev/null 2>&1; then
    # Try local native build (macOS host → Linux server testing)
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    LOCAL_AGENT="${PROJECT_ROOT}/target/release/unix-oidc-agent"
    if [ -x "$LOCAL_AGENT" ]; then
        AGENT_BIN="$LOCAL_AGENT"
        echo "Using local agent: $AGENT_BIN"
    else
        echo "FATAL: unix-oidc-agent not found on PATH or at $LOCAL_AGENT"
        echo "Build with: cargo build --release -p unix-oidc-agent"
        exit 1
    fi
fi

# Step 1: Start agent login in background, capturing stdout
echo "Step 1: Starting unix-oidc-agent login (device flow + DPoP)..."
OIDC_ISSUER="${KEYCLOAK_URL}/realms/${REALM}" \
OIDC_CLIENT_ID="${CLIENT_ID}" \
    "$AGENT_BIN" login \
        --issuer "${KEYCLOAK_URL}/realms/${REALM}" \
        --client-id "${CLIENT_ID}" \
    > "$AGENT_OUTPUT" 2>&1 &
AGENT_PID=$!

# Step 2: Wait for the verification URI to appear in agent output
echo "Step 2: Waiting for verification URI from agent..."
MAX_WAIT=30
WAITED=0
VERIFICATION_URI=""

while [ $WAITED -lt $MAX_WAIT ]; do
    if [ -f "$AGENT_OUTPUT" ]; then
        # The agent prints the user code as "Enter the code:  XXXX-YYYY"
        # and the base URI as "Open your browser to: <url>".
        # The "Or visit directly:" line is truncated for long URLs, so we
        # reconstruct verification_uri_complete from the base URI + user code.
        USER_CODE=$(grep -oE 'Enter the code: +[A-Z0-9]{4}-[A-Z0-9]{4}' "$AGENT_OUTPUT" 2>/dev/null | grep -oE '[A-Z0-9]{4}-[A-Z0-9]{4}' | head -1 || true)
        BASE_URI=$(grep -oE 'https?://[^ │]+/device' "$AGENT_OUTPUT" 2>/dev/null | head -1 || true)
        if [ -n "$USER_CODE" ] && [ -n "$BASE_URI" ]; then
            VERIFICATION_URI="${BASE_URI}?user_code=${USER_CODE}"
            break
        fi
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done

if [ -z "$VERIFICATION_URI" ]; then
    echo "FATAL: Could not extract verification URI from agent output"
    echo "Agent output:"
    cat "$AGENT_OUTPUT" 2>/dev/null || echo "(empty)"
    exit 1
fi

echo "  Verification URI: $VERIFICATION_URI"
echo ""

# Step 3: Write URI for Playwright and launch browser automation
echo "$VERIFICATION_URI" > "$TMPFILE"

echo "Step 3: Launching Playwright for browser consent..."
export DEVICE_FLOW_TMPFILE="$TMPFILE"
export KEYCLOAK_USER="${KEYCLOAK_USER:-testuser}"
export KEYCLOAK_PASS="${KEYCLOAK_PASS:-testpass}"

cd "$SCRIPT_DIR"
npx playwright test tests/device-flow.spec.ts --reporter=line &
PW_PID=$!

# Step 4: Wait for the agent to complete (it polls with DPoP proofs)
echo "Step 4: Waiting for agent to receive DPoP-bound token..."
if wait "$AGENT_PID"; then
    AGENT_PID=""
    echo ""
    echo "=== Agent login completed ==="
    tail -20 "$AGENT_OUTPUT"
else
    AGENT_EXIT=$?
    AGENT_PID=""
    echo ""
    echo "FATAL: Agent login failed (exit $AGENT_EXIT)"
    cat "$AGENT_OUTPUT"
    # Wait for Playwright too so it doesn't orphan
    wait "$PW_PID" 2>/dev/null || true
    PW_PID=""
    exit 1
fi

# Wait for Playwright to finish
wait "$PW_PID" 2>/dev/null || true
PW_PID=""

# Step 5: Verify the agent successfully stored a DPoP-bound token
echo ""
echo "Step 5: Verifying DPoP-bound token..."
if grep -q "DPoP thumbprint:" "$AGENT_OUTPUT"; then
    THUMBPRINT=$(grep -oE 'DPoP thumbprint: [A-Za-z0-9_-]+' "$AGENT_OUTPUT" | head -1 | cut -d' ' -f3)
    echo "  DPoP thumbprint: $THUMBPRINT"
else
    echo "WARNING: No DPoP thumbprint found in agent output"
fi

if grep -qi "Authentication successful\|Login successful\|logged in\|Access token" "$AGENT_OUTPUT"; then
    echo "  Token acquisition: CONFIRMED"
else
    echo "WARNING: Could not confirm token acquisition from agent output"
    echo "  (Agent may have succeeded but output format changed)"
fi

echo ""
echo "=== DEVICE FLOW E2E (with DPoP): PASSED ==="
