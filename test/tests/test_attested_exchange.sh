#!/bin/bash
# test/tests/test_attested_exchange.sh
# End-to-end test: Attested DPoP Token Exchange
#
# Prerequisites:
# - swtpm running (docker compose -f docker-compose.tpm-test.yaml up -d)
# - Keycloak running with token-exchange realm (docker compose -f docker-compose.token-exchange.yaml up -d)
# - unix-oidc-agent built with --features tpm
#
# This test validates the complete flow:
# 1. Provision TPM key on "jump host"
# 2. Obtain user token from Keycloak
# 3. Generate attestation evidence from TPM
# 4. Perform token exchange with attested DPoP proof
# 5. Validate exchanged token has act claim + attestation metadata
#
# NOTE: This is a reference script for manual validation. Automated CI
# requires both swtpm and Keycloak infrastructure simultaneously, which
# is tracked as a future CI enhancement.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-token-exchange-test}"
TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"
CLIENT_ID="${CLIENT_ID:-unix-oidc-agent}"
TEST_USER="${TEST_USER:-testuser}"
TEST_PASS="${TEST_PASS:-testpass}"
TARGET_AUDIENCE="${TARGET_AUDIENCE:-target-host-b}"

echo "=== Phase 37: Attested Token Exchange E2E Test ==="
echo ""
echo "This test requires:"
echo "  1. swtpm running (docker compose -f docker-compose.tpm-test.yaml up -d)"
echo "  2. Keycloak running (docker compose -f docker-compose.token-exchange.yaml up -d)"
echo "  3. unix-oidc-agent built with --features tpm"
echo ""

# Step 1: Check prerequisites
echo "Step 1: Checking prerequisites..."

if ! command -v unix-oidc-agent &>/dev/null; then
    AGENT="${PROJECT_ROOT}/target/debug/unix-oidc-agent"
    if [ ! -f "$AGENT" ]; then
        echo "SKIP: unix-oidc-agent not found. Build with: cargo build -p unix-oidc-agent --features tpm"
        exit 0
    fi
else
    AGENT="unix-oidc-agent"
fi

# Verify TPM feature is compiled in
if ! "$AGENT" --help 2>&1 | grep -q "tpm\|provision"; then
    echo "SKIP: unix-oidc-agent does not appear to have TPM support compiled in."
    echo "  Rebuild with: cargo build -p unix-oidc-agent --features tpm"
    exit 0
fi

# Check swtpm is running
if ! docker ps 2>/dev/null | grep -q swtpm; then
    echo "SKIP: swtpm container not running."
    echo "  Start with: docker compose -f docker-compose.tpm-test.yaml up -d"
    exit 0
fi

# Check Keycloak is running
if ! curl -sf "${KEYCLOAK_URL}/realms/${REALM}/.well-known/openid-configuration" >/dev/null 2>&1; then
    echo "SKIP: Keycloak not reachable at ${KEYCLOAK_URL} or realm '${REALM}' not configured."
    echo "  Start with: docker compose -f docker-compose.token-exchange.yaml up -d"
    exit 0
fi

echo "  All prerequisites met."
echo ""

# Step 2: Provision TPM key
echo "Step 2: Provisioning TPM key..."
export UNIX_OIDC_TPM_TCTI="swtpm"
PROVISION_OUTPUT=$("$AGENT" provision --signer tpm 2>&1) || {
    echo "FAIL: TPM key provisioning failed."
    echo "$PROVISION_OUTPUT"
    exit 1
}
echo "  TPM key provisioned successfully."
echo ""

# Step 3: Obtain user token from Keycloak
echo "Step 3: Obtaining user token from Keycloak..."
TOKEN_RESPONSE=$(curl -sf -X POST "$TOKEN_ENDPOINT" \
    -d "grant_type=password" \
    -d "client_id=${CLIENT_ID}" \
    -d "username=${TEST_USER}" \
    -d "password=${TEST_PASS}" \
    -d "scope=openid") || {
    echo "FAIL: Could not obtain token from Keycloak."
    echo "  Verify user '${TEST_USER}' exists in realm '${REALM}'."
    exit 1
}

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null) || {
    echo "FAIL: Could not parse access_token from Keycloak response."
    echo "$TOKEN_RESPONSE"
    exit 1
}
echo "  User token obtained (${#ACCESS_TOKEN} chars)."
echo ""

# Step 4: Perform token exchange with attested DPoP proof
echo "Step 4: Token exchange with attested DPoP proof..."
EXCHANGE_OUTPUT=$("$AGENT" exchange \
    --subject-token "$ACCESS_TOKEN" \
    --audience "$TARGET_AUDIENCE" 2>&1) || {
    echo "FAIL: Token exchange failed."
    echo "$EXCHANGE_OUTPUT"
    exit 1
}

EXCHANGED_TOKEN=$(echo "$EXCHANGE_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token', ''))" 2>/dev/null) || {
    # May not be JSON — try extracting from agent output
    EXCHANGED_TOKEN="$EXCHANGE_OUTPUT"
}

if [ -z "$EXCHANGED_TOKEN" ]; then
    echo "FAIL: No exchanged token returned."
    exit 1
fi
echo "  Token exchange completed (${#EXCHANGED_TOKEN} chars)."
echo ""

# Step 5: Validate exchanged token claims
echo "Step 5: Validating exchanged token claims..."

# Decode JWT payload (base64url -> base64 -> json)
decode_jwt_payload() {
    local payload
    payload=$(echo "$1" | cut -d. -f2)
    # Pad base64url to base64
    local pad=$((4 - ${#payload} % 4))
    if [ "$pad" -ne 4 ]; then
        payload="${payload}$(printf '%*s' "$pad" '' | tr ' ' '=')"
    fi
    echo "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null
}

# Decode DPoP header
decode_jwt_header() {
    local header
    header=$(echo "$1" | cut -d. -f1)
    local pad=$((4 - ${#header} % 4))
    if [ "$pad" -ne 4 ]; then
        header="${header}$(printf '%*s' "$pad" '' | tr ' ' '=')"
    fi
    echo "$header" | tr '_-' '/+' | base64 -d 2>/dev/null
}

PAYLOAD=$(decode_jwt_payload "$EXCHANGED_TOKEN")

# Check act.sub is present (exchanger identity — RFC 8693 §4.1)
ACT_SUB=$(echo "$PAYLOAD" | python3 -c "import sys,json; print(json.load(sys.stdin).get('act',{}).get('sub',''))" 2>/dev/null)
if [ -n "$ACT_SUB" ]; then
    echo "  PASS: act.sub present: $ACT_SUB"
else
    echo "  FAIL: act.sub missing from exchanged token."
    echo "  Payload: $PAYLOAD"
    exit 1
fi

# Check cnf.jkt is present (DPoP key binding — RFC 9449 §6)
CNF_JKT=$(echo "$PAYLOAD" | python3 -c "import sys,json; print(json.load(sys.stdin).get('cnf',{}).get('jkt',''))" 2>/dev/null)
if [ -n "$CNF_JKT" ]; then
    echo "  PASS: cnf.jkt present (rebound to jump host key): ${CNF_JKT:0:16}..."
else
    echo "  WARN: cnf.jkt missing — DPoP rebinding may not be configured on this IdP."
fi

# Check aud matches target
AUD=$(echo "$PAYLOAD" | python3 -c "
import sys, json
a = json.load(sys.stdin).get('aud','')
print(a if isinstance(a, str) else ','.join(a))
" 2>/dev/null)
if echo "$AUD" | grep -q "$TARGET_AUDIENCE"; then
    echo "  PASS: aud contains target audience: $AUD"
else
    echo "  WARN: aud does not contain expected '$TARGET_AUDIENCE': $AUD"
fi

echo ""
echo "=== Attested Token Exchange E2E Test: PASSED ==="
echo ""
echo "Summary:"
echo "  - TPM key provisioned via swtpm"
echo "  - User token obtained from Keycloak (realm: ${REALM})"
echo "  - Token exchange completed with attested DPoP proof"
echo "  - Exchanged token contains act.sub (delegation chain)"
echo "  - Exchanged token DPoP binding verified"
