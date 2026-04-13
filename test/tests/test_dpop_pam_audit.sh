#!/bin/bash
# test/tests/test_dpop_pam_audit.sh
# KCDPOP-02: DPoP-bound token through PAM validation with audit event verification.
#
# Validates the full chain:
#   1. Acquire DPoP-bound token from Keycloak via direct grant (test-only)
#   2. Send token through SSH -> PAM authentication
#   3. Parse SSH_LOGIN_SUCCESS audit event JSON with jq
#   4. Assert dpop_thumbprint field is present and matches computed JWK thumbprint
#
# Prerequisites:
#   - docker-compose.e2e.yaml stack running and healthy
#   - jq installed
#   - openssl installed (for EC key generation)
#
# Environment variables (defaults match docker-compose.e2e.yaml fixtures):
#   KEYCLOAK_URL  - Keycloak base URL (default: http://localhost:8080)
#   REALM         - Keycloak realm (default: prmana)
#   CLIENT_ID     - OIDC client ID (default: prmana)
#   CLIENT_SECRET - OIDC client secret (default: prmana-test-secret)
#   TEST_USERNAME - Test user (default: testuser)
#   TEST_PASSWORD - Test user password (default: testpass)
#   SSH_PORT      - SSH port on test host (default: 2222)
#   COMPOSE_FILE  - Docker compose file (default: docker-compose.e2e.yaml)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-prmana}"
CLIENT_ID="${CLIENT_ID:-prmana}"
CLIENT_SECRET="${CLIENT_SECRET:-prmana-test-secret}"
TEST_USERNAME="${TEST_USERNAME:-testuser}"
TEST_PASSWORD="${TEST_PASSWORD:-testpass}"
SSH_PORT="${SSH_PORT:-2222}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.e2e.yaml}"

PASS=0
FAIL=0

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

echo "=== DPoP PAM Audit Event Integration Test (KCDPOP-02) ==="
echo "Keycloak: $KEYCLOAK_URL"
echo "Realm: $REALM"
echo "Client: $CLIENT_ID"
echo ""

# ---- Step 1: Generate ephemeral EC P-256 key pair ----
echo "Step 1: Generating ephemeral EC P-256 key pair..."

TMPDIR_KEYS=$(mktemp -d)
trap 'rm -rf "$TMPDIR_KEYS"' EXIT

openssl ecparam -name prime256v1 -genkey -noout -out "$TMPDIR_KEYS/ec_private.pem" 2>/dev/null
openssl ec -in "$TMPDIR_KEYS/ec_private.pem" -pubout -out "$TMPDIR_KEYS/ec_public.pem" 2>/dev/null

# Extract x and y coordinates for JWK
EC_PARAMS=$(openssl ec -in "$TMPDIR_KEYS/ec_private.pem" -text -noout 2>/dev/null)

# Use openssl to get the raw public key bytes and extract x,y
PUB_HEX=$(openssl ec -in "$TMPDIR_KEYS/ec_private.pem" -text -noout 2>/dev/null | \
    grep -A 5 "^pub:" | tail -n +2 | tr -d ' :\n')

# Remove the 04 prefix (uncompressed point indicator)
PUB_HEX="${PUB_HEX#04}"

# Split into x (first 32 bytes = 64 hex chars) and y (next 32 bytes)
X_HEX="${PUB_HEX:0:64}"
Y_HEX="${PUB_HEX:64:64}"

# Convert hex to base64url
hex_to_base64url() {
    echo -n "$1" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '='
}

X_B64=$(hex_to_base64url "$X_HEX")
Y_B64=$(hex_to_base64url "$Y_HEX")

echo "  EC key generated (x: ${X_B64:0:12}..., y: ${Y_B64:0:12}...)"

# ---- Step 2: Compute JWK thumbprint (RFC 7638) ----
echo "Step 2: Computing JWK thumbprint..."

# Canonical JWK representation per RFC 7638 §3.2
CANONICAL_JWK="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"${X_B64}\",\"y\":\"${Y_B64}\"}"
COMPUTED_THUMBPRINT=$(printf '%s' "$CANONICAL_JWK" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')

echo "  Computed thumbprint: $COMPUTED_THUMBPRINT"

# ---- Step 3: Build DPoP proof JWT ----
echo "Step 3: Building DPoP proof JWT..."

base64url_encode() {
    base64 | tr '+/' '-_' | tr -d '='
}

DPOP_HEADER=$(printf '{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}}' "$X_B64" "$Y_B64" | base64url_encode)
NOW=$(date +%s)
JTI=$(openssl rand -hex 16)
TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"
DPOP_PAYLOAD=$(printf '{"jti":"%s","htm":"POST","htu":"%s","iat":%d}' "$JTI" "$TOKEN_ENDPOINT" "$NOW" | base64url_encode)

SIGNING_INPUT="${DPOP_HEADER}.${DPOP_PAYLOAD}"

# Sign with ES256 and convert DER signature to JWS format (R || S, each 32 bytes).
# Pattern from test_dpop_binding.sh (proven in CI).
DER_SIG=$(printf '%s' "$SIGNING_INPUT" | openssl dgst -sha256 -sign "$TMPDIR_KEYS/ec_private.pem" | xxd -p | tr -d '\n')
# Parse DER: 30 <len> 02 <r_len> <r_bytes> 02 <s_len> <s_bytes>
# Skip SEQUENCE header (30 XX) = 4 hex chars, then INTEGER tag (02) = 2 hex chars → offset 6
OFFSET=6
R_LEN=$((16#${DER_SIG:$OFFSET:2}))
OFFSET=$((OFFSET + 2))
R_HEX="${DER_SIG:$OFFSET:$((R_LEN * 2))}"
OFFSET=$((OFFSET + R_LEN * 2 + 2))
S_LEN=$((16#${DER_SIG:$OFFSET:2}))
OFFSET=$((OFFSET + 2))
S_HEX="${DER_SIG:$OFFSET:$((S_LEN * 2))}"
# Pad/trim to exactly 32 bytes (64 hex chars) each — handles leading-zero ASN.1 integers
R_HEX=$(printf '%064s' "$R_HEX" | tr ' ' '0' | tail -c 64)
S_HEX=$(printf '%064s' "$S_HEX" | tr ' ' '0' | tail -c 64)
SIGNATURE=$(echo -n "${R_HEX}${S_HEX}" | xxd -r -p | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')

DPOP_PROOF="${SIGNING_INPUT}.${SIGNATURE}"
echo "  DPoP proof built (jti: ${JTI:0:12}...)"

# ---- Step 4: Acquire DPoP-bound token from Keycloak ----
echo "Step 4: Acquiring DPoP-bound token..."

TOKEN_RESPONSE=$(curl -s -X POST "$TOKEN_ENDPOINT" \
    -H "DPoP: $DPOP_PROOF" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "username=$TEST_USERNAME" \
    -d "password=$TEST_PASSWORD" \
    -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE=$(echo "$TOKEN_RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$TOKEN_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then
    fail "Token request failed with HTTP $HTTP_CODE: $RESPONSE_BODY"
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

ACCESS_TOKEN=$(echo "$RESPONSE_BODY" | jq -r '.access_token // empty')
TOKEN_TYPE=$(echo "$RESPONSE_BODY" | jq -r '.token_type // empty')

if [ -z "$ACCESS_TOKEN" ]; then
    fail "No access_token in response"
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

pass "Token acquired (type: $TOKEN_TYPE)"

# ---- Step 5: Validate cnf.jkt in the access token ----
echo "Step 5: Validating cnf.jkt in access token..."

TOKEN_PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d. -f2)
# Add padding if needed
PADDED_PAYLOAD="$TOKEN_PAYLOAD"
case $((${#PADDED_PAYLOAD} % 4)) in
    2) PADDED_PAYLOAD="${PADDED_PAYLOAD}==" ;;
    3) PADDED_PAYLOAD="${PADDED_PAYLOAD}=" ;;
esac

CNF_JKT=$(echo "$PADDED_PAYLOAD" | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r '.cnf.jkt // empty')

if [ -z "$CNF_JKT" ]; then
    fail "Access token missing cnf.jkt claim"
elif [ "$CNF_JKT" = "$COMPUTED_THUMBPRINT" ]; then
    pass "cnf.jkt matches computed JWK thumbprint"
    echo "  cnf.jkt:    $CNF_JKT"
    echo "  computed:   $COMPUTED_THUMBPRINT"
else
    fail "cnf.jkt mismatch"
    echo "  cnf.jkt:    $CNF_JKT"
    echo "  computed:   $COMPUTED_THUMBPRINT"
fi

# ---- Step 6: Clear audit log in E2E container ----
echo "Step 6: Clearing audit log in E2E container..."

CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q test-host-e2e 2>/dev/null || true)
if [ -z "$CONTAINER" ]; then
    fail "test-host-e2e container not found — is docker-compose.e2e.yaml running?"
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

docker exec "$CONTAINER" bash -c 'truncate -s 0 /var/log/prmana-audit.log 2>/dev/null || true'
pass "Audit log cleared"

# ---- Step 7: Send DPoP-bound token through SSH -> PAM ----
echo "Step 7: Authenticating via SSH with DPoP-bound token..."

# Write askpass helper that returns the token
ASKPASS_SCRIPT="$TMPDIR_KEYS/askpass.sh"
cat > "$ASKPASS_SCRIPT" << ASKEOF
#!/bin/bash
echo "$ACCESS_TOKEN"
ASKEOF
chmod +x "$ASKPASS_SCRIPT"

SSH_RESULT=$(SSH_ASKPASS="$ASKPASS_SCRIPT" SSH_ASKPASS_REQUIRE=force \
    setsid ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p "$SSH_PORT" "$TEST_USERNAME@localhost" "echo authenticated" 2>&1 || true)

if echo "$SSH_RESULT" | grep -q "authenticated"; then
    pass "SSH authentication succeeded with DPoP-bound token"
else
    # Authentication may fail if PAM isn't configured for keyboard-interactive with token.
    # In that case, we still check the audit log for the attempt.
    echo "  Note: SSH session did not complete (expected if PAM not fully configured for E2E)"
    echo "  Checking audit log for authentication attempt..."
fi

# ---- Step 8: Parse audit event and verify dpop_thumbprint ----
echo "Step 8: Verifying dpop_thumbprint in audit event..."

# Give PAM a moment to write the audit event
sleep 1

AUDIT_LOG=$(docker exec "$CONTAINER" cat /var/log/prmana-audit.log 2>/dev/null || true)

if [ -z "$AUDIT_LOG" ]; then
    fail "Audit log is empty — no authentication events recorded"
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

# Parse the SSH_LOGIN_SUCCESS event with jq (D-03: structured assertion, not grep)
LOGIN_EVENT=$(echo "$AUDIT_LOG" | jq -r 'select(.event == "SSH_LOGIN_SUCCESS")' 2>/dev/null | tail -1)

if [ -z "$LOGIN_EVENT" ]; then
    fail "No SSH_LOGIN_SUCCESS audit event found in log"
    echo "  Audit log contents:"
    echo "$AUDIT_LOG" | head -5
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

pass "SSH_LOGIN_SUCCESS audit event found"

# Verify dpop_thumbprint field exists and is non-null
AUDIT_THUMBPRINT=$(echo "$LOGIN_EVENT" | jq -r '.dpop_thumbprint // empty')

if [ -z "$AUDIT_THUMBPRINT" ] || [ "$AUDIT_THUMBPRINT" = "null" ]; then
    fail "Audit event dpop_thumbprint is missing or null"
    echo "  Event: $LOGIN_EVENT"
else
    pass "Audit event contains dpop_thumbprint: ${AUDIT_THUMBPRINT:0:20}..."
fi

# Verify dpop_thumbprint matches the computed JWK thumbprint
if [ "$AUDIT_THUMBPRINT" = "$COMPUTED_THUMBPRINT" ]; then
    pass "Audit dpop_thumbprint matches computed JWK thumbprint"
else
    fail "Audit dpop_thumbprint does not match computed thumbprint"
    echo "  audit:    $AUDIT_THUMBPRINT"
    echo "  computed: $COMPUTED_THUMBPRINT"
fi

# ---- Results ----
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
