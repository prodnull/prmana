#!/bin/bash
# test/tests/test_dpop_binding.sh
# DPoP-bound token E2E validation against Keycloak
#
# Validates that Keycloak issues tokens with cnf.jkt matching the DPoP proof's
# JWK thumbprint (RFC 9449 + RFC 7638), and rejects requests without a DPoP
# proof when dpop.bound.access.tokens is enabled.
#
# Prerequisites: curl, jq, openssl, xxd

set -e

# Configuration (env vars with defaults matching prmana-test realm)
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-prmana-test}"
CLIENT_ID="${CLIENT_ID:-prmana}"
CLIENT_SECRET="${CLIENT_SECRET:-prmana-test-secret}"
TEST_USERNAME="${TEST_USERNAME:-testuser}"
TEST_PASSWORD="${TEST_PASSWORD:-testpass}"

TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"

# Temp dir for key material; cleaned on EXIT
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT
KEY_FILE="$TEMP_DIR/dpop_key.pem"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

# ---- Prerequisites ----
for cmd in curl jq openssl xxd; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not installed" >&2
        exit 1
    fi
done

# ---- Helpers (same patterns as test_token_exchange.sh) ----

base64url_encode() {
    local input="${1:-$(cat)}"
    # tr -d '\n' removes the trailing newline macOS base64 appends after each output line
    echo -n "$input" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

base64url_decode() {
    local input="$1"
    local padding=$((4 - ${#input} % 4))
    if [ "$padding" -ne 4 ]; then
        input="${input}$(printf '%*s' "$padding" '' | tr ' ' '=')"
    fi
    echo -n "$input" | tr '_-' '/+' | base64 -d 2>/dev/null || echo -n "$input" | tr '_-' '/+' | base64 -D
}

# ---- Step 1: Generate P-256 EC keypair ----
echo "=== DPoP Binding E2E Test ==="
echo "Token endpoint: $TOKEN_ENDPOINT"
echo ""

openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_FILE" 2>/dev/null

# Extract x, y coordinates from uncompressed EC point (04 || x[32] || y[32])
# Pipe directly to base64 to avoid bash variable assignment corrupting binary bytes
# containing backslash sequences (0x5c 0x30 = \0 → null byte truncation).
X_B64=$(openssl ec -in "$KEY_FILE" -pubout -outform DER 2>/dev/null | tail -c 64 | head -c 32 | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
Y_B64=$(openssl ec -in "$KEY_FILE" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')

# ---- Step 2: Compute JWK thumbprint (RFC 7638) ----
# Canonical JSON with members in lexicographic order: crv, kty, x, y
CANONICAL="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"$X_B64\",\"y\":\"$Y_B64\"}"
THUMBPRINT=$(echo -n "$CANONICAL" | openssl dgst -sha256 -binary | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
echo "Computed JWK thumbprint: $THUMBPRINT"

# ---- Step 3: Build and sign DPoP proof JWT ----
JWK="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"$X_B64\",\"y\":\"$Y_B64\"}"
JTI=$(openssl rand -hex 16)
IAT=$(date +%s)

HEADER=$(echo -n "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":$JWK}" | base64url_encode)
PAYLOAD=$(echo -n "{\"jti\":\"$JTI\",\"htm\":\"POST\",\"htu\":\"$TOKEN_ENDPOINT\",\"iat\":$IAT}" | base64url_encode)
SIGNING_INPUT="${HEADER}.${PAYLOAD}"

# Sign with ES256 and convert DER signature to JWS format (R || S, each 32 bytes)
DER_SIG=$(echo -n "$SIGNING_INPUT" | openssl dgst -sha256 -sign "$KEY_FILE" | xxd -p | tr -d '\n')
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

# Pad/trim to exactly 32 bytes each
R_HEX=$(printf '%064s' "$R_HEX" | tr ' ' '0' | tail -c 64)
S_HEX=$(printf '%064s' "$S_HEX" | tr ' ' '0' | tail -c 64)
SIGNATURE=$(echo -n "${R_HEX}${S_HEX}" | xxd -r -p | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')

DPOP_PROOF="${SIGNING_INPUT}.${SIGNATURE}"

# ---- Step 4: Request token WITH DPoP proof ----
echo ""
echo "--- Positive test: token request with DPoP proof ---"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "DPoP: $DPOP_PROOF" \
    -d "grant_type=password" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "username=$TEST_USERNAME" \
    -d "password=$TEST_PASSWORD" \
    -d "scope=openid")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    pass "Token request with DPoP returned 200"
else
    fail "Token request with DPoP returned $HTTP_CODE (expected 200)"
    echo "Response: $BODY"
fi

ACCESS_TOKEN=$(echo "$BODY" | jq -r '.access_token // empty')
if [ -z "$ACCESS_TOKEN" ]; then
    fail "No access_token in response"
    echo "Response: $BODY"
    exit 1
fi

# ---- Step 5: Validate cnf.jkt in the access token ----
# Decode the JWT payload (second dot-separated segment)
TOKEN_PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d. -f2)
CNF_JKT=$(base64url_decode "$TOKEN_PAYLOAD" | jq -r '.cnf.jkt // empty')

if [ -z "$CNF_JKT" ]; then
    fail "Access token missing cnf.jkt claim"
elif [ "$CNF_JKT" = "$THUMBPRINT" ]; then
    pass "cnf.jkt matches computed JWK thumbprint"
    echo "  cnf.jkt:    $CNF_JKT"
    echo "  thumbprint: $THUMBPRINT"
else
    fail "cnf.jkt mismatch"
    echo "  cnf.jkt:    $CNF_JKT"
    echo "  thumbprint: $THUMBPRINT"
fi

# ---- Step 6: Negative test -- request WITHOUT DPoP proof ----
echo ""
echo "--- Negative test: token request without DPoP proof ---"
NEG_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "username=$TEST_USERNAME" \
    -d "password=$TEST_PASSWORD" \
    -d "scope=openid")

NEG_HTTP_CODE=$(echo "$NEG_RESPONSE" | tail -1)

if [ "$NEG_HTTP_CODE" = "400" ]; then
    pass "Token request without DPoP correctly rejected (400)"
else
    fail "Token request without DPoP returned $NEG_HTTP_CODE (expected 400)"
    echo "Response: $(echo "$NEG_RESPONSE" | sed '$d')"
fi

# ---- Summary ----
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
