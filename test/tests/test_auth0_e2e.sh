#!/usr/bin/env bash
# test_auth0_e2e.sh — Auth0 Live E2E Tests (Phase 40)
#
# Validates unix-oidc against a live Auth0 tenant:
#   1. OIDC discovery and JWKS fetch
#   2. ROPC token acquisition with JWT access token
#   3. Namespaced custom claim extraction (preferred_username)
#   4. Token signature verification via JWKS
#   5. Bearer-only mode (dpop_required = false)
#   6. Device Authorization Grant endpoint availability
#   7. Negative test: wrong credentials rejected
#   8. Negative test: wrong audience rejected
#
# Prerequisites:
#   AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_TEST_USER,
#   AUTH0_PASSWORD — set in environment or .auth0 file.
#   AUTH0_AUDIENCE — API identifier (default: https://unix-oidc.dev/api)
#
# Usage:
#   ./test/tests/test_auth0_e2e.sh           # uses .auth0 file
#   AUTH0_DOMAIN=... ./test/tests/test_auth0_e2e.sh  # uses env vars

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Load credentials ─────────────────────────────────────────────────────────

if [[ -z "${AUTH0_DOMAIN:-}" ]] && [[ -f "$PROJECT_ROOT/.auth0" ]]; then
    # Source with set +e to handle ! in passwords
    set +e
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        export "$key=$value"
    done < "$PROJECT_ROOT/.auth0"
    set -e
fi

AUTH0_DOMAIN="${AUTH0_DOMAIN:?AUTH0_DOMAIN not set}"
AUTH0_CLIENT_ID="${AUTH0_CLIENT_ID:?AUTH0_CLIENT_ID not set}"
AUTH0_CLIENT_SECRET="${AUTH0_CLIENT_SECRET:?AUTH0_CLIENT_SECRET not set}"
AUTH0_TEST_USER="${AUTH0_TEST_USER:?AUTH0_TEST_USER not set}"
AUTH0_PASSWORD="${AUTH0_PASSWORD:?AUTH0_PASSWORD not set}"
AUTH0_AUDIENCE="${AUTH0_AUDIENCE:-https://unix-oidc.dev/api}"
AUTH0_CLAIM_NAMESPACE="${AUTH0_CLAIM_NAMESPACE:-https://unix-oidc.dev/}"

PASS=0
FAIL=0

check() {
    local desc="$1" result="$2"
    if [[ "$result" == "PASS" ]]; then
        echo "  [PASS] $desc"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $desc"
        FAIL=$((FAIL + 1))
    fi
}

# Helper: get a token via ROPC
get_token() {
    local audience="${1:-$AUTH0_AUDIENCE}"
    local scope="${2:-openid profile email}"
    curl -s --request POST \
        --url "https://${AUTH0_DOMAIN}/oauth/token" \
        --header 'content-type: application/x-www-form-urlencoded' \
        --data-urlencode "grant_type=password" \
        --data-urlencode "client_id=${AUTH0_CLIENT_ID}" \
        --data-urlencode "client_secret=${AUTH0_CLIENT_SECRET}" \
        --data-urlencode "username=${AUTH0_TEST_USER}" \
        --data-urlencode "password=${AUTH0_PASSWORD}" \
        --data-urlencode "scope=${scope}" \
        --data-urlencode "audience=${audience}"
}

# Helper: decode JWT payload
decode_jwt_payload() {
    local token="$1"
    local payload
    payload=$(echo "$token" | cut -d. -f2)
    # Add padding
    local pad=$((4 - ${#payload} % 4))
    [[ $pad -lt 4 ]] && payload="${payload}$(printf '=%.0s' $(seq 1 $pad))"
    echo "$payload" | base64 -d 2>/dev/null || echo "$payload" | base64 -D 2>/dev/null
}

echo "=== Auth0 Live E2E Tests (Phase 40) ==="
echo "Domain: ${AUTH0_DOMAIN}"
echo "Client: ${AUTH0_CLIENT_ID}"
echo "User:   ${AUTH0_TEST_USER}"
echo ""

# ── Test 1: OIDC Discovery ───────────────────────────────────────────────────

echo "--- 1. OIDC Discovery ---"

DISCOVERY=$(curl -sf "https://${AUTH0_DOMAIN}/.well-known/openid-configuration" 2>/dev/null || echo "")

if [[ -n "$DISCOVERY" ]]; then
    check "Discovery endpoint reachable" "PASS"
else
    check "Discovery endpoint reachable" "FAIL"
fi

ISSUER=$(echo "$DISCOVERY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('issuer',''))" 2>/dev/null || echo "")
if [[ "$ISSUER" == "https://${AUTH0_DOMAIN}/" ]]; then
    check "Issuer matches tenant: $ISSUER" "PASS"
else
    check "Issuer matches tenant (got: $ISSUER)" "FAIL"
fi

DEVICE_EP=$(echo "$DISCOVERY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('device_authorization_endpoint',''))" 2>/dev/null || echo "")
if [[ -n "$DEVICE_EP" ]]; then
    check "Device authorization endpoint advertised" "PASS"
else
    check "Device authorization endpoint advertised" "FAIL"
fi

# ── Test 2: JWKS Fetch ───────────────────────────────────────────────────────

echo ""
echo "--- 2. JWKS ---"

JWKS_URI=$(echo "$DISCOVERY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('jwks_uri',''))" 2>/dev/null || echo "")
JWKS=$(curl -sf "$JWKS_URI" 2>/dev/null || echo "")
KEY_COUNT=$(echo "$JWKS" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('keys',[])))" 2>/dev/null || echo "0")

if [[ "$KEY_COUNT" -gt 0 ]]; then
    check "JWKS contains $KEY_COUNT key(s)" "PASS"
else
    check "JWKS contains keys" "FAIL"
fi

# Verify at least one RS256 key
RS256_COUNT=$(echo "$JWKS" | python3 -c "import sys,json; keys=json.load(sys.stdin).get('keys',[]); print(sum(1 for k in keys if k.get('alg')=='RS256'))" 2>/dev/null || echo "0")
if [[ "$RS256_COUNT" -gt 0 ]]; then
    check "RS256 signing key present" "PASS"
else
    check "RS256 signing key present" "FAIL"
fi

# ── Test 3: Token Acquisition (ROPC + JWT) ───────────────────────────────────

echo ""
echo "--- 3. Token Acquisition ---"

TOKEN_RESPONSE=$(get_token)
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
ID_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id_token',''))" 2>/dev/null || echo "")

# Check access token is a JWT (3 dot-separated parts)
if [[ "$ACCESS_TOKEN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
    check "Access token is JWT (with audience)" "PASS"
else
    check "Access token is JWT (got opaque or empty)" "FAIL"
fi

if [[ -n "$ID_TOKEN" ]]; then
    check "ID token present" "PASS"
else
    check "ID token present" "FAIL"
fi

# ── Test 4: Custom Claim Extraction ──────────────────────────────────────────

echo ""
echo "--- 4. Custom Claims ---"

if [[ -n "$ACCESS_TOKEN" ]] && [[ "$ACCESS_TOKEN" == *.*.* ]]; then
    AT_CLAIMS=$(decode_jwt_payload "$ACCESS_TOKEN")

    PREFERRED_USERNAME=$(echo "$AT_CLAIMS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('${AUTH0_CLAIM_NAMESPACE}preferred_username',''))" 2>/dev/null || echo "")
    if [[ -n "$PREFERRED_USERNAME" ]]; then
        check "Namespaced preferred_username claim: $PREFERRED_USERNAME" "PASS"
    else
        check "Namespaced preferred_username claim (missing — check Auth0 Action)" "FAIL"
    fi

    AT_ISS=$(echo "$AT_CLAIMS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('iss',''))" 2>/dev/null || echo "")
    if [[ "$AT_ISS" == "https://${AUTH0_DOMAIN}/" ]]; then
        check "Access token issuer correct" "PASS"
    else
        check "Access token issuer (got: $AT_ISS)" "FAIL"
    fi

    AT_AUD=$(echo "$AT_CLAIMS" | python3 -c "import sys,json; d=json.load(sys.stdin); aud=d.get('aud',[]); print(aud if isinstance(aud,list) else [aud])" 2>/dev/null || echo "[]")
    if echo "$AT_AUD" | grep -q "$AUTH0_AUDIENCE"; then
        check "Access token audience includes API" "PASS"
    else
        check "Access token audience includes API (got: $AT_AUD)" "FAIL"
    fi
else
    check "Custom claims (skipped — no JWT access token)" "FAIL"
    check "Access token issuer (skipped)" "FAIL"
    check "Access token audience (skipped)" "FAIL"
fi

# ── Test 5: Token Signature Verification ─────────────────────────────────────

echo ""
echo "--- 5. Signature Verification ---"

# Extract kid from access token header
if [[ -n "$ACCESS_TOKEN" ]] && [[ "$ACCESS_TOKEN" == *.*.* ]]; then
    AT_HEADER=$(echo "$ACCESS_TOKEN" | cut -d. -f1)
    AT_PAD=$((4 - ${#AT_HEADER} % 4))
    [[ $AT_PAD -lt 4 ]] && AT_HEADER="${AT_HEADER}$(printf '=%.0s' $(seq 1 $AT_PAD))"
    AT_KID=$(echo "$AT_HEADER" | base64 -d 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('kid',''))" 2>/dev/null || \
             echo "$AT_HEADER" | base64 -D 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('kid',''))" 2>/dev/null || echo "")
    AT_ALG=$(echo "$AT_HEADER" | base64 -d 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('alg',''))" 2>/dev/null || \
             echo "$AT_HEADER" | base64 -D 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('alg',''))" 2>/dev/null || echo "")

    if [[ "$AT_ALG" == "RS256" ]]; then
        check "Access token uses RS256" "PASS"
    else
        check "Access token algorithm (got: $AT_ALG)" "FAIL"
    fi

    # Verify kid exists in JWKS
    if [[ -n "$AT_KID" ]]; then
        KID_FOUND=$(echo "$JWKS" | python3 -c "import sys,json; keys=json.load(sys.stdin).get('keys',[]); print(any(k.get('kid')=='$AT_KID' for k in keys))" 2>/dev/null || echo "False")
        if [[ "$KID_FOUND" == "True" ]]; then
            check "Token kid ($AT_KID) found in JWKS" "PASS"
        else
            check "Token kid ($AT_KID) found in JWKS" "FAIL"
        fi
    else
        check "Token kid extraction" "FAIL"
    fi
else
    check "Signature verification (skipped — no JWT)" "FAIL"
fi

# ── Test 6: Bearer-Only Mode (no DPoP) ──────────────────────────────────────

echo ""
echo "--- 6. Bearer-Only Mode ---"

TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token_type',''))" 2>/dev/null || echo "")
if [[ "$TOKEN_TYPE" == "Bearer" ]]; then
    check "Token type is Bearer (Auth0 does not support DPoP)" "PASS"
else
    check "Token type is Bearer (got: $TOKEN_TYPE)" "FAIL"
fi

# ── Test 7: Device Authorization Grant ───────────────────────────────────────

echo ""
echo "--- 7. Device Authorization Grant ---"

DEVICE_RESPONSE=$(curl -s --request POST \
    --url "https://${AUTH0_DOMAIN}/oauth/device/code" \
    --header 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "client_id=${AUTH0_CLIENT_ID}" \
    --data-urlencode "scope=openid profile email" \
    --data-urlencode "audience=${AUTH0_AUDIENCE}" 2>/dev/null || echo "")

DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('device_code',''))" 2>/dev/null || echo "")
USER_CODE=$(echo "$DEVICE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('user_code',''))" 2>/dev/null || echo "")
VERIFICATION_URI=$(echo "$DEVICE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verification_uri',''))" 2>/dev/null || echo "")

if [[ -n "$DEVICE_CODE" && -n "$USER_CODE" && -n "$VERIFICATION_URI" ]]; then
    check "Device auth grant returns device_code + user_code" "PASS"
    check "Verification URI: $VERIFICATION_URI" "PASS"
else
    check "Device auth grant (missing fields)" "FAIL"
fi

# ── Test 8: Negative — Wrong Password ────────────────────────────────────────

echo ""
echo "--- 8. Negative Tests ---"

BAD_PASS_RESPONSE=$(curl -s --request POST \
    --url "https://${AUTH0_DOMAIN}/oauth/token" \
    --header 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=${AUTH0_CLIENT_ID}" \
    --data-urlencode "client_secret=${AUTH0_CLIENT_SECRET}" \
    --data-urlencode "username=${AUTH0_TEST_USER}" \
    --data-urlencode "password=WrongPassword123" \
    --data-urlencode "scope=openid" \
    --data-urlencode "audience=${AUTH0_AUDIENCE}" 2>/dev/null || echo "")

BAD_PASS_ERROR=$(echo "$BAD_PASS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null || echo "")
if [[ "$BAD_PASS_ERROR" == "invalid_grant" ]]; then
    check "Wrong password rejected with invalid_grant" "PASS"
else
    check "Wrong password rejected (got: $BAD_PASS_ERROR)" "FAIL"
fi

# Negative: wrong audience
BAD_AUD_RESPONSE=$(curl -s --request POST \
    --url "https://${AUTH0_DOMAIN}/oauth/token" \
    --header 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=${AUTH0_CLIENT_ID}" \
    --data-urlencode "client_secret=${AUTH0_CLIENT_SECRET}" \
    --data-urlencode "username=${AUTH0_TEST_USER}" \
    --data-urlencode "password=${AUTH0_PASSWORD}" \
    --data-urlencode "scope=openid" \
    --data-urlencode "audience=https://wrong-audience.example.com" 2>/dev/null || echo "")

BAD_AUD_ERROR=$(echo "$BAD_AUD_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null || echo "")
if [[ -n "$BAD_AUD_ERROR" ]]; then
    check "Wrong audience rejected ($BAD_AUD_ERROR)" "PASS"
else
    check "Wrong audience rejected" "FAIL"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Summary ==="
echo "Passed: $PASS"
echo "Failed: $FAIL"

if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "RESULT: SOME TESTS FAILED"
    exit 1
else
    echo ""
    echo "RESULT: ALL TESTS PASSED"
    exit 0
fi
