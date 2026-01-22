#!/bin/bash
# deploy/idp-templates/keycloak/test/verify.sh
#
# Verification script for Keycloak IdP template
# Tests OIDC configuration, Device Authorization Grant, and token claims
#
# Usage:
#   ./verify.sh                          # Run all tests
#   ./verify.sh --skip-pamtester         # Skip pamtester tests
#   ./verify.sh --verbose                # Show detailed output
#
# Environment variables:
#   KEYCLOAK_URL    - Keycloak base URL (default: http://localhost:8080)
#   REALM           - Keycloak realm name (default: unix-oidc-test)
#   CLIENT_ID       - OIDC client ID (default: unix-oidc)
#   CLIENT_SECRET   - OIDC client secret (default: unix-oidc-test-secret)
#   TEST_USER       - Test username (default: testuser)
#   TEST_PASS       - Test password (default: testpass)

set -euo pipefail

# Configuration with defaults
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-unix-oidc-test}"
CLIENT_ID="${CLIENT_ID:-unix-oidc}"
CLIENT_SECRET="${CLIENT_SECRET:-unix-oidc-test-secret}"
TEST_USER="${TEST_USER:-testuser}"
TEST_PASS="${TEST_PASS:-testpass}"

# Options
SKIP_PAMTESTER=false
VERBOSE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-pamtester)
            SKIP_PAMTESTER=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            head -20 "$0" | tail -17
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Colors (if terminal supports them)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Derived URLs
OIDC_DISCOVERY_URL="${KEYCLOAK_URL}/realms/${REALM}/.well-known/openid-configuration"
TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"

# Test results
PASSED=0
FAILED=0
SKIPPED=0

log_info() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED=$((FAILED + 1))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    SKIPPED=$((SKIPPED + 1))
}

# Helper: decode JWT payload (base64url decode)
decode_jwt_payload() {
    local jwt="$1"
    local payload
    payload=$(echo "$jwt" | cut -d'.' -f2)
    # Add padding if needed and decode
    local padded="${payload}$(printf '%s' '==' | cut -c 1-$((4 - ${#payload} % 4)))"
    echo "$padded" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "{}"
}

# ============================================================================
# Test 1: OIDC Discovery Endpoint
# ============================================================================
test_oidc_discovery() {
    echo ""
    echo -e "${BLUE}=== Test: OIDC Discovery Endpoint ===${NC}"

    log_info "Fetching discovery document from: $OIDC_DISCOVERY_URL"

    local response
    local http_code

    # Fetch with error handling
    response=$(curl -s -w "\n%{http_code}" "$OIDC_DISCOVERY_URL" 2>&1) || {
        log_fail "Failed to connect to Keycloak at $KEYCLOAK_URL"
        return 1
    }

    http_code=$(echo "$response" | tail -1)
    response=$(echo "$response" | sed '$d')

    if [ "$http_code" != "200" ]; then
        log_fail "OIDC discovery returned HTTP $http_code (expected 200)"
        return 1
    fi

    # Verify it's valid JSON
    if ! echo "$response" | jq -e . >/dev/null 2>&1; then
        log_fail "OIDC discovery response is not valid JSON"
        return 1
    fi

    # Check required fields
    local issuer
    issuer=$(echo "$response" | jq -r '.issuer // empty')
    if [ -z "$issuer" ]; then
        log_fail "OIDC discovery missing 'issuer' field"
        return 1
    fi

    log_info "Issuer: $issuer"
    log_pass "OIDC discovery endpoint accessible and valid"

    # Store discovery document for later tests
    DISCOVERY_DOC="$response"
    return 0
}

# ============================================================================
# Test 2: Device Authorization Endpoint
# ============================================================================
test_device_authorization_endpoint() {
    echo ""
    echo -e "${BLUE}=== Test: Device Authorization Endpoint ===${NC}"

    if [ -z "$DISCOVERY_DOC" ]; then
        log_fail "Discovery document not available (previous test failed)"
        return 1
    fi

    local device_endpoint
    device_endpoint=$(echo "$DISCOVERY_DOC" | jq -r '.device_authorization_endpoint // empty')

    if [ -z "$device_endpoint" ]; then
        log_fail "device_authorization_endpoint not found in OIDC discovery"
        log_info "This means Device Authorization Grant is not enabled"
        return 1
    fi

    log_info "Device Authorization Endpoint: $device_endpoint"

    # Test that endpoint responds (even without valid request)
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$device_endpoint" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=$CLIENT_ID" 2>&1) || {
        log_fail "Failed to connect to device authorization endpoint"
        return 1
    }

    # 400 is expected (missing required params), anything other than connection error is OK
    if [ "$http_code" = "000" ]; then
        log_fail "Device authorization endpoint unreachable"
        return 1
    fi

    log_info "Device endpoint returned HTTP $http_code (connection successful)"
    log_pass "Device Authorization endpoint exists and is accessible"
    return 0
}

# ============================================================================
# Test 3: Token via Password Grant
# ============================================================================
test_password_grant() {
    echo ""
    echo -e "${BLUE}=== Test: Password Grant (Resource Owner) ===${NC}"

    log_info "Requesting token for user: $TEST_USER"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X POST "$TOKEN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$CLIENT_SECRET" \
        -d "username=$TEST_USER" \
        -d "password=$TEST_PASS" \
        -d "scope=openid profile" 2>&1) || {
        log_fail "Failed to connect to token endpoint"
        return 1
    }

    http_code=$(echo "$response" | tail -1)
    response=$(echo "$response" | sed '$d')

    if [ "$http_code" != "200" ]; then
        local error
        error=$(echo "$response" | jq -r '.error_description // .error // "unknown error"' 2>/dev/null)
        log_fail "Token request failed with HTTP $http_code: $error"
        return 1
    fi

    # Extract access token
    ACCESS_TOKEN=$(echo "$response" | jq -r '.access_token // empty')
    if [ -z "$ACCESS_TOKEN" ]; then
        log_fail "Response missing access_token"
        return 1
    fi

    # Also get ID token if available
    ID_TOKEN=$(echo "$response" | jq -r '.id_token // empty')

    log_info "Access token obtained (${#ACCESS_TOKEN} chars)"
    [ -n "$ID_TOKEN" ] && log_info "ID token obtained (${#ID_TOKEN} chars)"

    log_pass "Password grant successful - tokens obtained"
    return 0
}

# ============================================================================
# Test 4: Verify Token Claims
# ============================================================================
test_token_claims() {
    echo ""
    echo -e "${BLUE}=== Test: Token Claims Verification ===${NC}"

    if [ -z "$ACCESS_TOKEN" ]; then
        log_fail "No access token available (previous test failed)"
        return 1
    fi

    # Decode the access token payload
    local payload
    payload=$(decode_jwt_payload "$ACCESS_TOKEN")

    if [ "$payload" = "{}" ]; then
        log_fail "Failed to decode access token"
        return 1
    fi

    log_info "Token payload: $(echo "$payload" | jq -c '.')"

    local test_passed=true

    # Check 'iss' (issuer) claim
    local iss
    iss=$(echo "$payload" | jq -r '.iss // empty')
    if [ -z "$iss" ]; then
        log_fail "Token missing 'iss' (issuer) claim"
        test_passed=false
    else
        local expected_issuer="${KEYCLOAK_URL}/realms/${REALM}"
        if [ "$iss" = "$expected_issuer" ]; then
            log_info "Issuer claim: $iss (matches expected)"
        else
            log_info "Issuer claim: $iss (expected: $expected_issuer)"
            # Note: issuer might differ due to hostname configuration
        fi
    fi

    # Check 'aud' (audience) claim
    local aud
    aud=$(echo "$payload" | jq -r 'if .aud | type == "array" then .aud | join(",") else .aud // empty end')
    if [ -z "$aud" ]; then
        log_fail "Token missing 'aud' (audience) claim"
        test_passed=false
    else
        if echo "$aud" | grep -q "$CLIENT_ID"; then
            log_info "Audience claim includes client_id: $aud"
        else
            echo -e "${YELLOW}[WARN]${NC} Audience claim ($aud) does not include client_id ($CLIENT_ID)"
            # This is a warning, not a failure - audience mapper may not be configured
        fi
    fi

    # Check 'preferred_username' claim (CRITICAL for unix-oidc)
    local preferred_username
    preferred_username=$(echo "$payload" | jq -r '.preferred_username // empty')
    if [ -z "$preferred_username" ]; then
        log_fail "Token missing 'preferred_username' claim (REQUIRED for unix-oidc)"
        test_passed=false
    else
        log_info "preferred_username claim: $preferred_username"
        if [ "$preferred_username" = "$TEST_USER" ]; then
            log_info "preferred_username matches test user"
        else
            log_fail "preferred_username ($preferred_username) does not match test user ($TEST_USER)"
            test_passed=false
        fi
    fi

    # Check token expiration
    local exp
    exp=$(echo "$payload" | jq -r '.exp // empty')
    if [ -n "$exp" ]; then
        local now
        now=$(date +%s)
        local remaining=$((exp - now))
        log_info "Token expires in ${remaining}s"
    fi

    if [ "$test_passed" = true ]; then
        log_pass "All required token claims present and valid"
        return 0
    else
        return 1
    fi
}

# ============================================================================
# Test 5: pamtester Integration (Optional)
# ============================================================================
test_pamtester() {
    echo ""
    echo -e "${BLUE}=== Test: pamtester Integration (Optional) ===${NC}"

    if [ "$SKIP_PAMTESTER" = true ]; then
        log_skip "pamtester test skipped (--skip-pamtester)"
        return 0
    fi

    # Check if pamtester is available
    if ! command -v pamtester >/dev/null 2>&1; then
        log_skip "pamtester not installed"
        return 0
    fi

    # Check if unix-oidc PAM module is configured
    if [ ! -f /etc/pam.d/unix-oidc ] && [ ! -f /etc/pam.d/sshd ]; then
        log_skip "No unix-oidc PAM configuration found"
        return 0
    fi

    # Check if we have an access token
    if [ -z "$ACCESS_TOKEN" ]; then
        log_skip "No access token available for pamtester"
        return 0
    fi

    log_info "Testing PAM authentication with pamtester"

    # Try to authenticate using the token as password
    # This requires PAM to be configured for unix-oidc
    local pam_service="unix-oidc"
    if [ ! -f "/etc/pam.d/$pam_service" ]; then
        pam_service="sshd"
    fi

    # Note: This test may require root privileges
    if [ "$(id -u)" -ne 0 ]; then
        log_skip "pamtester requires root privileges"
        return 0
    fi

    if echo "$ACCESS_TOKEN" | pamtester "$pam_service" "$TEST_USER" authenticate 2>/dev/null; then
        log_pass "pamtester authentication successful"
        return 0
    else
        log_fail "pamtester authentication failed"
        return 1
    fi
}

# ============================================================================
# Main
# ============================================================================

echo ""
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}  Keycloak IdP Template Verification${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""
echo "Configuration:"
echo "  Keycloak URL: $KEYCLOAK_URL"
echo "  Realm:        $REALM"
echo "  Client ID:    $CLIENT_ID"
echo "  Test User:    $TEST_USER"
echo ""

# Run tests
test_oidc_discovery
test_device_authorization_endpoint
test_password_grant
test_token_claims
test_pamtester

# Summary
echo ""
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}  Verification Summary${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""
echo -e "  Passed:  ${GREEN}$PASSED${NC}"
echo -e "  Failed:  ${RED}$FAILED${NC}"
echo -e "  Skipped: ${YELLOW}$SKIPPED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All verification tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some verification tests failed.${NC}"
    exit 1
fi
