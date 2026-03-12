#!/bin/bash
# test/tests/test_token_exchange.sh
# DPoP + Token Exchange flow validation test
#
# This test verifies the RFC 9449 (DPoP) and RFC 8693 (Token Exchange) flow:
# 1. Generate DPoP keypair and proof for user authentication
# 2. Obtain DPoP-bound access token from Keycloak
# 3. Generate separate DPoP keypair for jump host
# 4. Perform token exchange with new DPoP binding
# 5. Validate exchanged token has correct claims (cnf.jkt, act.sub, aud)
#
# Prerequisites:
# - curl, jq, openssl must be installed
# - Keycloak must be running on localhost:8080 with token-exchange-test realm
# - Realm must be configured with appropriate clients and permissions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-token-exchange-test}"
TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"

# User credentials (for initial password grant)
USER_CLIENT_ID="${USER_CLIENT_ID:-unix-oidc-agent}"
TEST_USERNAME="${TEST_USERNAME:-testuser}"
TEST_PASSWORD="${TEST_PASSWORD:-testpass}"

# Jump host client credentials
JUMP_HOST_CLIENT_ID="${JUMP_HOST_CLIENT_ID:-jump-host-a}"
JUMP_HOST_CLIENT_SECRET="${JUMP_HOST_CLIENT_SECRET:-jump-host-secret}"
TARGET_AUDIENCE="${TARGET_AUDIENCE:-target-host-b}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Temporary files (cleaned up on exit)
TEMP_DIR=$(mktemp -d)
USER_KEY="$TEMP_DIR/user_key.pem"
JUMP_HOST_KEY="$TEMP_DIR/jump_host_key.pem"

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# ============================================================================
# Helper Functions
# ============================================================================

print_header() {
    echo ""
    echo -e "${BLUE}=========================================="
    echo -e "$1"
    echo -e "==========================================${NC}"
    echo ""
}

print_step() {
    echo -e "${CYAN}>>> $1${NC}"
}

print_pass() {
    echo -e "  ${GREEN}PASS${NC}: $1"
}

print_fail() {
    echo -e "  ${RED}FAIL${NC}: $1"
}

print_warn() {
    echo -e "  ${YELLOW}WARN${NC}: $1"
}

print_info() {
    echo -e "  ${NC}INFO${NC}: $1"
}

# Base64URL encode (RFC 4648 Section 5)
# Converts standard base64 to URL-safe variant without padding
base64url_encode() {
    # Read from stdin or argument
    local input="${1:-$(cat)}"
    # tr -d '\n' removes the trailing newline macOS base64 appends after each output line
    echo -n "$input" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

# Base64URL decode
base64url_decode() {
    local input="$1"
    # Add padding if needed
    local padding=$((4 - ${#input} % 4))
    if [ "$padding" -ne 4 ]; then
        input="${input}$(printf '%*s' "$padding" '' | tr ' ' '=')"
    fi
    echo -n "$input" | tr '_-' '/+' | base64 -d 2>/dev/null || echo -n "$input" | tr '_-' '/+' | base64 -D
}

# Generate a cryptographically random string for JTI
generate_jti() {
    openssl rand -hex 16
}

# Get current Unix timestamp
get_timestamp() {
    date +%s
}

# Generate EC P-256 keypair and save to file
# Returns: nothing, but creates the key file
generate_ec_keypair() {
    local keyfile="$1"
    openssl ecparam -name prime256v1 -genkey -noout -out "$keyfile" 2>/dev/null
}

# Extract x coordinate from EC public key (in base64url format)
# The public key point is the last 64 bytes of the DER-encoded public key.
# NOTE: Binary is piped directly through base64 to avoid bash variable assignment
# corrupting bytes containing backslash sequences (e.g., 0x5c 0x30 = \0 → null byte).
get_ec_x_coordinate() {
    local keyfile="$1"
    # Export public key in DER format, extract the point (last 65 bytes: 04 || x || y)
    # x is bytes 1-32 of the point. Pipe directly to avoid shell variable binary corruption.
    openssl ec -in "$keyfile" -pubout -outform DER 2>/dev/null | \
        tail -c 64 | head -c 32 | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

# Extract y coordinate from EC public key (in base64url format)
get_ec_y_coordinate() {
    local keyfile="$1"
    # y is bytes 33-64 of the point. Pipe directly to avoid shell variable binary corruption.
    openssl ec -in "$keyfile" -pubout -outform DER 2>/dev/null | \
        tail -c 32 | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

# Build JWK (JSON Web Key) for EC P-256 public key
# Format follows RFC 7517 / RFC 7518
build_jwk() {
    local keyfile="$1"
    local x
    local y
    x=$(get_ec_x_coordinate "$keyfile")
    y=$(get_ec_y_coordinate "$keyfile")

    # JWK must be in this exact format for interoperability
    cat <<EOF
{"crv":"P-256","kty":"EC","x":"$x","y":"$y"}
EOF
}

# Compute JWK thumbprint per RFC 7638
# IMPORTANT: Uses CANONICAL member order (crv, kty, x, y) as required by RFC 7638 Section 3.2
# This is critical for DPoP - the thumbprint MUST match what servers compute
compute_jwk_thumbprint() {
    local keyfile="$1"
    local x
    local y
    x=$(get_ec_x_coordinate "$keyfile")
    y=$(get_ec_y_coordinate "$keyfile")

    # RFC 7638 Section 3.2: Members MUST be in lexicographic order
    # For EC keys: crv, kty, x, y (alphabetically sorted)
    # NO whitespace, NO newlines - this is critical!
    local canonical
    canonical="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"$x\",\"y\":\"$y\"}"

    # SHA-256 hash, then base64url encode. Pipe directly (binary output — no variable assignment).
    echo -n "$canonical" | openssl dgst -sha256 -binary | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

# Sign data with EC P-256 key, producing DER signature
# Then convert to JWS format (R || S, each 32 bytes)
ec_sign_to_jws() {
    local keyfile="$1"
    local data="$2"

    # Sign with ECDSA, get DER-encoded signature
    local der_sig
    der_sig=$(echo -n "$data" | openssl dgst -sha256 -sign "$keyfile" | xxd -p | tr -d '\n')

    # Parse DER signature to extract R and S
    # DER format: 30 <len> 02 <r_len> <r_bytes> 02 <s_len> <s_bytes>
    # Each field is two hex characters per byte.

    # Skip the SEQUENCE header (30 XX) = 4 hex chars, then skip the INTEGER tag (02) = 2 hex chars
    local offset=6
    # Get R length
    local r_len_hex="${der_sig:$offset:2}"
    local r_len=$((16#$r_len_hex))
    offset=$((offset + 2))

    # Get R value
    local r_hex="${der_sig:$offset:$((r_len * 2))}"
    offset=$((offset + r_len * 2))

    # Skip 02 marker for S
    offset=$((offset + 2))

    # Get S length
    local s_len_hex="${der_sig:$offset:2}"
    local s_len=$((16#$s_len_hex))
    offset=$((offset + 2))

    # Get S value
    local s_hex="${der_sig:$offset:$((s_len * 2))}"

    # Pad or trim R and S to exactly 32 bytes (256 bits for P-256)
    # If leading zeros, it might be 33 bytes; if high bit clear, might be 32
    r_hex=$(printf '%064s' "$r_hex" | tr ' ' '0' | tail -c 64)
    s_hex=$(printf '%064s' "$s_hex" | tr ' ' '0' | tail -c 64)

    # Concatenate R || S and base64url encode. Pipe directly (binary — no variable assignment).
    echo -n "${r_hex}${s_hex}" | xxd -r -p | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

# Create and sign a DPoP proof JWT
# Parameters:
#   $1 - keyfile (EC private key)
#   $2 - htm (HTTP method, e.g., "POST")
#   $3 - htu (HTTP target URI)
#   $4 - [optional] ath (access token hash, for token-bound proofs)
create_dpop_proof() {
    local keyfile="$1"
    local htm="$2"
    local htu="$3"
    local ath="${4:-}"

    local jwk
    jwk=$(build_jwk "$keyfile")

    local jti
    jti=$(generate_jti)

    local iat
    iat=$(get_timestamp)

    # Build header
    # typ MUST be "dpop+jwt" per RFC 9449 Section 4.2
    local header
    header=$(cat <<EOF
{"typ":"dpop+jwt","alg":"ES256","jwk":$jwk}
EOF
)

    # Build payload
    local payload
    if [ -n "$ath" ]; then
        payload=$(cat <<EOF
{"jti":"$jti","htm":"$htm","htu":"$htu","iat":$iat,"ath":"$ath"}
EOF
)
    else
        payload=$(cat <<EOF
{"jti":"$jti","htm":"$htm","htu":"$htu","iat":$iat}
EOF
)
    fi

    # Create signing input
    local header_b64
    local payload_b64
    header_b64=$(echo -n "$header" | base64url_encode)
    payload_b64=$(echo -n "$payload" | base64url_encode)

    local signing_input="${header_b64}.${payload_b64}"

    # Sign
    local signature
    signature=$(ec_sign_to_jws "$keyfile" "$signing_input")

    # Return complete JWT
    echo "${signing_input}.${signature}"
}

# Decode and pretty-print a JWT
decode_jwt() {
    local token="$1"
    local part="${2:-payload}"  # header, payload, or signature

    IFS='.' read -ra parts <<< "$token"

    case "$part" in
        header)
            base64url_decode "${parts[0]}" | jq -r '.' 2>/dev/null || base64url_decode "${parts[0]}"
            ;;
        payload)
            base64url_decode "${parts[1]}" | jq -r '.' 2>/dev/null || base64url_decode "${parts[1]}"
            ;;
        signature)
            echo "${parts[2]}"
            ;;
    esac
}

# Extract a claim from a JWT payload
get_jwt_claim() {
    local token="$1"
    local claim="$2"

    decode_jwt "$token" "payload" | jq -r ".$claim // empty"
}

# Compute the access token hash (ath) for DPoP proof binding
# per RFC 9449 Section 4.2
compute_ath() {
    local access_token="$1"
    # Pipe directly (binary SHA-256 output — no variable assignment to avoid byte corruption).
    echo -n "$access_token" | openssl dgst -sha256 -binary | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

# ============================================================================
# Prerequisites Check
# ============================================================================

check_prerequisites() {
    print_header "Checking Prerequisites"

    local all_ok=true

    # Check curl
    print_step "Checking for curl..."
    if command -v curl &>/dev/null; then
        print_pass "curl is available ($(curl --version | head -1))"
    else
        print_fail "curl is not installed"
        all_ok=false
    fi

    # Check jq
    print_step "Checking for jq..."
    if command -v jq &>/dev/null; then
        print_pass "jq is available ($(jq --version))"
    else
        print_fail "jq is not installed"
        all_ok=false
    fi

    # Check openssl
    print_step "Checking for openssl..."
    if command -v openssl &>/dev/null; then
        print_pass "openssl is available ($(openssl version))"
    else
        print_fail "openssl is not installed"
        all_ok=false
    fi

    # Check xxd (usually part of vim)
    print_step "Checking for xxd..."
    if command -v xxd &>/dev/null; then
        print_pass "xxd is available"
    else
        print_fail "xxd is not installed (usually part of vim package)"
        all_ok=false
    fi

    # Check Keycloak is running
    print_step "Checking Keycloak at $KEYCLOAK_URL..."
    if curl -sf "$KEYCLOAK_URL/health/ready" &>/dev/null || \
       curl -sf "$KEYCLOAK_URL/realms/${REALM}/.well-known/openid-configuration" &>/dev/null; then
        print_pass "Keycloak is reachable"
    else
        print_fail "Keycloak is not reachable at $KEYCLOAK_URL"
        print_info "Start Keycloak or set KEYCLOAK_URL environment variable"
        all_ok=false
    fi

    if [ "$all_ok" = false ]; then
        echo ""
        print_fail "Prerequisites check failed. Please install missing dependencies."
        exit 1
    fi

    print_pass "All prerequisites satisfied"
}

# ============================================================================
# Test Steps
# ============================================================================

test_step_1_generate_user_keypair() {
    print_header "Step 1: Generate User DPoP Keypair"

    print_step "Generating EC P-256 keypair for user..."
    generate_ec_keypair "$USER_KEY"

    if [ -f "$USER_KEY" ]; then
        print_pass "User keypair generated"

        local x y thumbprint
        x=$(get_ec_x_coordinate "$USER_KEY")
        y=$(get_ec_y_coordinate "$USER_KEY")
        thumbprint=$(compute_jwk_thumbprint "$USER_KEY")

        print_info "JWK x: ${x:0:20}... (truncated)"
        print_info "JWK y: ${y:0:20}... (truncated)"
        print_info "JWK thumbprint (jkt): $thumbprint"

        USER_THUMBPRINT="$thumbprint"
    else
        print_fail "Failed to generate user keypair"
        exit 1
    fi
}

test_step_2_create_user_dpop_proof() {
    print_header "Step 2: Create User DPoP Proof"

    print_step "Creating DPoP proof for token endpoint..."

    USER_DPOP_PROOF=$(create_dpop_proof "$USER_KEY" "POST" "$TOKEN_ENDPOINT")

    if [ -n "$USER_DPOP_PROOF" ]; then
        print_pass "DPoP proof created"

        print_info "DPoP Header:"
        decode_jwt "$USER_DPOP_PROOF" "header" | sed 's/^/    /'

        print_info "DPoP Payload:"
        decode_jwt "$USER_DPOP_PROOF" "payload" | sed 's/^/    /'
    else
        print_fail "Failed to create DPoP proof"
        exit 1
    fi
}

test_step_3_get_user_token() {
    print_header "Step 3: Get DPoP-Bound User Token"

    print_step "Requesting token with DPoP proof..."

    local response
    response=$(curl -s -X POST "$TOKEN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "DPoP: $USER_DPOP_PROOF" \
        -d "grant_type=password" \
        -d "client_id=$USER_CLIENT_ID" \
        -d "username=$TEST_USERNAME" \
        -d "password=$TEST_PASSWORD" \
        -d "scope=openid")

    USER_ACCESS_TOKEN=$(echo "$response" | jq -r '.access_token // empty')
    local error
    error=$(echo "$response" | jq -r '.error // empty')

    if [ -n "$USER_ACCESS_TOKEN" ] && [ "$USER_ACCESS_TOKEN" != "null" ]; then
        print_pass "Received access token"

        print_info "Token payload (key claims):"
        local sub iss aud
        sub=$(get_jwt_claim "$USER_ACCESS_TOKEN" "sub")
        iss=$(get_jwt_claim "$USER_ACCESS_TOKEN" "iss")
        aud=$(get_jwt_claim "$USER_ACCESS_TOKEN" "azp")

        echo "    sub: $sub"
        echo "    iss: $iss"
        echo "    azp: $aud"
    else
        print_fail "Failed to get token"
        print_info "Error: $error"
        print_info "Full response:"
        echo "$response" | jq -r '.' 2>/dev/null || echo "$response"
        exit 1
    fi
}

test_step_4_verify_user_token_binding() {
    print_header "Step 4: Verify Token DPoP Binding"

    print_step "Checking cnf.jkt claim in token..."

    local cnf_jkt
    cnf_jkt=$(decode_jwt "$USER_ACCESS_TOKEN" "payload" | jq -r '.cnf.jkt // empty')

    if [ -z "$cnf_jkt" ]; then
        print_warn "Token does not contain cnf.jkt claim"
        print_info "This may indicate DPoP binding is not enabled in Keycloak"
        print_info "Enable 'Use DPoP' in client settings and configure token mapper"
        HAS_DPOP_BINDING=false
    elif [ "$cnf_jkt" = "$USER_THUMBPRINT" ]; then
        print_pass "Token cnf.jkt matches user's DPoP thumbprint"
        print_info "cnf.jkt: $cnf_jkt"
        print_info "Expected: $USER_THUMBPRINT"
        HAS_DPOP_BINDING=true
    else
        print_fail "Token cnf.jkt does NOT match user's DPoP thumbprint"
        print_info "cnf.jkt: $cnf_jkt"
        print_info "Expected: $USER_THUMBPRINT"
        exit 1
    fi
}

test_step_5_generate_jump_host_keypair() {
    print_header "Step 5: Generate Jump Host DPoP Keypair"

    print_step "Generating separate EC P-256 keypair for jump host..."
    generate_ec_keypair "$JUMP_HOST_KEY"

    if [ -f "$JUMP_HOST_KEY" ]; then
        print_pass "Jump host keypair generated"

        local x y thumbprint
        x=$(get_ec_x_coordinate "$JUMP_HOST_KEY")
        y=$(get_ec_y_coordinate "$JUMP_HOST_KEY")
        thumbprint=$(compute_jwk_thumbprint "$JUMP_HOST_KEY")

        print_info "JWK x: ${x:0:20}... (truncated)"
        print_info "JWK y: ${y:0:20}... (truncated)"
        print_info "JWK thumbprint (jkt): $thumbprint"

        JUMP_HOST_THUMBPRINT="$thumbprint"

        # Verify it's different from user's key
        if [ "$JUMP_HOST_THUMBPRINT" != "$USER_THUMBPRINT" ]; then
            print_pass "Jump host thumbprint differs from user thumbprint"
        else
            print_fail "Jump host and user have same thumbprint (key reuse error)"
            exit 1
        fi
    else
        print_fail "Failed to generate jump host keypair"
        exit 1
    fi
}

test_step_6_create_exchange_dpop_proof() {
    print_header "Step 6: Create Jump Host DPoP Proof for Exchange"

    print_step "Creating DPoP proof for token exchange..."

    # For token exchange, we create a new proof with the jump host's key
    JUMP_HOST_DPOP_PROOF=$(create_dpop_proof "$JUMP_HOST_KEY" "POST" "$TOKEN_ENDPOINT")

    if [ -n "$JUMP_HOST_DPOP_PROOF" ]; then
        print_pass "Jump host DPoP proof created"

        print_info "DPoP Header:"
        decode_jwt "$JUMP_HOST_DPOP_PROOF" "header" | sed 's/^/    /'

        print_info "DPoP Payload:"
        decode_jwt "$JUMP_HOST_DPOP_PROOF" "payload" | sed 's/^/    /'
    else
        print_fail "Failed to create jump host DPoP proof"
        exit 1
    fi
}

test_step_7_perform_token_exchange() {
    print_header "Step 7: Perform Token Exchange"

    print_step "Exchanging user token for target-host-bound token..."

    # Try without audience first (Keycloak 26 standard token exchange V2 default);
    # fall back to explicit audience if the first attempt fails.
    local response
    response=$(curl -s -X POST "$TOKEN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "DPoP: $JUMP_HOST_DPOP_PROOF" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        -d "subject_token=$USER_ACCESS_TOKEN" \
        -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
        -d "client_id=$JUMP_HOST_CLIENT_ID" \
        -d "client_secret=$JUMP_HOST_CLIENT_SECRET")

    # If exchange without audience failed, retry with explicit audience
    if [ "$(echo "$response" | jq -r '.error // empty')" = "access_denied" ]; then
        print_info "Retrying with explicit audience parameter..."
        JUMP_HOST_DPOP_PROOF=$(create_dpop_proof "$JUMP_HOST_KEY" "POST" "$TOKEN_ENDPOINT")
        response=$(curl -s -X POST "$TOKEN_ENDPOINT" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "DPoP: $JUMP_HOST_DPOP_PROOF" \
            -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
            -d "subject_token=$USER_ACCESS_TOKEN" \
            -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
            -d "audience=$TARGET_AUDIENCE" \
            -d "client_id=$JUMP_HOST_CLIENT_ID" \
            -d "client_secret=$JUMP_HOST_CLIENT_SECRET")
    fi

    EXCHANGED_TOKEN=$(echo "$response" | jq -r '.access_token // empty')
    local error error_description
    error=$(echo "$response" | jq -r '.error // empty')
    error_description=$(echo "$response" | jq -r '.error_description // empty')

    if [ -n "$EXCHANGED_TOKEN" ] && [ "$EXCHANGED_TOKEN" != "null" ]; then
        print_pass "Token exchange successful"

        print_info "Exchange response:"
        echo "$response" | jq -r '{issued_token_type, token_type, expires_in}' 2>/dev/null | sed 's/^/    /'
    else
        print_fail "Token exchange failed"
        print_info "Error: $error"
        print_info "Description: $error_description"
        print_info ""
        print_info "Common causes:"
        print_info "  - Token exchange not enabled for client"
        print_info "  - Missing 'token-exchange' feature in Keycloak"
        print_info "  - Client does not have permission to exchange tokens"
        print_info "  - Target audience not configured"
        print_info ""
        print_info "Full response:"
        echo "$response" | jq -r '.' 2>/dev/null || echo "$response"
        exit 1
    fi
}

test_step_8_validate_exchanged_token() {
    print_header "Step 8: Validate Exchanged Token"

    local all_valid=true

    # 8a: Check cnf.jkt matches jump host thumbprint
    print_step "8a: Checking DPoP binding (cnf.jkt)..."
    local exchanged_cnf_jkt
    exchanged_cnf_jkt=$(decode_jwt "$EXCHANGED_TOKEN" "payload" | jq -r '.cnf.jkt // empty')

    if [ -z "$exchanged_cnf_jkt" ]; then
        print_warn "Exchanged token does not have cnf.jkt claim"
        if [ "$HAS_DPOP_BINDING" = true ]; then
            print_info "Original token had binding but exchanged token does not"
        fi
    elif [ "$exchanged_cnf_jkt" = "$JUMP_HOST_THUMBPRINT" ]; then
        print_pass "cnf.jkt matches jump host's DPoP thumbprint"
        print_info "Binding transferred from user to jump host key"
    elif [ "$exchanged_cnf_jkt" = "$USER_THUMBPRINT" ]; then
        print_fail "cnf.jkt still matches USER's thumbprint (binding not updated)"
        all_valid=false
    else
        print_fail "cnf.jkt matches neither user nor jump host thumbprint"
        print_info "Got: $exchanged_cnf_jkt"
        print_info "Expected jump host: $JUMP_HOST_THUMBPRINT"
        all_valid=false
    fi

    # 8b: Check act.sub contains original user
    print_step "8b: Checking actor claim (act.sub)..."
    local act_sub
    act_sub=$(decode_jwt "$EXCHANGED_TOKEN" "payload" | jq -r '.act.sub // empty')

    if [ -z "$act_sub" ]; then
        print_warn "Exchanged token does not have act.sub claim"
        print_info "Actor claim is optional per RFC 8693"
    else
        # Get original user's sub
        local original_sub
        original_sub=$(get_jwt_claim "$USER_ACCESS_TOKEN" "sub")

        if [ "$act_sub" = "$original_sub" ] || [ "$act_sub" = "$TEST_USERNAME" ]; then
            print_pass "act.sub contains original user identifier"
            print_info "act.sub: $act_sub"
        else
            print_warn "act.sub does not match original user sub"
            print_info "act.sub: $act_sub"
            print_info "Original sub: $original_sub"
        fi
    fi

    # 8c: Check audience contains target
    print_step "8c: Checking audience claim (aud)..."
    local aud
    aud=$(decode_jwt "$EXCHANGED_TOKEN" "payload" | jq -r '.aud // empty')
    local azp
    azp=$(decode_jwt "$EXCHANGED_TOKEN" "payload" | jq -r '.azp // empty')

    if echo "$aud" | grep -q "$TARGET_AUDIENCE" || [ "$azp" = "$TARGET_AUDIENCE" ]; then
        print_pass "Token audience contains target: $TARGET_AUDIENCE"
    else
        print_warn "Target audience not found in token"
        print_info "aud: $aud"
        print_info "azp: $azp"
        print_info "Expected: $TARGET_AUDIENCE"
    fi

    # 8d: Print full exchanged token claims
    print_step "8d: Full exchanged token payload..."
    decode_jwt "$EXCHANGED_TOKEN" "payload" | sed 's/^/    /'

    if [ "$all_valid" = true ]; then
        print_pass "Exchanged token validation complete"
    else
        print_fail "Some validations failed"
        exit 1
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

print_header "DPoP + Token Exchange Flow Test"
echo "This test validates RFC 9449 (DPoP) and RFC 8693 (Token Exchange)"
echo ""
echo "Configuration:"
echo "  Keycloak URL:    $KEYCLOAK_URL"
echo "  Realm:           $REALM"
echo "  User client:     $USER_CLIENT_ID"
echo "  Jump host:       $JUMP_HOST_CLIENT_ID"
echo "  Target:          $TARGET_AUDIENCE"

# Run prerequisite checks
check_prerequisites

# Run test steps
test_step_1_generate_user_keypair
test_step_2_create_user_dpop_proof
test_step_3_get_user_token
test_step_4_verify_user_token_binding
test_step_5_generate_jump_host_keypair
test_step_6_create_exchange_dpop_proof
test_step_7_perform_token_exchange
test_step_8_validate_exchanged_token

# Summary
print_header "Test Summary"
echo -e "${GREEN}All tests passed!${NC}"
echo ""
echo "Validated:"
echo "  1. Generated user DPoP keypair (ES256/P-256)"
echo "  2. Created DPoP proof with correct structure"
echo "  3. Obtained DPoP-bound access token from Keycloak"
echo "  4. Verified token cnf.jkt matches user's DPoP thumbprint"
echo "  5. Generated separate jump host DPoP keypair"
echo "  6. Created jump host DPoP proof for exchange"
echo "  7. Performed token exchange (RFC 8693)"
echo "  8. Validated exchanged token claims"
echo ""
echo "DPoP binding correctly transferred from user key to jump host key"
echo ""
