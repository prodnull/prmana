#!/bin/bash
# test/tests/test_keycloak_real_sig.sh
# Phase 20: Full E2E test suite for real OIDC signature verification.
#
# E2E-01: SSH→PAM chain with real JWKS signature verification (no TEST_MODE).
# E2E-02: Structured audit event verification (SSH_LOGIN_SUCCESS in audit log).
# E2E-03: Negative security tests (tampered signature, wrong issuer).
#
# Prerequisites:
#   - docker-compose.e2e.yaml stack running and healthy
#   - Agent binary built (target/release/prmana-agent in target/release-linux/)
#   - sshpass or SSH_ASKPASS available for automated SSH login
#
# CI usage:
#   COMPOSE_FILE=docker-compose.e2e.yaml ./test/tests/test_keycloak_real_sig.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
E2E_DIR="${PROJECT_ROOT}/test/e2e"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.e2e.yaml}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="prmana"
CLIENT_ID="prmana"
CONTAINER="test-host-e2e"
SSH_PORT="${SSH_PORT:-2222}"

PASS=0
FAIL=0
SKIP=0

result() {
    local status=$1 name=$2
    if [ "$status" = "PASS" ]; then
        echo "  [PASS] $name"
        PASS=$((PASS + 1))
    elif [ "$status" = "FAIL" ]; then
        echo "  [FAIL] $name"
        FAIL=$((FAIL + 1))
    else
        echo "  [SKIP] $name"
        SKIP=$((SKIP + 1))
    fi
}

echo "=== E2E Real Signature Test Suite ==="
echo "Compose: $COMPOSE_FILE"
echo "Keycloak: $KEYCLOAK_URL"
echo "SSH Port: $SSH_PORT"
echo ""

# ═══════════════════════════════════════════════════════════════════════
# Prerequisite Checks
# ═══════════════════════════════════════════════════════════════════════
echo "--- Prerequisites ---"

# INFR-03: Sentinel — verify TEST_MODE is NOT set in the container.
if docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" env 2>/dev/null | grep -q "PRMANA_TEST_MODE"; then
    echo "FATAL: TEST_MODE is set in E2E container. Aborting."
    exit 1
fi
result "PASS" "TEST_MODE sentinel (not set in container)"

# BFIX-02: Agent binary on PATH inside the container.
if docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" which prmana-agent >/dev/null 2>&1; then
    result "PASS" "Agent binary on PATH in container"
else
    result "FAIL" "Agent binary on PATH in container"
fi

# BFIX-01: Keycloak issuer URL alignment.
DISCOVERY=$(curl -sf "${KEYCLOAK_URL}/realms/${REALM}/.well-known/openid-configuration" || echo "{}")
DISC_ISSUER=$(echo "$DISCOVERY" | jq -r '.issuer // empty')
if [ "$DISC_ISSUER" = "${KEYCLOAK_URL}/realms/${REALM}" ]; then
    result "PASS" "Issuer URL alignment ($DISC_ISSUER)"
else
    result "FAIL" "Issuer URL alignment (expected ${KEYCLOAK_URL}/realms/${REALM}, got $DISC_ISSUER)"
fi

# PAM module installed in container.
if docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" test -f /lib/security/pam_prmana.so 2>/dev/null; then
    result "PASS" "PAM module installed in container"
else
    result "FAIL" "PAM module not found in container"
    echo "    The PAM module is required for SSH→PAM chain tests."
    echo "    Ensure target/release-linux/libpam_prmana.so is built."
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# E2E-01: Token Acquisition (ROPC + DPoP — validates Keycloak is working)
# ═══════════════════════════════════════════════════════════════════════
echo "--- E2E-01: Token Acquisition ---"

# Keycloak client has dpop.bound.access.tokens=true, so all token requests
# require a DPoP proof header. Generate a minimal proof for ROPC.
E2E_KEY_FILE=$(mktemp /tmp/prmana-e2e-key-XXXXXX)
openssl ecparam -name prime256v1 -genkey -noout -out "$E2E_KEY_FILE" 2>/dev/null

E2E_X_B64=$(openssl ec -in "$E2E_KEY_FILE" -pubout -outform DER 2>/dev/null | tail -c 64 | head -c 32 | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
E2E_Y_B64=$(openssl ec -in "$E2E_KEY_FILE" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')

E2E_JWK="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"$E2E_X_B64\",\"y\":\"$E2E_Y_B64\"}"
E2E_JTI=$(openssl rand -hex 16)
E2E_IAT=$(date +%s)
E2E_TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"

e2e_b64url() { base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='; }

E2E_HDR=$(echo -n "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":$E2E_JWK}" | e2e_b64url)
E2E_PLD=$(echo -n "{\"jti\":\"$E2E_JTI\",\"htm\":\"POST\",\"htu\":\"$E2E_TOKEN_ENDPOINT\",\"iat\":$E2E_IAT}" | e2e_b64url)
E2E_SI="${E2E_HDR}.${E2E_PLD}"

E2E_DER=$(echo -n "$E2E_SI" | openssl dgst -sha256 -sign "$E2E_KEY_FILE" | xxd -p | tr -d '\n')
E2E_OFF=6
E2E_RL=$((16#${E2E_DER:$E2E_OFF:2})); E2E_OFF=$((E2E_OFF + 2))
E2E_RH="${E2E_DER:$E2E_OFF:$((E2E_RL * 2))}"; E2E_OFF=$((E2E_OFF + E2E_RL * 2 + 2))
E2E_SL=$((16#${E2E_DER:$E2E_OFF:2})); E2E_OFF=$((E2E_OFF + 2))
E2E_SH="${E2E_DER:$E2E_OFF:$((E2E_SL * 2))}"
E2E_RH=$(printf '%064s' "$E2E_RH" | tr ' ' '0' | tail -c 64)
E2E_SH=$(printf '%064s' "$E2E_SH" | tr ' ' '0' | tail -c 64)
E2E_SIG=$(echo -n "${E2E_RH}${E2E_SH}" | xxd -r -p | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
E2E_DPOP_PROOF="${E2E_SI}.${E2E_SIG}"

rm -f "$E2E_KEY_FILE"

TOKEN_RESPONSE=$(curl -s -X POST "$E2E_TOKEN_ENDPOINT" \
    -H "DPoP: $E2E_DPOP_PROOF" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=${CLIENT_ID}&username=testuser&password=testpass&scope=openid" \
    2>/dev/null || echo '{"error":"request_failed"}')

ACCESS_TOKEN=$(printf '%s' "$TOKEN_RESPONSE" | jq -r '.access_token // empty')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    result "FAIL" "Token acquisition via ROPC+DPoP"
    echo "    Response: ${TOKEN_RESPONSE:0:200}"
    echo ""
    echo "FATAL: Cannot proceed without a valid token."
    exit 1
fi

# Validate token claims
# JWT base64url payloads lack padding; macOS base64 -d silently truncates without it.
base64url_decode() {
    local input="$1"
    local pad=$((4 - ${#input} % 4))
    [ "$pad" -ne 4 ] && input="${input}$(printf '%*s' "$pad" '' | tr ' ' '=')"
    echo -n "$input" | tr '_-' '/+' | base64 -d 2>/dev/null || echo -n "$input" | tr '_-' '/+' | base64 -D 2>/dev/null
}
CLAIMS=$(base64url_decode "$(echo "$ACCESS_TOKEN" | cut -d'.' -f2)")
TOKEN_ISS=$(echo "$CLAIMS" | jq -r '.iss // empty')
TOKEN_USER=$(echo "$CLAIMS" | jq -r '.preferred_username // empty')
TOKEN_EXP=$(echo "$CLAIMS" | jq -r '.exp // 0')

if [ "$TOKEN_ISS" = "${KEYCLOAK_URL}/realms/${REALM}" ]; then
    result "PASS" "Token issuer correct ($TOKEN_ISS)"
else
    result "FAIL" "Token issuer (expected ${KEYCLOAK_URL}/realms/${REALM}, got $TOKEN_ISS)"
fi

if [ "$TOKEN_USER" = "testuser" ]; then
    result "PASS" "Token username claim (testuser)"
else
    result "FAIL" "Token username claim (expected testuser, got $TOKEN_USER)"
fi

NOW=$(date +%s)
if [ "$TOKEN_EXP" -gt "$NOW" ]; then
    result "PASS" "Token not expired (exp=$TOKEN_EXP, now=$NOW)"
else
    result "FAIL" "Token expired (exp=$TOKEN_EXP, now=$NOW)"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# E2E-01: Full SSH→PAM Chain Test
# ═══════════════════════════════════════════════════════════════════════
echo "--- E2E-01: SSH→PAM Chain (keyboard-interactive + JWKS verification) ---"

# Clear the audit log in the container before the test.
docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" \
    bash -c "truncate -s0 /var/log/prmana-audit.log 2>/dev/null; true" >/dev/null 2>&1

# Write the token to a temporary file for SSH_ASKPASS.
TOKEN_FILE=$(mktemp /tmp/prmana-e2e-token-XXXXXX)
echo -n "$ACCESS_TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
trap 'rm -f "$TOKEN_FILE"' EXIT

# SSH_ASKPASS requires no controlling terminal.
# SSH_ASKPASS_REQUIRE=force (OpenSSH 8.4+) bypasses tty detection.
SSH_ASKPASS_SCRIPT="${E2E_DIR}/ssh-askpass-e2e.sh"
if [ ! -x "$SSH_ASKPASS_SCRIPT" ]; then
    chmod +x "$SSH_ASKPASS_SCRIPT"
fi

SSH_RESULT=""
SSH_EXIT=0

# Use keyboard-interactive authentication with our custom SSH_ASKPASS.
# The PAM module will:
#   1. Send DPOP_NONCE:<value> → ASKPASS returns empty (acknowledged)
#   2. Send DPOP_PROOF: → ASKPASS returns empty (warn mode, no proof)
#   3. Send "OIDC Token: " → ASKPASS returns the real JWT
#   4. PAM validates JWT signature against Keycloak JWKS (real crypto, no TEST_MODE)
SSH_RESULT=$(DISPLAY=:0 \
    SSH_ASKPASS="$SSH_ASKPASS_SCRIPT" \
    SSH_ASKPASS_REQUIRE=force \
    PRMANA_E2E_TOKEN_FILE="$TOKEN_FILE" \
    ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=keyboard-interactive \
        -o NumberOfPasswordPrompts=3 \
        -o ConnectTimeout=10 \
        -p "$SSH_PORT" \
        testuser@localhost \
        "echo SSH_AUTH_OK" 2>/dev/null) || SSH_EXIT=$?

if [ "$SSH_EXIT" -eq 0 ] && echo "$SSH_RESULT" | grep -q "SSH_AUTH_OK"; then
    result "PASS" "SSH→PAM chain (keyboard-interactive, real JWKS)"
else
    result "FAIL" "SSH→PAM chain (exit=$SSH_EXIT)"
    echo "    SSH output: ${SSH_RESULT:-empty}"
    echo "    Checking container logs for diagnostics..."
    docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" \
        bash -c "tail -20 /var/log/auth.log 2>/dev/null || journalctl -u sshd -n 20 2>/dev/null || echo 'No auth logs available'" 2>/dev/null || true
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# E2E-02: Structured Audit Event Verification
# ═══════════════════════════════════════════════════════════════════════
echo "--- E2E-02: Audit Log Verification ---"

# The PAM module writes structured JSON audit events to /var/log/prmana-audit.log.
# Check for SSH_LOGIN_SUCCESS event.
AUDIT_LOG=$(docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" \
    cat /var/log/prmana-audit.log 2>/dev/null || echo "")

if [ -n "$AUDIT_LOG" ]; then
    if echo "$AUDIT_LOG" | grep -q '"event":"SSH_LOGIN_SUCCESS"'; then
        result "PASS" "Audit log contains SSH_LOGIN_SUCCESS event"

        # Verify the event contains expected fields.
        LOGIN_EVENT=$(echo "$AUDIT_LOG" | grep '"event":"SSH_LOGIN_SUCCESS"' | tail -1)
        if echo "$LOGIN_EVENT" | jq -e '.user' >/dev/null 2>&1; then
            AUDIT_USER=$(echo "$LOGIN_EVENT" | jq -r '.user')
            result "PASS" "Audit event has user field ($AUDIT_USER)"
        else
            result "FAIL" "Audit event missing user field"
        fi

        if echo "$LOGIN_EVENT" | jq -e '.session_id' >/dev/null 2>&1; then
            result "PASS" "Audit event has session_id field"
        else
            result "FAIL" "Audit event missing session_id field"
        fi
    else
        result "FAIL" "Audit log missing SSH_LOGIN_SUCCESS event"
        echo "    Audit log content: ${AUDIT_LOG:0:500}"
    fi
else
    # If SSH chain test failed, audit log may be empty — skip rather than fail.
    if [ "$SSH_EXIT" -ne 0 ]; then
        result "SKIP" "Audit log verification (SSH chain test did not succeed)"
    else
        result "FAIL" "Audit log is empty (expected SSH_LOGIN_SUCCESS)"
    fi
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# E2E-02b: DPoP Binding + Audit Thumbprint (KCDPOP-02)
# ═══════════════════════════════════════════════════════════════════════
echo "--- E2E-02b: DPoP Binding SSH→PAM→Audit Chain (KCDPOP-02) ---"

# Generate ephemeral EC P-256 key for DPoP proof.
DPOP_KEY_FILE=$(mktemp /tmp/prmana-e2e-dpop-XXXXXX)
trap 'rm -f "$TOKEN_FILE" "$DPOP_KEY_FILE"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$DPOP_KEY_FILE" 2>/dev/null

# Extract x, y coordinates (same method as test_dpop_binding.sh — proven in CI).
DPOP_X_B64=$(openssl ec -in "$DPOP_KEY_FILE" -pubout -outform DER 2>/dev/null | tail -c 64 | head -c 32 | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
DPOP_Y_B64=$(openssl ec -in "$DPOP_KEY_FILE" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')

# Compute JWK thumbprint (RFC 7638 canonical form).
DPOP_CANONICAL="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"$DPOP_X_B64\",\"y\":\"$DPOP_Y_B64\"}"
DPOP_THUMBPRINT=$(echo -n "$DPOP_CANONICAL" | openssl dgst -sha256 -binary | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')

# Build and sign DPoP proof JWT.
DPOP_JWK="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"$DPOP_X_B64\",\"y\":\"$DPOP_Y_B64\"}"
DPOP_JTI=$(openssl rand -hex 16)
DPOP_IAT=$(date +%s)
DPOP_TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"

base64url_encode_dpop() { base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='; }

DPOP_HEADER=$(echo -n "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":$DPOP_JWK}" | base64url_encode_dpop)
DPOP_PAYLOAD=$(echo -n "{\"jti\":\"$DPOP_JTI\",\"htm\":\"POST\",\"htu\":\"$DPOP_TOKEN_ENDPOINT\",\"iat\":$DPOP_IAT}" | base64url_encode_dpop)
DPOP_SIGNING_INPUT="${DPOP_HEADER}.${DPOP_PAYLOAD}"

# Sign with ES256, convert DER→P1363 (same pattern as test_dpop_binding.sh).
DPOP_DER_SIG=$(echo -n "$DPOP_SIGNING_INPUT" | openssl dgst -sha256 -sign "$DPOP_KEY_FILE" | xxd -p | tr -d '\n')
DPOP_OFF=6
DPOP_R_LEN=$((16#${DPOP_DER_SIG:$DPOP_OFF:2}))
DPOP_OFF=$((DPOP_OFF + 2))
DPOP_R_HEX="${DPOP_DER_SIG:$DPOP_OFF:$((DPOP_R_LEN * 2))}"
DPOP_OFF=$((DPOP_OFF + DPOP_R_LEN * 2 + 2))
DPOP_S_LEN=$((16#${DPOP_DER_SIG:$DPOP_OFF:2}))
DPOP_OFF=$((DPOP_OFF + 2))
DPOP_S_HEX="${DPOP_DER_SIG:$DPOP_OFF:$((DPOP_S_LEN * 2))}"
DPOP_R_HEX=$(printf '%064s' "$DPOP_R_HEX" | tr ' ' '0' | tail -c 64)
DPOP_S_HEX=$(printf '%064s' "$DPOP_S_HEX" | tr ' ' '0' | tail -c 64)
DPOP_SIGNATURE=$(echo -n "${DPOP_R_HEX}${DPOP_S_HEX}" | xxd -r -p | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
DPOP_PROOF="${DPOP_SIGNING_INPUT}.${DPOP_SIGNATURE}"

# Acquire DPoP-bound token from Keycloak.
DPOP_TOKEN_RESPONSE=$(curl -sf -X POST "$DPOP_TOKEN_ENDPOINT" \
    -H "DPoP: $DPOP_PROOF" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=${CLIENT_ID}&client_secret=prmana-test-secret&username=testuser&password=testpass&scope=openid" \
    2>/dev/null || echo '{"error":"request_failed"}')

DPOP_ACCESS_TOKEN=$(echo "$DPOP_TOKEN_RESPONSE" | jq -r '.access_token // empty')
DPOP_TOKEN_TYPE=$(echo "$DPOP_TOKEN_RESPONSE" | jq -r '.token_type // empty')

if [ -z "$DPOP_ACCESS_TOKEN" ] || [ "$DPOP_ACCESS_TOKEN" = "null" ]; then
    result "FAIL" "DPoP token acquisition"
    echo "    Response: ${DPOP_TOKEN_RESPONSE:0:200}"
else
    result "PASS" "DPoP token acquired (type: $DPOP_TOKEN_TYPE)"

    # Verify cnf.jkt in token matches computed thumbprint.
    DPOP_CLAIMS=$(base64url_decode "$(echo "$DPOP_ACCESS_TOKEN" | cut -d'.' -f2)")
    DPOP_CNF_JKT=$(echo "$DPOP_CLAIMS" | jq -r '.cnf.jkt // empty')
    if [ "$DPOP_CNF_JKT" = "$DPOP_THUMBPRINT" ]; then
        result "PASS" "cnf.jkt matches computed thumbprint ($DPOP_THUMBPRINT)"
    else
        result "FAIL" "cnf.jkt mismatch (expected $DPOP_THUMBPRINT, got $DPOP_CNF_JKT)"
    fi

    # Clear audit log, then send DPoP-bound token through SSH→PAM.
    docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" \
        bash -c "truncate -s0 /var/log/prmana-audit.log 2>/dev/null; true" >/dev/null 2>&1

    DPOP_TOKEN_FILE=$(mktemp /tmp/prmana-e2e-dpop-token-XXXXXX)
    echo -n "$DPOP_ACCESS_TOKEN" > "$DPOP_TOKEN_FILE"
    chmod 600 "$DPOP_TOKEN_FILE"

    DPOP_SSH_RESULT=""
    DPOP_SSH_EXIT=0
    DPOP_SSH_RESULT=$(DISPLAY=:0 \
        SSH_ASKPASS="$SSH_ASKPASS_SCRIPT" \
        SSH_ASKPASS_REQUIRE=force \
        PRMANA_E2E_TOKEN_FILE="$DPOP_TOKEN_FILE" \
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o PreferredAuthentications=keyboard-interactive \
            -o NumberOfPasswordPrompts=3 \
            -o ConnectTimeout=10 \
            -p "$SSH_PORT" \
            testuser@localhost \
            "echo SSH_DPOP_AUTH_OK" 2>/dev/null) || DPOP_SSH_EXIT=$?

    rm -f "$DPOP_TOKEN_FILE"

    if [ "$DPOP_SSH_EXIT" -eq 0 ] && echo "$DPOP_SSH_RESULT" | grep -q "SSH_DPOP_AUTH_OK"; then
        result "PASS" "SSH→PAM chain with DPoP-bound token"
    else
        result "FAIL" "SSH→PAM chain with DPoP-bound token (exit=$DPOP_SSH_EXIT)"
        echo "    SSH output: ${DPOP_SSH_RESULT:-empty}"
    fi

    # Verify dpop_thumbprint in audit event (KCDPOP-02 — structured jq assertion).
    sleep 1
    DPOP_AUDIT_LOG=$(docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" \
        cat /var/log/prmana-audit.log 2>/dev/null || echo "")

    if [ -n "$DPOP_AUDIT_LOG" ]; then
        DPOP_LOGIN_EVENT=$(echo "$DPOP_AUDIT_LOG" | grep '"event":"SSH_LOGIN_SUCCESS"' | tail -1)
        if [ -n "$DPOP_LOGIN_EVENT" ]; then
            AUDIT_DPOP_THUMBPRINT=$(echo "$DPOP_LOGIN_EVENT" | jq -r '.dpop_thumbprint // empty')
            if [ "$AUDIT_DPOP_THUMBPRINT" = "$DPOP_THUMBPRINT" ]; then
                result "PASS" "Audit dpop_thumbprint matches computed thumbprint"
            elif [ -n "$AUDIT_DPOP_THUMBPRINT" ] && [ "$AUDIT_DPOP_THUMBPRINT" != "null" ]; then
                result "FAIL" "Audit dpop_thumbprint mismatch (expected $DPOP_THUMBPRINT, got $AUDIT_DPOP_THUMBPRINT)"
            else
                result "FAIL" "Audit event missing dpop_thumbprint (field null or absent)"
                echo "    Event: ${DPOP_LOGIN_EVENT:0:300}"
            fi
        else
            if [ "$DPOP_SSH_EXIT" -ne 0 ]; then
                result "SKIP" "Audit dpop_thumbprint verification (SSH chain did not succeed)"
            else
                result "FAIL" "No SSH_LOGIN_SUCCESS event in audit log after DPoP auth"
            fi
        fi
    else
        if [ "$DPOP_SSH_EXIT" -ne 0 ]; then
            result "SKIP" "Audit dpop_thumbprint verification (SSH chain did not succeed)"
        else
            result "FAIL" "Audit log empty after DPoP SSH auth"
        fi
    fi
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# E2E-03: Negative Security Tests
# ═══════════════════════════════════════════════════════════════════════
echo "--- E2E-03: Negative Security Tests ---"

# --- Test 1: Tampered signature should be rejected ---
# Take the valid token and change the last character of the signature.
# This makes the ECDSA signature invalid; JWKS verification must reject it.
TAMPERED_TOKEN=""
if [ -n "$ACCESS_TOKEN" ]; then
    # JWT format: header.payload.signature
    HEADER_PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d'.' -f1-2)
    SIGNATURE=$(echo "$ACCESS_TOKEN" | cut -d'.' -f3)

    # Flip the last character: if it's 'A', make it 'B'; otherwise make it 'A'.
    LAST_CHAR="${SIGNATURE: -1}"
    if [ "$LAST_CHAR" = "A" ]; then
        NEW_LAST="B"
    else
        NEW_LAST="A"
    fi
    TAMPERED_SIG="${SIGNATURE:0:$((${#SIGNATURE}-1))}${NEW_LAST}"
    TAMPERED_TOKEN="${HEADER_PAYLOAD}.${TAMPERED_SIG}"
fi

if [ -n "$TAMPERED_TOKEN" ]; then
    # Write tampered token and attempt SSH.
    TAMPERED_FILE=$(mktemp /tmp/prmana-e2e-tampered-XXXXXX)
    echo -n "$TAMPERED_TOKEN" > "$TAMPERED_FILE"
    chmod 600 "$TAMPERED_FILE"

    TAMPER_RESULT=$(DISPLAY=:0 \
        SSH_ASKPASS="$SSH_ASKPASS_SCRIPT" \
        SSH_ASKPASS_REQUIRE=force \
        PRMANA_E2E_TOKEN_FILE="$TAMPERED_FILE" \
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o PreferredAuthentications=keyboard-interactive \
            -o NumberOfPasswordPrompts=3 \
            -o ConnectTimeout=10 \
            -p "$SSH_PORT" \
            testuser@localhost \
            "echo SHOULD_NOT_REACH" 2>/dev/null) || true

    rm -f "$TAMPERED_FILE"

    if echo "$TAMPER_RESULT" | grep -q "SHOULD_NOT_REACH"; then
        result "FAIL" "Tampered signature accepted (SECURITY VIOLATION)"
    else
        result "PASS" "Tampered signature rejected"
    fi
else
    result "SKIP" "Tampered signature test (no valid token available)"
fi

# --- Test 2: Wrong issuer should be rejected ---
# Temporarily reconfigure the PAM module to expect a different issuer.
# Any valid Keycloak token will then have a mismatched issuer.
WRONG_ISSUER_RESULT=""
if [ -n "$ACCESS_TOKEN" ]; then
    # Save original OIDC_ISSUER, change to a wrong value.
    docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" \
        bash -c 'sed -i "s|OIDC_ISSUER=.*|OIDC_ISSUER=http://wrong-issuer:9999/realms/fake|" /etc/environment' 2>/dev/null

    WRONG_ISSUER_RESULT=$(DISPLAY=:0 \
        SSH_ASKPASS="$SSH_ASKPASS_SCRIPT" \
        SSH_ASKPASS_REQUIRE=force \
        PRMANA_E2E_TOKEN_FILE="$TOKEN_FILE" \
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o PreferredAuthentications=keyboard-interactive \
            -o NumberOfPasswordPrompts=3 \
            -o ConnectTimeout=10 \
            -p "$SSH_PORT" \
            testuser@localhost \
            "echo SHOULD_NOT_REACH" 2>/dev/null) || true

    # Restore original OIDC_ISSUER.
    docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" \
        bash -c "sed -i 's|OIDC_ISSUER=http://localhost:8080/realms/prmana|' /etc/environment" 2>/dev/null

    if echo "$WRONG_ISSUER_RESULT" | grep -q "SHOULD_NOT_REACH"; then
        result "FAIL" "Wrong issuer token accepted (SECURITY VIOLATION)"
    else
        result "PASS" "Wrong issuer token rejected"
    fi
else
    result "SKIP" "Wrong issuer test (no valid token available)"
fi

# --- Test 3: Wrong realm JWKS endpoint ---
# Verify that a non-existent realm's OIDC discovery fails.
BAD_JWKS=$(curl -sf "${KEYCLOAK_URL}/realms/nonexistent/.well-known/openid-configuration" 2>/dev/null || echo "")
if [ -z "$BAD_JWKS" ] || echo "$BAD_JWKS" | jq -e '.error' >/dev/null 2>&1; then
    result "PASS" "Non-existent realm JWKS discovery fails correctly"
else
    result "FAIL" "Non-existent realm JWKS should have failed"
fi

# --- Test 4: Expired token detection ---
# Create a JWT-like string with exp in the past.
# We use Python to craft a proper expired token if available.
if command -v python3 >/dev/null 2>&1; then
    EXPIRED_TOKEN=$(python3 -c "
import json, base64, time, hmac, hashlib

# Create a token that looks like a JWT but has expired exp claim.
# The signature will be invalid (self-signed), so this also tests
# that expired tokens are caught before or during validation.
header = base64.urlsafe_b64encode(json.dumps({'alg':'ES256','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({
    'iss': '${KEYCLOAK_URL}/realms/${REALM}',
    'sub': 'expired-user',
    'aud': '${CLIENT_ID}',
    'exp': int(time.time()) - 3600,  # expired 1 hour ago
    'iat': int(time.time()) - 7200,
    'preferred_username': 'testuser'
}).encode()).rstrip(b'=').decode()
# Fake signature (will fail JWKS verification regardless)
sig = base64.urlsafe_b64encode(b'fake-sig-32-bytes-padded-here!!').rstrip(b'=').decode()
print(f'{header}.{payload}.{sig}')
" 2>/dev/null || echo "")

    if [ -n "$EXPIRED_TOKEN" ]; then
        EXPIRED_FILE=$(mktemp /tmp/prmana-e2e-expired-XXXXXX)
        echo -n "$EXPIRED_TOKEN" > "$EXPIRED_FILE"
        chmod 600 "$EXPIRED_FILE"

        EXPIRED_RESULT=$(DISPLAY=:0 \
            SSH_ASKPASS="$SSH_ASKPASS_SCRIPT" \
            SSH_ASKPASS_REQUIRE=force \
            PRMANA_E2E_TOKEN_FILE="$EXPIRED_FILE" \
            ssh -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o PreferredAuthentications=keyboard-interactive \
                -o NumberOfPasswordPrompts=3 \
                -o ConnectTimeout=10 \
                -p "$SSH_PORT" \
                testuser@localhost \
                "echo SHOULD_NOT_REACH" 2>/dev/null) || true

        rm -f "$EXPIRED_FILE"

        if echo "$EXPIRED_RESULT" | grep -q "SHOULD_NOT_REACH"; then
            result "FAIL" "Expired/forged token accepted (SECURITY VIOLATION)"
        else
            result "PASS" "Expired/forged token rejected"
        fi
    else
        result "SKIP" "Expired token test (python3 token generation failed)"
    fi
else
    result "SKIP" "Expired token test (python3 not available)"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════
TOTAL=$((PASS + FAIL + SKIP))
echo "=== Results ==="
echo "  Total: $TOTAL | Pass: $PASS | Fail: $FAIL | Skip: $SKIP"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "FAILED: $FAIL test(s) failed"
    exit 1
fi

echo ""
echo "=== ALL E2E TESTS PASSED ==="
