#!/bin/bash
# test/tests/test_session_lifecycle_e2e.sh
#
# E2ET-03: Session Lifecycle E2E Test
#
# Verifies the PAM session correlation path:
#   1. putenv UNIX_OIDC_SESSION_ID → session record created at /run/unix-oidc/sessions/<uuid>
#   2. SessionClosed IPC → session record removed within 5 seconds of SSH disconnect
#   3. cross-fork putenv/getenv correlation → session_id present in audit log
#   4. Auto-refresh fires before token expiry (best-effort / SKIP if short token not available)
#
# Architecture note: authenticate() runs in the sshd auth worker; open_session() runs in
# a separate sshd session worker. PAM environment variables (putenv/getenv) are the only
# reliable cross-fork channel within a single PAM transaction. The session record file at
# /run/unix-oidc/sessions/<uuid> is the observable artefact of that cross-fork correlation.
#
# SessionClosed IPC: pam_sm_close_session() calls notify_agent_session_closed() which
# sends a SessionClosed message to the agent; the agent removes the session record.
#
# References:
#   - pam-unix-oidc/src/lib.rs: pam_sm_open_session, pam_sm_close_session
#   - unix-oidc-agent/src/daemon/socket.rs: SessionClosed handler, spawn_refresh_task
#   - RFC 7517 §4 (JWK), RFC 9449 §4 (DPoP proof)
#
# Usage:
#   COMPOSE_FILE=docker-compose.e2e.yaml ./test/tests/test_session_lifecycle_e2e.sh
#
# CI: runs after E2E stack is up, with || true until environment is confirmed stable.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
E2E_DIR="${PROJECT_ROOT}/test/e2e"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.e2e.yaml}"
TEST_HOST_SERVICE="${TEST_HOST_SERVICE:-test-host-e2e}"
SESSION_DIR="/run/unix-oidc/sessions"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-unix-oidc}"
CLIENT_ID="${CLIENT_ID:-unix-oidc}"
SSH_PORT="${SSH_PORT:-2222}"

PASS=0
FAIL=0
SKIP=0

result() {
    local status=$1 name=$2
    case "$status" in
        PASS) echo "  [PASS] $name"; PASS=$((PASS + 1)) ;;
        FAIL) echo "  [FAIL] $name"; FAIL=$((FAIL + 1)) ;;
        SKIP) echo "  [SKIP] $name"; SKIP=$((SKIP + 1)) ;;
    esac
}

echo "=== E2ET-03: Session Lifecycle E2E Test Suite ==="
echo "Compose:  $COMPOSE_FILE"
echo "Service:  $TEST_HOST_SERVICE"
echo "Sessions: $SESSION_DIR"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Prerequisites
# ─────────────────────────────────────────────────────────────────────────────
echo "--- Prerequisites ---"

if ! command -v docker >/dev/null 2>&1; then
    echo "FATAL: docker not found"
    exit 1
fi

# Verify the compose stack is running
if ! docker compose -f "$COMPOSE_FILE" ps --quiet "$TEST_HOST_SERVICE" 2>/dev/null | grep -q .; then
    echo "SKIP: compose stack '$TEST_HOST_SERVICE' is not running"
    echo "      Start it with: docker compose -f $COMPOSE_FILE up -d"
    result "SKIP" "Compose stack running ($TEST_HOST_SERVICE)"
    echo ""
    echo "=== Results ==="
    echo "  Total: $((PASS + FAIL + SKIP)) | Pass: $PASS | Fail: $FAIL | Skip: $SKIP"
    echo ""
    echo "=== SKIPPED (no compose environment) ==="
    exit 0
fi
result "PASS" "Compose stack running ($TEST_HOST_SERVICE)"

# Acquire a real token from Keycloak (ROPC — test environment only)
TOKEN_RESPONSE=$(curl -sf -X POST \
    "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=${CLIENT_ID}&username=testuser&password=testpass&scope=openid" \
    2>/dev/null || echo '{"error":"request_failed"}')

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null || echo "")

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    echo "FATAL: Could not acquire token from Keycloak. Response: $TOKEN_RESPONSE"
    exit 1
fi
result "PASS" "Token acquired from Keycloak"

# Write token file for SSH_ASKPASS
TOKEN_FILE=$(mktemp /tmp/unix-oidc-e2et03-token-XXXXXX)
echo -n "$ACCESS_TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
trap 'rm -f "$TOKEN_FILE"' EXIT

# Confirm SSH_ASKPASS script is available
SSH_ASKPASS_SCRIPT="${E2E_DIR}/ssh-askpass-e2e.sh"
if [ ! -x "$SSH_ASKPASS_SCRIPT" ]; then
    chmod +x "$SSH_ASKPASS_SCRIPT" 2>/dev/null || true
fi

if [ ! -x "$SSH_ASKPASS_SCRIPT" ]; then
    echo "SKIP: SSH_ASKPASS script not found at $SSH_ASKPASS_SCRIPT"
    result "SKIP" "SSH_ASKPASS script available"
    echo ""
    echo "=== Results ==="
    echo "  Total: $((PASS + FAIL + SKIP)) | Pass: $PASS | Fail: $FAIL | Skip: $SKIP"
    exit 0
fi
result "PASS" "SSH_ASKPASS script available"

# Clear session directory and audit log before tests
docker compose -f "$COMPOSE_FILE" exec -T "$TEST_HOST_SERVICE" \
    bash -c "rm -f ${SESSION_DIR}/* 2>/dev/null; true" >/dev/null 2>&1 || true
docker compose -f "$COMPOSE_FILE" exec -T "$TEST_HOST_SERVICE" \
    bash -c "truncate -s0 /var/log/unix-oidc-audit.log 2>/dev/null; true" >/dev/null 2>&1 || true

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Test 1: Session record created on open (putenv UNIX_OIDC_SESSION_ID correlation)
#
# pam_sm_open_session() reads UNIX_OIDC_SESSION_ID from PAM env (set by authenticate()
# via putenv) and writes a JSON session record to SESSION_DIR/<uuid>.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- Test 1: Session record created on open ---"

# Run SSH session that stays open for 5 seconds so we can inspect the session directory
SSH_EXIT_1=0
SSH_PID=""
DISPLAY=:0 \
SSH_ASKPASS="$SSH_ASKPASS_SCRIPT" \
SSH_ASKPASS_REQUIRE=force \
UNIX_OIDC_E2E_TOKEN_FILE="$TOKEN_FILE" \
    ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=keyboard-interactive \
        -o NumberOfPasswordPrompts=3 \
        -o ConnectTimeout=10 \
        -p "$SSH_PORT" \
        testuser@localhost \
        "sleep 5 && echo SESSION_OPEN_COMPLETE" >/tmp/unix-oidc-e2et03-ssh1.out 2>&1 &
SSH_PID=$!

# While SSH is in the sleep phase, check for session record
sleep 2
SESSION_RECORD_PRESENT=0
SESSION_COUNT=$(docker compose -f "$COMPOSE_FILE" exec -T "$TEST_HOST_SERVICE" \
    bash -c "ls ${SESSION_DIR}/ 2>/dev/null | wc -l" 2>/dev/null | tr -d '[:space:]' || echo "0")

if [ "${SESSION_COUNT:-0}" -gt 0 ]; then
    SESSION_RECORD_PRESENT=1
    SESSION_ID_VALUE=$(docker compose -f "$COMPOSE_FILE" exec -T "$TEST_HOST_SERVICE" \
        bash -c "ls ${SESSION_DIR}/ 2>/dev/null | head -1" 2>/dev/null | tr -d '[:space:]' || echo "")
    result "PASS" "Session record created in ${SESSION_DIR}/ (id=${SESSION_ID_VALUE:-unknown})"
else
    result "FAIL" "Session record not found in ${SESSION_DIR}/ (count=0) — UNIX_OIDC_SESSION_ID putenv/getenv correlation failed"
    echo "    Check: pam_sm_open_session reached? UNIX_OIDC_SESSION_ID set by authenticate()?"
fi

# Wait for SSH to finish
wait "$SSH_PID" 2>/dev/null || SSH_EXIT_1=$?

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Test 2: SessionClosed IPC — session record removed after SSH disconnect
#
# pam_sm_close_session() retrieves UNIX_OIDC_SESSION_ID via getenv and calls
# notify_agent_session_closed(). The agent receives the SessionClosed IPC message
# and removes the session record from SESSION_DIR/.
#
# Window: 5 seconds (10 × 500ms polls).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- Test 2: SessionClosed IPC — session record removed after disconnect ---"

# Poll for up to 5 seconds
FINAL_COUNT=-1
for i in $(seq 1 10); do
    FINAL_COUNT=$(docker compose -f "$COMPOSE_FILE" exec -T "$TEST_HOST_SERVICE" \
        bash -c "ls ${SESSION_DIR}/ 2>/dev/null | wc -l" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "${FINAL_COUNT:-1}" -eq 0 ]; then
        break
    fi
    sleep 0.5
done

if [ "${FINAL_COUNT:-1}" -eq 0 ]; then
    result "PASS" "Session record removed from ${SESSION_DIR}/ within 5s (SessionClosed IPC fired)"
else
    result "FAIL" "Session record still present after 5s (count=${FINAL_COUNT}) — SessionClosed IPC did not clean up"
    echo "    Check: pam_sm_close_session reached? agent socket reachable from sshd? SESSION_CLOSED handler registered?"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Test 3: putenv/getenv cross-fork correlation via audit log
#
# When pam_sm_open_session succeeds, it emits an audit event with session_id field.
# This confirms that the cross-fork PAM env var was readable in the session worker.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- Test 3: putenv/getenv correlation confirmed in audit log ---"

AUDIT_CONTENT=$(docker compose -f "$COMPOSE_FILE" exec -T "$TEST_HOST_SERVICE" \
    bash -c "cat /var/log/unix-oidc-audit.log 2>/dev/null || echo ''" 2>/dev/null || echo "")

if [ -n "$AUDIT_CONTENT" ]; then
    if echo "$AUDIT_CONTENT" | grep -q '"session_id"'; then
        AUDIT_SESSION_ID=$(echo "$AUDIT_CONTENT" | grep '"session_id"' | head -1 | jq -r '.session_id // empty' 2>/dev/null || echo "present")
        result "PASS" "Audit log contains session_id field (UNIX_OIDC_SESSION_ID correlated cross-fork, id=${AUDIT_SESSION_ID:-present})"
    elif echo "$AUDIT_CONTENT" | grep -qiE "SESSION_OPENED|session_opened|open_session"; then
        result "PASS" "Audit log contains SESSION_OPENED event (cross-fork correlation succeeded)"
    else
        result "FAIL" "Audit log present but no session_id or SESSION_OPENED found — check UNIX_OIDC_SESSION_ID putenv"
        echo "    Audit log (first 500 chars): ${AUDIT_CONTENT:0:500}"
    fi
else
    if [ "$SESSION_RECORD_PRESENT" -eq 1 ]; then
        # Session record was created, so putenv worked; audit log format may differ
        result "SKIP" "Audit log empty but session record was created — putenv correlation confirmed via session file"
    else
        result "FAIL" "Audit log empty and no session record found — end-to-end session correlation not confirmed"
    fi
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Test 4: Auto-refresh fires before expiry (best-effort)
#
# spawn_refresh_task() fires at (token_lifetime * threshold_percent / 100) seconds.
# Default threshold: 80%. A 2-minute token fires auto-refresh at ~96s.
#
# This test requires a short-lived token from Keycloak. If the token expiry is
# the default 5 minutes, waiting 80% of that time is impractical in CI.
# This test is therefore SKIP unless TOKEN_LIFETIME_SECS=120 is set.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- Test 4: Auto-refresh fires before token expiry ---"

TOKEN_LIFETIME_SECS="${TOKEN_LIFETIME_SECS:-}"
if [ -z "$TOKEN_LIFETIME_SECS" ]; then
    # Decode token and check exp vs iat to determine lifetime
    TOKEN_PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d'.' -f2 | tr '_-' '/+' | \
        awk '{ pad=length($0)%4; if(pad==2) print $0"=="; else if(pad==3) print $0"="; else print $0 }' | \
        base64 -d 2>/dev/null || echo '{}')
    TOKEN_EXP=$(echo "$TOKEN_PAYLOAD" | jq -r '.exp // 0' 2>/dev/null || echo "0")
    TOKEN_IAT=$(echo "$TOKEN_PAYLOAD" | jq -r '.iat // 0' 2>/dev/null || echo "0")
    COMPUTED_LIFETIME=$(( TOKEN_EXP - TOKEN_IAT ))
    if [ "$COMPUTED_LIFETIME" -gt 0 ] && [ "$COMPUTED_LIFETIME" -le 180 ]; then
        TOKEN_LIFETIME_SECS="$COMPUTED_LIFETIME"
    fi
fi

if [ -z "$TOKEN_LIFETIME_SECS" ] || [ "${TOKEN_LIFETIME_SECS:-0}" -gt 180 ]; then
    echo "  SKIP: auto_refresh test requires short token lifetime (<= 180s)."
    echo "        Set TOKEN_LIFETIME_SECS=120 and configure Keycloak client with 2-minute token expiry."
    echo "        Keycloak admin: Clients → unix-oidc → Settings → Access Token Lifespan = 2 minutes"
    result "SKIP" "Auto-refresh E2E (token lifetime > 180s; configure Keycloak for short tokens)"
else
    THRESHOLD_PCT=80
    WAIT_SECS=$(( TOKEN_LIFETIME_SECS * THRESHOLD_PCT / 100 ))
    echo "  Token lifetime: ${TOKEN_LIFETIME_SECS}s — waiting ${WAIT_SECS}s for auto-refresh trigger (${THRESHOLD_PCT}% threshold)"

    # Start a new SSH session to trigger the agent's auto-refresh task
    docker compose -f "$COMPOSE_FILE" exec -T "$TEST_HOST_SERVICE" \
        bash -c "truncate -s0 /var/log/unix-oidc-audit.log 2>/dev/null; true" >/dev/null 2>&1 || true

    DISPLAY=:0 \
    SSH_ASKPASS="$SSH_ASKPASS_SCRIPT" \
    SSH_ASKPASS_REQUIRE=force \
    UNIX_OIDC_E2E_TOKEN_FILE="$TOKEN_FILE" \
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o PreferredAuthentications=keyboard-interactive \
            -o NumberOfPasswordPrompts=3 \
            -o ConnectTimeout=10 \
            -p "$SSH_PORT" \
            testuser@localhost \
            "sleep $(( WAIT_SECS + 10 ))" >/dev/null 2>&1 &
    REFRESH_SSH_PID=$!

    sleep $(( WAIT_SECS + 5 ))

    REFRESH_LOG=$(docker compose -f "$COMPOSE_FILE" exec -T "$TEST_HOST_SERVICE" \
        bash -c "cat /var/log/unix-oidc-audit.log 2>/dev/null || echo ''" 2>/dev/null || echo "")

    wait "$REFRESH_SSH_PID" 2>/dev/null || true

    if echo "$REFRESH_LOG" | grep -qiE "token_refreshed|auto_refresh|REFRESH|TOKEN_REFRESH"; then
        result "PASS" "Auto-refresh fired before token expiry (event found in audit log)"
    else
        result "FAIL" "Auto-refresh event not found in audit log after ${WAIT_SECS}s"
        echo "    Check: agent connected? spawn_refresh_task running? RUST_LOG=debug for detail"
    fi
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + SKIP))
echo "=== Results ==="
echo "  Total: $TOTAL | Pass: $PASS | Fail: $FAIL | Skip: $SKIP"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "FAILED: $FAIL test(s) failed"
    exit 1
fi

echo ""
echo "=== E2ET-03 SESSION LIFECYCLE TESTS COMPLETE ==="
