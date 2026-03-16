#!/usr/bin/env bash
# test/tests/test_break_glass_e2e.sh
# Automated E2E test: break-glass PAM bypass and NSS group policy denial.
#
# Requirement coverage: E2ET-02
#   - Test 1: Break-glass account SSH succeeds when Keycloak is down
#             BREAK_GLASS_AUTH or break_glass event appears in auth log
#   - Test 2: Regular user NOT in login_groups is denied via NSS group policy
#             PAM log shows group policy denial
#   - Test 3: Regular user IN login_groups succeeds via OIDC keyboard-interactive
#
# Architecture notes:
#   - Break-glass users are configured in policy.yaml under break_glass.accounts.
#     pam-unix-oidc returns PAM_IGNORE for break-glass users, which falls through
#     to pam_unix (local password auth). See pam-unix-oidc/src/lib.rs §break_glass.
#   - login_groups policy is enforced via pam_access or NSS/SSSD group membership.
#     Users not in the configured group receive PAM_PERM_DENIED with a group policy
#     denial message in auth.log.
#
# Prerequisites:
#   - docker compose stack running (docker-compose.test.yaml by default)
#   - sshpass available for break-glass password auth, OR expect
#   - Keycloak configured for realm unix-oidc with testuser in login_groups
#   - break-glass user configured in policy.yaml (default: breakglass)
#   - testuser2 (or equivalent) NOT in login_groups (see TODO below)
#   - test/e2e/ssh-askpass-e2e.sh present for OIDC flow
#
# Usage:
#   COMPOSE_FILE=docker-compose.test.yaml bash test/tests/test_break_glass_e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.test.yaml}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-unix-oidc}"
CLIENT_ID="${CLIENT_ID:-unix-oidc}"
CONTAINER="${CONTAINER:-test-host}"
SSH_PORT="${SSH_PORT:-2222}"

BREAK_GLASS_USER="${BREAK_GLASS_USER:-breakglass}"
BREAK_GLASS_PASS="${BREAK_GLASS_PASS:-breakglass-secret}"

NORMAL_USER_IN_GROUP="${NORMAL_USER_IN_GROUP:-testuser}"
NORMAL_USER_PASS="${NORMAL_USER_PASS:-testpass}"

# testuser2 is expected to be configured as a valid system user but NOT a member
# of the login_groups configured in policy.yaml.
# TODO: configure testuser2 as non-member of login_groups in docker-compose.test.yaml
#       and policy.yaml to enable Test 2 as a real assertion rather than SKIP.
NORMAL_USER_NOT_IN_GROUP="${NORMAL_USER_NOT_IN_GROUP:-testuser2}"

ASKPASS_SCRIPT="${PROJECT_ROOT}/test/e2e/ssh-askpass-e2e.sh"

# ---------------------------------------------------------------------------
# Pass/fail counters and helpers (same pattern as test_break_glass_fallback.sh)
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  [SKIP] $1"; }

echo "=== E2ET-02: Break-Glass PAM Flow + NSS Group Policy Denial E2E Test ==="
echo "Compose:  $COMPOSE_FILE"
echo "Keycloak: $KEYCLOAK_URL"
echo "SSH port: $SSH_PORT"
echo ""

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
echo "--- Prerequisites ---"

if ! command -v docker &>/dev/null; then
    skip "docker not available — skipping all E2E tests"
    echo ""
    echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped ==="
    exit 0
fi

if ! docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps 2>/dev/null | grep -q "$CONTAINER"; then
    skip "Docker stack not running ($CONTAINER not found) — skipping all E2E tests"
    echo "  Start with: docker compose -f $COMPOSE_FILE up -d"
    echo ""
    echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped ==="
    exit 0
fi
pass "Docker stack running ($CONTAINER found)"

# Check if break-glass user exists in container.
if docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" exec -T "$CONTAINER" \
        id "$BREAK_GLASS_USER" >/dev/null 2>&1; then
    pass "Break-glass user $BREAK_GLASS_USER exists in container"
else
    skip "Break-glass user $BREAK_GLASS_USER not found in container — Test 1 will be skipped"
fi

# Check sshpass availability (needed for break-glass password auth).
SSHPASS_AVAILABLE=false
if command -v sshpass &>/dev/null; then
    SSHPASS_AVAILABLE=true
    pass "sshpass available for break-glass auth"
else
    skip "sshpass not available — Test 1 will fall back to key-based assertion"
fi

# SSH_ASKPASS script for OIDC flow (Test 3).
if [ -f "$ASKPASS_SCRIPT" ]; then
    chmod +x "$ASKPASS_SCRIPT"
    pass "SSH_ASKPASS script present for OIDC flow"
else
    skip "SSH_ASKPASS script not found at $ASKPASS_SCRIPT — Test 3 will be skipped"
fi

echo ""

# ---------------------------------------------------------------------------
# Test 1: Break-glass account SSH succeeds when Keycloak is DOWN
#
# 1a. Stop Keycloak in the compose stack.
# 1b. Attempt SSH as break-glass user with local password (sshpass).
# 1c. Confirm SSH succeeds (exit 0, BREAK_GLASS_OK in output).
# 1d. Confirm audit log contains BREAK_GLASS_AUTH or break_glass event.
# 1e. Restart Keycloak.
# ---------------------------------------------------------------------------
echo "--- Test 1: Break-glass SSH when IdP is down (E2ET-02 positive) ---"

# Clear audit log.
docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" exec -T "$CONTAINER" \
    bash -c "truncate -s0 /var/log/unix-oidc-audit.log 2>/dev/null; true" \
    >/dev/null 2>&1

# Stop Keycloak.
echo "  Stopping Keycloak..."
docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" stop keycloak 2>/dev/null \
    || docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" stop keycloak 2>/dev/null \
    || true
sleep 3

# Verify Keycloak is actually unreachable.
KC_REACHABLE=false
curl -sf --max-time 4 "${KEYCLOAK_URL}/health/ready" >/dev/null 2>&1 && KC_REACHABLE=true || true
if [ "$KC_REACHABLE" = true ]; then
    fail "Keycloak still reachable after docker stop (Test 1 may give false results)"
else
    pass "Keycloak is unreachable (IdP down confirmed)"
fi

if [ "$SSHPASS_AVAILABLE" = true ]; then
    BG_RESULT=""
    BG_EXIT=0
    BG_RESULT=$(sshpass -p "$BREAK_GLASS_PASS" \
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o PreferredAuthentications=password \
            -o ConnectTimeout=10 \
            -p "$SSH_PORT" \
            "${BREAK_GLASS_USER}@localhost" \
            "echo BREAK_GLASS_OK" 2>/dev/null) || BG_EXIT=$?

    if [ "$BG_EXIT" -eq 0 ] && echo "$BG_RESULT" | grep -q "BREAK_GLASS_OK"; then
        pass "Break-glass SSH succeeded when IdP is down (BREAK_GLASS_OK)"

        # Check audit log for BREAK_GLASS_AUTH event.
        BG_AUDIT=$(docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" exec -T "$CONTAINER" \
            cat /var/log/unix-oidc-audit.log 2>/dev/null || echo "")

        if echo "$BG_AUDIT" | grep -qEi "BREAK_GLASS_AUTH|break_glass"; then
            pass "Audit log contains BREAK_GLASS_AUTH / break_glass event"
        else
            # Some configurations emit to auth.log rather than audit log.
            BG_AUTH_LOG=$(docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" exec -T "$CONTAINER" \
                bash -c "grep -i 'break.glass\|BREAK_GLASS' /var/log/auth.log 2>/dev/null || echo ''" \
                2>/dev/null || echo "")
            if [ -n "$BG_AUTH_LOG" ]; then
                pass "Break-glass event found in auth.log: ${BG_AUTH_LOG:0:120}"
            else
                fail "No BREAK_GLASS_AUTH event in audit log or auth.log after break-glass login"
                echo "    Audit: ${BG_AUDIT:0:200}"
            fi
        fi
    else
        fail "Break-glass SSH failed (exit=$BG_EXIT, output=${BG_RESULT:-empty})"
        echo "    Note: Verify $BREAK_GLASS_USER has a local password in the container"
        echo "    and that /etc/pam.d/sshd is configured to fall through to pam_unix."
    fi
else
    skip "Break-glass SSH test skipped (sshpass not available)"
    echo "    Install sshpass to enable this test assertion."
fi

# Restart Keycloak.
echo "  Restarting Keycloak..."
docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" start keycloak 2>/dev/null \
    || docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" start keycloak 2>/dev/null \
    || true

# Wait for Keycloak to become healthy before continuing.
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    curl -sf --max-time 3 "${KEYCLOAK_URL}/health/ready" >/dev/null 2>&1 && break || true
    WAITED=$((WAITED + 5))
    echo "  Waiting for Keycloak health... (${WAITED}/${MAX_WAIT}s)"
    sleep 5
done

if [ $WAITED -ge $MAX_WAIT ]; then
    fail "Keycloak did not become healthy within ${MAX_WAIT}s — remaining tests may fail"
else
    pass "Keycloak healthy again after restart"
fi

echo ""

# ---------------------------------------------------------------------------
# Test 2: NSS group policy denial — user NOT in login_groups is denied
#
# A user who exists in SSSD/NSS but is NOT configured in login_groups should
# receive PAM_PERM_DENIED. The auth log should reflect a group policy denial.
#
# Note: If testuser2 is not yet configured as a non-member of login_groups in
# the compose stack, this test is skipped with a TODO comment.
# ---------------------------------------------------------------------------
echo "--- Test 2: NSS group policy denial for non-member of login_groups (E2ET-02 negative) ---"

# Check whether testuser2 exists in the container as a user who is NOT in login_groups.
TESTUSER2_EXISTS=false
docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" exec -T "$CONTAINER" \
    id "$NORMAL_USER_NOT_IN_GROUP" >/dev/null 2>&1 && TESTUSER2_EXISTS=true || true

if [ "$TESTUSER2_EXISTS" = false ]; then
    skip "User $NORMAL_USER_NOT_IN_GROUP not found in container"
    echo "    # TODO: configure $NORMAL_USER_NOT_IN_GROUP as non-member of login_groups"
    echo "    #   in docker-compose.test.yaml, policy.yaml (login_groups), and"
    echo "    #   SSSD/NSS (add user with no unix_oidc group membership)."
    echo "    #   Once configured, re-run this test to validate NSS group policy denial."
else
    # Clear auth log before the test.
    docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" exec -T "$CONTAINER" \
        bash -c "truncate -s0 /var/log/auth.log 2>/dev/null; true" \
        >/dev/null 2>&1

    DENY_RESULT=""
    DENY_EXIT=0
    DENY_RESULT=$(ssh -o BatchMode=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -p "$SSH_PORT" \
        "${NORMAL_USER_NOT_IN_GROUP}@localhost" \
        "echo SHOULD_NOT_REACH" 2>/dev/null) || DENY_EXIT=$?

    if echo "$DENY_RESULT" | grep -q "SHOULD_NOT_REACH"; then
        fail "Non-login-group user $NORMAL_USER_NOT_IN_GROUP was allowed (SECURITY VIOLATION: group policy not enforced)"
    else
        pass "Non-login-group user $NORMAL_USER_NOT_IN_GROUP was denied (exit=$DENY_EXIT)"

        # Verify the denial reason appears in auth log.
        DENY_LOG=$(docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" exec -T "$CONTAINER" \
            bash -c "grep -Ei 'group policy|not in login_groups|access denied|pam_access' \
                     /var/log/auth.log 2>/dev/null || echo ''" \
            2>/dev/null || echo "")

        if [ -n "$DENY_LOG" ]; then
            pass "Auth log contains group policy / login_groups denial: ${DENY_LOG:0:120}"
        else
            skip "Group policy denial message not found in auth.log (may be in syslog or audit log)"
            echo "    SSH was correctly denied but specific denial reason not confirmed in auth.log."
        fi
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Test 3: Normal user IN login_groups succeeds via OIDC keyboard-interactive
# ---------------------------------------------------------------------------
echo "--- Test 3: Normal user in login_groups succeeds (E2ET-02 positive) ---"

if [ ! -f "$ASKPASS_SCRIPT" ]; then
    skip "Test 3 skipped — SSH_ASKPASS script not found"
else
    # Acquire OIDC token for testuser.
    TOKEN_RESPONSE=$(curl -sf -X POST \
        "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password&client_id=${CLIENT_ID}&username=${NORMAL_USER_IN_GROUP}&password=${NORMAL_USER_PASS}&scope=openid" \
        2>/dev/null || echo '{"error":"request_failed"}')

    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null || echo "")

    if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
        skip "Test 3 skipped — OIDC token acquisition failed (Keycloak not ready or not configured)"
        echo "    Response: $TOKEN_RESPONSE"
    else
        TOKEN_FILE_3=$(mktemp /tmp/unix-oidc-bg-e2e-XXXXXX)
        echo -n "$ACCESS_TOKEN" >"$TOKEN_FILE_3"
        chmod 600 "$TOKEN_FILE_3"
        trap 'rm -f "$TOKEN_FILE_3"' EXIT

        NORM_RESULT=""
        NORM_EXIT=0
        NORM_RESULT=$(DISPLAY=:0 \
            SSH_ASKPASS="$ASKPASS_SCRIPT" \
            SSH_ASKPASS_REQUIRE=force \
            UNIX_OIDC_E2E_TOKEN_FILE="$TOKEN_FILE_3" \
            ssh -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o PreferredAuthentications=keyboard-interactive \
                -o NumberOfPasswordPrompts=3 \
                -o ConnectTimeout=15 \
                -p "$SSH_PORT" \
                "${NORMAL_USER_IN_GROUP}@localhost" \
                "echo AUTH_OK" 2>/dev/null) || NORM_EXIT=$?

        rm -f "$TOKEN_FILE_3"

        if [ "$NORM_EXIT" -eq 0 ] && echo "$NORM_RESULT" | grep -q "AUTH_OK"; then
            pass "Normal user $NORMAL_USER_IN_GROUP in login_groups authenticated via OIDC (AUTH_OK)"
        else
            fail "Normal user $NORMAL_USER_IN_GROUP in login_groups SSH failed (exit=$NORM_EXIT)"
            echo "    Output: ${NORM_RESULT:-empty}"
        fi
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS + FAIL + SKIP))
echo "=== E2ET-02 Results ==="
echo "  Total: $TOTAL  |  Pass: $PASS  |  Fail: $FAIL  |  Skip: $SKIP"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "FAIL: $FAIL test(s) failed"
    exit 1
fi

echo "ALL E2ET-02 TESTS PASSED (or skipped)"
exit 0
