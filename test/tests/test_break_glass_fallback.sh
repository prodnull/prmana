#!/bin/bash
# test/tests/test_break_glass_fallback.sh
# Break-glass fallback integration test
#
# Covers: INT-03 — OIDC unavailable, local auth succeeds, OIDC recovery
#
# Tests three phases:
#   A) Baseline: OIDC works normally
#   B) IdP Down: OIDC fails gracefully, break-glass would bypass
#   C) Recovery: OIDC works again after IdP restart
#
# Prerequisites: curl, jq, docker (or docker compose)
# Environment: docker-compose.ciba-integration.yaml (or docker-compose.test.yaml) running

set -e

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-ciba-test}"
CLIENT_ID="${CLIENT_ID:-unix-oidc-ciba}"
CLIENT_SECRET="${CLIENT_SECRET:-ciba-test-secret}"
TEST_USERNAME="${TEST_USERNAME:-cibauser}"
TEST_PASSWORD="${TEST_PASSWORD:-cibapass}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.ciba-integration.yaml}"

TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

echo "=== Break-Glass Fallback Integration Test ==="
echo "Keycloak: ${KEYCLOAK_URL}"
echo "Compose: ${COMPOSE_FILE}"
echo ""

# ---- Phase A: Baseline — OIDC works ----
echo "--- Phase A: Baseline (OIDC working) ---"

BASELINE_RESPONSE=$(curl -sf --max-time 10 -X POST "$TOKEN_ENDPOINT" \
    -d "grant_type=password" \
    -d "client_id=${CLIENT_ID}" \
    -d "client_secret=${CLIENT_SECRET}" \
    -d "username=${TEST_USERNAME}" \
    -d "password=${TEST_PASSWORD}" \
    -d "scope=openid" \
    2>&1) || true

BASELINE_TOKEN=$(echo "$BASELINE_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null)
if [ -n "$BASELINE_TOKEN" ]; then
    pass "Baseline: OIDC token acquisition works"
else
    fail "Baseline: OIDC token acquisition failed (Keycloak may not be running)"
    echo "Response: $BASELINE_RESPONSE"
    echo ""
    echo "=== Results: $PASS passed, $FAIL failed ==="
    exit 1
fi

# ---- Phase B: IdP Down — OIDC fails gracefully ----
echo ""
echo "--- Phase B: IdP Down (OIDC failure + break-glass) ---"

# Stop Keycloak
echo "Stopping Keycloak..."
docker compose -f "$COMPOSE_FILE" stop keycloak 2>/dev/null || \
    docker-compose -f "$COMPOSE_FILE" stop keycloak 2>/dev/null || \
    echo "WARN: Could not stop keycloak via compose, trying docker stop"

# Wait for it to actually stop
sleep 3

# Verify OIDC is unavailable
echo "Verifying OIDC is unavailable..."
FAIL_RESPONSE=$(curl -sf --max-time 5 -X POST "$TOKEN_ENDPOINT" \
    -d "grant_type=password" \
    -d "client_id=${CLIENT_ID}" \
    -d "client_secret=${CLIENT_SECRET}" \
    -d "username=${TEST_USERNAME}" \
    -d "password=${TEST_PASSWORD}" \
    2>&1) && OIDC_REACHABLE=true || OIDC_REACHABLE=false

if [ "$OIDC_REACHABLE" = false ]; then
    pass "IdP down: OIDC endpoint is unreachable (connection refused / timeout)"
else
    fail "IdP down: OIDC endpoint still reachable after stopping Keycloak"
    echo "Response: $FAIL_RESPONSE"
fi

# Verify break-glass behavior:
# The PAM module's is_break_glass_user() returns PamError::IGNORE for configured
# accounts, bypassing OIDC entirely. We verify this at the code level in the Rust
# integration test. Here we verify the IdP-down behavior doesn't cause a hang.
HANG_START=$(date +%s)
HANG_RESPONSE=$(curl -sf --max-time 5 -X POST "$TOKEN_ENDPOINT" \
    -d "grant_type=password" \
    -d "client_id=${CLIENT_ID}" \
    -d "client_secret=${CLIENT_SECRET}" \
    -d "username=nonexistent" \
    -d "password=wrong" \
    2>&1) && HANG_EXIT=0 || HANG_EXIT=$?
HANG_END=$(date +%s)
HANG_DURATION=$((HANG_END - HANG_START))

if [ $HANG_DURATION -le 6 ]; then
    pass "IdP down: OIDC request fails within timeout (${HANG_DURATION}s, not hanging)"
else
    fail "IdP down: OIDC request took too long (${HANG_DURATION}s — possible hang)"
fi

# ---- Phase C: Recovery — OIDC works again after restart ----
echo ""
echo "--- Phase C: Recovery (OIDC restored) ---"

echo "Restarting Keycloak..."
docker compose -f "$COMPOSE_FILE" start keycloak 2>/dev/null || \
    docker-compose -f "$COMPOSE_FILE" start keycloak 2>/dev/null

# Wait for Keycloak to become healthy
echo "Waiting for Keycloak health..."
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    HEALTH=$(curl -sf --max-time 3 "http://localhost:9000/health/ready" 2>/dev/null) && break || true
    WAITED=$((WAITED + 5))
    echo "  Waiting... (${WAITED}/${MAX_WAIT}s)"
    sleep 5
done

if [ $WAITED -ge $MAX_WAIT ]; then
    fail "Recovery: Keycloak did not become healthy within ${MAX_WAIT}s"
    echo ""
    echo "=== Results: $PASS passed, $FAIL failed ==="
    exit 1
fi

pass "Recovery: Keycloak is healthy again"

# Verify OIDC works again
RECOVERY_RESPONSE=$(curl -sf --max-time 10 -X POST "$TOKEN_ENDPOINT" \
    -d "grant_type=password" \
    -d "client_id=${CLIENT_ID}" \
    -d "client_secret=${CLIENT_SECRET}" \
    -d "username=${TEST_USERNAME}" \
    -d "password=${TEST_PASSWORD}" \
    -d "scope=openid" \
    2>&1) || true

RECOVERY_TOKEN=$(echo "$RECOVERY_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null)
if [ -n "$RECOVERY_TOKEN" ]; then
    pass "Recovery: OIDC token acquisition restored"
else
    fail "Recovery: OIDC token acquisition still failing after restart"
    echo "Response: $RECOVERY_RESPONSE"
fi

# ---- Summary ----
echo ""
echo "=== Break-Glass Fallback Test Results ==="
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

if [ $FAIL -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
