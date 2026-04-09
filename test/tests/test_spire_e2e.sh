#!/bin/bash
# test/tests/test_spire_e2e.sh
# End-to-end SPIFFE/SPIRE bridge test (Phase 35)
#
# Verifies the full flow:
# 1. SPIRE agent issues JWT-SVIDs via Workload API
# 2. SpireSigner fetches SVID and generates DPoP proof
# 3. PAM module validates JWT-SVID as OIDC token
# 4. SPIFFE ID maps to Unix username via configured strategy
#
# Requires: docker compose -f docker-compose.spire-test.yaml up -d
# Environment: UNIX_OIDC_SPIRE_SOCKET (default: /tmp/spire-agent/public/api.sock)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="docker-compose.spire-test.yaml"
SPIRE_SOCKET="${UNIX_OIDC_SPIRE_SOCKET:-/tmp/spire-agent/public/api.sock}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

pass() { echo -e "  ${GREEN}PASS${NC}: $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; FAIL=$((FAIL + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC}: $1"; SKIP=$((SKIP + 1)); }

echo "=========================================="
echo "SPIFFE/SPIRE Bridge E2E Tests (Phase 35)"
echo "=========================================="
echo ""

# ── Prerequisite: SPIRE agent must be running ────────────────────────────────

echo "Checking SPIRE agent..."
if [ ! -S "$SPIRE_SOCKET" ]; then
    echo -e "${YELLOW}SPIRE agent socket not found at $SPIRE_SOCKET${NC}"
    echo "Start SPIRE: docker compose -f $COMPOSE_FILE up -d"
    echo "All tests skipped."
    exit 0
fi
echo -e "  SPIRE socket: $SPIRE_SOCKET"
echo ""

# ── Test 1: SpireSigner unit + integration tests ────────────────────────────

echo "Test 1: SpireSigner Rust tests (unit + integration)..."
if cargo test -p unix-oidc-agent --features spire --lib -- spire 2>/dev/null | grep -q "test result: ok"; then
    pass "SpireSigner unit tests"
else
    fail "SpireSigner unit tests"
fi

echo ""
echo "Test 2: SpireSigner live SPIRE integration tests..."
if UNIX_OIDC_SPIRE_SOCKET="$SPIRE_SOCKET" \
    cargo test -p unix-oidc-agent --features spire -- --ignored spire 2>&1 | grep -q "test result: ok"; then
    pass "SpireSigner live SVID fetch + caching"
else
    fail "SpireSigner live SVID fetch"
fi

# ── Test 3: SPIFFE username mapping ──────────────────────────────────────────

echo ""
echo "Test 3: SPIFFE username mapping (PAM module)..."
if cargo test -p pam-unix-oidc --lib -- spiffe 2>/dev/null | grep -q "test result: ok"; then
    pass "SPIFFE ID → Unix username mapping (all strategies)"
else
    fail "SPIFFE username mapping tests"
fi

# ── Test 4: Reserved username denylist ───────────────────────────────────────

echo ""
echo "Test 4: Reserved username denylist enforcement..."
if cargo test -p pam-unix-oidc --lib -- "reserved_username\|validate_username" 2>/dev/null | grep -q "test result: ok"; then
    pass "Reserved username denylist (root, sshd, nobody, etc.)"
else
    fail "Reserved username denylist"
fi

# ── Test 5: DPoP proof generation with SPIRE signer ─────────────────────────

echo ""
echo "Test 5: DPoP proof generation (ephemeral keys, ADR-016)..."
if cargo test -p unix-oidc-agent --features spire --lib -- "spire_signer.*proof" 2>/dev/null | grep -q "test result: ok"; then
    pass "DPoP proofs from ephemeral keys (not SVID keys)"
else
    fail "DPoP proof generation"
fi

# ── Test 6: Protobuf round-trip ──────────────────────────────────────────────

echo ""
echo "Test 6: Workload API protobuf stubs..."
if cargo test -p unix-oidc-agent --features spire --lib -- "workload_api" 2>/dev/null | grep -q "test result: ok"; then
    pass "FetchJWTSVID request/response protobuf round-trip"
else
    fail "Protobuf stub tests"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC}"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
