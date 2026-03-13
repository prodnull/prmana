#!/bin/bash
# test/scripts/run-e2e-sentinel.sh
# INFR-03: Sentinel assertion — verify UNIX_OIDC_TEST_MODE is NOT set
# in the E2E test environment. This must pass before any real-signature
# test runs, or the entire E2E suite is invalid.

set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.e2e.yaml}"
CONTAINER="${E2E_CONTAINER:-test-host-e2e}"

echo "=== E2E Sentinel: Verifying TEST_MODE is absent ==="

# Check 1: env var must not be set inside the container
if docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" env | grep -q "UNIX_OIDC_TEST_MODE"; then
    echo "FATAL: UNIX_OIDC_TEST_MODE is set inside $CONTAINER"
    echo "E2E tests require real OIDC signature verification."
    echo "Remove UNIX_OIDC_TEST_MODE from docker-compose.e2e.yaml."
    exit 1
fi

echo "  [PASS] UNIX_OIDC_TEST_MODE not set in $CONTAINER"

# Check 2: Verify the PAM module binary does not have test-mode compiled in
# (this checks the feature flag at binary level, not just env var)
if docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" \
    sh -c 'strings /lib/security/pam_unix_oidc.so 2>/dev/null | grep -qi "insecure_for_testing"' 2>/dev/null; then
    echo "WARNING: PAM module binary contains test-mode symbols."
    echo "Ensure the binary was built without --features test-mode."
fi

# Check 3: Verify agent binary is on PATH
if ! docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" which unix-oidc-agent >/dev/null 2>&1; then
    echo "FATAL: unix-oidc-agent not found on PATH inside $CONTAINER"
    exit 1
fi
echo "  [PASS] unix-oidc-agent binary found on PATH"

# Check 4: Verify agent binary is executable
if ! docker compose -f "$COMPOSE_FILE" exec -T "$CONTAINER" unix-oidc-agent --version >/dev/null 2>&1; then
    echo "WARNING: unix-oidc-agent --version failed (may need runtime dependencies)"
fi

echo ""
echo "=== E2E Sentinel: All checks passed ==="
