#!/bin/bash
# test/scripts/run-integration-tests.sh
#
# Run integration tests for unix-oidc
#
# Usage:
#   ./run-integration-tests.sh              # Run all tests
#   ./run-integration-tests.sh connectivity # Run only connectivity tests
#   ./run-integration-tests.sh oidc         # Run only OIDC tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/../tests"
PROJECT_ROOT="$SCRIPT_DIR/../.."

# Test results
PASSED=0
FAILED=0
SKIPPED=0

# Colors (if terminal supports them)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Create unique temp file and clean up on exit
TMPFILE=$(mktemp /tmp/test-output.XXXXXX)
trap "rm -f $TMPFILE" EXIT

print_header() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
    echo ""
}

run_test() {
    local name="$1"
    local script="$2"
    local skip_on_missing="${3:-false}"

    printf "  %-50s" "$name"

    if [ ! -f "$script" ]; then
        if [ "$skip_on_missing" = "true" ]; then
            echo -e "${YELLOW}SKIP${NC} (script not found)"
            SKIPPED=$((SKIPPED + 1))
            return 0
        else
            echo -e "${RED}FAIL${NC} (script not found: $script)"
            FAILED=$((FAILED + 1))
            return 1
        fi
    fi

    if ! [ -x "$script" ]; then
        chmod +x "$script"
    fi

    if bash "$script" > "$TMPFILE" 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        echo ""
        echo "    --- Output ---"
        sed 's/^/    /' "$TMPFILE"
        echo "    --------------"
        echo ""
        FAILED=$((FAILED + 1))
        return 1
    fi
}

run_connectivity_tests() {
    print_header "Connectivity Tests"
    run_test "Keycloak OIDC discovery" "$TEST_DIR/test_keycloak_reachable.sh"
    run_test "OpenLDAP server" "$TEST_DIR/test_ldap_reachable.sh"
    run_test "SSH server (test-host)" "$TEST_DIR/test_ssh_reachable.sh"
}

run_user_tests() {
    print_header "User Resolution Tests"
    run_test "SSSD resolves testuser from LDAP" "$TEST_DIR/test_sssd_user.sh"
}

run_oidc_tests() {
    print_header "OIDC Authentication Tests"
    run_test "Get access token from Keycloak" "$TEST_DIR/test_get_token.sh"
    run_test "PAM module validates OIDC token" "$TEST_DIR/test_ssh_oidc_valid.sh" "true"
}

run_sudo_tests() {
    print_header "Sudo Step-Up Tests"
    run_test "Sudo step-up authentication flow" "$TEST_DIR/test_sudo_step_up.sh" "true"
}

run_all_tests() {
    run_connectivity_tests
    run_user_tests
    run_oidc_tests
    run_sudo_tests
}

print_summary() {
    echo ""
    echo -e "${BLUE}=== Test Summary ===${NC}"
    echo ""
    echo -e "  Passed:  ${GREEN}$PASSED${NC}"
    echo -e "  Failed:  ${RED}$FAILED${NC}"
    echo -e "  Skipped: ${YELLOW}$SKIPPED${NC}"
    echo ""

    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed.${NC}"
        return 1
    fi
}

# Main
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           unix-oidc Integration Test Suite                   ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

case "${1:-all}" in
    connectivity)
        run_connectivity_tests
        ;;
    user|users)
        run_user_tests
        ;;
    oidc)
        run_oidc_tests
        ;;
    sudo)
        run_sudo_tests
        ;;
    all|*)
        run_all_tests
        ;;
esac

print_summary
exit $?
