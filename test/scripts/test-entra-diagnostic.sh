#!/usr/bin/env bash
# Mock-based unit tests for Entra ROPC Conditional Access diagnostic.
#
# Tests that check_conditional_access_error() correctly:
#   1. Fires diagnostic on Conditional Access errors (AADSTS50076, AADSTS53003, etc.)
#   2. Does NOT fire on valid token responses
#   3. Does NOT fire on non-CA errors (e.g., invalid_grant)
#
# Exit 0 if all tests pass, non-zero on any failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0
FAIL=0

# Source the diagnostic function from get-entra-token.sh without executing main body.
_ENTRA_TOKEN_SOURCED=1
# shellcheck source=get-entra-token.sh
source "${SCRIPT_DIR}/get-entra-token.sh"

assert_eq() {
  local test_name="$1" expected="$2" actual="$3"
  if [ "${expected}" = "${actual}" ]; then
    echo "  PASS: ${test_name}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${test_name} (expected=${expected}, actual=${actual})"
    FAIL=$((FAIL + 1))
  fi
}

assert_contains() {
  local test_name="$1" haystack="$2" needle="$3"
  if echo "${haystack}" | grep -qF "${needle}"; then
    echo "  PASS: ${test_name}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${test_name} (output does not contain '${needle}')"
    FAIL=$((FAIL + 1))
  fi
}

assert_not_contains() {
  local test_name="$1" haystack="$2" needle="$3"
  if echo "${haystack}" | grep -qF "${needle}"; then
    echo "  FAIL: ${test_name} (output unexpectedly contains '${needle}')"
    FAIL=$((FAIL + 1))
  else
    echo "  PASS: ${test_name}"
    PASS=$((PASS + 1))
  fi
}

# ---------------------------------------------------------------------------
# Test 1: AADSTS50076 (MFA required) triggers diagnostic
# ---------------------------------------------------------------------------
echo "Test 1: AADSTS50076 triggers Conditional Access diagnostic"
CA_RESPONSE='{"error":"interaction_required","error_description":"AADSTS50076: Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access."}'
STDERR_OUTPUT=$(check_conditional_access_error "${CA_RESPONSE}" 2>&1 1>/dev/null)
RETVAL=$?
assert_eq "return code is 0 (CA detected)" "0" "${RETVAL}"
assert_contains "stderr mentions DIAGNOSTIC" "${STDERR_OUTPUT}" "DIAGNOSTIC: Entra ROPC failed due to Conditional Access policy."
assert_contains "stderr mentions MFA" "${STDERR_OUTPUT}" "MFA required for test user"
assert_contains "stderr shows error code" "${STDERR_OUTPUT}" "interaction_required"

# ---------------------------------------------------------------------------
# Test 2: AADSTS53003 (Conditional Access block) triggers diagnostic
# ---------------------------------------------------------------------------
echo "Test 2: AADSTS53003 triggers Conditional Access diagnostic"
CA_RESPONSE2='{"error":"access_denied","error_description":"AADSTS53003: Access has been blocked by Conditional Access policies."}'
STDERR_OUTPUT2=$(check_conditional_access_error "${CA_RESPONSE2}" 2>&1 1>/dev/null)
RETVAL2=$?
assert_eq "return code is 0 (CA detected)" "0" "${RETVAL2}"
assert_contains "stderr mentions DIAGNOSTIC" "${STDERR_OUTPUT2}" "DIAGNOSTIC: Entra ROPC failed due to Conditional Access policy."

# ---------------------------------------------------------------------------
# Test 3: AADSTS50079 (MFA registration required) triggers diagnostic
# ---------------------------------------------------------------------------
echo "Test 3: AADSTS50079 triggers Conditional Access diagnostic"
CA_RESPONSE3='{"error":"interaction_required","error_description":"AADSTS50079: The user is required to use multi-factor authentication."}'
STDERR_OUTPUT3=$(check_conditional_access_error "${CA_RESPONSE3}" 2>&1 1>/dev/null)
RETVAL3=$?
assert_eq "return code is 0 (CA detected)" "0" "${RETVAL3}"

# ---------------------------------------------------------------------------
# Test 4: Valid token response does NOT trigger diagnostic
# ---------------------------------------------------------------------------
echo "Test 4: Valid token does NOT trigger diagnostic"
VALID_RESPONSE='{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake","token_type":"Bearer","expires_in":3600}'
STDERR_OUTPUT4=$(check_conditional_access_error "${VALID_RESPONSE}" 2>&1 1>/dev/null) && RETVAL4=0 || RETVAL4=$?
assert_eq "return code is 1 (no CA error)" "1" "${RETVAL4}"
assert_not_contains "no DIAGNOSTIC in stderr" "${STDERR_OUTPUT4}" "DIAGNOSTIC"

# ---------------------------------------------------------------------------
# Test 5: Non-CA error (invalid_grant) does NOT trigger CA diagnostic
# ---------------------------------------------------------------------------
echo "Test 5: Non-CA error does NOT trigger CA diagnostic"
NON_CA_RESPONSE='{"error":"invalid_grant","error_description":"AADSTS70002: Error validating credentials. AADSTS50126: Invalid username or password."}'
STDERR_OUTPUT5=$(check_conditional_access_error "${NON_CA_RESPONSE}" 2>&1 1>/dev/null) && RETVAL5=0 || RETVAL5=$?
assert_eq "return code is 1 (no CA error)" "1" "${RETVAL5}"
assert_not_contains "no DIAGNOSTIC in stderr" "${STDERR_OUTPUT5}" "DIAGNOSTIC"

# ---------------------------------------------------------------------------
# Test 6: interaction_required without AADSTS code still triggers diagnostic
# ---------------------------------------------------------------------------
echo "Test 6: interaction_required error code triggers diagnostic"
IR_RESPONSE='{"error":"interaction_required","error_description":"User interaction is required."}'
STDERR_OUTPUT6=$(check_conditional_access_error "${IR_RESPONSE}" 2>&1 1>/dev/null)
RETVAL6=$?
assert_eq "return code is 0 (CA detected)" "0" "${RETVAL6}"
assert_contains "stderr mentions DIAGNOSTIC" "${STDERR_OUTPUT6}" "DIAGNOSTIC"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [ "${FAIL}" -gt 0 ]; then
  exit 1
fi
echo "All tests passed."
exit 0
