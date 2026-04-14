#!/bin/bash
# Prmana AppArmor Policy Validator

PROFILE="usr.bin.prmana-agent"
PROFILE_PATH="packaging/apparmor/$PROFILE"

echo "--- SECTION A: Static Tests ---"

# Static parse (apparmor_parser is pre-installed on Ubuntu)
if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -S "$PROFILE_PATH" >/dev/null \
        && echo "PASS: Profile parses correctly" || echo "FAIL: Profile syntax error"
else
    echo "SKIP: apparmor_parser not installed"
fi

# Grep-based net_bind_service check
if grep -q 'net_bind_service' "$PROFILE_PATH"; then
    echo "FAIL: Profile still contains net_bind_service (over-privilege)"
else
    echo "PASS: net_bind_service absent"
fi

# Verify unix socket mediation rules are present
if grep -q 'unix (create, bind' "$PROFILE_PATH"; then
    echo "PASS: Unix socket mediation rules present"
else
    echo "FAIL: Missing unix socket mediation rules (will break on Ubuntu 22.04+)"
fi

# Verify sysfs paths are present
if grep -q 'sys/block' "$PROFILE_PATH"; then
    echo "PASS: sysfs rotational-device paths present"
else
    echo "FAIL: Missing /sys/block paths (detect_rotational_device will fail)"
fi

echo "--- SECTION B: Runtime Tests (Requires DT-0 fleet / Enforce mode) ---"
if ! aa-status 2>/dev/null | grep -q "$PROFILE (enforce)"; then
    echo "SKIP: Runtime tests require $PROFILE in Enforce mode"
    exit 0
fi

# Test allowed action — use id -un so owner match works for non-root runners
PRMANA_TEST_DIR="/home/$(id -un)/.local/share/prmana"
mkdir -p "$PRMANA_TEST_DIR"
aa-exec -p "$PROFILE" touch "$PRMANA_TEST_DIR/test_cred" 2>/dev/null \
    && echo "PASS: Credential write allowed" || echo "FAIL: Credential write blocked"
rm -f "$PRMANA_TEST_DIR/test_cred"

# Test blocked action
aa-exec -p "$PROFILE" cat /etc/shadow 2>&1 | grep -q "Permission denied" \
    && echo "PASS: Sensitive read blocked" || echo "FAIL: Security breach - /etc/shadow leaked"
