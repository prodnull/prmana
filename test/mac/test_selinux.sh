#!/bin/bash
# Prmana SELinux Policy Validator

echo "--- SECTION A: Static Tests (No policy load required) ---"

# Syntax check via checkmodule (requires: apt-get install checkpolicy)
if command -v checkmodule >/dev/null 2>&1; then
    _tmpdir=$(mktemp -d)
    checkmodule -M -m -o "$_tmpdir/prmana.mod" packaging/selinux/prmana.te 2>&1 \
        && echo "PASS: Policy parses correctly" || echo "FAIL: Policy syntax error"
    rm -rf "$_tmpdir"
else
    echo "SKIP: checkmodule not installed (apt-get install checkpolicy)"
fi

# Grep-based shadow_t check: works in CI without a loaded policy
if grep -qP 'allow\s+prmana_agent_t\s+shadow_t' packaging/selinux/prmana.te; then
    echo "FAIL: prmana.te grants shadow_t access"
else
    echo "PASS: No shadow_t access in source"
fi

# Grep-based net_bind_service check
if grep -qP 'net_bind_service' packaging/selinux/prmana.te; then
    echo "FAIL: prmana.te still contains net_bind_service (over-privilege)"
else
    echo "PASS: net_bind_service absent"
fi

# Verify PAM client rules are present
if grep -q 'sshd_t' packaging/selinux/prmana.te && grep -q 'sudo_t' packaging/selinux/prmana.te; then
    echo "PASS: PAM client (sshd_t, sudo_t) connect rules present"
else
    echo "FAIL: Missing PAM client connect rules"
fi

# Verify socket activation rules are present
if grep -q 'init_t:fd use' packaging/selinux/prmana.te; then
    echo "PASS: Socket activation fd inheritance rule present"
else
    echo "FAIL: Missing init_t:fd use rule (socket activation will fail)"
fi

echo "--- SECTION B: Runtime Tests (Requires DT-0 fleet / loaded policy) ---"
if [ "$(getenforce 2>/dev/null)" != "Enforcing" ]; then
    echo "SKIP: Runtime tests require SELinux in Enforcing mode"
    exit 0
fi

# Verify labeling
ls -Z /usr/bin/prmana-agent | grep -q "prmana_agent_exec_t" \
    && echo "PASS: Binary labeled" || echo "FAIL: Binary labeling"

# Test blocked action
sudo runcon -u system_u -r system_r -t prmana_agent_t cat /etc/shadow 2>&1 \
    | grep -q "Permission denied" \
    && echo "PASS: Blocked from sensitive files" \
    || echo "FAIL: Security breach - /etc/shadow accessible"
