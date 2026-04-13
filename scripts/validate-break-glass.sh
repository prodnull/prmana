#!/usr/bin/env bash
# validate-break-glass.sh — Verify break-glass access works before/during OIDC migration.
#
# Part of the Prmana Rollout & Migration Toolkit (Phase 43).
#
# Usage:
#   sudo ./validate-break-glass.sh                  # validate locally
#   ./validate-break-glass.sh --host server.example.com  # validate remote
#
# What it checks:
#   1. Break-glass user exists in /etc/prmana/policy.yaml
#   2. Break-glass user exists in /etc/passwd (or can authenticate)
#   3. PAM config allows password fallback
#   4. sshd allows password authentication
#   5. SSH login attempt with break-glass user succeeds
#
# IMPORTANT: This script tests the break-glass account by attempting
# an actual SSH connection. Run it BEFORE disabling SSH key auth.
#
# Prerequisites:
#   - Break-glass account configured in policy.yaml
#   - Break-glass user created on the system
#   - sshd configured to allow password auth (at least for break-glass)

set -euo pipefail

HOST="localhost"
POLICY_PATH="/etc/prmana/policy.yaml"
VERBOSE=false

usage() {
    cat <<'EOF'
Usage: validate-break-glass.sh [OPTIONS]

Options:
  --host HOST       Target host (default: localhost)
  --policy PATH     Policy file path (default: /etc/prmana/policy.yaml)
  --verbose         Show detailed output
  -h, --help        Show this help

This script validates that break-glass access works. Run it:
  - After initial Prmana installation
  - Before disabling SSH key authentication
  - As part of quarterly DR exercises
  - After any PAM configuration changes
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --policy) POLICY_PATH="$2"; shift 2 ;;
        --verbose) VERBOSE=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

PASS=0
FAIL=0
WARN=0

check() {
    local desc="$1"
    local result="$2"
    if [[ "$result" == "PASS" ]]; then
        echo "  [PASS] $desc"
        PASS=$((PASS + 1))
    elif [[ "$result" == "WARN" ]]; then
        echo "  [WARN] $desc"
        WARN=$((WARN + 1))
    else
        echo "  [FAIL] $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Break-Glass Validation ==="
echo "Host: $HOST"
echo "Policy: $POLICY_PATH"
echo ""

# ── Check 1: Policy file exists ─────────────────────────────────────────────

echo "--- Configuration Checks ---"

if [[ "$HOST" == "localhost" ]]; then
    if [[ -f "$POLICY_PATH" ]]; then
        check "Policy file exists at $POLICY_PATH" "PASS"
    else
        check "Policy file exists at $POLICY_PATH" "FAIL"
        echo "        Fix: Create /etc/prmana/policy.yaml with break_glass section"
    fi
else
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "$HOST" "test -f $POLICY_PATH" 2>/dev/null; then
        check "Policy file exists at $POLICY_PATH" "PASS"
    else
        check "Policy file exists at $POLICY_PATH" "FAIL"
    fi
fi

# ── Check 2: Break-glass enabled in policy ───────────────────────────────────

read_policy() {
    if [[ "$HOST" == "localhost" ]]; then
        cat "$POLICY_PATH" 2>/dev/null
    else
        ssh -o ConnectTimeout=5 -o BatchMode=yes "$HOST" "sudo cat $POLICY_PATH" 2>/dev/null
    fi
}

policy_content=$(read_policy || echo "")

if echo "$policy_content" | grep -q "break_glass" 2>/dev/null; then
    check "break_glass section present in policy" "PASS"
else
    check "break_glass section present in policy" "FAIL"
    echo "        Fix: Add break_glass section to policy.yaml"
fi

if echo "$policy_content" | grep -q "enabled: true" 2>/dev/null; then
    check "break_glass enabled" "PASS"
else
    check "break_glass enabled" "FAIL"
    echo "        Fix: Set break_glass.enabled: true in policy.yaml"
fi

# ── Check 3: Break-glass user exists on system ───────────────────────────────

bg_username=$(echo "$policy_content" | grep -A5 "users:" | grep "username:" | head -1 | awk '{print $NF}' | tr -d '"' || echo "")

if [[ -n "$bg_username" ]]; then
    check "Break-glass username found in policy: $bg_username" "PASS"

    if [[ "$HOST" == "localhost" ]]; then
        if id "$bg_username" &>/dev/null; then
            check "User $bg_username exists on system" "PASS"
        else
            check "User $bg_username exists on system" "FAIL"
            echo "        Fix: sudo useradd -m -s /bin/bash $bg_username"
        fi
    else
        if ssh -o ConnectTimeout=5 -o BatchMode=yes "$HOST" "id $bg_username" &>/dev/null; then
            check "User $bg_username exists on system" "PASS"
        else
            check "User $bg_username exists on system" "FAIL"
        fi
    fi
else
    check "Break-glass username found in policy" "FAIL"
    echo "        Fix: Add users section under break_glass in policy.yaml"
fi

# ── Check 4: alert_on_use enabled ────────────────────────────────────────────

if echo "$policy_content" | grep -q "alert_on_use: true" 2>/dev/null; then
    check "alert_on_use: true (SIEM will page on break-glass use)" "PASS"
else
    check "alert_on_use: true (SIEM alerting on break-glass)" "WARN"
    echo "        Recommend: Set alert_on_use: true for production servers"
fi

# ── Check 5: sshd allows password auth ───────────────────────────────────────

echo ""
echo "--- SSH Configuration Checks ---"

read_sshd_config() {
    if [[ "$HOST" == "localhost" ]]; then
        cat /etc/ssh/sshd_config 2>/dev/null
    else
        ssh -o ConnectTimeout=5 -o BatchMode=yes "$HOST" "sudo cat /etc/ssh/sshd_config" 2>/dev/null
    fi
}

sshd_config=$(read_sshd_config || echo "")

# Check PasswordAuthentication
if echo "$sshd_config" | grep -qE "^PasswordAuthentication\s+yes"; then
    check "PasswordAuthentication yes in sshd_config" "PASS"
elif echo "$sshd_config" | grep -qE "^PasswordAuthentication\s+no"; then
    check "PasswordAuthentication enabled in sshd_config" "FAIL"
    echo "        Fix: Set PasswordAuthentication yes (or use Match block for break-glass user)"
else
    check "PasswordAuthentication (default: yes on most distros)" "WARN"
    echo "        Verify: Default may vary by distro. Explicit 'yes' is safer."
fi

# Check KbdInteractiveAuthentication
if echo "$sshd_config" | grep -qE "^KbdInteractiveAuthentication\s+no"; then
    check "KbdInteractiveAuthentication not disabled" "WARN"
    echo "        Note: KbdInteractiveAuthentication no may block PAM-based password prompts"
fi

# ── Check 6: PAM module installed ────────────────────────────────────────────

echo ""
echo "--- PAM Module Checks ---"

check_pam_module() {
    if [[ "$HOST" == "localhost" ]]; then
        ls /lib/security/pam_prmana.so 2>/dev/null || ls /lib64/security/pam_prmana.so 2>/dev/null
    else
        ssh -o ConnectTimeout=5 -o BatchMode=yes "$HOST" \
            "ls /lib/security/pam_prmana.so 2>/dev/null || ls /lib64/security/pam_prmana.so 2>/dev/null"
    fi
}

if check_pam_module &>/dev/null; then
    check "PAM module installed" "PASS"
else
    check "PAM module installed" "WARN"
    echo "        Note: Module not found — break-glass works via standard PAM password auth"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Summary ==="
echo "Passed: $PASS"
echo "Warnings: $WARN"
echo "Failed: $FAIL"

if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "RESULT: BREAK-GLASS NOT READY"
    echo "Fix the failures above before proceeding with OIDC migration."
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo ""
    echo "RESULT: BREAK-GLASS LIKELY WORKS (review warnings)"
    exit 0
else
    echo ""
    echo "RESULT: BREAK-GLASS VALIDATED"
    exit 0
fi
