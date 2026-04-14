#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/installer/install.sh
source "$SCRIPT_DIR/install.sh"

tmp_bin=$(mktemp -d)
cleanup() {
    rm -rf "$tmp_bin"
}
trap cleanup EXIT

ln -s "$(command -v curl)" "$tmp_bin/curl"
ln -s "$(command -v jq)" "$tmp_bin/jq"

assert_fails() {
    local description="$1"
    shift
    if "$@"; then
        echo "FAIL: $description"
        exit 1
    fi
}

assert_succeeds() {
    local description="$1"
    shift
    if ! "$@"; then
        echo "FAIL: $description"
        exit 1
    fi
}

assert_fails \
    "non-dry-run install must fail when cosign is unavailable" \
    env TMP_BIN="$tmp_bin" bash -c '
        PATH="$TMP_BIN"
        source "$1"
        DRY_RUN=false
        VERIFY_SLSA=false
        check_prerequisites
    ' _ "$SCRIPT_DIR/install.sh" >/dev/null 2>&1

assert_succeeds \
    "dry-run install may proceed without cosign" \
    env TMP_BIN="$tmp_bin" bash -c '
        PATH="$TMP_BIN"
        source "$1"
        DRY_RUN=true
        VERIFY_SLSA=false
        check_prerequisites
    ' _ "$SCRIPT_DIR/install.sh" >/dev/null 2>&1

assert_fails \
    "--verify-slsa must fail when gh is unavailable" \
    env TMP_BIN="$tmp_bin" bash -c '
        PATH="$TMP_BIN"
        source "$1"
        DRY_RUN=false
        VERIFY_SLSA=true
        check_prerequisites
    ' _ "$SCRIPT_DIR/install.sh" >/dev/null 2>&1

echo "installer prerequisite tests passed"
