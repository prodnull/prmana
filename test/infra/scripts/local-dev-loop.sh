#!/usr/bin/env bash
# DT-0 local dev-loop helper.
#
# Runs all local validation checks without touching real cloud accounts.
# Prerequisites: terraform 1.7+, Rust 1.75+, shellcheck, python3 + pyyaml.
# Optional: yamllint (prints a warning if absent).
#
# Usage:
#   bash test/infra/scripts/local-dev-loop.sh
#
# Exit code: 0 if all steps pass, 1 if any step fails.

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
FAILED_STEPS=()

# Must run from repo root so relative paths resolve correctly.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "${REPO_ROOT}"

header() {
    echo ""
    echo "================================================================"
    echo "  $*"
    echo "================================================================"
}

step_pass() {
    echo "  [PASS] $*"
    PASS=$(( PASS + 1 ))
}

step_fail() {
    echo "  [FAIL] $*"
    FAIL=$(( FAIL + 1 ))
    FAILED_STEPS+=("$*")
}

# Run a command, capture output; on failure print it and record FAIL.
run_step() {
    local label="$1"
    shift
    local output
    if output=$("$@" 2>&1); then
        step_pass "${label}"
    else
        step_fail "${label}"
        while IFS= read -r line; do echo "    ${line}"; done <<< "${output}"
    fi
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

header "DT-0 local dev loop"
echo "  Repo root : ${REPO_ROOT}"
echo "  Started   : $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# ---------------------------------------------------------------------------
# Step 1: terraform validate + fmt on aws-fleet
# ---------------------------------------------------------------------------

header "Step 1: aws-fleet Terraform validate + fmt"

if ! command -v terraform &>/dev/null; then
    step_fail "terraform not found — install 1.7+ and retry"
else
    # Init with -backend=false so no backend configuration is required.
    run_step "aws-fleet: terraform init -backend=false" \
        terraform -chdir=test/infra/aws-fleet init -backend=false -input=false

    run_step "aws-fleet: terraform validate" \
        terraform -chdir=test/infra/aws-fleet validate

    run_step "aws-fleet: terraform fmt -check" \
        terraform -chdir=test/infra/aws-fleet fmt -check
fi

# ---------------------------------------------------------------------------
# Step 2: terraform validate + fmt on azure-fleet
# ---------------------------------------------------------------------------

header "Step 2: azure-fleet Terraform validate + fmt"

if ! command -v terraform &>/dev/null; then
    step_fail "terraform not found (already reported above)"
else
    run_step "azure-fleet: terraform init -backend=false" \
        terraform -chdir=test/infra/azure-fleet init -backend=false -input=false

    run_step "azure-fleet: terraform validate" \
        terraform -chdir=test/infra/azure-fleet validate

    run_step "azure-fleet: terraform fmt -check" \
        terraform -chdir=test/infra/azure-fleet fmt -check
fi

# ---------------------------------------------------------------------------
# Step 3: cargo build + cargo test on idp-proxy
# ---------------------------------------------------------------------------

header "Step 3: idp-proxy cargo build + test"

if ! command -v cargo &>/dev/null; then
    step_fail "cargo not found — install Rust 1.75+ via rustup and retry"
else
    run_step "idp-proxy: cargo build" \
        cargo build --manifest-path test/infra/idp-proxy/Cargo.toml

    run_step "idp-proxy: cargo test" \
        cargo test --manifest-path test/infra/idp-proxy/Cargo.toml
fi

# ---------------------------------------------------------------------------
# Step 4: shellcheck on logcollect and scripts
# ---------------------------------------------------------------------------

header "Step 4: shellcheck on logcollect and scripts"

if ! command -v shellcheck &>/dev/null; then
    step_fail "shellcheck not found — install via brew/apt and retry"
else
    run_step "shellcheck: logcollect/*.sh" \
        shellcheck test/infra/logcollect/collect.sh test/infra/logcollect/aggregate.sh

    run_step "shellcheck: scripts/*.sh" \
        shellcheck test/infra/scripts/local-dev-loop.sh \
                   test/infra/scripts/verify-success-criteria.sh
fi

# ---------------------------------------------------------------------------
# Step 5: YAML parse of fleet-test.yml
# ---------------------------------------------------------------------------

header "Step 5: YAML parse of .github/workflows/fleet-test.yml"

if ! command -v python3 &>/dev/null; then
    step_fail "python3 not found"
else
    run_step "fleet-test.yml: python3 yaml.safe_load" \
        python3 -c "import yaml; yaml.safe_load(open('.github/workflows/fleet-test.yml'))"

    # Optional: yamllint
    if command -v yamllint &>/dev/null; then
        run_step "fleet-test.yml: yamllint" \
            yamllint -d relaxed .github/workflows/fleet-test.yml
    else
        echo "  [SKIP] yamllint not installed (optional — install with: pip install yamllint)"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

header "Summary"
echo "  Passed : ${PASS}"
echo "  Failed : ${FAIL}"

if [ "${FAIL}" -gt 0 ]; then
    echo ""
    echo "  Failed steps:"
    for s in "${FAILED_STEPS[@]}"; do
        echo "    - ${s}"
    done
    echo ""
    echo "  RESULT: FAIL — fix the above and re-run"
    exit 1
fi

echo ""
echo "  RESULT: PASS — all local checks green"
echo "  Next: run 'gh workflow run fleet-test.yml ...' to trigger a live cloud run"
