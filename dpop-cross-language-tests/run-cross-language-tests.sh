#!/bin/bash
# Cross-language DPoP E2E tests
# Tests that proofs generated in any language can be validated by any other language

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROOFS_DIR="$SCRIPT_DIR/proofs"
RESULTS_FILE="$SCRIPT_DIR/results.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Languages to test
LANGUAGES=("rust" "go" "python" "java")

# Setup
mkdir -p "$PROOFS_DIR"
rm -f "$RESULTS_FILE"

echo "=========================================="
echo "DPoP Cross-Language E2E Tests"
echo "=========================================="
echo ""

# Build all test programs
echo "Building test programs..."

# Rust
echo "  Building Rust..."
(cd "$SCRIPT_DIR/rust-test" && cargo build --release -q 2>/dev/null) || {
    echo -e "${RED}Failed to build Rust test${NC}"
    exit 1
}
RUST_BIN="$SCRIPT_DIR/rust-test/target/release/dpop-cross-test"

# Go
echo "  Building Go..."
(cd "$SCRIPT_DIR/go-test" && go build -o go-cross-test . 2>/dev/null) || {
    echo -e "${RED}Failed to build Go test${NC}"
    exit 1
}
GO_BIN="$SCRIPT_DIR/go-test/go-cross-test"

# Python (no build needed, but check deps)
echo "  Checking Python..."
PYTHON_SCRIPT="$SCRIPT_DIR/python-test/cross_test.py"
PYTHON_VENV="$SCRIPT_DIR/../python-oauth-dpop/.venv"
if [ -d "$PYTHON_VENV" ]; then
    PYTHON_CMD="$PYTHON_VENV/bin/python"
else
    PYTHON_CMD="python3"
fi

# Java
echo "  Building Java..."
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}"
export PATH="$JAVA_HOME/bin:$PATH"
JAVA_DIR="$SCRIPT_DIR/../java-oauth-dpop"
(cd "$JAVA_DIR" && gradle compileJava -q 2>/dev/null) || {
    echo -e "${RED}Failed to build Java${NC}"
    exit 1
}

# Build Java classpath
JAVA_CP="$JAVA_DIR/build/classes/java/main"
JAVA_CP="$JAVA_CP:$(find ~/.gradle/caches/modules-2/files-2.1 -name 'jackson-databind-*.jar' 2>/dev/null | head -1)"
JAVA_CP="$JAVA_CP:$(find ~/.gradle/caches/modules-2/files-2.1 -name 'jackson-core-*.jar' 2>/dev/null | head -1)"
JAVA_CP="$JAVA_CP:$(find ~/.gradle/caches/modules-2/files-2.1 -name 'jackson-annotations-*.jar' 2>/dev/null | head -1)"
JAVA_CP="$JAVA_CP:$(find ~/.gradle/caches/modules-2/files-2.1 -name 'eclipse-collections-1*.jar' 2>/dev/null | head -1)"
JAVA_CP="$JAVA_CP:$(find ~/.gradle/caches/modules-2/files-2.1 -name 'eclipse-collections-api-*.jar' 2>/dev/null | head -1)"

echo ""
echo "=========================================="
echo "Phase 1: Generating proofs"
echo "=========================================="

# Generate proofs from each language
echo "  Rust generating..."
"$RUST_BIN" generate "$PROOFS_DIR/rust_proof.json"

echo "  Go generating..."
"$GO_BIN" generate "$PROOFS_DIR/go_proof.json"

echo "  Python generating..."
"$PYTHON_CMD" "$PYTHON_SCRIPT" generate "$PROOFS_DIR/python_proof.json"

echo "  Java generating..."
java -cp "$JAVA_CP" com.github.unixoidcproject.oauthdpop.crosstest.CrossTest generate "$PROOFS_DIR/java_proof.json"

echo ""
echo "=========================================="
echo "Phase 2: Cross-validation matrix"
echo "=========================================="
echo ""

# Validation function - returns 0 for pass, 1 for fail
run_validation() {
    local validator=$1
    local proof_file=$2

    case $validator in
        rust)
            "$RUST_BIN" validate "$proof_file" 2>/dev/null
            ;;
        go)
            "$GO_BIN" validate "$proof_file" 2>/dev/null
            ;;
        python)
            "$PYTHON_CMD" "$PYTHON_SCRIPT" validate "$proof_file" 2>/dev/null
            ;;
        java)
            java -cp "$JAVA_CP" \
                com.github.unixoidcproject.oauthdpop.crosstest.CrossTest validate "$proof_file" 2>/dev/null
            ;;
    esac
}

# Print header
printf "%-12s" "Generator"
for validator in "${LANGUAGES[@]}"; do
    printf "%-10s" "$validator"
done
echo ""
echo "--------------------------------------------------------"

# Save results header
echo "Generator,Validator,Result" > "$RESULTS_FILE"

PASS_COUNT=0
FAIL_COUNT=0

# Run validation matrix and print results inline
for generator in "${LANGUAGES[@]}"; do
    proof_file="$PROOFS_DIR/${generator}_proof.json"

    printf "%-12s" "$generator"

    if [ ! -f "$proof_file" ]; then
        for validator in "${LANGUAGES[@]}"; do
            printf "${YELLOW}%-10s${NC}" "SKIP"
            echo "$generator,$validator,SKIP" >> "$RESULTS_FILE"
        done
        echo ""
        continue
    fi

    for validator in "${LANGUAGES[@]}"; do
        if run_validation "$validator" "$proof_file"; then
            printf "${GREEN}%-10s${NC}" "PASS"
            echo "$generator,$validator,PASS" >> "$RESULTS_FILE"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            printf "${RED}%-10s${NC}" "FAIL"
            echo "$generator,$validator,FAIL" >> "$RESULTS_FILE"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    done
    echo ""
done

echo ""
echo "=========================================="
echo "Summary: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=========================================="

if [ $FAIL_COUNT -gt 0 ]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
