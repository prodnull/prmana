#!/bin/bash
# demo/record-demo.sh
# Complete demo recording script that captures both terminal and browser

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "================================================"
echo "unix-oidc Training Video Recorder"
echo "================================================"
echo ""

# Check dependencies
check_dependency() {
    if ! command -v "$1" &>/dev/null; then
        echo "Missing dependency: $1"
        echo "Install with: $2"
        return 1
    fi
}

echo "Checking dependencies..."
check_dependency "docker" "Install Docker Desktop" || exit 1
check_dependency "node" "brew install node" || exit 1

# Optional: Check for asciinema for terminal recording
if command -v asciinema &>/dev/null; then
    HAS_ASCIINEMA=true
    echo "  asciinema: installed (terminal recording available)"
else
    HAS_ASCIINEMA=false
    echo "  asciinema: not installed (terminal recording disabled)"
    echo "    Install with: brew install asciinema"
fi

echo ""

# Ensure npm dependencies are installed
echo "Installing npm dependencies..."
cd "$SCRIPT_DIR"
npm install --silent
npx playwright install chromium --quiet

# Start test environment
echo ""
echo "Starting test environment..."
cd "$PROJECT_ROOT"
docker compose -f docker-compose.test.yaml up -d

echo "Waiting for services to be healthy..."
./test/scripts/wait-for-healthy.sh

# Run Playwright demos
echo ""
echo "Recording browser demos..."
cd "$SCRIPT_DIR"
npm run record 2>&1 | grep -E "(Demo|PASS|FAIL|video)"

# Summary
echo ""
echo "================================================"
echo "Recording Complete"
echo "================================================"
echo ""
echo "Browser recordings saved to:"
find test-results -name "*.webm" 2>/dev/null | while read f; do
    echo "  - $f"
done

echo ""
echo "Screenshots saved to:"
find test-results -name "*.png" 2>/dev/null | while read f; do
    echo "  - $f"
done

echo ""
echo "To view the HTML report:"
echo "  cd demo && npm run show-report"
echo ""
echo "To record terminal demos:"
echo "  asciinema rec terminal-demo.cast"
echo ""
