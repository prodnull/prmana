#!/bin/bash
# run-multiarch-tests.sh
# Run integration tests for multiple architectures using Docker + QEMU
#
# Usage:
#   ./test/scripts/run-multiarch-tests.sh              # Run both amd64 and arm64
#   ./test/scripts/run-multiarch-tests.sh amd64        # Run only amd64
#   ./test/scripts/run-multiarch-tests.sh arm64        # Run only arm64

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for required tools
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi

    # Check if buildx is available
    if ! docker buildx version &> /dev/null; then
        log_error "Docker Buildx is not available"
        exit 1
    fi

    log_info "All prerequisites met"
}

# Set up QEMU for cross-platform builds
setup_qemu() {
    log_info "Setting up QEMU for cross-platform builds..."
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes 2>/dev/null || true
    log_info "QEMU setup complete"
}

# Run tests for a specific platform
run_tests_for_platform() {
    local platform=$1
    local platform_name=$2

    log_info "=========================================="
    log_info "Running integration tests for $platform_name"
    log_info "=========================================="

    export DOCKER_DEFAULT_PLATFORM="$platform"

    # Clean up any existing containers
    docker compose -f docker-compose.test-multiarch.yaml down -v 2>/dev/null || true

    # Pull platform-specific images for infrastructure containers
    log_info "Pulling infrastructure images for $platform_name..."
    docker pull --platform "$platform" quay.io/keycloak/keycloak:24.0 || log_warn "Could not pull Keycloak image"
    docker pull --platform "$platform" osixia/openldap:1.5.0 || log_warn "Could not pull OpenLDAP image"

    # Build containers
    log_info "Building test containers for $platform_name..."
    if ! docker compose -f docker-compose.test-multiarch.yaml build --no-cache; then
        log_error "Failed to build containers for $platform_name"
        return 1
    fi

    # Start environment
    log_info "Starting test environment..."
    docker compose -f docker-compose.test-multiarch.yaml up -d

    # Wait for services
    log_info "Waiting for services to be healthy..."
    if [ "$platform" = "linux/arm64" ]; then
        # ARM64 needs more time due to QEMU emulation
        sleep 60
    fi
    COMPOSE_FILE="docker-compose.test-multiarch.yaml" ./test/scripts/wait-for-healthy.sh

    # Verify architecture
    log_info "Verifying architecture..."
    ARCH=$(docker compose -f docker-compose.test-multiarch.yaml exec -T test-host uname -m)
    log_info "Container architecture: $ARCH"

    # Verify PAM module
    log_info "Verifying PAM module is installed..."
    docker compose -f docker-compose.test-multiarch.yaml exec -T test-host \
        ls -la /usr/lib/security/libpam_unix_oidc.so

    # Verify agent
    log_info "Verifying agent binary..."
    docker compose -f docker-compose.test-multiarch.yaml exec -T test-host \
        /usr/local/bin/unix-oidc-agent --version

    # Run integration tests
    log_info "Running integration tests..."
    if ./test/scripts/run-integration-tests.sh; then
        log_info "Integration tests PASSED for $platform_name"
        result=0
    else
        log_error "Integration tests FAILED for $platform_name"
        result=1
    fi

    # Cleanup
    log_info "Cleaning up..."
    docker compose -f docker-compose.test-multiarch.yaml down -v

    return $result
}

# Main
main() {
    local platforms=("$@")

    if [ ${#platforms[@]} -eq 0 ]; then
        platforms=("amd64" "arm64")
    fi

    check_prerequisites

    # Set up QEMU if arm64 is in the list
    for p in "${platforms[@]}"; do
        if [ "$p" = "arm64" ]; then
            setup_qemu
            break
        fi
    done

    local failed=0
    local results=()

    for platform in "${platforms[@]}"; do
        case "$platform" in
            amd64)
                if run_tests_for_platform "linux/amd64" "Linux x86_64"; then
                    results+=("amd64: PASSED")
                else
                    results+=("amd64: FAILED")
                    failed=1
                fi
                ;;
            arm64)
                if run_tests_for_platform "linux/arm64" "Linux ARM64"; then
                    results+=("arm64: PASSED")
                else
                    results+=("arm64: FAILED")
                    failed=1
                fi
                ;;
            *)
                log_error "Unknown platform: $platform"
                log_error "Supported platforms: amd64, arm64"
                exit 1
                ;;
        esac
    done

    # Print summary
    echo ""
    log_info "=========================================="
    log_info "Multi-Architecture Test Summary"
    log_info "=========================================="
    for result in "${results[@]}"; do
        if [[ "$result" == *"PASSED"* ]]; then
            echo -e "  ${GREEN}✓${NC} $result"
        else
            echo -e "  ${RED}✗${NC} $result"
        fi
    done
    echo ""

    if [ $failed -eq 0 ]; then
        log_info "All tests passed!"
        exit 0
    else
        log_error "Some tests failed"
        exit 1
    fi
}

main "$@"
