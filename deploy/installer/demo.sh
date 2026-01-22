#!/bin/bash
# unix-oidc 5-minute demo launcher
# Usage: curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/demo.sh | bash
set -euo pipefail

GITHUB_REPO="prodnull/unix-oidc"
GITHUB_BRANCH="main"
DEMO_DIR="${HOME}/.unix-oidc-demo"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

#######################################
# Logging functions
#######################################
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_step() {
    echo -e "\n${CYAN}==>${NC} ${BOLD}$1${NC}"
}

#######################################
# Print banner
#######################################
print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
                _                    _     _
  _   _ _ __   (_)_  __      ___   (_) __| | ___
 | | | | '_ \  | \ \/ /____ / _ \  | |/ _` |/ __|
 | |_| | | | | | |>  <_____| (_) | | | (_| | (__
  \__,_|_| |_| |_/_/\_\     \___/  |_|\__,_|\___|

EOF
    echo -e "${NC}"
    echo -e "${BOLD}5-Minute Demo${NC} - See OIDC SSH authentication in action"
    echo ""
}

#######################################
# Check prerequisites
#######################################
check_docker() {
    log_step "Checking prerequisites"

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        echo ""
        echo "Please install Docker first:"
        echo "  - macOS/Windows: https://docs.docker.com/desktop/"
        echo "  - Linux: https://docs.docker.com/engine/install/"
        exit 1
    fi
    log_success "Docker is installed"

    # Check if docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        echo ""
        echo "Please start Docker and try again"
        exit 1
    fi
    log_success "Docker daemon is running"

    # Check for docker compose (v2 or v1)
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
        log_success "Docker Compose v2 is available"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
        log_success "Docker Compose v1 is available"
    else
        log_error "Docker Compose is not installed"
        echo ""
        echo "Please install Docker Compose:"
        echo "  https://docs.docker.com/compose/install/"
        exit 1
    fi
}

#######################################
# Download demo files
#######################################
download_files() {
    log_step "Downloading demo files"

    mkdir -p "${DEMO_DIR}"
    cd "${DEMO_DIR}"

    # Download docker-compose.test.yaml
    local compose_url="https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/docker-compose.test.yaml"
    log_info "Downloading docker-compose.test.yaml..."
    if ! curl -fsSL "${compose_url}" -o docker-compose.yaml; then
        log_error "Failed to download docker-compose.yaml"
        exit 1
    fi
    log_success "Downloaded docker-compose.yaml"

    # Download keycloak realm config
    mkdir -p test/fixtures/keycloak
    local realm_url="https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/test/fixtures/keycloak/unix-oidc-test-realm.json"
    log_info "Downloading keycloak realm configuration..."
    if ! curl -fsSL "${realm_url}" -o test/fixtures/keycloak/unix-oidc-test-realm.json; then
        log_error "Failed to download keycloak realm config"
        exit 1
    fi
    log_success "Downloaded keycloak realm config"

    # Download LDAP fixtures
    mkdir -p test/fixtures/ldap
    local ldap_url="https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/test/fixtures/ldap/01-users.ldif"
    log_info "Downloading LDAP fixtures..."
    if curl -fsSL "${ldap_url}" -o test/fixtures/ldap/01-users.ldif 2>/dev/null; then
        log_success "Downloaded LDAP fixtures"
    else
        log_warn "LDAP fixtures not found (optional)"
    fi

    # Download test-host Dockerfile
    mkdir -p test/docker
    local dockerfile_url="https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/test/docker/Dockerfile.test-host"
    log_info "Downloading test-host Dockerfile..."
    if ! curl -fsSL "${dockerfile_url}" -o test/docker/Dockerfile.test-host; then
        log_error "Failed to download test-host Dockerfile"
        exit 1
    fi
    log_success "Downloaded test-host Dockerfile"

    # Create target directory for binaries (will be empty for demo)
    mkdir -p target/release

    log_success "All files downloaded to ${DEMO_DIR}"
}

#######################################
# Start services
#######################################
start_services() {
    log_step "Starting demo services"

    cd "${DEMO_DIR}"

    # Stop any existing demo
    log_info "Cleaning up any existing demo containers..."
    ${COMPOSE_CMD} down --remove-orphans 2>/dev/null || true

    # Start only keycloak for the demo (test-host requires building binaries)
    log_info "Starting Keycloak..."
    ${COMPOSE_CMD} up -d keycloak openldap

    log_success "Services starting..."
}

#######################################
# Wait for Keycloak health
#######################################
wait_for_keycloak() {
    log_step "Waiting for Keycloak to be ready"

    local max_attempts=60
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        attempt=$((attempt + 1))

        if curl -sf http://localhost:8080/health/ready &>/dev/null; then
            log_success "Keycloak is ready!"
            return 0
        fi

        # Show progress
        printf "\r${BLUE}[INFO]${NC} Waiting for Keycloak... (%d/%d)" "$attempt" "$max_attempts"
        sleep 2
    done

    echo ""
    log_error "Keycloak failed to start within 2 minutes"
    echo ""
    echo "Check logs with: cd ${DEMO_DIR} && ${COMPOSE_CMD} logs keycloak"
    exit 1
}

#######################################
# Print usage instructions
#######################################
print_instructions() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   Demo is ready!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${BOLD}What's running:${NC}"
    echo "  - Keycloak IdP:  http://localhost:8080"
    echo "  - OpenLDAP:      ldap://localhost:389"
    echo ""
    echo -e "${BOLD}Keycloak Admin Console:${NC}"
    echo "  URL:      http://localhost:8080/admin"
    echo "  Username: admin"
    echo "  Password: admin"
    echo ""
    echo -e "${BOLD}Test Users:${NC}"
    echo "  +-----------+------------+-------------------+"
    echo "  | Username  | Password   | Email             |"
    echo "  +-----------+------------+-------------------+"
    echo "  | testuser  | testpass   | testuser@test.local|"
    echo "  | adminuser | adminpass  | adminuser@test.local|"
    echo "  +-----------+------------+-------------------+"
    echo ""
    echo -e "${BOLD}OIDC Configuration:${NC}"
    echo "  Issuer:        http://localhost:8080/realms/unix-oidc-test"
    echo "  Client ID:     unix-oidc"
    echo "  Client Secret: unix-oidc-test-secret"
    echo ""
    echo -e "${CYAN}Step 1: Get an access token${NC}"
    echo ""
    echo "  curl -s -X POST http://localhost:8080/realms/unix-oidc-test/protocol/openid-connect/token \\"
    echo "    -d 'grant_type=password' \\"
    echo "    -d 'client_id=unix-oidc' \\"
    echo "    -d 'client_secret=unix-oidc-test-secret' \\"
    echo "    -d 'username=testuser' \\"
    echo "    -d 'password=testpass' | jq -r '.access_token'"
    echo ""
    echo -e "${CYAN}Step 2: Decode and inspect the token${NC}"
    echo ""
    echo "  # Copy the token and paste at: https://jwt.io"
    echo "  # Or decode locally:"
    echo "  echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null | jq"
    echo ""
    echo -e "${CYAN}Step 3: View the OIDC discovery document${NC}"
    echo ""
    echo "  curl -s http://localhost:8080/realms/unix-oidc-test/.well-known/openid-configuration | jq"
    echo ""
    echo -e "${BOLD}To stop the demo:${NC}"
    echo "  cd ${DEMO_DIR} && ${COMPOSE_CMD} down"
    echo ""
    echo -e "${BOLD}To view logs:${NC}"
    echo "  cd ${DEMO_DIR} && ${COMPOSE_CMD} logs -f"
    echo ""
    echo -e "${BOLD}Next steps:${NC}"
    echo "  - 15-minute production guide: https://github.com/${GITHUB_REPO}/blob/main/deploy/quickstart/production-setup.md"
    echo "  - Full documentation: https://github.com/${GITHUB_REPO}"
    echo ""
}

#######################################
# Handle cleanup on exit
#######################################
cleanup() {
    if [ "${1:-}" = "error" ]; then
        log_error "Demo setup failed"
        echo ""
        echo "To clean up: cd ${DEMO_DIR} && ${COMPOSE_CMD} down"
    fi
}

trap 'cleanup error' ERR

#######################################
# Main
#######################################
main() {
    print_banner
    check_docker
    download_files
    start_services
    wait_for_keycloak
    print_instructions
}

main "$@"
