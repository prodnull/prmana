#!/bin/bash
# unix-oidc installer
# Usage: curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh | bash
set -euo pipefail

VERSION="0.1.0"
SCRIPT_VERSION="1.0.0"
GITHUB_REPO="prodnull/unix-oidc"
INSTALL_DIR="/etc/unix-oidc"
PAM_DIR=""  # Set by detect_os

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
DRY_RUN=false
YES_MODE=false
FORCE_MODE=false
OIDC_ISSUER=""
OIDC_CLIENT_ID="unix-oidc"
INSTALL_AGENT=true

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

log_dry() {
    echo -e "${YELLOW}[DRY-RUN]${NC} Would: $1"
}

#######################################
# Detect OS and architecture
#######################################
detect_os() {
    local os=""
    local version=""
    local arch=""

    # Detect architecture
    case "$(uname -m)" in
        x86_64)  arch="x86_64" ;;
        aarch64) arch="aarch64" ;;
        arm64)   arch="aarch64" ;;
        *)
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac

    # Detect OS
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        os="$ID"
        version="$VERSION_ID"
    else
        log_error "Cannot detect OS (no /etc/os-release)"
        exit 1
    fi

    # Set PAM directory based on OS
    case "$os" in
        ubuntu|debian)
            PAM_DIR="/lib/security"
            ;;
        rhel|rocky|almalinux|centos|fedora|amzn)
            if [ "$arch" = "x86_64" ]; then
                PAM_DIR="/lib64/security"
            else
                PAM_DIR="/lib/security"
            fi
            ;;
        *)
            log_error "Unsupported OS: $os"
            exit 1
            ;;
    esac

    # Validate version
    case "$os" in
        ubuntu)
            if [ "${version%%.*}" -lt 20 ]; then
                log_error "Ubuntu 20.04+ required (found $version)"
                exit 1
            fi
            ;;
        debian)
            if [ "${version%%.*}" -lt 11 ]; then
                log_error "Debian 11+ required (found $version)"
                exit 1
            fi
            ;;
        rhel|rocky|almalinux|centos)
            if [ "${version%%.*}" -lt 8 ]; then
                log_error "RHEL/Rocky 8+ required (found $version)"
                exit 1
            fi
            ;;
    esac

    echo "$os:$version:$arch:$PAM_DIR"
}

#######################################
# Check PAM safety before installation
#######################################
check_pam_safety() {
    local sshd_has_oidc=false
    local sudo_has_oidc=false
    local sshd_has_fallback=false
    local sudo_has_fallback=false

    if [ "$DRY_RUN" = true ]; then
        log_dry "Check PAM safety (sshd/sudo configs)"
        return 0
    fi

    # Check if sshd already has pam_unix_oidc configured
    if [ -f /etc/pam.d/sshd ]; then
        if grep -q "pam_unix_oidc" /etc/pam.d/sshd 2>/dev/null; then
            sshd_has_oidc=true
            log_warn "sshd already has pam_unix_oidc.so configured"
        fi
        # Check for fallback auth (pam_unix)
        if grep -q "pam_unix.so" /etc/pam.d/sshd 2>/dev/null; then
            sshd_has_fallback=true
        fi
    fi

    # Check if sudo already has pam_unix_oidc configured
    if [ -f /etc/pam.d/sudo ]; then
        if grep -q "pam_unix_oidc" /etc/pam.d/sudo 2>/dev/null; then
            sudo_has_oidc=true
            log_warn "sudo already has pam_unix_oidc.so configured"
        fi
        # Check for fallback auth (pam_unix)
        if grep -q "pam_unix.so" /etc/pam.d/sudo 2>/dev/null; then
            sudo_has_fallback=true
        fi
    fi

    # Warn if no fallback exists
    if [ "$sshd_has_oidc" = true ] && [ "$sshd_has_fallback" = false ]; then
        log_warn "sshd has pam_unix_oidc but no pam_unix fallback!"
    fi
    if [ "$sudo_has_oidc" = true ] && [ "$sudo_has_fallback" = false ]; then
        log_warn "sudo has pam_unix_oidc but no pam_unix fallback!"
    fi

    # Critical: Refuse if both sshd AND sudo would be affected with no password fallback
    if [ "$sshd_has_oidc" = true ] && [ "$sudo_has_oidc" = true ]; then
        if [ "$sshd_has_fallback" = false ] || [ "$sudo_has_fallback" = false ]; then
            log_error "CRITICAL: Both sshd and sudo have pam_unix_oidc configured"
            log_error "and at least one is missing a password fallback."
            log_error "Overwriting the PAM module could lock you out of the system!"
            if [ "$FORCE_MODE" = true ]; then
                log_warn "Proceeding anyway due to --force flag"
                return 0
            else
                log_error "Use --force to override this safety check"
                exit 1
            fi
        fi
    fi

    log_success "PAM safety check passed"
}

#######################################
# Check prerequisites
#######################################
check_prerequisites() {
    local missing=()

    # Check for root
    if [ "$EUID" -ne 0 ] && [ "$DRY_RUN" = false ]; then
        log_error "This script must be run as root (or use --dry-run)"
        exit 1
    fi

    # Check for required commands
    for cmd in curl jq; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing required commands: ${missing[*]}"
        log_info "Install with: apt-get install -y ${missing[*]} (Debian/Ubuntu)"
        log_info "         or: dnf install -y ${missing[*]} (RHEL/Rocky)"
        exit 1
    fi

    # Check for cosign (optional but recommended)
    if ! command -v cosign &> /dev/null; then
        log_warn "cosign not found - signature verification will be skipped"
        log_info "Install cosign: https://docs.sigstore.dev/cosign/installation/"
    fi
}

#######################################
# Download and verify binary
#######################################
download_binary() {
    local os_info="$1"
    # Parse os:version:arch:pam_dir - we need the third field (arch)
    local remaining="${os_info#*:}"  # version:arch:pam_dir
    remaining="${remaining#*:}"       # arch:pam_dir
    local arch="${remaining%%:*}"     # arch
    local download_url=""
    local checksum_url=""
    local sig_url=""
    local cert_url=""

    local release_base="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}"
    local artifact_name="unix-oidc-v${VERSION}-linux-${arch}.tar.gz"

    download_url="${release_base}/${artifact_name}"
    checksum_url="${release_base}/${artifact_name}.sha256"
    sig_url="${release_base}/${artifact_name}.sig"
    cert_url="${release_base}/${artifact_name}.pem"

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf '"$tmp_dir" EXIT

    log_info "Downloading unix-oidc v${VERSION} for linux-${arch}..."

    if [ "$DRY_RUN" = true ]; then
        log_dry "Download $download_url"
        log_dry "Verify checksum from $checksum_url"
        return 0
    fi

    # Download files
    curl -fsSL "$download_url" -o "$tmp_dir/archive.tar.gz" || {
        log_error "Failed to download binary"
        exit 1
    }

    curl -fsSL "$checksum_url" -o "$tmp_dir/checksum.sha256" || {
        log_error "Failed to download checksum"
        exit 1
    }

    # Verify checksum
    log_info "Verifying checksum..."
    cd "$tmp_dir"
    if ! sha256sum -c checksum.sha256 --status 2>/dev/null; then
        # Try BSD sha256 format
        expected=$(awk '{print $1}' checksum.sha256)
        actual=$(sha256sum archive.tar.gz | awk '{print $1}')
        if [ "$expected" != "$actual" ]; then
            log_error "Checksum verification failed!"
            exit 1
        fi
    fi
    log_success "Checksum verified"

    # Verify signature if cosign available
    if command -v cosign &> /dev/null; then
        log_info "Verifying signature..."
        curl -fsSL "$sig_url" -o "$tmp_dir/archive.sig" || {
            log_warn "Could not download signature, skipping verification"
        }
        curl -fsSL "$cert_url" -o "$tmp_dir/archive.pem" || {
            log_warn "Could not download certificate, skipping verification"
        }

        if [ -f "$tmp_dir/archive.sig" ] && [ -f "$tmp_dir/archive.pem" ]; then
            if cosign verify-blob \
                --certificate "$tmp_dir/archive.pem" \
                --signature "$tmp_dir/archive.sig" \
                --certificate-identity-regexp "https://github.com/${GITHUB_REPO}" \
                --certificate-oidc-issuer https://token.actions.githubusercontent.com \
                "$tmp_dir/archive.tar.gz" 2>/dev/null; then
                log_success "Signature verified"
            else
                log_warn "Signature verification failed - continuing anyway"
            fi
        fi
    fi

    # Extract
    log_info "Extracting..."
    tar -xzf archive.tar.gz

    # Return path to extracted files
    echo "$tmp_dir"
}

#######################################
# Install PAM module
#######################################
install_pam_module() {
    local tmp_dir="$1"
    local pam_module="$tmp_dir/libpam_unix_oidc.so"
    local dest="$PAM_DIR/pam_unix_oidc.so"

    if [ "$DRY_RUN" = true ]; then
        log_dry "Copy PAM module to $dest"
        log_dry "Set permissions 644 and ownership root:root"
        return 0
    fi

    if [ ! -f "$pam_module" ]; then
        log_error "PAM module not found in archive"
        exit 1
    fi

    # Backup existing if present
    if [ -f "$dest" ]; then
        local backup
        backup="${dest}.backup.$(date +%Y%m%d%H%M%S)"
        log_info "Backing up existing PAM module to $backup"
        cp "$dest" "$backup"
    fi

    # Install
    cp "$pam_module" "$dest"
    chmod 644 "$dest"
    chown root:root "$dest"

    log_success "Installed PAM module to $dest"
}

#######################################
# Install agent
#######################################
install_agent() {
    local tmp_dir="$1"
    local agent="$tmp_dir/unix-oidc-agent"
    local dest="/usr/local/bin/unix-oidc-agent"

    if [ "$INSTALL_AGENT" = false ]; then
        log_info "Skipping agent installation (--no-agent)"
        return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        log_dry "Copy agent to $dest"
        log_dry "Set permissions 755"
        return 0
    fi

    if [ ! -f "$agent" ]; then
        log_warn "Agent binary not found in archive, skipping"
        return 0
    fi

    # Backup existing if present
    if [ -f "$dest" ]; then
        local backup
        backup="${dest}.backup.$(date +%Y%m%d%H%M%S)"
        log_info "Backing up existing agent to $backup"
        cp "$dest" "$backup"
    fi

    # Install
    cp "$agent" "$dest"
    chmod 755 "$dest"

    log_success "Installed agent to $dest"
}

#######################################
# Create configuration
#######################################
create_config() {
    if [ "$DRY_RUN" = true ]; then
        log_dry "Create directory $INSTALL_DIR"
        log_dry "Create config file $INSTALL_DIR/config.env"
        return 0
    fi

    mkdir -p "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"

    # Create config file
    cat > "$INSTALL_DIR/config.env" << EOF
# unix-oidc configuration
# Generated by installer v${SCRIPT_VERSION} on $(date -Iseconds)

# Required: OIDC Issuer URL
OIDC_ISSUER=${OIDC_ISSUER:-"https://your-idp.example.com/realms/your-realm"}

# Client ID (default: unix-oidc)
OIDC_CLIENT_ID=${OIDC_CLIENT_ID}

# Optional: Required ACR level for SSH login
# OIDC_REQUIRED_ACR=urn:your-idp:acr:mfa

# Optional: Maximum auth age in seconds (for step-up)
# OIDC_MAX_AUTH_AGE=3600

# Optional: Enable DPoP token binding (recommended)
# OIDC_DPOP_REQUIRED=true
EOF

    chmod 600 "$INSTALL_DIR/config.env"

    log_success "Created configuration at $INSTALL_DIR/config.env"

    if [ -z "$OIDC_ISSUER" ]; then
        log_warn "OIDC_ISSUER not set - edit $INSTALL_DIR/config.env before use"
    fi
}

#######################################
# Generate PAM configuration (does not apply)
#######################################
generate_pam_config() {
    local pam_sshd_config="$INSTALL_DIR/pam.d-sshd.recommended"
    local pam_sudo_config="$INSTALL_DIR/pam.d-sudo.recommended"

    if [ "$DRY_RUN" = true ]; then
        log_dry "Generate recommended PAM configs in $INSTALL_DIR/"
        return 0
    fi

    # Generate sshd config
    cat > "$pam_sshd_config" << 'EOF'
# /etc/pam.d/sshd - Recommended configuration for unix-oidc
# WARNING: Test thoroughly before applying to production!

# Load environment from unix-oidc config
auth       required     pam_env.so envfile=/etc/unix-oidc/config.env

# Try unix-oidc first, fall back to standard auth
auth       sufficient   pam_unix_oidc.so
auth       required     pam_unix.so

# Standard account, session, password handling
@include common-account
@include common-session
@include common-password
EOF

    # Generate sudo config
    cat > "$pam_sudo_config" << 'EOF'
# /etc/pam.d/sudo - Recommended configuration for unix-oidc
# WARNING: Test thoroughly before applying to production!

# Load environment from unix-oidc config
auth       required     pam_env.so envfile=/etc/unix-oidc/config.env

# Try unix-oidc first, fall back to standard auth
auth       sufficient   pam_unix_oidc.so
auth       required     pam_unix.so

# Standard account, session, password handling
@include common-account
@include common-session
EOF

    log_success "Generated recommended PAM configs:"
    log_info "  $pam_sshd_config"
    log_info "  $pam_sudo_config"
    log_warn "Review and manually copy to /etc/pam.d/ when ready"
}

#######################################
# Create install manifest for uninstall
#######################################
create_manifest() {
    local manifest="$INSTALL_DIR/.install-manifest"

    if [ "$DRY_RUN" = true ]; then
        log_dry "Create install manifest at $manifest"
        return 0
    fi

    cat > "$manifest" << EOF
# unix-oidc install manifest
# Created: $(date -Iseconds)
# Version: $VERSION
# Installer: $SCRIPT_VERSION

$PAM_DIR/pam_unix_oidc.so
/usr/local/bin/unix-oidc-agent
$INSTALL_DIR/config.env
$INSTALL_DIR/pam.d-sshd.recommended
$INSTALL_DIR/pam.d-sudo.recommended
EOF

    log_success "Created install manifest at $manifest"
}

#######################################
# Validate OIDC issuer
#######################################
validate_issuer() {
    if [ -z "$OIDC_ISSUER" ]; then
        log_warn "No OIDC issuer specified, skipping validation"
        return 0
    fi

    log_info "Validating OIDC issuer: $OIDC_ISSUER"

    if [ "$DRY_RUN" = true ]; then
        log_dry "Fetch $OIDC_ISSUER/.well-known/openid-configuration"
        return 0
    fi

    local discovery_url="${OIDC_ISSUER}/.well-known/openid-configuration"
    if ! curl -fsSL "$discovery_url" > /dev/null 2>&1; then
        log_warn "Could not reach OIDC discovery endpoint: $discovery_url"
        log_warn "Verify the issuer URL is correct and accessible"
        return 1
    fi

    log_success "OIDC issuer is reachable"
}

#######################################
# Run pamtester if available
#######################################
test_with_pamtester() {
    if ! command -v pamtester &> /dev/null; then
        log_info "pamtester not found, skipping PAM test"
        log_info "Install with: apt-get install pamtester (Debian/Ubuntu)"
        return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        log_dry "Run pamtester to verify PAM module loads"
        return 0
    fi

    log_info "Testing PAM module loads correctly..."

    # Run pamtester with a timeout to verify the module loads
    # We expect auth to fail (no token), but the module should load successfully
    local pamtest_output
    if pamtest_output=$(timeout 5 pamtester sshd root authenticate 2>&1 </dev/null); then
        # Unexpected success - shouldn't happen without a valid token
        log_warn "pamtester unexpectedly succeeded (auth should have failed)"
    else
        local exit_code=$?
        # Check if the error indicates module not found (real problem)
        if echo "$pamtest_output" | grep -qi "module.*not found\|cannot.*load\|no such file"; then
            log_error "PAM module failed to load!"
            log_error "Output: $pamtest_output"
            log_error "Check that $PAM_DIR/pam_unix_oidc.so exists and has correct permissions"
            return 1
        elif [ "$exit_code" -eq 124 ]; then
            # Timeout - module loaded but hung waiting for input
            log_success "PAM module loads correctly (timed out waiting for auth)"
        else
            # Auth failed as expected - module loaded successfully
            log_success "PAM module loads correctly (auth failed as expected without token)"
        fi
    fi

    log_info "For interactive testing: pamtester sshd yourusername authenticate"
}

#######################################
# Print usage
#######################################
usage() {
    cat << EOF
unix-oidc installer v${SCRIPT_VERSION}

Usage: $0 [OPTIONS]

Options:
    --issuer URL        OIDC issuer URL (required for production)
    --client-id ID      OIDC client ID (default: unix-oidc)
    --version VER       unix-oidc version to install (default: $VERSION)
    --no-agent          Skip agent installation
    --dry-run           Show what would be done without making changes
    --yes, -y           Skip confirmation prompts
    --force             Bypass PAM safety checks (use with caution!)
    --help, -h          Show this help message

Examples:
    # Dry run to see what would happen
    $0 --dry-run

    # Install with specific IdP
    $0 --issuer https://login.example.com/realms/myorg --client-id myapp

    # Non-interactive install
    $0 --issuer https://login.example.com --yes

EOF
}

#######################################
# Parse arguments
#######################################
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --issuer)
                OIDC_ISSUER="$2"
                shift 2
                ;;
            --client-id)
                OIDC_CLIENT_ID="$2"
                shift 2
                ;;
            --version)
                VERSION="$2"
                shift 2
                ;;
            --no-agent)
                INSTALL_AGENT=false
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --yes|-y)
                YES_MODE=true
                shift
                ;;
            --force)
                FORCE_MODE=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

#######################################
# Confirm with user
#######################################
confirm() {
    local message="$1"

    if [ "$YES_MODE" = true ] || [ "$DRY_RUN" = true ]; then
        return 0
    fi

    read -r -p "$message [y/N] " REPLY
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Aborted by user"
        exit 0
    fi
}

#######################################
# Main
#######################################
main() {
    parse_args "$@"

    echo ""
    echo "==============================================================="
    echo "                 unix-oidc Installer v${SCRIPT_VERSION}"
    echo "==============================================================="
    echo ""

    if [ "$DRY_RUN" = true ]; then
        log_warn "DRY RUN MODE - no changes will be made"
        echo ""
    fi

    # Step 1: Detect OS
    log_info "Detecting system..."
    local os_info
    os_info=$(detect_os)
    # Parse os:version:arch:pam_dir format
    local os="${os_info%%:*}"
    local remaining="${os_info#*:}"
    local version="${remaining%%:*}"
    remaining="${remaining#*:}"
    local arch="${remaining%%:*}"
    PAM_DIR="${remaining#*:}"
    log_success "Detected: $os $version ($arch)"
    log_success "PAM directory: $PAM_DIR"

    # Step 2: Check prerequisites
    log_info "Checking prerequisites..."
    check_prerequisites
    log_success "Prerequisites satisfied"

    # Step 3: PAM safety check
    log_info "Checking PAM safety..."
    check_pam_safety

    # Step 4: Confirm
    echo ""
    log_info "This will install:"
    log_info "  - PAM module: $PAM_DIR/pam_unix_oidc.so"
    if [ "$INSTALL_AGENT" = true ]; then
        log_info "  - Agent: /usr/local/bin/unix-oidc-agent"
    fi
    log_info "  - Config: $INSTALL_DIR/"
    echo ""

    confirm "Proceed with installation?"

    # Step 5: Download and verify
    log_info "Downloading unix-oidc..."
    local tmp_dir
    if [ "$DRY_RUN" = false ]; then
        tmp_dir=$(download_binary "$os_info")
    else
        download_binary "$os_info"
        tmp_dir="/tmp/dry-run"
    fi

    # Step 6: Install
    log_info "Installing..."
    install_pam_module "$tmp_dir"
    install_agent "$tmp_dir"

    # Step 7: Configure
    log_info "Creating configuration..."
    create_config
    generate_pam_config
    create_manifest

    # Step 8: Validate
    validate_issuer
    test_with_pamtester

    # Done
    echo ""
    echo "==============================================================="
    if [ "$DRY_RUN" = true ]; then
        log_success "DRY RUN COMPLETE - no changes were made"
    else
        log_success "INSTALLATION COMPLETE"
    fi
    echo "==============================================================="
    echo ""
    log_info "Next steps:"
    log_info "  1. Edit $INSTALL_DIR/config.env with your OIDC issuer"
    log_info "  2. Review $INSTALL_DIR/pam.d-sshd.recommended"
    log_info "  3. Copy PAM config to /etc/pam.d/sshd (carefully!)"
    log_info "  4. Test with: pamtester sshd yourusername authenticate"
    echo ""
    log_info "Documentation: https://github.com/${GITHUB_REPO}#readme"
    log_info "Quickstart: https://github.com/${GITHUB_REPO}/blob/main/deploy/quickstart/"
}

main "$@"
