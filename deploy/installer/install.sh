#!/bin/bash
# unix-oidc installer
# Usage: curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh | bash
set -euo pipefail

VERSION="3.0.0"
SCRIPT_VERSION="2.0.0"
GITHUB_REPO="prodnull/unix-oidc"
INSTALL_DIR="/etc/unix-oidc"
PAM_DIR=""  # Set by detect_os
OS_FAMILY="" # debian or rhel, set by detect_os

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
VERIFY_SLSA=false
OFFLINE_TARBALL=""
CONFIGURE_PAM=false
BREAKGLASS_USER=""
ROLLBACK_PAM=false

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

    # Set PAM directory and OS family based on OS
    case "$os" in
        ubuntu|debian)
            PAM_DIR="/lib/security"
            OS_FAMILY="debian"
            ;;
        rhel|rocky|almalinux|centos|fedora|amzn)
            if [ "$arch" = "x86_64" ]; then
                PAM_DIR="/lib64/security"
            else
                PAM_DIR="/lib/security"
            fi
            OS_FAMILY="rhel"
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

    local release_base="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}"
    local artifact_name="unix-oidc-v${VERSION}-linux-${arch}.tar.gz"

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf '"$tmp_dir" EXIT

    if [ "$DRY_RUN" = true ]; then
        if [ -n "$OFFLINE_TARBALL" ]; then
            log_dry "Use offline tarball: $OFFLINE_TARBALL"
        else
            log_dry "Download ${release_base}/${artifact_name}"
        fi
        log_dry "Verify SHA-256 checksum"
        log_dry "Verify Sigstore signature (if cosign available)"
        if [ "$VERIFY_SLSA" = true ]; then
            log_dry "Verify SLSA provenance (gh attestation verify)"
        fi
        return 0
    fi

    # Offline mode: use pre-downloaded tarball
    if [ -n "$OFFLINE_TARBALL" ]; then
        log_info "Using offline tarball: $OFFLINE_TARBALL"
        if [ ! -f "$OFFLINE_TARBALL" ]; then
            log_error "Offline tarball not found: $OFFLINE_TARBALL"
            exit 1
        fi
        cp "$OFFLINE_TARBALL" "$tmp_dir/archive.tar.gz"
    else
        log_info "Downloading unix-oidc v${VERSION} for linux-${arch}..."
        curl -fsSL "${release_base}/${artifact_name}" -o "$tmp_dir/archive.tar.gz" || {
            log_error "Failed to download binary"
            exit 1
        }
    fi

    # Download and verify against consolidated SHA256SUMS
    log_info "Verifying checksum..."
    if [ -z "$OFFLINE_TARBALL" ]; then
        curl -fsSL "${release_base}/SHA256SUMS" -o "$tmp_dir/SHA256SUMS" || {
            # Fall back to per-artifact checksum for older releases
            log_warn "Consolidated SHA256SUMS not found, trying per-artifact checksum"
            curl -fsSL "${release_base}/${artifact_name}.sha256" -o "$tmp_dir/SHA256SUMS" || {
                log_error "Failed to download checksum"
                exit 1
            }
        }
    fi

    cd "$tmp_dir"
    # Rename archive to match the expected filename in SHA256SUMS
    cp archive.tar.gz "$artifact_name"
    if sha256sum --version &>/dev/null 2>&1; then
        # GNU coreutils
        if ! grep "$artifact_name" SHA256SUMS | sha256sum -c --status 2>/dev/null; then
            log_error "SHA-256 checksum verification FAILED"
            exit 1
        fi
    else
        # BSD (macOS) — not expected during Linux install but handle gracefully
        expected=$(grep "$artifact_name" SHA256SUMS | awk '{print $1}')
        actual=$(shasum -a 256 "$artifact_name" | awk '{print $1}')
        if [ "$expected" != "$actual" ]; then
            log_error "SHA-256 checksum verification FAILED"
            exit 1
        fi
    fi
    log_success "Checksum verified"

    # Verify Sigstore signature on SHA256SUMS (covers all artifacts transitively)
    if command -v cosign &> /dev/null; then
        log_info "Verifying Sigstore signature..."
        curl -fsSL "${release_base}/SHA256SUMS.sig" -o "$tmp_dir/SHA256SUMS.sig" 2>/dev/null || true
        curl -fsSL "${release_base}/SHA256SUMS.pem" -o "$tmp_dir/SHA256SUMS.pem" 2>/dev/null || true

        if [ -f "$tmp_dir/SHA256SUMS.sig" ] && [ -f "$tmp_dir/SHA256SUMS.pem" ]; then
            if cosign verify-blob \
                --certificate "$tmp_dir/SHA256SUMS.pem" \
                --signature "$tmp_dir/SHA256SUMS.sig" \
                --certificate-identity-regexp "https://github.com/${GITHUB_REPO}" \
                --certificate-oidc-issuer https://token.actions.githubusercontent.com \
                "$tmp_dir/SHA256SUMS" 2>/dev/null; then
                log_success "Sigstore signature verified"
            else
                log_warn "Sigstore signature verification failed — continuing"
            fi
        else
            log_warn "Signature files not available, skipping Sigstore verification"
        fi
    else
        log_warn "cosign not found — skipping Sigstore verification"
        log_info "Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/"
    fi

    # Verify SLSA provenance if requested
    if [ "$VERIFY_SLSA" = true ]; then
        if command -v gh &> /dev/null; then
            log_info "Verifying SLSA build provenance..."
            if gh attestation verify "$tmp_dir/$artifact_name" --repo "${GITHUB_REPO}" 2>/dev/null; then
                log_success "SLSA provenance verified"
            else
                log_warn "SLSA provenance verification failed — continuing"
            fi
        else
            log_warn "gh CLI not found — skipping SLSA verification"
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
/usr/lib/systemd/user/unix-oidc-agent.service
/usr/lib/systemd/user/unix-oidc-agent.socket
/etc/tmpfiles.d/unix-oidc.conf
/usr/share/pam-configs/unix-oidc
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
# Configure PAM using native OS tools (33-02)
# Uses pam-auth-update (Debian) or authselect (RHEL)
# Never edits /etc/pam.d/ files directly.
#######################################
configure_pam() {
    if [ "$CONFIGURE_PAM" = false ]; then
        log_info "Skipping PAM configuration (use --configure-pam to enable)"
        return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        log_dry "Configure PAM via native OS tools"
        log_dry "Backup current PAM config"
        return 0
    fi

    # Backup current PAM state
    local backup_dir
    backup_dir="$INSTALL_DIR/.pam-backup-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    cp -a /etc/pam.d/sshd "$backup_dir/" 2>/dev/null || true
    cp -a /etc/pam.d/sudo "$backup_dir/" 2>/dev/null || true
    log_info "PAM config backed up to $backup_dir"

    case "$OS_FAMILY" in
        debian)
            if command -v pam-auth-update &>/dev/null; then
                log_info "Configuring PAM via pam-auth-update..."
                # Install the pam-auth-update profile
                cat > /usr/share/pam-configs/unix-oidc << 'PAMCFG'
Name: unix-oidc OIDC Authentication
Default: no
Priority: 192
Auth-Type: Primary
Auth:
    [success=end default=ignore] pam_unix_oidc.so
PAMCFG
                log_success "Installed pam-auth-update profile"
                log_info "Enable with: sudo pam-auth-update --enable unix-oidc"
                log_warn "Review the PAM stack before enabling in production"
            else
                log_warn "pam-auth-update not found — generating recommended configs only"
                generate_pam_config
            fi
            ;;
        rhel)
            if command -v authselect &>/dev/null; then
                log_info "Configuring PAM via authselect..."
                # Create a custom authselect profile based on the current one
                local current_profile
                current_profile=$(authselect current -r 2>/dev/null || echo "sssd")
                local custom_dir="/etc/authselect/custom/unix-oidc"
                if [ ! -d "$custom_dir" ]; then
                    authselect create-profile unix-oidc --base-on "$current_profile" 2>/dev/null || {
                        log_warn "Could not create authselect profile — generating recommended configs only"
                        generate_pam_config
                        return 0
                    }
                fi
                log_success "Created authselect profile 'unix-oidc'"
                log_info "Enable with: sudo authselect select custom/unix-oidc"
                log_warn "Review the profile before activating in production"
            else
                log_warn "authselect not found — generating recommended configs only"
                generate_pam_config
            fi
            ;;
        *)
            log_warn "Unknown OS family — generating recommended PAM configs only"
            generate_pam_config
            ;;
    esac

    # Verify pam_unix.so is still in the stack (safety check)
    if [ -f /etc/pam.d/sshd ]; then
        if ! grep -q "pam_unix.so" /etc/pam.d/sshd 2>/dev/null; then
            log_error "CRITICAL: pam_unix.so is missing from /etc/pam.d/sshd after PAM configuration!"
            log_error "Restoring from backup..."
            cp -a "$backup_dir/sshd" /etc/pam.d/sshd 2>/dev/null || true
            log_error "Restored. PAM configuration was NOT applied."
            return 1
        fi
    fi
    log_success "PAM fallback (pam_unix.so) verified present"
}

#######################################
# Rollback PAM configuration (33-02)
#######################################
rollback_pam() {
    local latest_backup
    if [ ! -d "$INSTALL_DIR" ]; then
        log_error "No PAM backup found (install directory does not exist)"
        exit 1
    fi
    latest_backup=$(find "$INSTALL_DIR" -maxdepth 1 -name '.pam-backup-*' -type d | sort -r | head -1)

    if [ -z "$latest_backup" ]; then
        log_error "No PAM backup found in $INSTALL_DIR"
        exit 1
    fi

    log_info "Restoring PAM config from: $latest_backup"

    if [ "$DRY_RUN" = true ]; then
        log_dry "Restore /etc/pam.d/sshd from $latest_backup/sshd"
        log_dry "Restore /etc/pam.d/sudo from $latest_backup/sudo"
        return 0
    fi

    [ -f "$latest_backup/sshd" ] && cp -a "$latest_backup/sshd" /etc/pam.d/sshd
    [ -f "$latest_backup/sudo" ] && cp -a "$latest_backup/sudo" /etc/pam.d/sudo

    # Remove pam-auth-update profile if present
    rm -f /usr/share/pam-configs/unix-oidc

    log_success "PAM configuration restored from backup"
}

#######################################
# Install systemd/launchd service files (33-03)
#######################################
install_service_files() {
    if [ "$DRY_RUN" = true ]; then
        log_dry "Install systemd service, socket, and tmpfiles config"
        return 0
    fi

    local src_dir
    # Service files are bundled in the release tarball under contrib/systemd/
    # or alongside this script in the repo checkout
    for candidate in \
        "$1/contrib/systemd" \
        "$(dirname "$0")/../contrib/systemd" \
        "/usr/share/unix-oidc/systemd"; do
        if [ -d "$candidate" ]; then
            src_dir="$candidate"
            break
        fi
    done

    if [ -z "$src_dir" ]; then
        log_warn "systemd service files not found in release — skipping service installation"
        return 0
    fi

    # Install systemd user service and socket (for per-user agent)
    local user_unit_dir="/usr/lib/systemd/user"
    mkdir -p "$user_unit_dir"

    if [ -f "$src_dir/unix-oidc-agent.service" ]; then
        cp "$src_dir/unix-oidc-agent.service" "$user_unit_dir/"
        log_success "Installed $user_unit_dir/unix-oidc-agent.service"
    fi

    if [ -f "$src_dir/unix-oidc-agent.socket" ]; then
        cp "$src_dir/unix-oidc-agent.socket" "$user_unit_dir/"
        log_success "Installed $user_unit_dir/unix-oidc-agent.socket"
    fi

    # Install tmpfiles.d config (for system-level JTI/nonce directories)
    if [ -f "$src_dir/unix-oidc.tmpfiles.conf" ]; then
        cp "$src_dir/unix-oidc.tmpfiles.conf" /etc/tmpfiles.d/unix-oidc.conf
        systemd-tmpfiles --create /etc/tmpfiles.d/unix-oidc.conf 2>/dev/null || {
            log_warn "systemd-tmpfiles --create failed (directories may need manual creation)"
        }
        log_success "Installed /etc/tmpfiles.d/unix-oidc.conf"
    fi

    # Reload systemd
    systemctl daemon-reload 2>/dev/null || true
    log_success "systemd units installed (enable with: systemctl --user enable --now unix-oidc-agent.socket)"
}

#######################################
# Validate break-glass access (33-04)
# Verifies a local fallback account exists and can authenticate
# without OIDC, preventing lockout if the IdP is unreachable.
#######################################
validate_breakglass() {
    if [ -z "$BREAKGLASS_USER" ]; then
        echo ""
        log_warn "============================================================"
        log_warn "  No break-glass user specified (--breakglass-user)"
        log_warn "  Without a local fallback account, an IdP outage will"
        log_warn "  lock you out of this server."
        log_warn "  See: docs/release-verification.md, CLAUDE.md §Break-Glass"
        log_warn "============================================================"
        echo ""
        return 0
    fi

    log_info "Validating break-glass user: $BREAKGLASS_USER"

    if [ "$DRY_RUN" = true ]; then
        log_dry "Verify user '$BREAKGLASS_USER' exists"
        log_dry "Verify user has a password set"
        log_dry "Verify pam_unix.so fallback is in PAM stack"
        return 0
    fi

    # When --breakglass-user is explicitly set and validation fails,
    # hard-fail the install (per Gemini security review 2026-04-09).
    # An operator who specifies a break-glass user cares about lockout
    # protection — proceeding with a broken fallback defeats the purpose.

    # Check user exists
    if ! id "$BREAKGLASS_USER" &>/dev/null; then
        log_error "Break-glass user '$BREAKGLASS_USER' does not exist"
        log_info "Create with: useradd -m -s /bin/bash $BREAKGLASS_USER && passwd $BREAKGLASS_USER"
        exit 1
    fi
    log_success "User '$BREAKGLASS_USER' exists"

    # Check user has a password set (not locked/expired)
    local pw_status
    pw_status=$(passwd -S "$BREAKGLASS_USER" 2>/dev/null || chage -l "$BREAKGLASS_USER" 2>/dev/null || echo "unknown")
    if echo "$pw_status" | grep -qi "locked\|LK\|L "; then
        log_error "Break-glass user '$BREAKGLASS_USER' account is locked"
        log_info "Unlock with: passwd -u $BREAKGLASS_USER"
        exit 1
    fi
    # Check for 'NP' (no password) or '!' in shadow
    if echo "$pw_status" | grep -qi "NP\| NP "; then
        log_error "Break-glass user '$BREAKGLASS_USER' has no password set"
        log_info "Set password with: passwd $BREAKGLASS_USER"
        exit 1
    fi
    log_success "User '$BREAKGLASS_USER' has a password set"

    # Verify pam_unix.so is in the sshd PAM stack
    if [ -f /etc/pam.d/sshd ]; then
        if grep -q "pam_unix.so" /etc/pam.d/sshd 2>/dev/null; then
            log_success "pam_unix.so fallback present in /etc/pam.d/sshd"
        else
            log_error "pam_unix.so NOT found in /etc/pam.d/sshd — break-glass will fail!"
            exit 1
        fi
    else
        log_warn "/etc/pam.d/sshd not found — cannot verify PAM fallback"
    fi

    # Verify user can log in via SSH (password auth enabled)
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -qE "^PasswordAuthentication\s+no" /etc/ssh/sshd_config 2>/dev/null; then
            log_warn "PasswordAuthentication is disabled in sshd_config"
            log_warn "Break-glass user won't be able to SSH with password"
            log_info "Consider: Match User $BREAKGLASS_USER + PasswordAuthentication yes"
        fi
    fi

    log_success "Break-glass validation passed for '$BREAKGLASS_USER'"
}

#######################################
# Print usage
#######################################
usage() {
    cat << EOF
unix-oidc installer v${SCRIPT_VERSION}

Usage: $0 [OPTIONS]

Options:
    --issuer URL              OIDC issuer URL (required for production)
    --client-id ID            OIDC client ID (default: unix-oidc)
    --version VER             unix-oidc version to install (default: $VERSION)
    --no-agent                Skip agent installation
    --configure-pam           Configure PAM via native OS tools (pam-auth-update/authselect)
    --rollback-pam            Restore PAM config from most recent backup
    --breakglass-user USER    Validate break-glass account for IdP outage recovery
    --verify-slsa             Verify SLSA build provenance (requires gh CLI)
    --offline TARBALL         Use a pre-downloaded release tarball (air-gapped installs)
    --dry-run                 Show what would be done without making changes
    --yes, -y                 Skip confirmation prompts
    --force                   Bypass PAM safety checks (use with caution!)
    --help, -h                Show this help message

Examples:
    # Dry run to see what would happen
    $0 --dry-run

    # Install with specific IdP and break-glass validation
    $0 --issuer https://login.example.com/realms/myorg --breakglass-user breakglass

    # Full install with PAM configuration
    $0 --issuer https://login.example.com --configure-pam --breakglass-user breakglass --yes

    # Air-gapped install from pre-downloaded tarball
    $0 --offline ./unix-oidc-v${VERSION}-linux-x86_64.tar.gz --issuer https://login.example.com

    # Verify full supply chain (checksums + Sigstore + SLSA)
    $0 --issuer https://login.example.com --verify-slsa

    # Rollback PAM to pre-install state
    $0 --rollback-pam

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
            --configure-pam)
                CONFIGURE_PAM=true
                shift
                ;;
            --rollback-pam)
                ROLLBACK_PAM=true
                shift
                ;;
            --breakglass-user)
                BREAKGLASS_USER="$2"
                shift 2
                ;;
            --verify-slsa)
                VERIFY_SLSA=true
                shift
                ;;
            --offline)
                OFFLINE_TARBALL="$2"
                shift 2
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

    # Handle rollback mode (standalone operation)
    if [ "$ROLLBACK_PAM" = true ]; then
        rollback_pam
        exit 0
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
    log_success "Detected: $os $version ($arch), family: $OS_FAMILY"
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
    log_info "  - systemd units: /usr/lib/systemd/user/"
    log_info "  - tmpfiles: /etc/tmpfiles.d/unix-oidc.conf"
    if [ "$CONFIGURE_PAM" = true ]; then
        log_info "  - PAM config via $OS_FAMILY native tools"
    fi
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

    # Step 6: Install binaries
    log_info "Installing binaries..."
    install_pam_module "$tmp_dir"
    install_agent "$tmp_dir"

    # Step 7: Install service files (systemd/tmpfiles)
    log_info "Installing service files..."
    install_service_files "$tmp_dir"

    # Step 8: Configure
    log_info "Creating configuration..."
    create_config
    configure_pam
    if [ "$CONFIGURE_PAM" = false ]; then
        generate_pam_config
    fi

    # Step 9: Create manifest (includes new files)
    create_manifest

    # Step 10: Validate
    validate_issuer
    validate_breakglass
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
    if [ -z "$OIDC_ISSUER" ]; then
        log_info "  1. Edit $INSTALL_DIR/config.env with your OIDC issuer"
    fi
    if [ "$CONFIGURE_PAM" = false ]; then
        log_info "  2. Review $INSTALL_DIR/pam.d-sshd.recommended"
        log_info "  3. Apply PAM config: $0 --configure-pam (or copy manually)"
    fi
    log_info "  4. Enable agent: systemctl --user enable --now unix-oidc-agent.socket"
    if [ -z "$BREAKGLASS_USER" ]; then
        log_warn "  5. Configure a break-glass account! (--breakglass-user)"
    fi
    log_info "  6. Test with: pamtester sshd yourusername authenticate"
    echo ""
    log_info "Documentation: https://github.com/${GITHUB_REPO}#readme"
    log_info "Quickstart: https://github.com/${GITHUB_REPO}/blob/main/deploy/quickstart/"
}

main "$@"
