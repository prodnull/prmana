#!/bin/bash
# prmana uninstaller v2.0.0
# Idempotent — safe to run multiple times.
set -euo pipefail

INSTALL_DIR="/etc/prmana"
MANIFEST="$INSTALL_DIR/.install-manifest"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

DRY_RUN=false
KEEP_CONFIG=false
YES_MODE=false
PURGE=false

usage() {
    cat << EOF
prmana uninstaller v2.0.0

Usage: $0 [OPTIONS]

Options:
    --keep-config    Keep configuration files in $INSTALL_DIR
    --purge          Also remove persistent state (/var/lib/prmana)
    --dry-run        Show what would be removed without making changes
    --yes, -y        Skip confirmation prompts
    --help, -h       Show this help

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --keep-config) KEEP_CONFIG=true; shift ;;
            --purge) PURGE=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --yes|-y) YES_MODE=true; shift ;;
            --help|-h) usage; exit 0 ;;
            *) log_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

check_pam_in_use() {
    local in_use=false

    for pam_file in /etc/pam.d/sshd /etc/pam.d/sudo; do
        if [ -f "$pam_file" ] && grep -q "pam_prmana" "$pam_file" 2>/dev/null; then
            log_warn "PAM still configured to use prmana in $pam_file"
            in_use=true
        fi
    done

    if [ "$in_use" = true ]; then
        log_warn "Remove prmana from PAM config before uninstalling!"
        log_warn "Otherwise authentication may fail."
        echo ""
        if [ "$YES_MODE" = false ] && [ "$DRY_RUN" = false ]; then
            read -r -p "Continue anyway? [y/N] " REPLY
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Aborted by user"
                exit 0
            fi
        fi
    fi
}

#######################################
# Remove PAM configuration installed by the installer
#######################################
cleanup_pam_config() {
    log_info "Cleaning up PAM configuration..."

    # Remove pam-auth-update profile (Debian/Ubuntu)
    if [ -f /usr/share/pam-configs/prmana ]; then
        if [ "$DRY_RUN" = true ]; then
            log_info "Would remove: /usr/share/pam-configs/prmana"
        else
            rm -f /usr/share/pam-configs/prmana
            # Re-run pam-auth-update to regenerate configs without our profile
            if command -v pam-auth-update &>/dev/null; then
                pam-auth-update --remove prmana 2>/dev/null || true
            fi
            log_success "Removed pam-auth-update profile"
        fi
    fi

    # Remove authselect custom profile (RHEL/Rocky)
    if [ -d /etc/authselect/custom/prmana ]; then
        if [ "$DRY_RUN" = true ]; then
            log_info "Would remove: /etc/authselect/custom/prmana"
        else
            # Switch back to default profile if currently active
            if command -v authselect &>/dev/null; then
                local current
                current=$(authselect current -r 2>/dev/null || echo "")
                if [ "$current" = "custom/prmana" ]; then
                    authselect select sssd --force 2>/dev/null || true
                    log_info "Switched authselect back to sssd profile"
                fi
            fi
            rm -rf /etc/authselect/custom/prmana
            log_success "Removed authselect custom profile"
        fi
    fi
}

#######################################
# Remove systemd service files
#######################################
cleanup_systemd() {
    log_info "Cleaning up systemd units..."

    local units=(
        "/usr/lib/systemd/user/prmana-agent.service"
        "/usr/lib/systemd/user/prmana-agent.socket"
        "/etc/tmpfiles.d/prmana.conf"
    )

    for unit in "${units[@]}"; do
        if [ -f "$unit" ]; then
            if [ "$DRY_RUN" = true ]; then
                log_info "Would remove: $unit"
            else
                rm -f "$unit"
                log_success "Removed: $unit"
            fi
        fi
    done

    if [ "$DRY_RUN" = false ]; then
        systemctl daemon-reload 2>/dev/null || true
    fi
}

#######################################
# Verify PAM stack is safe after removal
#######################################
verify_pam_safe() {
    if [ -f /etc/pam.d/sshd ]; then
        if grep -q "pam_unix.so" /etc/pam.d/sshd 2>/dev/null; then
            log_success "PAM fallback (pam_unix.so) verified present in /etc/pam.d/sshd"
        else
            log_error "WARNING: pam_unix.so not found in /etc/pam.d/sshd!"
            log_error "Authentication may not work. Verify your PAM configuration."
        fi
    fi
}

main() {
    parse_args "$@"

    if [ "$EUID" -ne 0 ] && [ "$DRY_RUN" = false ]; then
        log_error "This script must be run as root (or use --dry-run)"
        exit 1
    fi

    echo ""
    echo "==============================================="
    echo "          prmana Uninstaller v2.0.0"
    echo "==============================================="
    echo ""

    if [ "$DRY_RUN" = true ]; then
        log_warn "DRY RUN MODE - no changes will be made"
        echo ""
    fi

    # Idempotency: if no manifest and no known files exist, nothing to do
    if [ ! -f "$MANIFEST" ]; then
        local any_found=false
        for f in /usr/local/bin/prmana-agent \
                 /usr/lib/systemd/user/prmana-agent.service \
                 /etc/tmpfiles.d/prmana.conf \
                 /usr/share/pam-configs/prmana; do
            [ -f "$f" ] && any_found=true && break
        done
        # Check PAM dirs for the module
        for pam_dir in /lib/security /lib64/security; do
            [ -f "$pam_dir/pam_prmana.so" ] && any_found=true && break
        done

        if [ "$any_found" = false ]; then
            log_info "prmana does not appear to be installed (no manifest, no known files)"
            log_success "Nothing to do"
            exit 0
        fi
        log_warn "Install manifest not found but prmana files detected — removing known files"
    fi

    # Check if PAM is still using prmana
    check_pam_in_use

    # Remove PAM configuration (profiles, authselect)
    cleanup_pam_config

    # Remove systemd units
    cleanup_systemd

    # Remove files from manifest
    local removed=0
    local skipped=0
    local not_found=0

    if [ -f "$MANIFEST" ]; then
        log_info "Reading install manifest..."
        echo ""

        while IFS= read -r file; do
            # Skip comments and empty lines
            [[ "$file" =~ ^#.*$ ]] && continue
            [[ -z "$file" ]] && continue

            # Skip config if --keep-config
            if [ "$KEEP_CONFIG" = true ] && [[ "$file" == "$INSTALL_DIR"* ]]; then
                log_info "Keeping: $file"
                ((skipped++)) || true
                continue
            fi

            if [ -f "$file" ]; then
                if [ "$DRY_RUN" = true ]; then
                    log_info "Would remove: $file"
                else
                    rm -f "$file"
                    log_success "Removed: $file"
                fi
                ((removed++)) || true
            else
                # Idempotent: already removed is not an error
                ((not_found++)) || true
            fi
        done < "$MANIFEST"
    else
        # No manifest — remove known files directly
        if [ -f /usr/local/bin/prmana-agent ]; then
            if [ "$DRY_RUN" = true ]; then
                log_info "Would remove: /usr/local/bin/prmana-agent"
            else
                rm -f /usr/local/bin/prmana-agent
                log_success "Removed: /usr/local/bin/prmana-agent"
            fi
            ((removed++)) || true
        fi
        for pam_dir in /lib/security /lib64/security; do
            if [ -f "$pam_dir/pam_prmana.so" ]; then
                if [ "$DRY_RUN" = true ]; then
                    log_info "Would remove: $pam_dir/pam_prmana.so"
                else
                    rm -f "$pam_dir/pam_prmana.so"
                    log_success "Removed: $pam_dir/pam_prmana.so"
                fi
                ((removed++)) || true
            fi
        done
    fi

    # Remove manifest and config directory
    if [ "$KEEP_CONFIG" = false ]; then
        if [ "$DRY_RUN" = true ]; then
            [ -f "$MANIFEST" ] && log_info "Would remove: $MANIFEST"
            [ -d "$INSTALL_DIR" ] && log_info "Would remove directory: $INSTALL_DIR"
        else
            rm -f "$MANIFEST"
            # Remove PAM backups and config dir
            rm -rf "$INSTALL_DIR" 2>/dev/null || log_warn "Could not remove $INSTALL_DIR (not empty)"
            log_success "Removed install manifest and config directory"
        fi
    fi

    # Purge persistent state if requested
    if [ "$PURGE" = true ]; then
        if [ "$DRY_RUN" = true ]; then
            log_info "Would remove: /var/lib/prmana"
            log_info "Would remove: /run/prmana"
        else
            rm -rf /var/lib/prmana 2>/dev/null || true
            rm -rf /run/prmana 2>/dev/null || true
            log_success "Purged persistent state"
        fi
    fi

    # Verify PAM is safe after removal
    verify_pam_safe

    echo ""
    echo "==============================================="
    if [ "$DRY_RUN" = true ]; then
        log_success "DRY RUN COMPLETE"
        log_info "Would remove $removed files, skip $skipped, $not_found already absent"
    else
        log_success "UNINSTALL COMPLETE"
        log_info "Removed $removed files, skipped $skipped, $not_found already absent"
    fi
    echo "==============================================="
    echo ""

    if [ "$DRY_RUN" = false ]; then
        log_info "prmana has been removed from this system"
        if [ "$KEEP_CONFIG" = true ]; then
            log_info "Configuration preserved in $INSTALL_DIR"
        fi
        if [ "$PURGE" = false ]; then
            log_info "Persistent state in /var/lib/prmana preserved (use --purge to remove)"
        fi
    fi
}

main "$@"
