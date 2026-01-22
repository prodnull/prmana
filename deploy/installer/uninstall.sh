#!/bin/bash
# unix-oidc uninstaller
set -euo pipefail

INSTALL_DIR="/etc/unix-oidc"
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

usage() {
    cat << EOF
unix-oidc uninstaller

Usage: $0 [OPTIONS]

Options:
    --keep-config    Keep configuration files in $INSTALL_DIR
    --dry-run        Show what would be removed without making changes
    --yes, -y        Skip confirmation prompts
    --help, -h       Show this help

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --keep-config) KEEP_CONFIG=true; shift ;;
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
        if [ -f "$pam_file" ] && grep -q "pam_unix_oidc" "$pam_file" 2>/dev/null; then
            log_warn "PAM still configured to use unix-oidc in $pam_file"
            in_use=true
        fi
    done

    if [ "$in_use" = true ]; then
        log_warn "Remove unix-oidc from PAM config before uninstalling!"
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

main() {
    parse_args "$@"

    if [ "$EUID" -ne 0 ] && [ "$DRY_RUN" = false ]; then
        log_error "This script must be run as root (or use --dry-run)"
        exit 1
    fi

    echo ""
    echo "==============================================="
    echo "          unix-oidc Uninstaller"
    echo "==============================================="
    echo ""

    if [ "$DRY_RUN" = true ]; then
        log_warn "DRY RUN MODE - no changes will be made"
        echo ""
    fi

    if [ ! -f "$MANIFEST" ]; then
        log_error "Install manifest not found: $MANIFEST"
        log_info "unix-oidc may not be installed or was installed manually"
        exit 1
    fi

    # Check if PAM is still using unix-oidc
    check_pam_in_use

    log_info "Reading install manifest..."
    echo ""

    local removed=0
    local skipped=0
    local not_found=0

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
            log_warn "Not found: $file"
            ((not_found++)) || true
        fi
    done < "$MANIFEST"

    # Remove manifest and directory (unless keeping config)
    if [ "$KEEP_CONFIG" = false ]; then
        if [ "$DRY_RUN" = true ]; then
            log_info "Would remove: $MANIFEST"
            log_info "Would remove directory: $INSTALL_DIR"
        else
            rm -f "$MANIFEST"
            rmdir "$INSTALL_DIR" 2>/dev/null || log_warn "Could not remove $INSTALL_DIR (not empty)"
            log_success "Removed install manifest and directory"
        fi
    fi

    echo ""
    echo "==============================================="
    if [ "$DRY_RUN" = true ]; then
        log_success "DRY RUN COMPLETE"
        log_info "Would remove $removed files, skip $skipped, $not_found not found"
    else
        log_success "UNINSTALL COMPLETE"
        log_info "Removed $removed files, skipped $skipped, $not_found not found"
    fi
    echo "==============================================="
    echo ""

    if [ "$DRY_RUN" = false ]; then
        log_info "unix-oidc has been removed from this system"
        if [ "$KEEP_CONFIG" = true ]; then
            log_info "Configuration preserved in $INSTALL_DIR"
        fi
    fi
}

main "$@"
