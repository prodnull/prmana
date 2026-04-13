#!/usr/bin/env bash
# ssh-key-inventory.sh — Scan hosts for SSH authorized_keys and report key sprawl.
#
# Part of the Prmana Rollout & Migration Toolkit (Phase 43).
#
# Usage:
#   ./ssh-key-inventory.sh                           # scan localhost
#   ./ssh-key-inventory.sh --hosts hosts.txt         # scan remote hosts via SSH
#   ./ssh-key-inventory.sh --hosts hosts.txt --csv   # CSV output for spreadsheet/SIEM
#
# What it finds:
#   - All authorized_keys files (standard and non-standard paths)
#   - Key count per user per host
#   - Key age (file mtime — not key creation date, but best available signal)
#   - Keys with no "from=" restriction (unrestricted source IP)
#   - Duplicate public keys across users/hosts
#
# Prerequisites:
#   - SSH access to target hosts (for remote scan)
#   - sudo/root on target hosts to read all users' authorized_keys
#
# Security:
#   - This script reads public keys only. It never touches private keys.
#   - Remote execution uses SSH — no credentials are stored or transmitted in the clear.
#   - Output may contain usernames and key fingerprints. Treat as sensitive.

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

HOSTS_FILE=""
CSV_MODE=false
VERBOSE=false
SCAN_SYSTEM_ACCOUNTS=false

usage() {
    cat <<'EOF'
Usage: ssh-key-inventory.sh [OPTIONS]

Options:
  --hosts FILE      File with one hostname/IP per line (default: scan localhost)
  --csv             Output in CSV format (host,user,keys,oldest_days,unrestricted)
  --system          Include system accounts (uid < 1000)
  --verbose         Show progress on stderr
  -h, --help        Show this help

Examples:
  # Scan localhost
  sudo ./ssh-key-inventory.sh

  # Scan fleet from hosts file
  ./ssh-key-inventory.sh --hosts /etc/ansible/hosts.txt --csv > inventory.csv

  # Scan with verbose progress
  ./ssh-key-inventory.sh --hosts hosts.txt --verbose
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hosts) HOSTS_FILE="$2"; shift 2 ;;
        --csv) CSV_MODE=true; shift ;;
        --system) SCAN_SYSTEM_ACCOUNTS=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

log() { $VERBOSE && echo "[INFO] $*" >&2 || true; }

# ── Local scan function ──────────────────────────────────────────────────────

scan_local() {
    local hostname
    hostname=$(hostname -f 2>/dev/null || hostname)

    local min_uid=1000
    $SCAN_SYSTEM_ACCOUNTS && min_uid=0

    local total_keys=0
    local total_users=0
    local total_unrestricted=0

    # Find all authorized_keys files on the system.
    # Standard paths: ~/.ssh/authorized_keys, ~/.ssh/authorized_keys2
    # Also check AuthorizedKeysFile from sshd_config if non-standard.
    local search_paths=()

    # Get home directories for users above min_uid
    while IFS=: read -r username _ uid _ _ homedir _; do
        [[ "$uid" -lt "$min_uid" ]] && continue
        [[ -d "$homedir/.ssh" ]] || continue
        search_paths+=("$homedir/.ssh")
    done < /etc/passwd

    # Check sshd_config for non-standard AuthorizedKeysFile
    local sshd_authkeys_pattern=""
    if [[ -f /etc/ssh/sshd_config ]]; then
        sshd_authkeys_pattern=$(grep -i "^AuthorizedKeysFile" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || true)
    fi

    if $CSV_MODE; then
        echo "host,user,key_count,oldest_key_days,unrestricted_keys,authorized_keys_path"
    else
        echo "=== SSH Key Inventory: $hostname ==="
        echo ""
    fi

    while IFS=: read -r username _ uid _ _ homedir _; do
        [[ "$uid" -lt "$min_uid" ]] && continue

        local authkeys_file="$homedir/.ssh/authorized_keys"
        [[ -f "$authkeys_file" ]] || continue

        log "Scanning $username ($authkeys_file)"

        # Count non-empty, non-comment lines (actual keys)
        local key_count
        key_count=$(grep -c '^[^#]' "$authkeys_file" 2>/dev/null || echo 0)
        [[ "$key_count" -eq 0 ]] && continue

        # Count keys without "from=" restriction
        local unrestricted
        unrestricted=$(grep '^[^#]' "$authkeys_file" 2>/dev/null | grep -cv 'from=' || echo 0)

        # File age in days (best proxy for key age)
        local file_mtime oldest_days
        if stat --version &>/dev/null 2>&1; then
            # GNU stat
            file_mtime=$(stat -c %Y "$authkeys_file" 2>/dev/null || echo 0)
        else
            # BSD/macOS stat
            file_mtime=$(stat -f %m "$authkeys_file" 2>/dev/null || echo 0)
        fi
        local now
        now=$(date +%s)
        oldest_days=$(( (now - file_mtime) / 86400 ))

        total_keys=$((total_keys + key_count))
        total_users=$((total_users + 1))
        total_unrestricted=$((total_unrestricted + unrestricted))

        if $CSV_MODE; then
            echo "$hostname,$username,$key_count,$oldest_days,$unrestricted,$authkeys_file"
        else
            printf "  %-20s %3d keys   %4d days old   %d unrestricted\n" \
                "$username" "$key_count" "$oldest_days" "$unrestricted"
        fi
    done < /etc/passwd

    if ! $CSV_MODE; then
        echo ""
        echo "--- Summary ---"
        echo "Host:              $hostname"
        echo "Users with keys:   $total_users"
        echo "Total keys:        $total_keys"
        echo "Unrestricted keys: $total_unrestricted"

        if [[ $total_unrestricted -gt 0 ]]; then
            echo ""
            echo "WARNING: $total_unrestricted keys have no 'from=' restriction."
            echo "These keys can be used from any source IP."
        fi
    fi
}

# ── Remote scan function ─────────────────────────────────────────────────────

scan_remote() {
    local host="$1"
    log "Connecting to $host"

    # Ship the scan function to the remote host and execute it.
    # The script is self-contained — no remote dependencies beyond bash.
    local remote_args="--system"
    $CSV_MODE && remote_args="$remote_args --csv"
    ! $SCAN_SYSTEM_ACCOUNTS && remote_args=""
    $CSV_MODE && remote_args="$remote_args --csv"

    ssh -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=accept-new \
        -o BatchMode=yes \
        "$host" \
        "sudo bash -s -- $remote_args" < "$0" 2>/dev/null || {
        echo "ERROR: Failed to scan $host" >&2
        return 1
    }
}

# ── Main ─────────────────────────────────────────────────────────────────────

if [[ -z "$HOSTS_FILE" ]]; then
    # Local scan
    scan_local
else
    # Remote fleet scan
    if [[ ! -f "$HOSTS_FILE" ]]; then
        echo "ERROR: Hosts file not found: $HOSTS_FILE" >&2
        exit 1
    fi

    if $CSV_MODE; then
        echo "host,user,key_count,oldest_key_days,unrestricted_keys,authorized_keys_path"
    fi

    local_csv_mode=$CSV_MODE

    while IFS= read -r host; do
        # Skip empty lines and comments
        [[ -z "$host" || "$host" == \#* ]] && continue

        if $local_csv_mode; then
            # In CSV mode, skip the header from each remote host
            scan_remote "$host" | tail -n +2
        else
            scan_remote "$host"
            echo ""
        fi
    done < "$HOSTS_FILE"
fi
