#!/usr/bin/env bash
# collect.sh — Per-instance log collection script.
#
# Runs ON each fleet instance (invoked over SSH by aggregate.sh).
# Collects system diagnostics into a tarball and prints the tarball path
# as the last line of stdout so the orchestrator can scp it back.
#
# Usage:
#   bash /tmp/collect.sh
#
# Output:
#   /tmp/prmana-ci-logs-<hostname>.tar.gz
#
# Security note: Logs are collected raw — no filtering or redaction is
# applied here. DT-0 does not install prmana, so no OIDC tokens appear in
# the collected output. DT-A will add a redaction note when it runs.

set -euo pipefail

HOSTNAME=$(hostname -s)
OUTDIR="/tmp/prmana-ci-logs-${HOSTNAME}"
TARBALL="/tmp/prmana-ci-logs-${HOSTNAME}.tar.gz"
ERRORS_FILE="${OUTDIR}/collection-errors.txt"

# ---------------------------------------------------------------------------
# Preparation
# ---------------------------------------------------------------------------
rm -rf "${OUTDIR}"
mkdir -p "${OUTDIR}"
true > "${ERRORS_FILE}"

# ---------------------------------------------------------------------------
# Helper: run with optional sudo -n. Falls back to unprivileged on EPERM.
# ---------------------------------------------------------------------------
run_maybe_sudo() {
  local desc="$1"
  shift
  if sudo -n true 2>/dev/null; then
    sudo -n "$@" 2>/dev/null || {
      echo "WARN: sudo '$desc' failed" >> "${ERRORS_FILE}"
      "$@" 2>/dev/null || echo "WARN: unprivileged '$desc' also failed" >> "${ERRORS_FILE}"
    }
  else
    "$@" 2>/dev/null || echo "WARN: '$desc' failed (no sudo)" >> "${ERRORS_FILE}"
  fi
}

# ---------------------------------------------------------------------------
# journalctl — prefer JSON for structured parsing; fall back to plain text
# ---------------------------------------------------------------------------
if journalctl --no-pager -o json --lines=50000 > "${OUTDIR}/journalctl.json" 2>/dev/null; then
  : # JSON succeeded
elif journalctl --no-pager > "${OUTDIR}/journalctl.log" 2>/dev/null; then
  # Rename so aggregate.sh finds a consistent filename
  mv "${OUTDIR}/journalctl.log" "${OUTDIR}/journalctl.json"
else
  echo "WARN: journalctl unavailable" >> "${ERRORS_FILE}"
  echo "journalctl not available on this instance" > "${OUTDIR}/journalctl.json"
fi

# ---------------------------------------------------------------------------
# dmesg
# ---------------------------------------------------------------------------
if run_maybe_sudo "dmesg" dmesg --time-format iso > "${OUTDIR}/dmesg.log" 2>/dev/null; then
  : # iso format succeeded
else
  run_maybe_sudo "dmesg-plain" dmesg > "${OUTDIR}/dmesg.log" 2>/dev/null \
    || echo "dmesg not available" > "${OUTDIR}/dmesg.log"
fi

# ---------------------------------------------------------------------------
# systemctl status (best-effort; non-zero exit code is normal if any unit failed)
# ---------------------------------------------------------------------------
systemctl status --all --no-pager > "${OUTDIR}/systemctl-status.txt" 2>/dev/null || true

# ---------------------------------------------------------------------------
# audit.log
# ---------------------------------------------------------------------------
if ! run_maybe_sudo "audit.log" cp /var/log/audit/audit.log "${OUTDIR}/audit.log" 2>/dev/null; then
  echo "no audit log (auditd may not be installed or running)" > "${OUTDIR}/audit.log"
fi

# ---------------------------------------------------------------------------
# prmana-ci metadata (written by Terraform user-data/cloud-init)
# ---------------------------------------------------------------------------
cp /etc/prmana-ci-metadata "${OUTDIR}/metadata.txt" 2>/dev/null \
  || echo "no metadata (pre-prmana-install or metadata file absent)" > "${OUTDIR}/metadata.txt"

# ---------------------------------------------------------------------------
# Basic host info
# ---------------------------------------------------------------------------
uname -a > "${OUTDIR}/uname.txt"
cat /etc/os-release > "${OUTDIR}/os-release.txt"

# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------
tar -czf "${TARBALL}" -C /tmp "prmana-ci-logs-${HOSTNAME}"

# Last line must be the tarball path (parsed by aggregate.sh)
echo "${TARBALL}"
