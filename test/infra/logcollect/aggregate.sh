#!/usr/bin/env bash
# aggregate.sh — Orchestrator-side log aggregation script.
#
# Runs on the GitHub Actions runner after the fleet scenario completes.
# For each instance IP:
#   1. Copies collect.sh to the instance via scp
#   2. Runs collect.sh over SSH, capturing the tarball path from the last line
#   3. scps the tarball back to OUTPUT_DIR/<ip>.tar.gz
#   4. Extracts it to OUTPUT_DIR/<ip>/
#
# Inputs (via environment variables or positional arguments):
#   INSTANCE_IPS   — space-separated list of instance IP addresses
#   SSH_USER       — SSH username (distro-dependent, from terraform output)
#   SSH_KEY_PATH   — path to the private key file (e.g., /tmp/fleet_key)
#   OUTPUT_DIR     — local directory to write logs into (default: ./fleet-logs)
#
# Exit codes:
#   0 — at least one instance succeeded
#   1 — all instances failed
#
# Usage:
#   INSTANCE_IPS="1.2.3.4 5.6.7.8" SSH_USER=ubuntu SSH_KEY_PATH=/tmp/fleet_key \
#     OUTPUT_DIR=./fleet-logs bash aggregate.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
INSTANCE_IPS="${INSTANCE_IPS:-}"
SSH_USER="${SSH_USER:-}"
SSH_KEY_PATH="${SSH_KEY_PATH:-}"
OUTPUT_DIR="${OUTPUT_DIR:-./fleet-logs}"

COLLECT_SCRIPT="$(dirname "$0")/collect.sh"
COLLECT_SCRIPT_REMOTE="/tmp/collect.sh"

SSH_OPTS=(
  -i "${SSH_KEY_PATH}"
  -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=30
  -o BatchMode=yes
)

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
if [[ -z "${INSTANCE_IPS}" ]]; then
  echo "ERROR: INSTANCE_IPS is not set" >&2
  exit 1
fi
if [[ -z "${SSH_USER}" ]]; then
  echo "ERROR: SSH_USER is not set" >&2
  exit 1
fi
if [[ -z "${SSH_KEY_PATH}" ]]; then
  echo "ERROR: SSH_KEY_PATH is not set" >&2
  exit 1
fi
if [[ ! -f "${COLLECT_SCRIPT}" ]]; then
  echo "ERROR: collect.sh not found at ${COLLECT_SCRIPT}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# ---------------------------------------------------------------------------
# Per-instance collection
# ---------------------------------------------------------------------------
SUCCESS=0
FAILURE=0

for IP in ${INSTANCE_IPS}; do
  echo "=== Collecting logs from ${IP} ==="

  INSTANCE_DIR="${OUTPUT_DIR}/${IP}"
  ERROR_FILE="${OUTPUT_DIR}/${IP}.error.txt"

  if ! scp "${SSH_OPTS[@]}" \
      "${COLLECT_SCRIPT}" \
      "${SSH_USER}@${IP}:${COLLECT_SCRIPT_REMOTE}" 2>&1; then
    echo "FAILED to copy collect.sh to ${IP}" | tee "${ERROR_FILE}"
    FAILURE=$((FAILURE + 1))
    continue
  fi

  # Run collect.sh; capture all output, extract tarball path from last line
  # SC2029: COLLECT_SCRIPT_REMOTE is a fixed constant expanded intentionally on client
  # shellcheck disable=SC2029
  COLLECT_OUTPUT=$(ssh "${SSH_OPTS[@]}" \
    "${SSH_USER}@${IP}" "bash ${COLLECT_SCRIPT_REMOTE}" 2>&1) || {
    echo "FAILED to run collect.sh on ${IP}: ${COLLECT_OUTPUT}" | tee "${ERROR_FILE}"
    FAILURE=$((FAILURE + 1))
    continue
  }

  TARBALL_PATH=$(echo "${COLLECT_OUTPUT}" | tail -n 1)

  if [[ -z "${TARBALL_PATH}" ]]; then
    echo "FAILED: collect.sh on ${IP} produced no tarball path" | tee "${ERROR_FILE}"
    FAILURE=$((FAILURE + 1))
    continue
  fi

  LOCAL_TARBALL="${OUTPUT_DIR}/${IP}.tar.gz"
  if ! scp "${SSH_OPTS[@]}" \
      "${SSH_USER}@${IP}:${TARBALL_PATH}" \
      "${LOCAL_TARBALL}" 2>&1; then
    echo "FAILED to scp tarball from ${IP}:${TARBALL_PATH}" | tee "${ERROR_FILE}"
    FAILURE=$((FAILURE + 1))
    continue
  fi

  mkdir -p "${INSTANCE_DIR}"
  if ! tar -xzf "${LOCAL_TARBALL}" -C "${INSTANCE_DIR}" --strip-components=1 2>&1; then
    echo "FAILED to extract tarball for ${IP}" | tee "${ERROR_FILE}"
    FAILURE=$((FAILURE + 1))
    continue
  fi

  echo "  OK: logs extracted to ${INSTANCE_DIR}/"
  SUCCESS=$((SUCCESS + 1))
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((SUCCESS + FAILURE))
echo ""
echo "Log collection complete: ${SUCCESS} successes, ${FAILURE} failures (of ${TOTAL} instances)"

if [[ "${SUCCESS}" -eq 0 ]]; then
  echo "ERROR: all instances failed log collection" >&2
  exit 1
fi

exit 0
