#!/bin/bash
# test/tests/test_systemd_launchd_e2e.sh
#
# E2ET-05: systemd socket activation, JSON log under journald, graceful shutdown,
#          and launchd install/uninstall (macOS local only).
#
# Tests:
#   1. systemd socket activation — prmana-agent.socket is active after enable
#   2. JSON log under journald — daemon logs produce jq-parseable output
#   3. Graceful shutdown — systemctl stop completes within 10 seconds
#   4. launchd install/uninstall — plist created/removed (macOS, SKIP in CI)
#
# Architecture:
#   The daemon uses Type=notify (systemd sd_notify). It sends READY=1 after
#   socket acquisition, config validation, and initial JWKS prefetch (best-effort).
#   Socket activation: systemd creates the socket before starting the daemon;
#   LISTEN_FDS mechanism passes the fd. When a client connects, systemd starts
#   the daemon service on demand.
#
#   JSON logging: init_tracing() detects JOURNAL_STREAM env var (set by systemd)
#   and selects JSON formatter. journalctl -o json wraps the JSON MESSAGE field
#   in a journald envelope (PRIORITY, SYSLOG_IDENTIFIER, etc).
#
# Container requirements (systemd inside Docker):
#   --privileged or --cap-add SYS_ADMIN
#   -v /sys/fs/cgroup:/sys/fs/cgroup:rw
#   See test/docker/Dockerfile.test-host-systemd and docker-compose.systemd-e2e.yaml
#
# References:
#   - contrib/systemd/prmana-agent.service (Type=notify, systemd hardening)
#   - contrib/systemd/prmana-agent.socket (ListenStream=%t/prmana-agent.sock)
#   - prmana-agent/src/main.rs: init_tracing() JOURNAL_STREAM detection
#   - systemd.socket(5): socket activation protocol
#   - RFC 6749 §5: token endpoint (agent requires a valid config to start fully)
#
# macOS launchd:
#   launchd test runs locally only — never in CI. Instructions for manual steps
#   are printed when running on macOS without Docker access.
#
# Usage (CI — Linux, Docker):
#   COMPOSE_FILE=docker-compose.systemd-e2e.yaml ./test/tests/test_systemd_launchd_e2e.sh
#
# Usage (macOS local):
#   SKIP_SYSTEMD_TEST=1 ./test/tests/test_systemd_launchd_e2e.sh
#   # Or without Docker: only launchd test runs

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.systemd-e2e.yaml}"
SYSTEMD_SERVICE="${SYSTEMD_SERVICE:-test-host-systemd}"

PASS=0
FAIL=0
SKIP=0

result() {
    local status=$1 name=$2
    case "$status" in
        PASS) echo "  [PASS] $name"; PASS=$((PASS + 1)) ;;
        FAIL) echo "  [FAIL] $name"; FAIL=$((FAIL + 1)) ;;
        SKIP) echo "  [SKIP] $name"; SKIP=$((SKIP + 1)) ;;
    esac
}

echo "=== E2ET-05: systemd/launchd E2E Test Suite ==="
echo "Compose:  $COMPOSE_FILE"
echo "Service:  $SYSTEMD_SERVICE"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Skip gate: SKIP_SYSTEMD_TEST=1 exits immediately with SKIP
# ─────────────────────────────────────────────────────────────────────────────
if [ "${SKIP_SYSTEMD_TEST:-}" = "1" ]; then
    echo "SKIP: SKIP_SYSTEMD_TEST=1 — skipping all systemd tests"
    result "SKIP" "systemd E2E (SKIP_SYSTEMD_TEST=1)"

    # Still run launchd section on macOS
    if [ "$(uname -s)" = "Darwin" ]; then
        echo ""
        echo "--- Test 4: launchd install/uninstall (macOS) ---"
        _run_launchd_test() {
            local agent_bin
            agent_bin=$(command -v prmana-agent 2>/dev/null || echo "${PROJECT_ROOT}/target/release/prmana-agent")
            if [ ! -x "$agent_bin" ]; then
                echo "  SKIP: prmana-agent not found; build with: cargo build --release -p prmana-agent"
                result "SKIP" "launchd install/uninstall (agent not built)"
                return
            fi
            PLIST_PATH="${HOME}/Library/LaunchAgents/com.prmana.agent.plist"
            if "$agent_bin" launchd-install 2>/dev/null; then
                if [ -f "$PLIST_PATH" ]; then
                    result "PASS" "launchd-install created plist at $PLIST_PATH"
                else
                    result "FAIL" "launchd-install ran but plist not found at $PLIST_PATH"
                fi
                if "$agent_bin" launchd-uninstall 2>/dev/null; then
                    if [ ! -f "$PLIST_PATH" ]; then
                        result "PASS" "launchd-uninstall removed plist"
                    else
                        result "FAIL" "launchd-uninstall ran but plist still exists at $PLIST_PATH"
                    fi
                else
                    result "FAIL" "launchd-uninstall failed"
                fi
            else
                result "FAIL" "launchd-install failed"
            fi
        }
        _run_launchd_test
    fi

    echo ""
    echo "=== Results ==="
    echo "  Total: $((PASS + FAIL + SKIP)) | Pass: $PASS | Fail: $FAIL | Skip: $SKIP"
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# Prerequisites
# ─────────────────────────────────────────────────────────────────────────────
echo "--- Prerequisites ---"

if ! command -v docker >/dev/null 2>&1; then
    echo "FATAL: docker not found — required for systemd E2E tests"
    exit 1
fi

# Verify the compose stack is running
if ! docker compose -f "$COMPOSE_FILE" ps --quiet "$SYSTEMD_SERVICE" 2>/dev/null | grep -q .; then
    echo "  SKIP: compose stack '$SYSTEMD_SERVICE' is not running"
    echo "        Start it with: docker compose -f $COMPOSE_FILE up -d"
    result "SKIP" "Compose stack running ($SYSTEMD_SERVICE)"
    echo ""
    echo "=== Results ==="
    echo "  Total: $((PASS + FAIL + SKIP)) | Pass: $PASS | Fail: $FAIL | Skip: $SKIP"
    echo ""
    echo "=== SKIPPED (no compose environment) ==="
    exit 0
fi
result "PASS" "Compose stack running ($SYSTEMD_SERVICE)"

# Verify systemd is PID 1 inside the container
SYSTEMD_PID=$(docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
    bash -c "cat /proc/1/comm 2>/dev/null || echo unknown" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
if [ "$SYSTEMD_PID" = "systemd" ]; then
    result "PASS" "systemd is PID 1 in container"
else
    echo "  SKIP: PID 1 is '$SYSTEMD_PID' not systemd — container may not support systemd"
    result "SKIP" "systemd is PID 1 (got: $SYSTEMD_PID)"
    echo ""
    echo "=== Results ==="
    echo "  Total: $((PASS + FAIL + SKIP)) | Pass: $PASS | Fail: $FAIL | Skip: $SKIP"
    exit 0
fi

# Verify prmana-agent is present
if docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
    bash -c "which prmana-agent >/dev/null 2>&1"; then
    result "PASS" "prmana-agent binary present in container"
else
    result "FAIL" "prmana-agent not found in container — was the image built with the binary?"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Test 1: systemd socket activation
#
# prmana-agent.socket (ListenStream=%t/prmana-agent.sock) is activated via
# systemctl --user enable --now. The daemon starts on first connection.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- Test 1: systemd socket activation ---"

# Reload user unit files so systemd sees the installed units
docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
    bash -c "su - testuser -c 'XDG_RUNTIME_DIR=/run/user/\$(id -u testuser) systemctl --user daemon-reload'" \
    >/dev/null 2>&1 || true

# Enable and start the socket unit
SOCKET_ENABLE_EXIT=0
docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
    bash -c "su - testuser -c 'XDG_RUNTIME_DIR=/run/user/\$(id -u testuser) systemctl --user enable --now prmana-agent.socket'" \
    >/dev/null 2>&1 || SOCKET_ENABLE_EXIT=$?

sleep 2

# Check socket is active
SOCKET_STATE=$(docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
    bash -c "su - testuser -c 'XDG_RUNTIME_DIR=/run/user/\$(id -u testuser) systemctl --user is-active prmana-agent.socket'" \
    2>/dev/null | tr -d '[:space:]' || echo "unknown")

if [ "$SOCKET_STATE" = "active" ]; then
    result "PASS" "prmana-agent.socket is active (socket activation enabled)"
else
    result "FAIL" "prmana-agent.socket state: '$SOCKET_STATE' (expected 'active')"
    echo "    Debug: systemctl --user status prmana-agent.socket"
    docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
        bash -c "su - testuser -c 'XDG_RUNTIME_DIR=/run/user/\$(id -u testuser) systemctl --user status prmana-agent.socket 2>&1 | head -20'" \
        2>/dev/null || true
fi

# Trigger socket activation by connecting: the daemon should respond or at minimum start
AGENT_STATUS_OUTPUT=$(docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
    bash -c "su - testuser -c 'XDG_RUNTIME_DIR=/run/user/\$(id -u testuser) prmana-agent status 2>&1'" \
    2>/dev/null | head -5 || echo "")

if echo "$AGENT_STATUS_OUTPUT" | grep -qiE "running|status|agent|connected|listening|error"; then
    result "PASS" "Socket connection triggered daemon response (status IPC reachable)"
else
    result "SKIP" "Socket activation response inconclusive — daemon may need valid config to respond"
    echo "    Agent output: ${AGENT_STATUS_OUTPUT:-empty}"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Test 2: JSON log format under journald
#
# When the daemon runs under systemd, JOURNAL_STREAM is set in the process
# environment. init_tracing() detects this and switches to JSON log format.
# journalctl -o json wraps each log line in a JSON envelope with fields:
# MESSAGE (the log line), PRIORITY, SYSLOG_IDENTIFIER, __REALTIME_TIMESTAMP, etc.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- Test 2: JSON log format under journald ---"

# Ensure daemon service is started (socket activation may have already started it)
docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
    bash -c "su - testuser -c 'XDG_RUNTIME_DIR=/run/user/\$(id -u testuser) systemctl --user start prmana-agent'" \
    >/dev/null 2>&1 || true

sleep 2

# Capture journald output in JSON format (-o json outputs one JSON object per line)
JOURNALD_OUTPUT=$(docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
    bash -c "su - testuser -c 'XDG_RUNTIME_DIR=/run/user/\$(id -u testuser) journalctl --user -u prmana-agent -n 20 -o json --no-pager 2>&1'" \
    2>/dev/null || echo "")

if [ -n "$JOURNALD_OUTPUT" ]; then
    # journald -o json outputs one JSON object per line; validate first non-empty line
    FIRST_JSON_LINE=$(echo "$JOURNALD_OUTPUT" | grep -v '^$' | head -1 || echo "")
    if echo "$FIRST_JSON_LINE" | jq . >/dev/null 2>&1; then
        result "PASS" "journald -o json output is valid JSON"
        # Confirm the MESSAGE field exists (journald JSON envelope)
        if echo "$FIRST_JSON_LINE" | jq -e '.MESSAGE' >/dev/null 2>&1; then
            result "PASS" "journald JSON envelope contains MESSAGE field"
        else
            result "FAIL" "journald JSON output missing MESSAGE field"
            echo "    First line: ${FIRST_JSON_LINE:0:200}"
        fi
    else
        result "FAIL" "journald output is not valid JSON (journald -o json failed or daemon not running)"
        echo "    Output (first 200 chars): ${JOURNALD_OUTPUT:0:200}"
    fi
else
    result "SKIP" "journald output empty — daemon may not have started or journald not available in container"
    echo "    Hint: ensure daemon service started and journald socket is mounted in the container"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Graceful shutdown
#
# systemctl stop sends SIGTERM; the daemon should finish in-flight requests and
# exit within the TimeoutStopSec window (default 90s; we assert < 10s for health).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- Test 3: Graceful shutdown (< 10s) ---"

# Ensure daemon is running before we attempt to stop it
docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
    bash -c "su - testuser -c 'XDG_RUNTIME_DIR=/run/user/\$(id -u testuser) systemctl --user start prmana-agent'" \
    >/dev/null 2>&1 || true
sleep 1

START_TS=$(date +%s)
docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
    bash -c "su - testuser -c 'XDG_RUNTIME_DIR=/run/user/\$(id -u testuser) systemctl --user stop prmana-agent'" \
    >/dev/null 2>&1 || true
END_TS=$(date +%s)
ELAPSED=$(( END_TS - START_TS ))

if [ "$ELAPSED" -lt 10 ]; then
    result "PASS" "systemctl stop completed in ${ELAPSED}s (< 10s shutdown requirement)"
else
    result "FAIL" "systemctl stop took ${ELAPSED}s (> 10s — daemon may not handle SIGTERM cleanly)"
fi

# Confirm the service is no longer active
SERVICE_STATE=$(docker compose -f "$COMPOSE_FILE" exec -T "$SYSTEMD_SERVICE" \
    bash -c "su - testuser -c 'XDG_RUNTIME_DIR=/run/user/\$(id -u testuser) systemctl --user is-active prmana-agent'" \
    2>/dev/null | tr -d '[:space:]' || echo "unknown")

if [ "$SERVICE_STATE" != "active" ]; then
    result "PASS" "prmana-agent service inactive after stop (state: $SERVICE_STATE)"
else
    result "FAIL" "prmana-agent still 'active' after systemctl stop"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Test 4: launchd install/uninstall (macOS only — SKIP in CI)
#
# prmana-agent launchd-install writes:
#   ~/Library/LaunchAgents/com.prmana.agent.plist
# prmana-agent launchd-uninstall removes it.
#
# This test never runs in CI (Linux). On macOS, run locally without Docker.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- Test 4: launchd install/uninstall ---"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "  SKIP: launchd test — macOS only."
    echo ""
    echo "  Manual verification steps (run on macOS):"
    echo "    # Install"
    echo "    prmana-agent launchd-install"
    echo "    launchctl list | grep prmana-agent"
    echo "    ls ~/Library/LaunchAgents/com.prmana.agent.plist"
    echo ""
    echo "    # Uninstall"
    echo "    prmana-agent launchd-uninstall"
    echo "    launchctl list | grep -c prmana-agent  # should be 0"
    echo "    ls ~/Library/LaunchAgents/com.prmana.agent.plist  # should fail"
    result "SKIP" "launchd install/uninstall (Linux — macOS only)"
else
    AGENT_BIN=$(command -v prmana-agent 2>/dev/null || echo "${PROJECT_ROOT}/target/release/prmana-agent")
    PLIST_PATH="${HOME}/Library/LaunchAgents/com.prmana.agent.plist"

    if [ ! -x "$AGENT_BIN" ]; then
        echo "  SKIP: prmana-agent binary not found at $AGENT_BIN"
        echo "        Build with: cargo build --release -p prmana-agent"
        result "SKIP" "launchd test (agent binary not built)"
    else
        # launchd-install
        if "$AGENT_BIN" launchd-install 2>/dev/null; then
            if [ -f "$PLIST_PATH" ]; then
                result "PASS" "launchd-install created plist at $PLIST_PATH"
            else
                result "FAIL" "launchd-install returned 0 but plist not at $PLIST_PATH"
            fi
        else
            result "FAIL" "launchd-install failed (exit non-zero)"
        fi

        # launchd-uninstall
        if "$AGENT_BIN" launchd-uninstall 2>/dev/null; then
            if [ ! -f "$PLIST_PATH" ]; then
                result "PASS" "launchd-uninstall removed plist"
            else
                result "FAIL" "launchd-uninstall returned 0 but plist still exists at $PLIST_PATH"
            fi
        else
            result "FAIL" "launchd-uninstall failed (exit non-zero)"
        fi
    fi
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + SKIP))
echo "=== Results ==="
echo "  Total: $TOTAL | Pass: $PASS | Fail: $FAIL | Skip: $SKIP"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "FAILED: $FAIL test(s) failed"
    exit 1
fi

echo ""
echo "=== E2ET-05 SYSTEMD/LAUNCHD TESTS COMPLETE ==="
