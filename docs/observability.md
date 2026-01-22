# Observability Guide

This guide covers monitoring and observability for unix-oidc deployments.

## Agent Metrics

The unix-oidc-agent exposes metrics via IPC for monitoring health and performance.

### Querying Metrics

```bash
# JSON format (default)
echo '{"action":"metrics"}' | nc -U $XDG_RUNTIME_DIR/unix-oidc-agent.sock

# Prometheus format
echo '{"action":"metrics","format":"prometheus"}' | nc -U $XDG_RUNTIME_DIR/unix-oidc-agent.sock
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `uptime_seconds` | Gauge | Agent uptime in seconds |
| `proof_requests_total` | Counter | Total DPoP proof generation requests |
| `proof_requests_success` | Counter | Successful proof generations |
| `proof_requests_failed` | Counter | Failed proof generations |
| `proof_latency_p50_us` | Summary | 50th percentile proof latency (microseconds) |
| `proof_latency_p95_us` | Summary | 95th percentile proof latency |
| `proof_latency_p99_us` | Summary | 99th percentile proof latency |
| `token_refresh_total` | Counter | Total token refresh attempts |
| `token_refresh_success` | Counter | Successful token refreshes |
| `token_refresh_failed` | Counter | Failed token refreshes |
| `refresh_latency_p50_us` | Summary | 50th percentile refresh latency |
| `refresh_latency_p95_us` | Summary | 95th percentile refresh latency |
| `refresh_latency_p99_us` | Summary | 99th percentile refresh latency |
| `ipc_connections_total` | Counter | Total IPC connections handled |
| `ipc_requests_total` | Counter | Total IPC requests processed |
| `ipc_errors_total` | Counter | IPC request errors |
| `last_proof_time` | Timestamp | Unix timestamp of last successful proof |
| `last_refresh_time` | Timestamp | Unix timestamp of last token refresh |

### Example JSON Response

```json
{
  "status": "success",
  "uptime_seconds": 3600,
  "start_timestamp": 1705849200,
  "proof_requests_total": 150,
  "proof_requests_success": 148,
  "proof_requests_failed": 2,
  "proof_latency_p50_us": 250,
  "proof_latency_p95_us": 1200,
  "proof_latency_p99_us": 2500,
  "token_refresh_total": 12,
  "token_refresh_success": 12,
  "token_refresh_failed": 0,
  "refresh_latency_p50_us": 150000,
  "refresh_latency_p95_us": 350000,
  "refresh_latency_p99_us": 500000,
  "ipc_connections_total": 162,
  "ipc_requests_total": 175,
  "ipc_errors_total": 1,
  "last_proof_time": 1705852800,
  "last_refresh_time": 1705851600
}
```

### Prometheus Integration

For Prometheus scraping, you can create a simple exporter:

```bash
#!/bin/bash
# /usr/local/bin/unix-oidc-metrics
echo '{"action":"metrics","format":"prometheus"}' | \
  nc -U $XDG_RUNTIME_DIR/unix-oidc-agent.sock 2>/dev/null | \
  jq -r '.text // empty'
```

Then expose via node_exporter textfile collector or a simple HTTP wrapper.

## PAM Module Audit Events

The PAM module logs structured audit events to syslog (AUTH facility) and optionally to a dedicated file.

### Audit Log Location

- **Syslog**: AUTH facility (typically `/var/log/auth.log` or `/var/log/secure`)
- **Dedicated file**: `/var/log/unix-oidc-audit.log` (configurable via `UNIX_OIDC_AUDIT_LOG`)

### Event Types

| Event | Description |
|-------|-------------|
| `SSH_LOGIN_SUCCESS` | Successful SSH authentication |
| `SSH_LOGIN_FAILED` | Failed SSH authentication |
| `TOKEN_VALIDATION_FAILED` | Token validation error |
| `USER_NOT_FOUND` | SSSD user lookup failure |
| `STEP_UP_INITIATED` | Sudo step-up flow started |
| `STEP_UP_SUCCESS` | Sudo step-up completed |
| `STEP_UP_FAILED` | Sudo step-up failed |

### Example Audit Event

```json
{
  "timestamp": "2026-01-21T10:30:00Z",
  "event": "SSH_LOGIN_SUCCESS",
  "session_id": "abc123",
  "username": "alice",
  "uid": 1001,
  "source_ip": "192.168.1.100",
  "oidc_claims": {
    "jti": "token-id-123",
    "acr": "urn:mace:incommon:iap:silver",
    "auth_time": 1705852200
  }
}
```

## Alerting Recommendations

### Critical Alerts

| Condition | Threshold | Action |
|-----------|-----------|--------|
| Agent down | Process not running | Restart agent, investigate logs |
| High proof failure rate | >10% failures in 5 min | Check IdP connectivity, token validity |
| Token refresh failures | >3 consecutive failures | Investigate refresh token, IdP status |
| High latency | p99 > 5000ms | Check network, IdP performance |

### Warning Alerts

| Condition | Threshold | Action |
|-----------|-----------|--------|
| Elevated failure rate | >5% failures in 15 min | Monitor, prepare investigation |
| IPC errors | >10 errors/hour | Check socket permissions, client issues |
| Stale metrics | No proof in 1 hour | Verify agent is receiving requests |

### Example Prometheus Alert Rules

```yaml
groups:
  - name: unix-oidc
    rules:
      - alert: UnixOIDCAgentDown
        expr: up{job="unix-oidc-agent"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "unix-oidc-agent is down"

      - alert: UnixOIDCHighProofFailureRate
        expr: |
          rate(unix_oidc_agent_proof_requests_total{status="failed"}[5m]) /
          rate(unix_oidc_agent_proof_requests_total[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High proof failure rate (>10%)"

      - alert: UnixOIDCHighLatency
        expr: unix_oidc_agent_proof_latency_us{quantile="0.99"} > 5000000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High proof latency (p99 > 5s)"
```

## Log Analysis

### Useful Log Queries

```bash
# Recent authentication failures
journalctl -u sshd --since "1 hour ago" | grep "unix-oidc" | grep "FAILED"

# Count events by type
grep "unix-oidc" /var/log/auth.log | jq -r '.event' | sort | uniq -c

# Failed logins by source IP
grep "SSH_LOGIN_FAILED" /var/log/unix-oidc-audit.log | jq -r '.source_ip' | sort | uniq -c | sort -rn

# Token validation errors
grep "TOKEN_VALIDATION_FAILED" /var/log/unix-oidc-audit.log | jq -r '.reason' | sort | uniq -c
```

## Dashboards

### Key Panels for Grafana

1. **Agent Health**
   - Uptime gauge
   - Proof success rate (%)
   - Token refresh success rate (%)

2. **Performance**
   - Proof latency histogram (p50, p95, p99)
   - Refresh latency histogram
   - Requests per second

3. **Errors**
   - Proof failures over time
   - IPC errors over time
   - Authentication failures by reason

4. **Activity**
   - Active sessions
   - Logins per hour
   - Step-up authentications

## Troubleshooting with Metrics

### Agent Not Responding

```bash
# Check if agent is running
pgrep -f unix-oidc-agent

# Check socket exists
ls -la $XDG_RUNTIME_DIR/unix-oidc-agent.sock

# Test connectivity
echo '{"action":"status"}' | nc -U $XDG_RUNTIME_DIR/unix-oidc-agent.sock
```

### High Latency

```bash
# Get current latency metrics
echo '{"action":"metrics"}' | nc -U $XDG_RUNTIME_DIR/unix-oidc-agent.sock | \
  jq '{p50: .proof_latency_p50_us, p95: .proof_latency_p95_us, p99: .proof_latency_p99_us}'

# Check network to IdP
curl -w "@curl-format.txt" -o /dev/null -s https://your-idp.com/.well-known/openid-configuration
```

### Token Issues

```bash
# Check token status
echo '{"action":"status"}' | nc -U $XDG_RUNTIME_DIR/unix-oidc-agent.sock | jq .

# Check refresh metrics
echo '{"action":"metrics"}' | nc -U $XDG_RUNTIME_DIR/unix-oidc-agent.sock | \
  jq '{total: .token_refresh_total, success: .token_refresh_success, failed: .token_refresh_failed}'
```
