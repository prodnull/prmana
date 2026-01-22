# User Guide

This guide explains how to use unix-oidc for SSH login and sudo step-up authentication.

## Overview

unix-oidc provides OIDC-based authentication for Linux systems:

1. **SSH Login** - Authenticate to SSH using your organization's identity provider
2. **Sudo Step-Up** - Additional verification when running privileged commands

## SSH Login with OIDC

### Standard Login Flow

When you SSH to a unix-oidc enabled server, you'll be prompted for an OIDC token instead of a password:

```
$ ssh server.example.com
OIDC Token: <paste your token here>
```

### Getting an OIDC Token

Your organization will provide a method to obtain tokens. Common approaches:

#### Web Portal

1. Visit your organization's authentication portal
2. Log in with your credentials (and MFA if required)
3. Copy the displayed token
4. Paste into SSH prompt

#### CLI Tool

```bash
# Example using a CLI authentication tool
my-org-auth login
# Token is copied to clipboard or displayed

ssh server.example.com
# Paste token when prompted
```

#### Device Flow (Headless)

For servers without browser access:

```bash
ssh server.example.com
# If device flow is configured, you'll see:
#
# ═══════════════════════════════════════════════════════════
#   Authentication Required
#
#   Visit: https://idp.example.com/device
#   Enter code: ABCD-1234
#
#   Waiting for authentication...
# ═══════════════════════════════════════════════════════════

# On your phone or another computer:
# 1. Visit the URL
# 2. Enter the code
# 3. Log in with your credentials
# 4. SSH connection completes automatically
```

## Sudo Step-Up Authentication

When running privileged commands, you may be asked to re-authenticate:

```bash
$ sudo systemctl restart nginx

═══════════════════════════════════════════════════════════
  Sudo requires step-up authentication

  Visit: https://idp.example.com/device
  Enter code: WXYZ-5678

  Waiting for authentication... (285s remaining)
═══════════════════════════════════════════════════════════
```

### Completing Step-Up

1. **On your phone or computer**, open the verification URL
2. **Enter the code** shown on your terminal
3. **Authenticate** with your credentials (MFA may be required)
4. **Return to terminal** - the command will proceed automatically

### Why Step-Up?

Step-up authentication provides defense-in-depth:

- Verifies you're still at your computer (not a hijacked session)
- Requires fresh authentication for sensitive operations
- Creates an audit trail linking commands to authentication events

### Commands That Require Step-Up

Your organization configures which commands require step-up. Common examples:

| Command | Reason |
|---------|--------|
| `sudo apt install/remove` | Package management |
| `sudo systemctl restart` | Service management |
| `sudo useradd/userdel` | User management |
| `sudo shutdown/reboot` | System power |

Read-only commands typically don't require step-up:

```bash
# These usually work without step-up
sudo cat /var/log/syslog
sudo ls /root
sudo grep error /var/log/auth.log
```

## Troubleshooting

### "OIDC Token:" prompt appears but nothing happens

- Ensure you're pasting a valid JWT token
- Check that the token hasn't expired
- Verify you're using the correct identity provider

### "User not found" error

Your OIDC username must match your system username:

```
unix-oidc: User 'alice@example.com' not found in directory
```

Contact your administrator - they may need to:
- Map your OIDC username to your system username
- Ensure your account exists in SSSD/LDAP

### Step-up times out

The default timeout is 5 minutes. If you can't complete authentication in time:

1. Run the command again to get a new code
2. Have your phone ready before running sudo
3. Contact your administrator if timeouts are too short

### "Access denied" during step-up

This means you explicitly denied the authentication request or an error occurred:

- Try again with a new code
- Ensure you're approving the correct request
- Check that you're using the correct account

### Step-up not working / no prompt appears

If sudo works without step-up when it should require it:

1. Check the policy configuration with your administrator
2. The command may be in an "allowed without step-up" list
3. The host may be classified as "standard" (no step-up)

## Security Best Practices

### Protect Your Tokens

- Never share tokens with others
- Don't save tokens in shell history
- Tokens expire - get a fresh one if needed

### Verify Step-Up Requests

Before completing step-up:

1. Verify you initiated the request
2. Check the code matches what's on your terminal
3. Don't approve unexpected requests

### Report Suspicious Activity

Contact your security team if you see:

- Step-up prompts you didn't initiate
- Unexpected authentication requests
- Login attempts you don't recognize

## Observability & Metrics

unix-oidc provides built-in metrics for monitoring authentication health and performance.

### Querying Metrics

The agent exposes metrics via IPC. Query current status:

```bash
# Get metrics in JSON format
echo '{"type":"metrics","format":"json"}' | sudo nc -U /var/run/unix-oidc/agent.sock | jq

# Get metrics in Prometheus format
echo '{"type":"metrics","format":"prometheus"}' | sudo nc -U /var/run/unix-oidc/agent.sock
```

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `proof_requests_total` | Counter | Total DPoP proof requests |
| `proof_requests_success` | Counter | Successful proof generations |
| `proof_requests_failed` | Counter | Failed proof generations |
| `proof_latency_p50_us` | Gauge | 50th percentile proof latency (μs) |
| `proof_latency_p95_us` | Gauge | 95th percentile proof latency (μs) |
| `token_refresh_total` | Counter | Token refresh attempts |
| `ipc_connections_total` | Counter | Total IPC connections |
| `ipc_errors_total` | Counter | IPC errors |
| `uptime_seconds` | Gauge | Agent uptime |

### Prometheus Integration

Add a scrape job for the unix-oidc metrics exporter:

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'unix-oidc'
    static_configs:
      - targets: ['localhost:9898']  # If using metrics exporter
    scrape_interval: 15s
```

Or use node_exporter textfile collector:

```bash
# Write metrics to textfile
echo '{"type":"metrics","format":"prometheus"}' | \
  nc -U /var/run/unix-oidc/agent.sock > /var/lib/prometheus/node-exporter/unix_oidc.prom
```

### Recommended Alerts

```yaml
# Example Prometheus alerting rules
groups:
  - name: unix-oidc
    rules:
      - alert: UnixOidcHighFailureRate
        expr: rate(unix_oidc_agent_proof_requests_total{status="failed"}[5m]) / rate(unix_oidc_agent_proof_requests_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High DPoP proof failure rate"

      - alert: UnixOidcAgentDown
        expr: up{job="unix-oidc"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "unix-oidc agent is not responding"
```

For detailed observability documentation, see [docs/observability.md](observability.md).

## Mobile Authenticator Apps

Many organizations use mobile apps for step-up:

### Supported Apps

- Microsoft Authenticator
- Okta Verify
- Google Authenticator
- Duo Mobile
- Custom enterprise apps

### Setup

Your organization will provide instructions to:

1. Install the authenticator app
2. Link it to your account
3. Enable push notifications

### Using Push Notifications

With push notifications configured:

```bash
$ sudo systemctl restart nginx

═══════════════════════════════════════════════════════════
  Approval request sent to your device

  Waiting for approval... (285s remaining)
═══════════════════════════════════════════════════════════

# Your phone shows a push notification
# Tap "Approve" to continue
# Command proceeds automatically
```

## FAQ

### Do I need to re-authenticate for every sudo command?

It depends on your organization's policy:
- Some commands don't require step-up (read-only)
- Some servers don't require step-up (standard classification)
- Successful step-up may allow a grace period

### Can I use a hardware security key?

FIDO2/WebAuthn support is planned. Currently, device flow works with any browser-accessible device.

### What happens if the identity provider is down?

Your organization may have break-glass procedures:
- Backup authentication methods
- Emergency access accounts
- Contact your administrator

### Is my password ever sent to the server?

No. unix-oidc uses token-based authentication:
- You authenticate to your identity provider
- The server receives only a signed token
- Your password stays with the identity provider

### Can I see my authentication history?

Your organization may provide an audit portal. Authentication events are logged including:
- Login times
- Commands requiring step-up
- Success/failure status
