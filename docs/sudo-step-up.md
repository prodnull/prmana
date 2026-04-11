# Sudo Step-Up Authentication

This document describes how to configure and use sudo step-up authentication with prmana, including the Phase 44 risk-aware privilege policy model.

## Overview

Step-up authentication requires users to perform additional authentication (beyond their initial SSH login) when executing privileged commands via sudo. This provides defense-in-depth against session hijacking and credential theft.

The step-up flow can use the OAuth 2.0 Device Authorization Grant (RFC 8628) or IdP-native push/FIDO2 methods when configured. Phase 44 adds per-command policy actions (`allow`, `step_up`, `deny`), optional host-class matching, and time-bounded reuse of a recent successful challenge.

## How It Works

1. User executes a sudo command.
2. PAM module evaluates the command against the sudo privilege policy.
3. Policy returns one of three actions: `allow`, `step_up`, or `deny`.
4. If `step_up` is required and no grace-window record satisfies the policy, a fresh IdP challenge is initiated.
5. User completes the device-flow or push-based challenge.
6. PAM validates the resulting token and records the successful challenge for optional grace-window reuse.
7. If policy says `allow` or a valid grace record exists, the command proceeds without a fresh challenge.
8. If policy says `deny`, the command is rejected before execution.

```
┌─────────────────────────────────────────────────────────────┐
│  Terminal                                                    │
│  ═══════════════════════════════════════════════════════    │
│    Sudo requires step-up authentication                      │
│                                                              │
│    Visit: https://keycloak.example.com/realms/xyz/device     │
│    Enter code: ABCD-1234                                     │
│                                                              │
│    Waiting for authentication... (285s remaining)            │
│  ═══════════════════════════════════════════════════════    │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Policy File

Create `/etc/prmana/policy.yaml`:

```yaml
# Host classification affects default SSH and sudo policy decisions.
host:
  classification: elevated

# SSH login requirements
ssh_login:
  require_oidc: true
  minimum_acr: null  # Any ACR accepted for SSH
  max_auth_age: 3600  # Maximum age of authentication (seconds)

# Sudo privilege policy
sudo:
  # Backward-compatible fallback when no command rule matches.
  # New configs should prefer default_action.
  step_up_required: true
  default_action: step_up
  allowed_methods:
    - push
    - device_flow
  challenge_timeout: 300
  poll_interval_secs: 5
  grace_period_secs: 300
  dry_run: false

  # Optional: first-match command rules
  commands:
    - name: service-restart
      pattern: "/usr/bin/systemctl restart *"
      action: step_up
      required_acr: phr
      grace_period_secs: 60
      host_classification: elevated

    - name: read-only-observability
      pattern: "/usr/bin/journalctl *"
      action: allow

    - name: destructive-account-change
      pattern: "/usr/bin/userdel *"
      action: deny
```

### Policy Semantics

- Rules are evaluated top-to-bottom.
- The first matching rule wins.
- If no rule matches, `sudo.default_action` applies.
- `dry_run: true` logs the Phase 44 decision but falls back to the legacy boolean `step_up_required` behavior.
- `grace_period_secs` allows a recent successful step-up to satisfy a later matching `step_up` decision without re-challenging.
- `host_classification` on a rule scopes that rule to `standard`, `elevated`, or `critical` hosts only.

### Environment Variables

Set these in the PAM environment or system-wide:

| Variable | Required | Description |
|----------|----------|-------------|
| `OIDC_ISSUER` | Yes | OIDC issuer URL (e.g., `https://keycloak.example.com/realms/myrealm`) |
| `OIDC_CLIENT_ID` | No | Client ID (default: `prmana`) |
| `OIDC_CLIENT_SECRET` | No | Client secret if required by IdP |
| `PRMANA_POLICY_FILE` | No | Path to policy file (default: `/etc/prmana/policy.yaml`) |

### PAM Configuration

Add prmana to `/etc/pam.d/sudo`:

```
# Unix-oidc step-up authentication
auth    required    pam_prmana.so

# Fallback to standard Unix auth (for break-glass)
auth    required    pam_unix.so try_first_pass

# Standard account/session handling
account required    pam_unix.so
session required    pam_unix.so
```

### Keycloak Configuration

Enable Device Authorization Grant for your client:

1. Go to Clients > your-client > Settings
2. Under "Capability config", enable "OAuth 2.0 Device Authorization Grant"
3. Under "Advanced", set:
   - Device Authorization Grant Max Lifespan: 300 seconds
   - Device Authorization Grant Polling Interval: 5 seconds

## Host Classifications

| Classification | Description | Default Behavior |
|---------------|-------------|------------------|
| `standard` | Regular workstations | Usually `allow` for low-risk commands; step-up only where explicitly configured |
| `elevated` | Development/staging servers | Common place to start command-specific step-up rules |
| `critical` | Production/sensitive systems | Often paired with stricter rules, shorter grace windows, and `phr` requirements |

## ACR Levels

The `required_acr` setting specifies the minimum Authentication Context Class Reference required:

| ACR | Description |
|-----|-------------|
| `urn:keycloak:acr:0` | No authentication (anonymous) |
| `urn:keycloak:acr:1` | Single-factor authentication |
| `urn:keycloak:acr:loa2` | Two-factor authentication (MFA) |
| `phr` | Phishing-resistant (FIDO2/WebAuthn) |

## Audit Logging

Policy decisions and step-up events are logged for security monitoring:

```json
{"event":"PRIVILEGE_POLICY_DECISION","timestamp":"2026-04-10T10:30:00Z","user":"alice","command":"/usr/bin/systemctl restart nginx","host":"server1","policy_action":"step_up","matched_rule":"service-restart","host_classification":"critical","grace_period_secs":300,"grace_period_applied":false,"dry_run":false}
{"event":"STEP_UP_INITIATED","timestamp":"2024-01-17T10:30:00Z","user":"alice","command":"/usr/bin/systemctl restart nginx","host":"server1","method":"device_flow"}
{"event":"STEP_UP_SUCCESS","timestamp":"2024-01-17T10:30:45Z","user":"alice","command":"/usr/bin/systemctl restart nginx","host":"server1","method":"device_flow","session_id":"sudo-abc123","oidc_acr":"urn:keycloak:acr:loa2","matched_rule":"service-restart","policy_action":"step_up","host_classification":"critical","grace_period_secs":300,"grace_period_applied":false,"dry_run":false}
```

Events are written to:
- stderr (typically captured by syslog)
- `$PRMANA_AUDIT_LOG` file if configured

## Troubleshooting

### "OIDC_ISSUER not set"

Ensure the OIDC_ISSUER environment variable is set. For systemd services, add it to the service file or environment file.

### "No supported step-up method available"

The policy requires a step-up method not available. Ensure at least one of `push` (CIBA) or `device_flow` is in the `allowed_methods` list. If using CIBA push, the IdP must support the backchannel authentication endpoint.

### "Timeout waiting for authentication"

User did not complete authentication within the timeout period. Check `challenge_timeout` and per-method overrides in `method_timeouts` (push defaults to 60s, device_flow to 120s). Also verify network connectivity to the IdP and that the user's device received the push notification.

### "Access denied by user"

User explicitly denied the authentication request in the IdP interface.

### "User mismatch"

The user who authenticated in the IdP does not match the user running sudo. Ensure the correct account is used.

### "Privilege policy denied command"

The matching sudo rule returned `action: deny`. Check the `PRIVILEGE_POLICY_DECISION` audit event to see:

- `matched_rule`
- `policy_action`
- `host_classification`
- `dry_run`

### "Why didn't sudo re-challenge?"

Check for:

- a matching `action: allow` rule
- a recent successful step-up that satisfied `grace_period_secs`
- `dry_run: true`, which logs the Phase 44 decision but preserves legacy behavior

## Security Considerations

1. **Token Binding**: Tokens are validated to ensure the authenticated user matches the sudo user
2. **Freshness**: `grace_period_secs` defaults to `0`, so fresh step-up is still the default unless operators explicitly allow short reuse windows.
3. **ACR Enforcement**: Rule-level `required_acr` values are validated against the step-up token.
4. **Deny Before Execution**: `action: deny` blocks high-risk commands before sudo runs them.
5. **Audit Trail**: Both policy decisions and step-up outcomes are logged with rule metadata and grace-window context.
6. **Dry-Run Safety**: `dry_run` lets operators observe new rules before enforcement, reducing rollout risk.
