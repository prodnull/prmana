# Sudo Step-Up Authentication

This document describes how to configure and use step-up authentication for sudo commands with unix-oidc.

## Overview

Step-up authentication requires users to perform additional authentication (beyond their initial SSH login) when executing privileged commands via sudo. This provides defense-in-depth against session hijacking and credential theft.

The step-up flow uses the OAuth 2.0 Device Authorization Grant (RFC 8628), which allows authentication to complete on a separate device such as a mobile phone.

## How It Works

1. User executes a sudo command
2. PAM module checks policy configuration
3. If step-up is required, device flow is initiated
4. User sees a verification URL and code on their terminal
5. User visits the URL and enters the code on their phone/browser
6. User authenticates (optionally with MFA) in the IdP
7. PAM module polls for completion and validates the resulting token
8. If successful, sudo command proceeds

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

Create `/etc/unix-oidc/policy.yaml`:

```yaml
# Host classification affects default requirements
# Options: standard, elevated, critical
host_classification: elevated

# SSH login requirements
ssh:
  require_oidc: true
  minimum_acr: null  # Any ACR accepted for SSH
  max_auth_age: 3600  # Maximum age of authentication (seconds)

# Sudo step-up requirements
sudo:
  step_up_required: true
  allowed_methods:
    - device_flow  # OAuth 2.0 Device Flow
    - webhook      # Custom webhook approval (see examples/webhook-server/)
    # - push       # Future: Push notification
    # - fido2      # Future: FIDO2/WebAuthn
  timeout_seconds: 300  # 5 minutes to complete step-up
  required_acr: urn:keycloak:acr:loa2  # Require MFA for step-up

  # Optional: Command-specific rules
  commands:
    # Package management always requires step-up
    - pattern: "/usr/bin/apt*"
      step_up_required: true
    - pattern: "/usr/bin/yum*"
      step_up_required: true
    # System administration
    - pattern: "/usr/sbin/shutdown*"
      step_up_required: true
    - pattern: "/usr/bin/systemctl*"
      step_up_required: true
    # Allow read-only commands without step-up
    - pattern: "/usr/bin/cat *"
      step_up_required: false
    - pattern: "/bin/ls *"
      step_up_required: false
```

### Environment Variables

Set these in the PAM environment or system-wide:

| Variable | Required | Description |
|----------|----------|-------------|
| `OIDC_ISSUER` | Yes | OIDC issuer URL (e.g., `https://keycloak.example.com/realms/myrealm`) |
| `OIDC_CLIENT_ID` | No | Client ID (default: `unix-oidc`) |
| `OIDC_CLIENT_SECRET` | No | Client secret if required by IdP |
| `UNIX_OIDC_POLICY_PATH` | No | Path to policy file (default: `/etc/unix-oidc/policy.yaml`) |

### PAM Configuration

Add unix-oidc to `/etc/pam.d/sudo`:

```
# Unix-oidc step-up authentication
auth    required    pam_unix_oidc.so

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
| `standard` | Regular workstations | No step-up required |
| `elevated` | Development/staging servers | Step-up for system changes |
| `critical` | Production/sensitive systems | Step-up for all sudo |

## ACR Levels

The `required_acr` setting specifies the minimum Authentication Context Class Reference required:

| ACR | Description |
|-----|-------------|
| `urn:keycloak:acr:0` | No authentication (anonymous) |
| `urn:keycloak:acr:1` | Single-factor authentication |
| `urn:keycloak:acr:loa2` | Two-factor authentication (MFA) |
| `phr` | Phishing-resistant (FIDO2/WebAuthn) |

## Audit Logging

Step-up events are logged for security monitoring:

```json
{"event":"STEP_UP_INITIATED","timestamp":"2024-01-17T10:30:00Z","user":"alice","command":"/usr/bin/systemctl restart nginx","host":"server1","method":"device_flow"}
{"event":"STEP_UP_SUCCESS","timestamp":"2024-01-17T10:30:45Z","user":"alice","command":"/usr/bin/systemctl restart nginx","host":"server1","method":"device_flow","session_id":"sudo-abc123","oidc_acr":"urn:keycloak:acr:loa2"}
```

Events are written to:
- stderr (typically captured by syslog)
- `$UNIX_OIDC_AUDIT_LOG` file if configured

## Troubleshooting

### "OIDC_ISSUER not set"

Ensure the OIDC_ISSUER environment variable is set. For systemd services, add it to the service file or environment file.

### "No supported step-up method available"

The policy requires a step-up method not available. Ensure `device_flow` is in the `allowed_methods` list.

### "Timeout waiting for authentication"

User did not complete authentication within the timeout period. Increase `timeout_seconds` in the policy or ensure network connectivity to the IdP.

### "Access denied by user"

User explicitly denied the authentication request in the IdP interface.

### "User mismatch"

The user who authenticated in the IdP does not match the user running sudo. Ensure the correct account is used.

## Security Considerations

1. **Token Binding**: Tokens are validated to ensure the authenticated user matches the sudo user
2. **Freshness**: Step-up authentication always requires fresh authentication (no max_auth_age)
3. **ACR Enforcement**: Required ACR levels are validated against the token
4. **Audit Trail**: All step-up events are logged with timestamps and session IDs
5. **Timeout**: Requests automatically expire to prevent hanging sessions
