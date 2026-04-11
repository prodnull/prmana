# Installation Guide

This guide covers installing and configuring prmana for production use.

## Prerequisites

### System Requirements

- Linux with PAM support (Ubuntu 20.04+, RHEL 8+, Debian 11+)
- SSSD configured and connected to your user directory (LDAP, Active Directory, etc.)
- Rust toolchain for building (or pre-built binaries)

### Identity Provider Requirements

- OIDC-compliant Identity Provider (Keycloak, Azure AD, Okta, Auth0, etc.)
- Device Authorization Grant (RFC 8628) enabled for step-up authentication
- Client configured with appropriate scopes and claims

## Building from Source

### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Clone and Build

```bash
git clone https://github.com/your-org/prmana.git
cd prmana

# Build release binary
cargo build --release

# The PAM module will be at:
# target/release/libpam_prmana.so
```

## Installation

### 1. Install the PAM Module

```bash
# Copy the PAM module to the system PAM directory
sudo cp target/release/libpam_prmana.so /lib/security/pam_prmana.so

# Set permissions
sudo chmod 644 /lib/security/pam_prmana.so
sudo chown root:root /lib/security/pam_prmana.so
```

### 2. Create Configuration Directory

```bash
sudo mkdir -p /etc/prmana
sudo chmod 755 /etc/prmana
```

### 3. Configure Environment Variables

Create `/etc/prmana/env`:

```bash
# Required: OIDC Issuer URL
OIDC_ISSUER=https://your-idp.example.com/realms/your-realm

# Optional: Client ID (default: prmana)
OIDC_CLIENT_ID=prmana

# Optional: Client secret (if required by IdP)
OIDC_CLIENT_SECRET=your-client-secret

# Optional: Required ACR level for SSH login
# OIDC_REQUIRED_ACR=urn:your-idp:acr:mfa

# Optional: Maximum auth age in seconds
# OIDC_MAX_AUTH_AGE=3600

# Optional: Audit log file path
# PRMANA_AUDIT_LOG=/var/log/prmana/audit.log

# Optional: Webhook approval provider (for custom approval workflows)
# PRMANA_WEBHOOK_URL=https://approvals.example.com/api
# PRMANA_WEBHOOK_AUTH=Bearer your-secret-token
# PRMANA_WEBHOOK_TIMEOUT=30
```

Set permissions:

```bash
sudo chmod 600 /etc/prmana/env
sudo chown root:root /etc/prmana/env
```

### 4. Configure Policy

Create `/etc/prmana/policy.yaml`:

```yaml
host:
  classification: elevated

# SSH login requirements
ssh_login:
  require_oidc: true
  minimum_acr: null
  max_auth_age: 3600

# Sudo privilege policy
sudo:
  step_up_required: true
  default_action: step_up
  allowed_methods:
    - device_flow
  challenge_timeout: 300
  grace_period_secs: 0
  dry_run: false
  commands: []
```

See [examples/policy.yaml](../examples/policy.yaml) for a complete example, and [Sudo Step-Up](sudo-step-up.md) for Phase 44 command-specific `allow` / `step_up` / `deny` rules, grace windows, and dry-run rollout guidance.

### 5. Configure Break-Glass Access (MANDATORY)

> **Never deploy OIDC authentication as the only authentication path.** If your IdP goes down, you will be locked out.

Add a break-glass section to `/etc/prmana/policy.yaml`:

```yaml
break_glass:
  enabled: true
  accounts:
    - breakglass  # Must exist as a local Unix account with password set
  alert_on_use: true
```

Create and test the local break-glass account:

```bash
# Create the account
sudo useradd -m -s /bin/bash breakglass
sudo passwd breakglass  # Set a strong password, store in secure vault

# Test that local password auth works for this account
su - breakglass

# Document credentials in your organization's emergency procedures
```

See [Security Guide — Break-Glass Procedure](security-guide.md#break-glass-procedure) for full details.

### 6. Configure PAM

#### For SSH

Edit `/etc/pam.d/sshd`:

```
# prmana authentication (primary)
auth    sufficient    pam_prmana.so

# Fallback to standard Unix auth (for break-glass)
auth    required      pam_unix.so try_first_pass

# Standard account/session handling
account required      pam_unix.so
session required      pam_unix.so
```

#### For Sudo

Edit `/etc/pam.d/sudo`:

```
# prmana step-up authentication
auth    required      pam_prmana.so

# Fallback to standard Unix auth
auth    required      pam_unix.so try_first_pass

# Standard account/session handling
account required      pam_unix.so
session required      pam_unix.so
```

### 7. Configure SSH Daemon

Edit `/etc/ssh/sshd_config`:

```
# Enable PAM authentication
UsePAM yes

# Enable keyboard-interactive authentication (for OIDC token prompts)
# OpenSSH 9.0+: KbdInteractiveAuthentication yes
# OpenSSH <9.0: ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes

# Optionally disable password authentication
PasswordAuthentication no
```

Restart SSH:

```bash
sudo systemctl restart sshd
```

### 8. Configure Audit Logging (Optional)

Create audit log directory:

```bash
sudo mkdir -p /var/log/prmana
sudo chmod 750 /var/log/prmana
```

Configure rsyslog to capture prmana events:

```bash
# /etc/rsyslog.d/prmana.conf
:programname, isequal, "prmana-audit" /var/log/prmana/audit.log
```

## Identity Provider Configuration

### Keycloak

1. Create a new client:
   - Client ID: `prmana`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`

2. Configure client settings:
   - Valid Redirect URIs: `urn:ietf:wg:oauth:2.0:oob`
   - Enable "OAuth 2.0 Device Authorization Grant"

3. Configure device flow settings (Advanced tab):
   - Device Authorization Grant Max Lifespan: 300
   - Device Authorization Grant Polling Interval: 5

4. Add protocol mappers for required claims:
   - `preferred_username` (required)
   - `acr` (if using ACR requirements)

### Azure AD

1. Register a new application:
   - Name: `prmana`
   - Supported account types: Your organization

2. Configure authentication:
   - Add platform: Mobile and desktop applications
   - Enable "Allow public client flows" for device flow

3. Configure API permissions:
   - `openid`
   - `profile`

4. Note your:
   - Application (client) ID
   - Directory (tenant) ID
   - Issuer URL: `https://login.microsoftonline.com/{tenant-id}/v2.0`

### Okta

1. Create a new application:
   - Application type: Native Application
   - Grant type: Device Authorization

2. Configure settings:
   - Login redirect URIs: `urn:ietf:wg:oauth:2.0:oob`
   - Allowed grant types: Device Authorization

3. Note your:
   - Client ID
   - Issuer URL: `https://{your-domain}.okta.com`

## Verification

### Test OIDC Connectivity

```bash
# Test that the OIDC discovery endpoint is reachable
curl -s "${OIDC_ISSUER}/.well-known/openid-configuration" | jq '.issuer'
```

### Test Token Acquisition

```bash
# Start device flow
curl -s -X POST \
  "${OIDC_ISSUER}/protocol/openid-connect/auth/device" \
  -d "client_id=${OIDC_CLIENT_ID}" \
  -d "scope=openid"
```

### Test PAM Module

```bash
# Verify PAM module is loadable
sudo pamtester sshd testuser authenticate
```

### Test SSH Login

```bash
# From another terminal, try SSH
ssh testuser@localhost
# Should prompt for OIDC token
```

## Troubleshooting

### PAM module not found

```
pam_prmana.so: cannot open shared object file
```

Solution: Verify the module is in the correct path:
```bash
ls -la /lib/security/pam_prmana.so
# Or on some systems:
ls -la /lib64/security/pam_prmana.so
```

### OIDC_ISSUER not set

```
prmana: OIDC_ISSUER environment variable not set
```

Solution: Ensure environment is loaded in PAM context:
```bash
# Add to /etc/environment or /etc/profile.d/prmana.sh
export OIDC_ISSUER=https://your-idp.example.com/realms/your-realm
```

### Token validation failed

```
prmana: Token validation failed: issuer mismatch
```

Solution: Verify the issuer URL exactly matches:
```bash
# Check token issuer
echo "$TOKEN" | cut -d'.' -f2 | base64 -d | jq '.iss'

# Should match OIDC_ISSUER exactly
```

### User not found

```
prmana: User 'username' not found in directory
```

Solution: Verify SSSD is configured and user exists:
```bash
getent passwd username
id username
```

## Uninstallation

```bash
# Remove PAM module
sudo rm /lib/security/pam_prmana.so

# Remove configuration
sudo rm -rf /etc/prmana

# Restore original PAM configuration
sudo cp /etc/pam.d/sshd.bak /etc/pam.d/sshd
sudo cp /etc/pam.d/sudo.bak /etc/pam.d/sudo

# Restart SSH
sudo systemctl restart sshd
```

## Next Steps

- [User Guide](user-guide.md) - How to use prmana day-to-day
- [Sudo Step-Up](sudo-step-up.md) - Configuring step-up authentication
- [Testing Guide](testing.md) - Running tests
