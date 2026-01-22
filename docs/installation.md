# Installation Guide

This guide covers installing and configuring unix-oidc for production use.

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
git clone https://github.com/your-org/unix-oidc.git
cd unix-oidc

# Build release binary
cargo build --release

# The PAM module will be at:
# target/release/libpam_unix_oidc.so
```

## Installation

### 1. Install the PAM Module

```bash
# Copy the PAM module to the system PAM directory
sudo cp target/release/libpam_unix_oidc.so /lib/security/pam_unix_oidc.so

# Set permissions
sudo chmod 644 /lib/security/pam_unix_oidc.so
sudo chown root:root /lib/security/pam_unix_oidc.so
```

### 2. Create Configuration Directory

```bash
sudo mkdir -p /etc/unix-oidc
sudo chmod 755 /etc/unix-oidc
```

### 3. Configure Environment Variables

Create `/etc/unix-oidc/env`:

```bash
# Required: OIDC Issuer URL
OIDC_ISSUER=https://your-idp.example.com/realms/your-realm

# Optional: Client ID (default: unix-oidc)
OIDC_CLIENT_ID=unix-oidc

# Optional: Client secret (if required by IdP)
OIDC_CLIENT_SECRET=your-client-secret

# Optional: Required ACR level for SSH login
# OIDC_REQUIRED_ACR=urn:your-idp:acr:mfa

# Optional: Maximum auth age in seconds
# OIDC_MAX_AUTH_AGE=3600

# Optional: Audit log file path
# UNIX_OIDC_AUDIT_LOG=/var/log/unix-oidc/audit.log

# Optional: Webhook approval provider (for custom approval workflows)
# UNIX_OIDC_WEBHOOK_URL=https://approvals.example.com/api
# UNIX_OIDC_WEBHOOK_AUTH=Bearer your-secret-token
# UNIX_OIDC_WEBHOOK_TIMEOUT=30
```

Set permissions:

```bash
sudo chmod 600 /etc/unix-oidc/env
sudo chown root:root /etc/unix-oidc/env
```

### 4. Configure Policy

Create `/etc/unix-oidc/policy.yaml`:

```yaml
# Host classification: standard, elevated, or critical
host_classification: elevated

# SSH login requirements
ssh:
  require_oidc: true
  minimum_acr: null
  max_auth_age: 3600

# Sudo step-up requirements
sudo:
  step_up_required: true
  allowed_methods:
    - device_flow
  timeout_seconds: 300
  required_acr: null
  commands: []
```

See [examples/policy.yaml](../examples/policy.yaml) for a complete example with command-specific rules.

### 5. Configure PAM

#### For SSH

Edit `/etc/pam.d/sshd`:

```
# unix-oidc authentication (primary)
auth    sufficient    pam_unix_oidc.so

# Fallback to standard Unix auth (for break-glass)
auth    required      pam_unix.so try_first_pass

# Standard account/session handling
account required      pam_unix.so
session required      pam_unix.so
```

#### For Sudo

Edit `/etc/pam.d/sudo`:

```
# unix-oidc step-up authentication
auth    required      pam_unix_oidc.so

# Fallback to standard Unix auth
auth    required      pam_unix.so try_first_pass

# Standard account/session handling
account required      pam_unix.so
session required      pam_unix.so
```

### 6. Configure SSH Daemon

Edit `/etc/ssh/sshd_config`:

```
# Enable PAM authentication
UsePAM yes

# Enable challenge-response (for OIDC token prompts)
ChallengeResponseAuthentication yes

# Optionally disable password authentication
PasswordAuthentication no
```

Restart SSH:

```bash
sudo systemctl restart sshd
```

### 7. Configure Audit Logging (Optional)

Create audit log directory:

```bash
sudo mkdir -p /var/log/unix-oidc
sudo chmod 750 /var/log/unix-oidc
```

Configure rsyslog to capture unix-oidc events:

```bash
# /etc/rsyslog.d/unix-oidc.conf
:programname, isequal, "unix-oidc-audit" /var/log/unix-oidc/audit.log
```

## Identity Provider Configuration

### Keycloak

1. Create a new client:
   - Client ID: `unix-oidc`
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
   - Name: `unix-oidc`
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
pam_unix_oidc.so: cannot open shared object file
```

Solution: Verify the module is in the correct path:
```bash
ls -la /lib/security/pam_unix_oidc.so
# Or on some systems:
ls -la /lib64/security/pam_unix_oidc.so
```

### OIDC_ISSUER not set

```
unix-oidc: OIDC_ISSUER environment variable not set
```

Solution: Ensure environment is loaded in PAM context:
```bash
# Add to /etc/environment or /etc/profile.d/unix-oidc.sh
export OIDC_ISSUER=https://your-idp.example.com/realms/your-realm
```

### Token validation failed

```
unix-oidc: Token validation failed: issuer mismatch
```

Solution: Verify the issuer URL exactly matches:
```bash
# Check token issuer
echo "$TOKEN" | cut -d'.' -f2 | base64 -d | jq '.iss'

# Should match OIDC_ISSUER exactly
```

### User not found

```
unix-oidc: User 'username' not found in directory
```

Solution: Verify SSSD is configured and user exists:
```bash
getent passwd username
id username
```

## Uninstallation

```bash
# Remove PAM module
sudo rm /lib/security/pam_unix_oidc.so

# Remove configuration
sudo rm -rf /etc/unix-oidc

# Restore original PAM configuration
sudo cp /etc/pam.d/sshd.bak /etc/pam.d/sshd
sudo cp /etc/pam.d/sudo.bak /etc/pam.d/sudo

# Restart SSH
sudo systemctl restart sshd
```

## Next Steps

- [User Guide](user-guide.md) - How to use unix-oidc day-to-day
- [Sudo Step-Up](sudo-step-up.md) - Configuring step-up authentication
- [Testing Guide](testing.md) - Running tests
