# unix-oidc Minimal Vagrant Image

A minimal Vagrant environment with unix-oidc pre-installed, ready for integration with your own OIDC provider (BYOIDP - Bring Your Own Identity Provider).

## Prerequisites

- [Vagrant](https://www.vagrantup.com/downloads) (2.3+)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (6.1+)

## Quick Start

```bash
# Clone the repository (if not already done)
git clone https://github.com/prodnull/unix-oidc.git
cd unix-oidc/deploy/vagrant/minimal

# Start the VM
vagrant up

# SSH into the VM
vagrant ssh
```

## What's Included

- Ubuntu 22.04 LTS base
- unix-oidc PAM module and agent (placeholder for binary installation)
- Configuration templates at `/etc/unix-oidc/`
- Test user: `testuser` / `testpass`
- pamtester for PAM testing

## Configuration

### 1. Configure Your OIDC Provider

Edit `/etc/unix-oidc/config.env` with your IdP settings:

```bash
vagrant ssh
sudo nano /etc/unix-oidc/config.env
```

Example configurations:

**Keycloak:**
```bash
OIDC_ISSUER="https://keycloak.example.com/realms/your-realm"
OIDC_CLIENT_ID="unix-oidc"
```

**Okta:**
```bash
OIDC_ISSUER="https://your-org.okta.com"
OIDC_CLIENT_ID="your-client-id"
```

**Auth0:**
```bash
OIDC_ISSUER="https://your-tenant.auth0.com"
OIDC_CLIENT_ID="your-client-id"
```

**Azure AD:**
```bash
OIDC_ISSUER="https://login.microsoftonline.com/{tenant-id}/v2.0"
OIDC_CLIENT_ID="your-client-id"
```

### 2. Install unix-oidc Binaries

```bash
vagrant ssh
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh | sudo bash
```

### 3. Apply PAM Configuration

**Important:** Test in a non-production environment first!

```bash
# Review the recommended configuration
cat /etc/unix-oidc/pam.d-sshd.recommended

# Backup existing config
sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.backup

# Apply unix-oidc PAM config
sudo cp /etc/unix-oidc/pam.d-sshd.recommended /etc/pam.d/sshd
```

## Testing

### Test PAM Module

```bash
# Test that the PAM module loads correctly
pamtester sshd testuser authenticate
```

### Test SSH Authentication

From the host machine:

```bash
# Get a token from your IdP first, then:
OIDC_TOKEN="your-access-token" ssh -p 2222 testuser@localhost
```

### Verify Configuration

```bash
# Check unix-oidc configuration
cat /etc/unix-oidc/config.env

# Test OIDC issuer connectivity
curl -s "$(grep OIDC_ISSUER /etc/unix-oidc/config.env | cut -d'=' -f2 | tr -d '"')/.well-known/openid-configuration" | jq
```

## Network Configuration

| Port (Host) | Port (Guest) | Service |
|-------------|--------------|---------|
| 2222        | 22           | SSH     |

## Files and Directories

| Path | Description |
|------|-------------|
| `/etc/unix-oidc/config.env` | Main configuration file |
| `/etc/unix-oidc/pam.d-sshd.recommended` | Recommended SSHD PAM config |
| `/etc/unix-oidc/pam.d-sudo.recommended` | Recommended sudo PAM config |
| `/lib/security/pam_unix_oidc.so` | PAM module (after installation) |
| `/usr/local/bin/unix-oidc-agent` | Agent binary (after installation) |

## Vagrant Commands

```bash
# Start/provision the VM
vagrant up

# SSH into the VM
vagrant ssh

# Restart the VM
vagrant reload

# Stop the VM
vagrant halt

# Destroy the VM (removes all data)
vagrant destroy
```

## Troubleshooting

### PAM Module Not Loading

```bash
# Check if the module exists
ls -la /lib/security/pam_unix_oidc.so

# Check PAM configuration syntax
pamtester sshd testuser authenticate
```

### OIDC Issuer Unreachable

```bash
# Test network connectivity
curl -v "https://your-idp.example.com/.well-known/openid-configuration"

# Check DNS resolution
nslookup your-idp.example.com
```

### SSH Connection Issues

```bash
# Check SSH service status
sudo systemctl status sshd

# Check PAM configuration
cat /etc/pam.d/sshd

# View auth logs
sudo journalctl -u sshd -f
```

## Security Notes

- This image is for development and testing purposes
- The default test user password is intentionally weak
- Always use strong passwords and proper OIDC configuration in production
- Review and understand PAM configurations before applying them

## Next Steps

- See the [demo image](../demo/) for a complete environment with Keycloak
- Read the [15-minute production guide](../../quickstart/15-minute-production.md)
- Explore [IdP-specific setup guides](../../idp-templates/)
