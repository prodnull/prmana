# 15-Minute Production Setup

**Time to complete:** 15 minutes
**Prerequisites:** Linux server with root access + OIDC Identity Provider

This guide walks you through deploying unix-oidc on a production server with your existing identity provider. By the end, your users will authenticate to Linux servers using OIDC tokens instead of passwords or SSH keys.

---

## Prerequisites Checklist (2 min)

Before starting, confirm you have:

| Requirement | Details | Check |
|-------------|---------|-------|
| **Linux Server** | Ubuntu 20.04+, Debian 11+, RHEL 8+, or Rocky 9 | `cat /etc/os-release` |
| **Root/sudo access** | Required for PAM configuration | `sudo -v` |
| **OIDC Identity Provider** | Keycloak, Okta, Azure AD, Auth0, or similar | Must support Device Authorization Grant |
| **Admin access to IdP** | Ability to create OIDC applications | For client registration |

### Quick System Check

```bash
# Verify your OS is supported
cat /etc/os-release | grep -E '^(ID|VERSION_ID)='

# Verify you have sudo access
sudo echo "Root access confirmed"

# Verify required tools are installed
command -v curl && command -v jq && echo "Tools available"
```

**Missing tools?** Install them:
```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y curl jq

# RHEL/Rocky
sudo dnf install -y curl jq
```

---

## Step 1: Configure Your Identity Provider (5 min)

Choose your IdP and follow the linked guide to create a unix-oidc application:

| Identity Provider | Setup Guide | Estimated Time |
|-------------------|-------------|----------------|
| **Keycloak** | [Keycloak Setup](../idp-templates/keycloak/) | 3-5 min |
| **Okta** | [Okta Setup](../idp-templates/okta/) | 3-5 min |
| **Azure AD** | [Azure AD Setup](../idp-templates/azure-ad/) | 3-5 min |
| **Auth0** | [Auth0 Setup](../idp-templates/auth0/) | 3-5 min |

### What You Need After IdP Setup

After configuring your IdP, you should have:

| Setting | Example | Your Value |
|---------|---------|------------|
| **Issuer URL** | `https://login.example.com/realms/myorg` | _____________ |
| **Client ID** | `unix-oidc` | _____________ |

### Verify It Works: Test OIDC Discovery

```bash
# Replace with your issuer URL
ISSUER="https://your-idp.example.com/realms/your-realm"

# Fetch the discovery document
curl -fsSL "${ISSUER}/.well-known/openid-configuration" | jq '{
  issuer,
  device_authorization_endpoint,
  token_endpoint
}'
```

**Expected output:**
```json
{
  "issuer": "https://your-idp.example.com/realms/your-realm",
  "device_authorization_endpoint": "https://your-idp.example.com/.../device",
  "token_endpoint": "https://your-idp.example.com/.../token"
}
```

If the `device_authorization_endpoint` is missing, your IdP may not have Device Authorization Grant enabled. Return to your IdP setup guide and enable it.

---

## Step 2: Install unix-oidc (3 min)

### Option 1: One-liner Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh | sudo bash -s -- \
  --issuer "https://your-idp.example.com/realms/your-realm" \
  --client-id "unix-oidc"
```

### Option 2: Step-by-Step (Inspect First)

If you prefer to review the installer before running:

```bash
# 1. Download the installer
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh -o install.sh

# 2. Review the script
less install.sh

# 3. Dry run (shows what would happen without making changes)
sudo bash install.sh --dry-run \
  --issuer "https://your-idp.example.com/realms/your-realm" \
  --client-id "unix-oidc"

# 4. Run the installer
sudo bash install.sh \
  --issuer "https://your-idp.example.com/realms/your-realm" \
  --client-id "unix-oidc"
```

### Verify It Works: Check Installation

```bash
# PAM module installed
ls -la /lib/security/pam_unix_oidc.so 2>/dev/null || \
ls -la /lib64/security/pam_unix_oidc.so

# Configuration created
cat /etc/unix-oidc/config.env

# Recommended PAM configs generated
ls /etc/unix-oidc/pam.d-*.recommended
```

**Expected output:**
```
-rw-r--r-- 1 root root 12345 ... /lib/security/pam_unix_oidc.so
```

---

## Step 3: Configure PAM (3 min)

> **WARNING: PAM Configuration Risk**
>
> Incorrect PAM configuration can lock you out of the system. **Before proceeding:**
> 1. Keep a root shell open in a separate terminal
> 2. Have physical/console access available as backup
> 3. Test in a non-production environment first if possible

### 3.1 Review the Recommended Configuration

The installer generated a recommended PAM configuration. Review it:

```bash
cat /etc/unix-oidc/pam.d-sshd.recommended
```

This configuration:
- Tries OIDC authentication first
- Falls back to password authentication if OIDC fails
- Preserves your ability to log in with traditional methods

### 3.2 Backup Your Current Configuration

```bash
# Create timestamped backups
sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.backup.$(date +%Y%m%d%H%M%S)
echo "Backup created at: /etc/pam.d/sshd.backup.$(date +%Y%m%d%H%M%S)"
```

### 3.3 Apply the New Configuration

**IMPORTANT: Keep your current terminal session open!**

```bash
# Apply the recommended configuration
sudo cp /etc/unix-oidc/pam.d-sshd.recommended /etc/pam.d/sshd

# Restart sshd to apply changes
sudo systemctl restart sshd
```

### 3.4 Install pamtester (Optional but Recommended)

pamtester allows you to test PAM modules without risking lockout:

```bash
# Debian/Ubuntu
sudo apt-get install -y pamtester

# RHEL/Rocky
sudo dnf install -y pamtester
```

### Verify It Works: Test PAM Module

```bash
# Test that the PAM module loads correctly
# This should fail auth (no token) but confirm the module loads
sudo pamtester sshd $(whoami) authenticate <<< ""
```

**Expected output:**
```
pamtester: Authentication failure
```

This confirms the module loads. Auth fails because we didn't provide a token (expected behavior).

---

## Step 4: Test SSH Login (2 min)

Now test a complete end-to-end OIDC authentication.

### 4.1 Get an Access Token from Your IdP

The exact method depends on your IdP. Here's a device flow example:

```bash
# Start device authorization flow
CLIENT_ID="unix-oidc"
ISSUER="https://your-idp.example.com/realms/your-realm"

# Get the device authorization endpoint
DEVICE_ENDPOINT=$(curl -s "${ISSUER}/.well-known/openid-configuration" | jq -r '.device_authorization_endpoint')

# Request device code
DEVICE_RESPONSE=$(curl -s -X POST "$DEVICE_ENDPOINT" \
  -d "client_id=${CLIENT_ID}" \
  -d "scope=openid profile")

echo "$DEVICE_RESPONSE" | jq

# Follow the verification_uri_complete in your browser
# Then poll for the token (see your IdP docs)
```

Alternatively, if your IdP supports password grant (for testing only):

```bash
TOKEN_ENDPOINT=$(curl -s "${ISSUER}/.well-known/openid-configuration" | jq -r '.token_endpoint')

TOKEN=$(curl -s -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "username=your-username" \
  -d "password=your-password" \
  -d "scope=openid" | jq -r '.access_token')

echo "Token obtained: ${TOKEN:0:50}..."
```

### 4.2 SSH with the Token

```bash
# Set the token in environment and SSH
OIDC_TOKEN="$TOKEN" ssh your-username@localhost
```

Or pass it interactively when prompted.

### Verify It Works: Successful Login

**Expected output:**
```
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-generic x86_64)

 * Documentation:  https://help.ubuntu.com

Last login: Mon Jan 20 10:30:00 2026 from 127.0.0.1
your-username@server:~$
```

If you see the shell prompt, OIDC authentication is working.

---

## Summary: What You've Accomplished

| Step | Status |
|------|--------|
| IdP configured with Device Authorization Grant | Done |
| unix-oidc PAM module installed | Done |
| PAM configured with fallback authentication | Done |
| OIDC SSH login tested | Done |

Your Linux server now accepts OIDC tokens for authentication!

---

## Next Steps

Now that basic OIDC authentication is working, consider these enhancements:

### Enable MFA Step-up for sudo

Require re-authentication when users run privileged commands:

```bash
# Apply the sudo PAM configuration
sudo cp /etc/unix-oidc/pam.d-sudo.recommended /etc/pam.d/sudo
```

See: [Sudo Step-Up Guide](../../docs/sudo-step-up.md)

### Set Up the Agent for Token Caching

The unix-oidc agent caches tokens and handles refresh automatically:

```bash
# Start the agent
unix-oidc-agent

# Configure your shell to use it
echo 'eval "$(unix-oidc-agent --shell)"' >> ~/.bashrc
```

See: [User Guide](../../docs/user-guide.md)

### Enable DPoP for Enhanced Security

DPoP (Demonstration of Proof-of-Possession) binds tokens to cryptographic keys, preventing token theft:

```bash
# Edit config to require DPoP
sudo sed -i 's/# OIDC_DPOP_REQUIRED=true/OIDC_DPOP_REQUIRED=true/' /etc/unix-oidc/config.env
```

See: [Security Guide](../../docs/security-guide.md)

### Deploy to More Servers

Use configuration management for fleet-wide deployment:

| Tool | Documentation |
|------|---------------|
| Terraform | [Terraform Module](../terraform/) |
| Ansible | [Ansible Role](../ansible/) |
| Chef | [Chef Cookbook](../chef/) |
| Puppet | [Puppet Module](../puppet/) |

---

## Troubleshooting

### "PAM module not found"

```
pam_unix_oidc.so: cannot open shared object file: No such file or directory
```

**Solution:** The module may be in a different directory. Check both locations:

```bash
# Find the module
sudo find /lib* -name "pam_unix_oidc.so" 2>/dev/null

# Update PAM config to use correct path if needed
```

### "OIDC_ISSUER not set"

```
unix-oidc: OIDC_ISSUER environment variable not set
```

**Solution:** Ensure PAM is loading the environment file:

```bash
# Verify config exists
cat /etc/unix-oidc/config.env | grep OIDC_ISSUER

# Verify PAM is loading it (check first line of PAM config)
head -5 /etc/pam.d/sshd
# Should include: pam_env.so envfile=/etc/unix-oidc/config.env
```

### "Token validation failed: issuer mismatch"

**Solution:** The issuer in your token doesn't match the configured issuer. Verify they match exactly:

```bash
# Decode your token to see the issuer
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.iss'

# Compare with configured issuer
grep OIDC_ISSUER /etc/unix-oidc/config.env
```

### "User not found"

**Solution:** The username from the token doesn't exist on the system:

```bash
# Check what username the token provides
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.preferred_username'

# Verify user exists
getent passwd the-username
```

### Locked out of the system

If you can't SSH in:

1. **Console access:** Log in via physical console or cloud provider console
2. **Single-user mode:** Boot into recovery mode
3. **Restore backup:**
   ```bash
   sudo cp /etc/pam.d/sshd.backup.* /etc/pam.d/sshd
   sudo systemctl restart sshd
   ```

### Need more help?

- [Full Installation Guide](../../docs/installation.md)
- [Architecture Overview](../../docs/deployment-patterns.md)
- [Security Model](../../docs/THREAT_MODEL.md)
- [GitHub Issues](https://github.com/prodnull/unix-oidc/issues)

---

*This guide is part of the [unix-oidc deployment documentation](../README.md).*
