# Community Testing Guide

Thank you for helping test unix-oidc! This guide covers testing on various platforms and identity providers.

## Testing Status

We're actively seeking community testing for combinations marked with 🔄:

| Platform | x86_64 | aarch64 | Notes |
|----------|--------|---------|-------|
| Ubuntu 22.04 LTS | ✅ CI | ✅ CI | Primary test platform |
| Ubuntu 24.04 LTS | ✅ Tested | 🔄 | Manual testing done |
| Debian 12 | 🔄 | 🔄 | Community reports welcome |
| RHEL 9 / Rocky 9 | 🔄 | 🔄 | Community reports welcome |
| RHEL 8 / Rocky 8 | 🔄 | 🔄 | Community reports welcome |
| Amazon Linux 2023 | 🔄 | 🔄 | Community reports welcome |
| Fedora 39+ | 🔄 | 🔄 | Community reports welcome |

| Identity Provider | Status | Notes |
|-------------------|--------|-------|
| Keycloak | ✅ CI | Automated testing |
| Auth0 | ✅ Tested | Manual testing done |
| Google Cloud Identity | ✅ Tested | Manual testing done |
| Azure AD (Entra ID) | ⚠️ Basic | Needs more testing |
| Okta | 🔄 | Community reports welcome |
| Ping Identity | 🔄 | Community reports welcome |
| OneLogin | 🔄 | Community reports welcome |

---

## Prerequisites (All Platforms)

Before testing, ensure you have:

1. **Root/sudo access** to the test machine
2. **SSSD configured** and connected to a user directory (LDAP, AD, FreeIPA)
3. **An OIDC provider** with Device Authorization Grant enabled
4. **A test user** that exists in both your IdP and local directory

Verify SSSD is working:
```bash
getent passwd <your-test-user>
id <your-test-user>
```

---

## Step 1: Download Release

```bash
# Set version and platform
V=v0.1.0-beta.1
P=linux-x86_64      # or linux-aarch64 for ARM

# Download release artifacts
curl -LO https://github.com/prodnull/unix-oidc/releases/download/$V/unix-oidc-$V-$P.tar.gz
curl -LO https://github.com/prodnull/unix-oidc/releases/download/$V/unix-oidc-$V-$P.tar.gz.sha256
curl -LO https://github.com/prodnull/unix-oidc/releases/download/$V/unix-oidc-$V-$P.tar.gz.sig
curl -LO https://github.com/prodnull/unix-oidc/releases/download/$V/unix-oidc-$V-$P.tar.gz.pem

# Verify checksum
sha256sum -c unix-oidc-$V-$P.tar.gz.sha256

# Extract
tar -xzf unix-oidc-$V-$P.tar.gz
ls -la libpam_unix_oidc.so
```

### Optional: Verify Signature (requires cosign)

All releases are signed with [Sigstore](https://www.sigstore.dev/) keyless signing:

```bash
# Install cosign if needed (see platform-specific section below)

cosign verify-blob \
  --certificate unix-oidc-$V-$P.tar.gz.pem \
  --signature unix-oidc-$V-$P.tar.gz.sig \
  --certificate-identity-regexp 'https://github.com/prodnull/unix-oidc' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  unix-oidc-$V-$P.tar.gz
```

---

## Step 2: Install PAM Module

### Ubuntu / Debian

```bash
# PAM modules live in /lib/security (or /lib/x86_64-linux-gnu/security)
PAM_DIR=/lib/x86_64-linux-gnu/security
# Fallback for older systems
[ -d "$PAM_DIR" ] || PAM_DIR=/lib/security

sudo cp libpam_unix_oidc.so $PAM_DIR/pam_unix_oidc.so
sudo chmod 644 $PAM_DIR/pam_unix_oidc.so
sudo chown root:root $PAM_DIR/pam_unix_oidc.so
```

### RHEL / Rocky / Alma / Fedora / Amazon Linux

```bash
# RHEL-family uses /lib64/security
sudo cp libpam_unix_oidc.so /lib64/security/pam_unix_oidc.so
sudo chmod 644 /lib64/security/pam_unix_oidc.so
sudo chown root:root /lib64/security/pam_unix_oidc.so

# Restore SELinux context
sudo restorecon /lib64/security/pam_unix_oidc.so
```

### Verify Installation

```bash
# Should show the module
ls -la /lib*/security/pam_unix_oidc.so
```

---

## Step 3: Configure unix-oidc

### Create Configuration Directory

```bash
sudo mkdir -p /etc/unix-oidc
sudo chmod 755 /etc/unix-oidc
```

### Create Environment File

```bash
sudo tee /etc/unix-oidc/env << 'EOF'
# Required: Your OIDC issuer URL
OIDC_ISSUER=https://your-idp.example.com/realms/your-realm

# Required: Client ID registered with your IdP
OIDC_CLIENT_ID=unix-oidc

# Optional: Client secret (if your IdP requires it)
# OIDC_CLIENT_SECRET=your-secret

# Optional: Required ACR level
# OIDC_REQUIRED_ACR=urn:your-idp:acr:mfa
EOF

sudo chmod 600 /etc/unix-oidc/env
sudo chown root:root /etc/unix-oidc/env
```

### Provider-Specific Issuer URLs

| Provider | Issuer URL Format |
|----------|-------------------|
| **Keycloak** | `https://keycloak.example.com/realms/your-realm` |
| **Azure AD** | `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| **Okta** | `https://your-domain.okta.com` |
| **Auth0** | `https://your-tenant.auth0.com` |
| **Google** | `https://accounts.google.com` |
| **Ping Identity** | `https://auth.pingone.com/{environment-id}/as` |

### Create Policy File

```bash
sudo tee /etc/unix-oidc/policy.yaml << 'EOF'
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
EOF

sudo chmod 644 /etc/unix-oidc/policy.yaml
```

---

## Step 4: Configure PAM

### Backup Existing Configuration

```bash
sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.bak
sudo cp /etc/pam.d/sudo /etc/pam.d/sudo.bak
```

### Configure SSH PAM

Edit `/etc/pam.d/sshd` and add at the **TOP** (before other auth lines):

```
# unix-oidc authentication (primary)
auth    sufficient    pam_unix_oidc.so

# Fallback to standard Unix auth (for break-glass)
auth    required      pam_unix.so try_first_pass
```

### Configure Sudo PAM (Optional)

Edit `/etc/pam.d/sudo` and add at the **TOP**:

```
# unix-oidc step-up authentication
auth    required      pam_unix_oidc.so
```

---

## Step 5: Configure SSH Daemon

Edit `/etc/ssh/sshd_config`:

```
# Enable PAM
UsePAM yes

# Enable challenge-response for OIDC prompts
ChallengeResponseAuthentication yes
# Note: On newer OpenSSH, this may be called:
# KbdInteractiveAuthentication yes

# Optionally disable password auth (after testing works)
# PasswordAuthentication no
```

Restart SSH:

```bash
# Systemd (most modern systems)
sudo systemctl restart sshd

# Or on older systems
sudo service sshd restart
```

---

## Step 6: Platform-Specific Considerations

### SELinux (RHEL / Fedora / Rocky / Alma)

If SELinux is enforcing, the PAM module needs permission to make network connections:

```bash
# Check SELinux status
getenforce

# If you see AVC denials in audit log:
sudo ausearch -m avc -ts recent

# Create and install a policy module (if needed)
sudo ausearch -c 'sshd' --raw | audit2allow -M unix_oidc_pam
sudo semodule -i unix_oidc_pam.pp
```

Common SELinux booleans that may need to be enabled:
```bash
# Allow PAM to connect to network (for OIDC discovery/validation)
sudo setsebool -P authlogin_nsswitch_use_ldap on
```

### AppArmor (Ubuntu / Debian)

AppArmor typically doesn't block PAM modules, but if you encounter issues:

```bash
# Check AppArmor status
sudo aa-status

# Check for denials
sudo dmesg | grep -i apparmor
```

### Firewall

Ensure outbound HTTPS (443) is allowed to your IdP:

```bash
# RHEL/Fedora
sudo firewall-cmd --list-all

# Ubuntu (ufw)
sudo ufw status
```

---

## Step 7: Test

### Test from Another Machine

```bash
# Basic SSH test
ssh testuser@your-test-host

# Should prompt for OIDC token or trigger browser flow
```

### Monitor Logs During Testing

On the test server, in a separate terminal:

```bash
# RHEL / Fedora
sudo tail -f /var/log/secure

# Ubuntu / Debian
sudo tail -f /var/log/auth.log

# Systemd journal (all platforms)
sudo journalctl -u sshd -f
```

### Test OIDC Connectivity

```bash
# Verify OIDC discovery endpoint is reachable
source /etc/unix-oidc/env
curl -s "${OIDC_ISSUER}/.well-known/openid-configuration" | jq '.issuer'
```

### Test Sudo Step-Up (if configured)

```bash
# After successful SSH login
sudo ls /root
# Should trigger device flow authentication
```

---

## Step 8: Report Results

Please open a GitHub issue at https://github.com/prodnull/unix-oidc/issues with:

### Required Information

```
**Platform:** (e.g., RHEL 9.3 x86_64, Ubuntu 24.04 aarch64)
**Kernel:** `uname -r`
**IdP:** (e.g., Azure AD, Okta, Keycloak 24.0)

**What worked:**
- [ ] PAM module loaded
- [ ] OIDC discovery succeeded
- [ ] SSH authentication succeeded
- [ ] Sudo step-up worked

**What didn't work:**
(describe any issues)

**Error messages:**
(paste relevant log entries)

**SELinux/AppArmor status:**
(output of getenforce or aa-status)
```

### Helpful Additional Info

- PAM configuration used
- Any custom IdP configuration needed
- Workarounds you discovered
- Performance observations (auth latency)

**Even "everything worked perfectly" is valuable!** It helps us update the compatibility matrix.

---

## Troubleshooting

### PAM Module Not Found

```
pam_unix_oidc.so: cannot open shared object file
```

**Solution:** Verify the path matches your distro:
```bash
# Find where PAM looks for modules
cat /etc/pam.d/sshd | grep -i pam
ls -la /lib*/security/pam_unix_oidc.so
```

### OIDC Discovery Failed

```
unix-oidc: Failed to fetch OIDC configuration
```

**Solution:** Check network connectivity and issuer URL:
```bash
source /etc/unix-oidc/env
curl -v "${OIDC_ISSUER}/.well-known/openid-configuration"
```

### SELinux AVC Denial

```
avc: denied { name_connect } ... sshd
```

**Solution:** Create SELinux policy module:
```bash
sudo ausearch -m avc -ts recent | audit2allow -M unix_oidc
sudo semodule -i unix_oidc.pp
```

### User Not Found

```
unix-oidc: User 'username' not found in directory
```

**Solution:** Verify SSSD can resolve the user:
```bash
getent passwd username
id username
```

### Token Validation Failed

```
unix-oidc: Token validation failed: issuer mismatch
```

**Solution:** Verify issuer URL matches exactly:
```bash
# Check what's in the token
echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.iss'

# Should match OIDC_ISSUER exactly
```

---

## Rollback

If testing fails and you need to restore original auth:

```bash
# Restore PAM configs
sudo cp /etc/pam.d/sshd.bak /etc/pam.d/sshd
sudo cp /etc/pam.d/sudo.bak /etc/pam.d/sudo

# Restart SSH
sudo systemctl restart sshd

# Optionally remove the module
sudo rm /lib*/security/pam_unix_oidc.so
sudo rm -rf /etc/unix-oidc
```

---

## Installing Cosign (for signature verification)

### Ubuntu / Debian
```bash
# Via Go
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Or download binary
curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
```

### RHEL / Fedora
```bash
# Fedora
sudo dnf install cosign

# RHEL (via EPEL or download binary)
curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
```

---

## Questions?

- **GitHub Issues:** https://github.com/prodnull/unix-oidc/issues
- **Security Issues:** See [SECURITY.md](../SECURITY.md)
- **Full Documentation:** https://github.com/prodnull/unix-oidc/tree/main/docs
