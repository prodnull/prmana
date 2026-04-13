# Migration Guide: SSH Keys to OIDC Authentication

This guide walks through transitioning Linux servers from SSH key authentication to Prmana OIDC authentication. The migration is designed to be incremental and reversible — you can run both authentication methods in parallel during the transition.

## Prerequisites

Before starting migration on any server:

- [ ] IdP (Okta, Entra ID, Keycloak) configured with an OIDC client for Prmana
- [ ] Client agent binary available for user workstations
- [ ] PAM module `.so` available for target servers
- [ ] Break-glass account configured and tested (see `docs/break-glass-validation.md`)
- [ ] SSH key inventory completed (see `scripts/ssh-key-inventory.sh`)
- [ ] At least one test server identified for pilot

## Migration Strategy

### Recommended: Parallel Authentication

Run OIDC and SSH keys side by side. Users can authenticate with either method during transition. Once confidence is established, disable key-based auth server by server.

```
Phase 1: Pilot        1 server, 2-3 users, 1 week
Phase 2: Early Adopt  10% of fleet, willing team, 2 weeks
Phase 3: Majority     Remaining servers, all users
Phase 4: Key Sunset   Disable key auth, remove authorized_keys
```

### Alternative: Per-Team Rollout

Migrate one team's servers at a time. Each team validates before the next begins.

### What NOT to Do

- Do not disable SSH keys before OIDC is validated on that server
- Do not skip break-glass configuration
- Do not migrate all servers at once
- Do not migrate during a maintenance window for your IdP

## Step-by-Step: Single Server Migration

### Step 1: Run the Key Inventory

```bash
# Identify what you're migrating away from
sudo ./scripts/ssh-key-inventory.sh
```

Record the output. You'll use this to verify all users can authenticate via OIDC before removing keys.

### Step 2: Install the PAM Module

```bash
# Debian/Ubuntu
sudo cp libpam_prmana.so /lib/security/
# RHEL/Rocky
sudo cp libpam_prmana.so /lib64/security/
```

Or use the Ansible role: `deploy/ansible/roles/prmana/`

### Step 3: Configure the Policy

Create `/etc/prmana/policy.yaml`:

```yaml
issuers:
  - issuer_url: https://your-idp.example.com/realms/corp
    client_id: prmana
    dpop_enforcement: strict

break_glass:
  enabled: true
  users:
    - username: breakglass
      # Generate: python3 -c "import crypt; print(crypt.crypt('PASSWORD', crypt.mksalt(crypt.METHOD_SHA512)))"
      password_hash: "$6$rounds=656000$..."
  alert_on_use: true

security_modes:
  jti_enforcement: warn
  dpop_required: strict
```

See `deploy/templates/` for additional configuration patterns.

### Step 4: Configure PAM (Parallel Mode)

Edit `/etc/pam.d/sshd` to add OIDC as an **additional** auth method (not replacement):

```
# Existing password/key auth (keep during transition)
@include common-auth

# Add OIDC authentication — sufficient means "if OIDC succeeds, allow login"
auth    sufficient    pam_prmana.so
```

With `sufficient`, OIDC success grants access. OIDC failure falls through to existing auth (keys/password). This is the safe parallel-running configuration.

### Step 5: Validate Break-Glass

**Before any user tests OIDC**, verify break-glass works:

```bash
./scripts/validate-break-glass.sh --host localhost
```

See `docs/break-glass-validation.md` for the full procedure.

### Step 6: Install Client Agent on User Workstations

```bash
# User installs the agent (no root needed)
prmana-agent login --issuer https://your-idp.example.com/realms/corp
```

This triggers the device flow or auth code + PKCE flow. The user authenticates via their browser, and the agent stores the token.

### Step 7: Test OIDC Login

```bash
# User SSHs normally — the agent provides the OIDC token automatically
ssh user@server
```

Verify in the server's audit log:

```bash
# Check for SSH_LOGIN_SUCCESS with OIDC fields
sudo journalctl -u sshd | grep SSH_LOGIN_SUCCESS
```

### Step 8: Validate All Users

For each user who had SSH keys on this server (from the inventory in Step 1), verify they can authenticate via OIDC:

```bash
# From the key inventory, for each user:
ssh $user@server "echo OIDC auth works"
```

### Step 9: Switch to OIDC-Primary

Once all users are validated, change PAM to make OIDC the primary auth method:

```
# OIDC first, fall through to password only if OIDC fails
auth    sufficient    pam_prmana.so
auth    required      pam_unix.so
```

### Step 10: Sunset SSH Keys

After a confidence period (recommended: 2 weeks of OIDC-primary), remove authorized_keys:

```bash
# Archive first — don't delete without backup
sudo tar czf /root/authorized_keys_backup_$(date +%Y%m%d).tar.gz \
    $(find /home -name authorized_keys -type f 2>/dev/null)

# Then remove
sudo find /home -name authorized_keys -type f -delete

# Disable key-based auth in sshd_config
sudo sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication no/' /etc/ssh/sshd_config
sudo systemctl reload sshd
```

## Fleet Migration with Ansible

For fleet-wide deployment, use the provided Ansible role:

```bash
ansible-playbook -i inventory deploy/ansible/site.yml \
    -e prmana_issuer_url=https://your-idp.example.com/realms/corp \
    -e prmana_client_id=prmana
```

The role handles: PAM module installation, policy configuration, break-glass setup, and PAM config. See `deploy/ansible/roles/prmana/` for details.

## Rollback

At any point during migration, you can revert:

### Rollback PAM (keep module installed)

```bash
# Comment out the OIDC PAM line
sudo sed -i 's/^auth.*pam_prmana/#&/' /etc/pam.d/sshd
```

### Rollback completely

```bash
# Remove PAM module
sudo rm /lib/security/pam_prmana.so  # or /lib64/security/
# Remove config
sudo rm -rf /etc/prmana/
# Restore original PAM config
sudo sed -i '/pam_prmana/d' /etc/pam.d/sshd
```

SSH key auth continues to work throughout — keys are never touched by the install or uninstall.

## Common Issues During Migration

| Issue | Cause | Fix |
|---|---|---|
| "Authentication failed" after OIDC install | Token not acquired — agent not running or not configured | Run `prmana-agent login` on the client |
| OIDC works, but fall-through to keys is slow | PAM tries OIDC first, times out, then falls through | Set `request_timeout_secs` in policy to 5-10s |
| User exists in IdP but SSH fails | Unix username doesn't match IdP `preferred_username` | Configure `claim_mapping` in issuer config |
| Break-glass doesn't work | Password hash format wrong or break-glass not enabled | Verify with `scripts/validate-break-glass.sh` |
| Token expired mid-session | Token TTL too short for long sessions | Agent auto-refreshes; verify refresh token is present |

## Post-Migration Checklist

- [ ] All users validated via OIDC login
- [ ] Break-glass tested and documented
- [ ] Audit logs showing OIDC auth events
- [ ] Old SSH keys archived (not deleted without backup)
- [ ] On-call team briefed on rollback procedure
- [ ] IdP outage runbook updated with break-glass instructions
- [ ] Monitoring configured for `SSH_LOGIN_FAILED` and `AUTH_NO_TOKEN` events

---

*Migration is designed to be boring. Parallel running, incremental rollout, easy rollback. The goal is zero-downtime transition with a safety net at every step.*
