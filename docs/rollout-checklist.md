# Prmana Rollout Checklist

Operator-facing checklist for deploying Prmana to production. Each section references the relevant guide or tool from the Rollout & Migration Toolkit.

---

## Pre-Deployment

### IdP Configuration

- [ ] OIDC client registered in your IdP (Okta, Entra ID, Keycloak, etc.)
- [ ] Client ID and secret (if confidential client) documented securely
- [ ] OIDC discovery endpoint accessible: `curl https://your-idp/.well-known/openid-configuration`
- [ ] DPoP support verified for your IdP (or enforcement set to `warn`/`disabled` if unsupported)
- [ ] If using CIBA step-up: CIBA backchannel endpoint verified in discovery document
- [ ] If using failover: secondary IdP configured with matching client registration

### Infrastructure

- [ ] PAM module binary (`libpam_unix_oidc.so`) built or downloaded for target architecture
- [ ] Client agent binary (`unix-oidc-agent`) available for user workstations
- [ ] SSH key inventory completed: `./scripts/ssh-key-inventory.sh` (see output)
- [ ] Break-glass password generated and stored in emergency access vault
- [ ] Monitoring/SIEM configured to receive syslog from target servers

### Team Readiness

- [ ] On-call team briefed on Prmana and rollback procedure
- [ ] Break-glass credentials accessible to on-call (not just the deployer)
- [ ] Test users identified for pilot phase
- [ ] Rollback plan documented and reviewed

---

## Pilot Deployment (1 Server)

### Install and Configure

- [ ] PAM module installed: `deploy/ansible/` or manual copy to `/lib/security/`
- [ ] Policy configured: `/etc/unix-oidc/policy.yaml` (use `deploy/templates/single-issuer.yaml` as starting point)
- [ ] PAM configured in parallel mode (OIDC + existing auth)
- [ ] Break-glass user created on the server
- [ ] Break-glass validated: `./scripts/validate-break-glass.sh`

### Validate

- [ ] Test user can SSH via OIDC: `ssh testuser@pilot-server`
- [ ] Test user can still SSH via existing key (parallel mode)
- [ ] Audit log shows `SSH_LOGIN_SUCCESS` with OIDC fields: `sudo grep SSH_LOGIN_SUCCESS /var/log/unix-oidc-audit.log`
- [ ] If CIBA enabled: `sudo` triggers step-up on test user's phone
- [ ] Break-glass SSH login works: `ssh breakglass@pilot-server`
- [ ] SIEM received `BREAK_GLASS_AUTH` event from break-glass test

### Rollback Test

- [ ] Comment out OIDC PAM line: `sudo sed -i 's/^auth.*pam_unix_oidc/#&/' /etc/pam.d/sshd`
- [ ] Verify existing auth still works
- [ ] Uncomment OIDC PAM line to restore

---

## Fleet Deployment

### Ansible Deployment

```bash
ansible-playbook -i inventory deploy/ansible/site.yml \
    -e prmana_issuer_url=https://your-idp.example.com/realms/corp \
    -e prmana_pam_module_src=./libpam_unix_oidc.so \
    -e prmana_break_glass_password_hash='$6$...'
```

### Per-Server Validation

For each server in the fleet:

- [ ] OIDC login works for at least one user
- [ ] Break-glass validated (automated: `./scripts/validate-break-glass.sh --host $HOST`)
- [ ] Audit events flowing to SIEM

### Fleet-Wide Checks

- [ ] All servers have break-glass configured (run validation across fleet)
- [ ] SIEM dashboard shows auth events from all deployed servers
- [ ] Client agent deployed to user workstations
- [ ] Users briefed on new login flow (device flow or auth code)

---

## Post-Deployment

### Migration to OIDC-Primary

After confidence period (recommended: 2 weeks of parallel running):

- [ ] Switch PAM mode from `parallel` to `primary` (OIDC first, password fallback)
- [ ] Monitor for `SSH_LOGIN_FAILED` events (users who haven't migrated)
- [ ] Follow up with users still using SSH keys

### SSH Key Sunset

After all users validated on OIDC:

- [ ] Archive authorized_keys files: `tar czf /root/authorized_keys_backup.tar.gz $(find /home -name authorized_keys)`
- [ ] Remove authorized_keys files
- [ ] Disable PubkeyAuthentication in sshd_config
- [ ] Verify break-glass still works after key removal

### Ongoing

- [ ] Quarterly break-glass validation (see `docs/break-glass-validation.md`)
- [ ] Monitor `IDP_FAILOVER_ACTIVATED` events (if failover configured)
- [ ] Monitor `IDP_FAILOVER_EXHAUSTED` events (critical — both IdPs down)
- [ ] Review `AUTH_NO_TOKEN` events (users attempting SSH without OIDC tokens)

---

## Reference Documents

| Document | Purpose |
|---|---|
| `docs/migration-guide.md` | Step-by-step migration from SSH keys to OIDC |
| `docs/dns-failover-guide.md` | DNS-level IdP failover patterns |
| `docs/break-glass-validation.md` | Break-glass testing procedures |
| `docs/deployment-patterns.md` | Architecture patterns for different environments |
| `deploy/templates/` | YAML configuration templates |
| `deploy/ansible/` | Ansible role for fleet deployment |
| `scripts/ssh-key-inventory.sh` | SSH key discovery tool |
| `scripts/validate-break-glass.sh` | Automated break-glass validation |

---

*Deploy incrementally. Validate at every step. Keep break-glass working. The goal is a boring migration with no surprises.*
