# Break-Glass Validation Playbook

Break-glass access is the last line of defense when OIDC authentication is unavailable. **Validate it before every migration, and test it quarterly.**

## What Break-Glass Provides

A local account on each server that authenticates via password (not OIDC). When the IdP is down, DNS is broken, or the PAM module has a bug, break-glass gets you in.

## Automated Validation

```bash
# Validate locally
sudo ./scripts/validate-break-glass.sh

# Validate a remote host
./scripts/validate-break-glass.sh --host server.example.com

# Validate all hosts in a fleet
while read host; do
    echo "--- $host ---"
    ./scripts/validate-break-glass.sh --host "$host"
    echo ""
done < hosts.txt
```

The script checks: policy config, break-glass user existence, PAM configuration, sshd password auth, and alert settings.

## Manual Validation Procedure

When automated validation passes, do a real login test:

### 1. Verify the break-glass account can SSH in

```bash
# From a machine that does NOT have the unix-oidc-agent installed
# (simulates "IdP is completely down" scenario)
ssh breakglass@server.example.com
# Enter the break-glass password when prompted
```

### 2. Verify the SIEM alert fires

If `alert_on_use: true` is set (it should be), the `BREAK_GLASS_AUTH` audit event is emitted at CRITICAL severity. Verify your SIEM receives it:

```bash
# On the server, check the audit log
sudo grep BREAK_GLASS_AUTH /var/log/unix-oidc-audit.log
```

### 3. Verify sudo works under break-glass

```bash
# As the break-glass user
sudo whoami
# Should output: root
```

### 4. Document the credentials

Break-glass credentials must be stored in your organization's emergency access vault (not a wiki, not a Slack channel, not a sticky note):

- **Recommended:** Hardware security module or physical safe
- **Acceptable:** Secrets manager (HashiCorp Vault, AWS Secrets Manager) with break-glass-specific access policy
- **Not acceptable:** Shared document, email, chat message

## When to Run This Playbook

| Trigger | Why |
|---|---|
| After initial Prmana installation | Validate before relying on OIDC |
| Before disabling SSH key auth | Last chance to verify fallback works |
| After PAM config changes | PAM ordering affects break-glass reachability |
| After sshd_config changes | PasswordAuthentication could be disabled |
| Quarterly DR exercise | Credentials may have been rotated or account locked |
| After IdP configuration changes | Policy changes could affect break-glass behavior |

## Common Failures

| Failure | Cause | Fix |
|---|---|---|
| "Permission denied" | Password hash mismatch or account locked | Regenerate hash; check `passwd -S breakglass` |
| "Connection refused" | sshd not running or firewall blocking | Check `systemctl status sshd`; check firewall rules |
| No SIEM alert | `alert_on_use: false` or audit log not forwarded | Set `alert_on_use: true`; check syslog forwarding |
| "Account expired" | Break-glass user account expired | `sudo chage -E -1 breakglass` to remove expiry |

---

*Break-glass is not optional. Every server running Prmana must have a validated break-glass path. Test it before you need it.*
