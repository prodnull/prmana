# prmana PAM Integration Guide

This document explains how to configure the `pam_prmana.so` PAM module for SSH, sudo,
and console authentication.

## Prerequisites

- `prmana` package installed (provides both `pam_prmana.so` and `prmana-agent`)
- Identity provider (Okta, Entra ID, Auth0, Keycloak) configured
- `/etc/prmana/policy.yaml` configured (copy from `/etc/prmana/policy.yaml.example`)
- **Break-glass local account configured and tested** — see §Break-Glass below

## PAM Configuration

### SSH (recommended starting point)

Edit `/etc/pam.d/sshd`:

```
# prmana OIDC authentication — must appear before pam_unix.so
auth    sufficient  pam_prmana.so  config=/etc/prmana/policy.yaml
auth    required    pam_unix.so    use_first_pass

account required    pam_prmana.so  config=/etc/prmana/policy.yaml
account required    pam_unix.so

session required    pam_prmana.so  config=/etc/prmana/policy.yaml
session required    pam_unix.so
```

Or use the included snippet:

```bash
echo "@include prmana-auth" >> /etc/pam.d/sshd
cp /usr/share/prmana/pam.d/prmana-auth /etc/pam.d/prmana-auth
```

Also ensure `/etc/ssh/sshd_config` has:

```
ChallengeResponseAuthentication yes
UsePAM yes
```

### sudo

Edit `/etc/pam.d/sudo`:

```
auth    sufficient  pam_prmana.so  config=/etc/prmana/policy.yaml step_up=device
auth    required    pam_unix.so    use_first_pass
```

The `step_up=device` option triggers a device authorization flow (RFC 8628) when sudo
is invoked, requiring the user to approve via browser. Omit it if you want transparent
sudo without step-up.

## PAM Module Path

The `.so` is installed at the path appropriate for your distribution:

| Distribution | PAM module path |
|---|---|
| Debian 12 / Ubuntu 22.04+ (amd64) | `/lib/x86_64-linux-gnu/security/pam_prmana.so` |
| Debian 12 / Ubuntu 22.04+ (arm64) | `/lib/aarch64-linux-gnu/security/pam_prmana.so` |
| RHEL 9 / Rocky 9 / AL2023 | `/usr/lib64/security/pam_prmana.so` |

PAM resolves module names without the `lib` prefix and without the full path (when
`/etc/ld.so.conf.d/` is configured correctly). The package maintainer scripts run
`ldconfig` on install. You can use the bare module name `pam_prmana.so` in PAM configs.

## Policy Configuration

The policy file at `/etc/prmana/policy.yaml` controls:

- Which OIDC issuers are accepted
- DPoP requirements (required/optional/disabled)
- Username mapping (from JWT claims to local Unix usernames)
- Group membership enforcement
- Break-glass bypass accounts

See `/etc/prmana/policy.yaml.example` for a documented template.

## Break-Glass

**Always configure a break-glass account before enabling prmana.**

If the prmana agent is unavailable (IdP outage, network failure, misconfiguration),
PAM falls back to `pam_unix.so` because `pam_prmana.so` is configured `sufficient`.
However, you must have a local account with a password set:

```bash
# Create break-glass account (before enabling prmana)
sudo useradd -m -s /bin/bash breakglass
sudo passwd breakglass
# Store the password in your organization's secure vault
```

See [docs/rollout-checklist.md](rollout-checklist.md) for the full pre-deployment
checklist including break-glass validation procedures.

## Troubleshooting

### Authentication fails immediately

Check journald for PAM module logs:

```bash
journalctl -u sshd --since "5 minutes ago"
```

Common causes:
- Agent not running: `systemctl status prmana-agent.socket`
- Config not found: check `/etc/prmana/policy.yaml` exists
- Clock skew: `date` on client and server should match within 60 seconds

### "pam_prmana.so: cannot open shared object file"

Run `ldconfig` to refresh the dynamic linker cache:

```bash
sudo ldconfig
```

### Token rejected ("invalid issuer" or "audience mismatch")

Check that `policy.yaml` `issuers[].issuer` matches the `iss` claim in the JWT exactly
(including trailing slash if present in the IdP's configuration).

## References

- [Installation guide](installation.md)
- [User guide](user-guide.md)
- [Deployment patterns](deployment-patterns.md)
- [Rollout checklist](rollout-checklist.md)
- RFC 7468 — PAM API specification
- RFC 9449 — DPoP
