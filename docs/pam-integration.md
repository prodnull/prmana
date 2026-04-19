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
# Must run first so prmana gets a fresh per-login session keyring
# rather than the shared per-UID @us keyring.
session required    pam_keyinit.so  force revoke

# prmana OIDC authentication — must appear before pam_unix.so
auth    sufficient  pam_prmana.so  config=/etc/prmana/policy.yaml
auth    required    pam_unix.so    use_first_pass

account required    pam_prmana.so  config=/etc/prmana/policy.yaml
account required    pam_unix.so

session required    pam_prmana.so  config=/etc/prmana/policy.yaml
session required    pam_unix.so
```

The `pam_keyinit.so force revoke` line is required when downstream PAM consumers read session claims from the kernel keyring via `PRMANA_KEY` (see §"Session Claims in the Kernel Keyring" below). Without it, the session keyring falls back to the shared per-UID `@us` keyring, and prmana refuses to publish there (warn + continue, non-fatal). Integrators that only consume PAM env vars (`PRMANA_SESSION_ID`, `PRMANA_TOKEN_JTI`, `PRMANA_TOKEN_EXP`, `PRMANA_ISSUER`) don't need this line, but it's recommended anyway.

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

## Session Claims in the Kernel Keyring

On successful authentication, `pam_prmana` publishes a small, versioned,
printable-ASCII payload of selected token claims into the Linux kernel
session keyring and exposes the key's serial number as `PRMANA_KEY` in
the PAM environment. Downstream PAM modules in the same transaction
(audit correlators, nftables session gating, attestation-aware helpers)
can retrieve the payload via `keyctl read $PRMANA_KEY` without needing
the agent or trusting PAM env vars to survive the sshd privsep fork.

**Payload format (wire contract, ABI-stable within version 1):**

```
v=1;jti=<token jti>;exp=<unix ts>;iss=<issuer url>;sid=<prmana session id>;user=<unix user>;uid=<unix uid>[;acr=<value>][;dpop=<jwk thumbprint>]
```

Values are percent-encoded for `;`, `=`, `%`, NUL, CR, LF. Oversized
claims that would push the payload past 256 bytes are skipped whole —
the output is always a valid wire format.

**Keyring semantics:**

- Anchor: per-login session keyring (`KEY_SPEC_SESSION_KEYRING`). prmana
  refuses to publish if the resolved target is the shared `@us` keyring
  (see `pam_keyinit.so` note above).
- ACL: POSSESSOR view/read/search only. The user's shell, descendants,
  and any setuid helpers (including `sudo`) possess the key. Other UIDs
  cannot access it.
- TTL: aligned to the token's `exp` claim, clamped to `[1, 86400]`
  seconds. Kernel reaps the key on expiry or last-reference drop.
- Failure: non-fatal. If publication fails for any reason (kernel quota,
  `@us` detected, LSM policy), `PRMANA_KEY` is absent and consumers
  MUST fall through to the env-var-only path.

**Consuming the payload from a downstream PAM module:**

```c
const char *serial_str = pam_getenv(pamh, "PRMANA_KEY");
if (serial_str) {
    key_serial_t serial = atoi(serial_str);
    char buf[256];
    long n = keyctl_read(serial, buf, sizeof buf);
    // parse v=1;k=v;... with percent-decoding
}
```

Consumers MUST key off the `sid` field (or the key description
`prmana_<sid>`) rather than assuming a singleton `prmana_*` key per
session tree. Multiple successful authentications in the same tree
each publish a distinct entry.

Details in [ADR-026](adr/026-kernel-keyring-session-claims.md) and
[TB-8 in the threat model](threat-model.md).

## References

- [Installation guide](installation.md)
- [User guide](user-guide.md)
- [Deployment patterns](deployment-patterns.md)
- [Rollout checklist](rollout-checklist.md)
- [ADR-026](adr/026-kernel-keyring-session-claims.md) — kernel-keyring session-claims ABI
- RFC 7468 — PAM API specification
- RFC 9449 — DPoP
- `keyrings(7)`, `session-keyring(7)`, `pam_keyinit(8)`
