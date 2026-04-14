# logcollect — Fleet Log Collection Scripts

These scripts collect per-instance diagnostics from the prmana-ci fleet after a test
scenario runs. They are invoked by the `fleet-test.yml` workflow after the scenario
step and before `terraform destroy`.

## What Is Collected

| File | Source | Notes |
|------|--------|-------|
| `journalctl.json` | `journalctl --no-pager -o json` | Structured JSON; falls back to plain text if json output unsupported |
| `dmesg.log` | `dmesg --time-format iso` | ISO-format timestamps; falls back to `dmesg` |
| `systemctl-status.txt` | `systemctl status --all --no-pager` | All unit statuses; non-zero exit tolerated |
| `audit.log` | `/var/log/audit/audit.log` | Requires auditd; falls back to a placeholder message |
| `metadata.txt` | `/etc/prmana-ci-metadata` | Written by Terraform user-data/cloud-init; absent pre-install |
| `uname.txt` | `uname -a` | Kernel and architecture |
| `os-release.txt` | `/etc/os-release` | Distro name and version |
| `collection-errors.txt` | (internal) | Records commands that failed during collection |

## Output Directory Structure

After `aggregate.sh` runs, the `OUTPUT_DIR` (default `./fleet-logs`) contains:

```
fleet-logs/
  10.0.1.5/
    journalctl.json
    dmesg.log
    systemctl-status.txt
    audit.log
    metadata.txt
    uname.txt
    os-release.txt
    collection-errors.txt
  10.0.1.5.tar.gz          # raw tarball (kept for re-extraction)
  10.0.1.6/
    ...
  10.0.1.6.error.txt       # written only if collection failed for that IP
```

The directory is uploaded as a GitHub Actions artifact named
`fleet-logs-<run_id>` with 7-day retention.

## Running Manually

```bash
# From the repository root, with an active fleet:
INSTANCE_IPS="1.2.3.4 5.6.7.8" \
SSH_USER=ubuntu \
SSH_KEY_PATH=/tmp/fleet_key \
OUTPUT_DIR=./fleet-logs \
  bash test/infra/logcollect/aggregate.sh
```

## Security Notes

- **No redaction is applied.** Logs are collected raw. This is intentional: adding a
  half-baked redaction layer creates false confidence while missing edge cases.
  DT-0 does not install prmana, so no OIDC tokens, DPoP proofs, or client secrets
  appear in the collected output. The logs may contain PAM authentication attempt
  records (usernames, timestamps) from the OS itself.
- **DT-A note:** When prmana is installed (DT-A and later), evaluate whether
  `audit.log` entries warrant redaction before upload. The artifact retention period
  (7 days) limits exposure; the repo is private so artifacts are visible only to
  collaborators.
- **SSH keypair:** The private key at `SSH_KEY_PATH` is an ephemeral keypair generated
  in-workflow. It is never uploaded as an artifact.

## Failure Modes

| Failure | Behavior |
|---------|---------|
| SSH unreachable | Per-instance `<ip>.error.txt` written; collection continues for remaining IPs |
| sudo unavailable | `collect.sh` falls back to unprivileged collection; gaps noted in `collection-errors.txt` |
| Disk full on instance | `tar` fails; `<ip>.error.txt` written; collection continues |
| All instances fail | `aggregate.sh` exits 1 (workflow step fails, but `if: always()` teardown still runs) |

## Dependencies

- `ssh`, `scp` — present in all GitHub-hosted ubuntu-latest runners by default
- `tar`, `gzip` — present in all GitHub-hosted ubuntu-latest runners by default
- No additional installation required on the runner

On the instances, `collect.sh` requires:
- `journalctl` — available on all systemd distros (all supported distros in the matrix)
- `dmesg` — available on all Linux instances
- `systemctl` — available on all systemd distros
- `tar`, `gzip` — available on all distros
