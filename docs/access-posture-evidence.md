# Access Posture & Evidence

Phase 45 adds a local/export-first evidence path for `pam-prmana`.

The goal is not to create a dashboard or management plane inside the PAM module.
Instead, it provides two deterministic outputs that operators can use directly or
feed into a later fleet service:

- a host posture snapshot derived from `policy.yaml`
- a filtered evidence export derived from structured audit events

## Binary

The crate now installs:

```bash
prmana-evidence-export
```

## Posture Snapshots

Generate a host-local posture snapshot from the effective policy:

```bash
prmana-evidence-export posture \
  --policy /etc/prmana/policy.yaml
```

The JSON snapshot includes:

- `policy_sha256` for change tracking
- `module_version`
- host classification
- issuer posture such as DPoP, ACR, attestation, and delegation state
- sudo privilege-policy posture
- break-glass posture
- high-signal findings such as dry-run mode or weak DPoP enforcement

This is intended for:

- rollout verification
- audit preparation
- future fleet posture collection

## Evidence Exports

Generate a filtered evidence bundle from the structured audit log:

```bash
prmana-evidence-export export \
  --file /var/log/prmana-audit.log \
  --policy /etc/prmana/policy.yaml \
  --event BREAK_GLASS_AUTH \
  --event STEP_UP_FAILED
```

By default the output is pretty-printed JSON. CSV is also supported:

```bash
prmana-evidence-export export \
  --file /var/log/prmana-audit.log \
  --format csv
```

Optional filters:

- `--from 2026-04-10T00:00:00Z`
- `--to 2026-04-10T23:59:59Z`
- repeated `--event EVENT_NAME`

## What Gets Summarized

The evidence bundle summarizes high-signal posture and access activity, including:

- break-glass usage
- IdP failover activity
- failover-served logins
- privilege-policy denies
- privilege-policy dry-run hits
- step-up successes and failures
- per-event-type counts

The export intentionally normalizes the audit stream into stable rows instead of
exposing every event-specific field. That keeps downstream ingestion simpler and
reduces schema churn.

## Security Notes

- The exporter is read-only. It does not modify policy or audit state.
- The exporter fails closed on malformed audit lines rather than silently skipping them.
- Posture snapshots are derived from the current local policy file, not from guessed defaults.
- Evidence exports rely on the existing structured audit trail; if audit logging is disabled,
  there is no evidence stream to export.

## Example Uses

Review hosts still running dry-run sudo policy:

```bash
prmana-evidence-export posture | jq '.findings[] | select(.id == "sudo_policy_dry_run")'
```

Export break-glass and failover events for an audit window:

```bash
prmana-evidence-export export \
  --file /var/log/prmana-audit.log \
  --from 2026-04-01T00:00:00Z \
  --to 2026-04-30T23:59:59Z \
  --event BREAK_GLASS_AUTH \
  --event IDP_FAILOVER_ACTIVATED \
  --event IDP_FAILOVER_EXHAUSTED
```
