# GDPR Article 17 Erasure Guide for prmana

**Audience:** Data Protection Officers, compliance teams, system administrators
responsible for responding to GDPR "right to erasure" (right to be forgotten) requests.

**Scope:** This document covers all personal data (as defined in GDPR Art. 4(1)) that
prmana stores, processes, or logs during normal operation, together with the
procedures required to erase that data upon a valid erasure request under GDPR Art. 17.

**Limitation of liability notice:** This guide describes the technical erasure procedures
available within prmana. It does not constitute legal advice. Organizations subject
to GDPR must work with their Data Protection Officer and legal counsel to determine
whether an erasure request qualifies under Art. 17(1) and whether any Art. 17(3)
exemptions apply.

---

## Section 1: Data Inventory

The following table enumerates every data category prmana handles, where it lives,
how long it persists, and whether it constitutes personal data under GDPR Art. 4(1).

| Data Type | Storage Location | Retention | Contains PII | Notes |
|-----------|-----------------|-----------|--------------|-------|
| OIDC access tokens | Agent process memory (`SecretString`) | Session lifetime — cleared on agent exit or token refresh | Yes — `sub`, `email`, `preferred_username` claims | Protected in memory by `secrecy` crate; never appears in logs |
| OIDC refresh tokens | System keyring (Secret Service / macOS Keychain) or `~/.local/share/prmana/` | Until explicitly revoked or agent storage cleared | Yes — bearer credential tied to user identity | Stored via `prmana-agent storage` backend |
| DPoP private keys (ephemeral, in-memory) | Agent process memory (`ProtectedSigningKey`) | Session lifetime — zeroed on drop via `ZeroizeOnDrop` | No — ephemeral key material with no identity linkage | Pages locked via `mlock(2)`; never written to disk in normal operation |
| DPoP private keys (persisted) | System keyring or `~/.local/share/prmana/` | Until key rotation or storage clear | No | Stored by key thumbprint; no PII in the key itself |
| Session records | `/run/prmana/sessions/{session-id}.json` | Active session lifetime; swept by `SESSION_SWEEP` task | Yes — username, source IP, session start time | Under `/run`; lost on reboot; files are mode 0600 root |
| Audit log entries (file) | `/var/log/prmana-audit.log` | Per logrotate retention policy (default: 1 year) | Yes — username, source IP, issuer URL, timestamps | See `docs/log-retention.md` for compliance periods |
| Audit log entries (syslog) | syslog daemon (varies: `/var/log/auth.log`, journald) | Per syslog/journald retention policy | Yes | Rotation managed by system syslog, not prmana |
| Audit log entries (SIEM) | External SIEM (Splunk, ELK, Datadog, CloudWatch, etc.) | Per SIEM/org retention policy | Yes | Outside prmana's control — see §3 |
| Issuer health state | `/run/prmana/issuer-health/{issuer-hash}.json` | Transient; lost on reboot | No — contains issuer URL hash, failure count, timestamps only | Not linked to any individual user |
| Configuration files | `/etc/prmana/policy.yaml`, `/etc/prmana/config.yaml` | Indefinite — until updated by administrator | Conditionally — break-glass usernames if configured | PII only if operator includes real usernames in break-glass config |

### PII Classification Summary

prmana's primary PII exposure is in **audit log entries** and **session records**.
Tokens and keys are cryptographic material — the token JWT payload may contain PII
(identity claims) but the token itself is held in memory as a `SecretString` and is
never written to logs in plaintext.

---

## Section 2: Erasure Procedures

### 2.1 Erasure by Data Type

#### In-Memory Data (Access Tokens, Ephemeral DPoP Keys)

**Mechanism:** Automatic. No manual action is possible or necessary.

- `SecretString` (access/refresh tokens in memory) is zeroed by the `secrecy` crate's
  `Drop` implementation when the owning struct is dropped.
- `ProtectedSigningKey` (DPoP private keys in memory) calls `ZeroizeOnDrop` (via the
  `zeroize` crate) and `libc::munlock()` on drop.
- Both occur when the prmana-agent process terminates or the session ends.

**Limitation:** `zeroize` uses volatile writes to resist compiler optimization; it
cannot guarantee zeroing on all compiler/architecture combinations, though the `zeroize`
crate makes a best-effort guarantee (see crate documentation). `mlock` prevents OS swap
but does not protect against root-level memory access.

#### Keyring-Stored Credentials (Refresh Tokens, Persisted DPoP Keys)

**Mechanism:** `prmana-agent storage clear` or manual keyring deletion.

```bash
# Preferred: use the agent's built-in storage management command
prmana-agent storage clear

# Linux — Secret Service (GNOME Keyring / KWallet)
# List items to confirm before deletion:
secret-tool search service prmana
# Delete all prmana items:
secret-tool clear service prmana

# Linux — kernel keyutils (user keyring)
# List items:
keyctl show @u | grep prmana
# Revoke each key by ID:
keyctl revoke <key-id>

# macOS — Keychain
security delete-generic-password -s prmana -a <username>
```

**Verification:**

```bash
# After clearing, confirm no prmana items remain
secret-tool search service prmana   # Linux Secret Service
keyctl show @u                          # Linux keyutils
security find-generic-password -s prmana  # macOS
```

#### File-Based Storage (`~/.local/share/prmana/`)

**Mechanism:** `prmana-agent storage clear` invokes a three-pass secure overwrite
per NIST SP 800-88 Rev 1 §2.4 (Clear method) before calling `unlink`. The passes are:

1. Write random bytes + `sync_all()`
2. Write bitwise complement (XOR 0xFF) of pass 1 + `sync_all()`
3. Write new random bytes + `sync_all()`
4. `unlink`

Manual deletion if the agent is unavailable:

```bash
# Secure wipe and remove (GNU coreutils shred)
shred -u ~/.local/share/prmana/token
shred -u ~/.local/share/prmana/dpop-key

# Or remove the entire directory
shred -u ~/.local/share/prmana/*
rmdir ~/.local/share/prmana/
```

**CoW/SSD limitation:** On Copy-on-Write filesystems (btrfs, APFS) and SSD devices
with wear-leveling firmware, the three-pass overwrite may not modify the original data
blocks. prmana logs a WARNING at startup if CoW or SSD is detected. The authoritative
mitigation for these environments is full-disk encryption — see NIST SP 800-88 Rev 1
§2.5. On encrypted volumes, key erasure (destroying the encryption key) is sufficient
to render the data irrecoverable.

#### Session Records (`/run/prmana/sessions/`)

**Mechanism:** Session files are automatically deleted when the session closes. A
session sweep task removes stale records for sessions that did not close cleanly.

Manual erasure for a specific user's sessions:

```bash
# Find session files for a specific user
grep -rl '"username":"alice"' /run/prmana/sessions/

# Remove them (these are under /run — not persistent across reboots)
# Files are mode 0600 root; requires root access
find /run/prmana/sessions/ -name '*.json' \
  -exec grep -l '"username":"alice"' {} \; -delete
```

All session records under `/run` are lost on reboot. If a system reboot is performed
as part of the erasure procedure, session records are automatically cleared.

#### Audit Logs (Local File: `/var/log/prmana-audit.log`)

**Mechanism:** Secure deletion of the audit log file plus any rotated copies.

```bash
# Erase the active audit log and all rotated copies
shred -u /var/log/prmana-audit.log
shred -u /var/log/prmana-audit.log.1
shred -u /var/log/prmana-audit.log.*.gz  # compressed rotations

# Or, for the full prmana log directory:
find /var/log/prmana/ -type f | xargs shred -u
```

**Partial erasure (targeted user):** If only the affected user's log entries must be
erased (not the entire log file), extract a new log file excluding the user's entries
and replace the original:

```bash
# Requires jq; erases entries for username "alice"
# Step 1: Create filtered copy (no alice entries)
jq -c 'select(.username != "alice")' \
  /var/log/prmana-audit.log > /tmp/audit-filtered.log

# Step 2: Verify the filtered file looks correct
wc -l /var/log/prmana-audit.log /tmp/audit-filtered.log

# Step 3: Atomically replace with shred of original
shred -u /var/log/prmana-audit.log
mv /tmp/audit-filtered.log /var/log/prmana-audit.log
chmod 0640 /var/log/prmana-audit.log
chown root:adm /var/log/prmana-audit.log

# Step 4: Apply the same procedure to all rotated files
```

**Tamper-evidence chain break warning:** If HMAC chain tamper-evidence is enabled
(see `docs/observability.md`), removing individual log entries will break the HMAC
chain for subsequent entries. After targeted erasure, the chain cannot be repaired
for the affected log file. Document this in your erasure record.

#### Audit Logs (syslog / journald)

```bash
# journald — rotate and vacuum entries for a specific user
# (journald does not support per-message deletion)
# Rotate: forces a new journal file, permitting vacuum of old file
journalctl --rotate

# Vacuum all journal entries older than a specific date
journalctl --vacuum-time=2026-01-01  # removes journals before this date

# Targeted: export filtered journal, clear, re-import is NOT supported.
# For per-user erasure, the only option is a full journal segment deletion
# which may remove entries from other users/services in the same segment.
```

**Note:** syslog/journald does not support surgical per-record deletion. If per-user
audit log erasure is required and syslog is the primary log channel, consider migrating
to file-based audit logging (prmana `audit.output: file`) to enable the targeted
erasure procedure above.

#### Configuration Files (`/etc/prmana/`)

Configuration files normally contain no PII. The only exception is if an operator
has configured real usernames as break-glass account names:

```yaml
# If policy.yaml contains real usernames:
break_glass:
  username: alice  # PII — should use a dedicated service account, not a real user
```

If a break-glass username corresponds to a departed user whose data must be erased,
replace the username with a non-identifiable service account name and save the file.

---

## Section 3: What Cannot Be Erased by prmana

The following data categories are outside prmana's control once they leave the
system. Data controllers must contact the relevant parties to complete erasure.

### 3.1 External SIEM and Log Aggregators

Audit events forwarded to Splunk, Elastic, Datadog, AWS CloudWatch Logs, or any
other external system cannot be deleted or modified by prmana. The data controller
must:

1. Submit a deletion request to the SIEM platform's API (e.g., Splunk `delete`
   command, Elastic `delete by query`, Datadog `delete logs`).
2. If the SIEM is a managed service operated by a third party, issue a deletion
   instruction under the relevant data processing agreement (GDPR Art. 28(3)(f)).
3. Confirm deletion is complete and document the confirmation in the erasure record.

**Note:** Many SIEM platforms do not support per-record deletion. Check your platform's
documentation and confirm with your DPA obligations.

### 3.2 Kernel Audit Subsystem (auditd)

If the Linux `auditd` daemon is configured to capture PAM events (common in FedRAMP
and PCI-DSS environments), authentication events will appear in `/var/log/audit/audit.log`
independently of prmana's own audit log. Erasure from auditd requires:

```bash
# Rotate the audit log to close the current file
auditctl --rotate

# Archive or shred old audit files
shred -u /var/log/audit/audit.log.1  # after rotation
```

The `aureport` and `ausearch` utilities can be used to locate specific user entries
before deletion.

### 3.3 Identity Provider (IdP) Records

The OIDC identity provider (Okta, Azure Entra ID, Keycloak, Auth0, etc.) retains its
own records of token issuance, refresh, and revocation events. These records are
controlled by the IdP administrator, not prmana. To erase IdP-side records:

- **Revoke all tokens:** Use the IdP's admin console or API to revoke the user's
  active sessions and tokens. This is a required step regardless of erasure scope.
- **Delete activity logs:** Contact the IdP's support or use their audit log API.
  Most enterprise IdPs retain audit logs for 30–90 days by default.
- **Delete the user account:** If full erasure is required, delete the user from
  the IdP. Note this will prevent re-login and may affect other services.

### 3.4 CoW Filesystem Snapshots

On btrfs or APFS filesystems, volume snapshots may retain copies of overwritten files.
These snapshots are outside prmana's control. To ensure complete erasure:

1. Delete all snapshots that predate the erasure event.
2. If snapshots cannot be deleted, document the limitation in the erasure record and
   note that full-disk encryption (with key destruction) is the mitigation per
   NIST SP 800-88 Rev 1 §2.5.

### 3.5 Storage Media Backups

Backup copies of log files or credential storage files that exist on tape, object
storage (S3, GCS), or backup appliances must be erased separately. The data controller
is responsible for identifying all backup media containing the subject's data and
initiating erasure per the backup system's procedures.

---

## Section 4: Implementation Guidance for Data Controllers

This section provides a step-by-step procedure for responding to a GDPR Article 17
erasure request for a specific user in a prmana deployment.

### 4.1 Pre-Erasure: Validate the Request

Before erasing data, verify:

1. The request is from the data subject or a legally authorized representative.
2. The erasure is not subject to an Art. 17(3) exemption (see §4.4 below).
3. The request is documented in your organization's erasure request log.

### 4.2 Step-by-Step Erasure Checklist

```
[ ] 1. Revoke tokens at the IdP
        - Log into the IdP admin console
        - Revoke all active sessions and tokens for the user
        - If the IdP supports API-based revocation, use it for automation

[ ] 2. Disable the user's account (prevent re-authentication during erasure)
        - Disable at IdP level, OR
        - Remove from any prmana group/role policies

[ ] 3. Clear agent storage (if the user runs prmana-agent on any endpoint)
        - On each affected endpoint, as the user or root:
          prmana-agent storage clear
        - Verify no entries remain (see §2.1 verification commands)

[ ] 4. Delete active session records
        - find /run/prmana/sessions/ -name '*.json' \
            -exec grep -l '"username":"<user>"' {} \; -delete

[ ] 5. Purge local audit log entries
        - File log: targeted erasure or full log rotation (see §2.1)
        - syslog/journald: vacuum affected journal segments
        - Document if per-record deletion was not possible

[ ] 6. Purge external SIEM entries
        - Submit deletion request per SIEM platform procedure
        - Obtain confirmation and retain as evidence

[ ] 7. Purge backup copies
        - Identify all backup jobs/media containing prmana logs
        - Initiate erasure per backup system procedures
        - Document any media that cannot be erased (e.g., offline tapes)

[ ] 8. Purge IdP-side audit logs
        - Use IdP admin API to delete token issuance records (if API available)
        - Document retention period and expected auto-deletion date if API
          deletion is not supported

[ ] 9. Record erasure completion
        - Document: what was erased, when, by whom, and any limitations
        - File in your erasure request registry
        - Retain the erasure record itself (this is not PII of the subject)
        - Respond to the data subject within the GDPR 30-day window
```

### 4.3 Automation Template

The following shell script provides a starting point for automating Steps 3–5. Adapt
to your environment before use. This script requires root access on the target server.

```bash
#!/usr/bin/env bash
# prmana-gdpr-erase.sh
# GDPR Article 17 erasure helper for prmana
# Usage: prmana-gdpr-erase.sh <username>
#
# IMPORTANT: Review and adapt before production use.
# This script does NOT revoke IdP tokens or SIEM entries — do those manually.

set -euo pipefail

USERNAME="${1:?Usage: $0 <username>}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LOG_FILE="/var/log/prmana-gdpr-erase-${USERNAME}-${TIMESTAMP}.log"

echo "Starting GDPR erasure for username: ${USERNAME}" | tee -a "${LOG_FILE}"
echo "Timestamp: ${TIMESTAMP}" | tee -a "${LOG_FILE}"

# Step 1: Remove session records
echo "==> Removing session records..." | tee -a "${LOG_FILE}"
SESSION_FILES=$(grep -rl "\"username\":\"${USERNAME}\"" \
  /run/prmana/sessions/ 2>/dev/null || true)
if [[ -n "${SESSION_FILES}" ]]; then
    echo "${SESSION_FILES}" | xargs rm -f
    echo "    Removed: ${SESSION_FILES}" | tee -a "${LOG_FILE}"
else
    echo "    No active session records found." | tee -a "${LOG_FILE}"
fi

# Step 2: Targeted erasure of local audit log entries
echo "==> Filtering audit log..." | tee -a "${LOG_FILE}"
if [[ -f /var/log/prmana-audit.log ]]; then
    ORIG_COUNT=$(wc -l < /var/log/prmana-audit.log)
    jq -c --arg u "${USERNAME}" 'select(.username != $u)' \
      /var/log/prmana-audit.log > /tmp/prmana-audit-filtered.log
    FILTERED_COUNT=$(wc -l < /tmp/prmana-audit-filtered.log)
    REMOVED=$(( ORIG_COUNT - FILTERED_COUNT ))
    echo "    Removed ${REMOVED} log entries for ${USERNAME}" | tee -a "${LOG_FILE}"
    shred -u /var/log/prmana-audit.log
    mv /tmp/prmana-audit-filtered.log /var/log/prmana-audit.log
    chmod 0640 /var/log/prmana-audit.log
    chown root:adm /var/log/prmana-audit.log
    echo "    NOTE: If HMAC tamper-evidence is enabled, the chain is now broken." \
      | tee -a "${LOG_FILE}"
else
    echo "    /var/log/prmana-audit.log not found; skipping." | tee -a "${LOG_FILE}"
fi

# Step 3: Rotate agent storage (run as the user if possible)
echo "==> To clear agent storage for ${USERNAME}, run as that user:" | tee -a "${LOG_FILE}"
echo "    prmana-agent storage clear" | tee -a "${LOG_FILE}"

echo "" | tee -a "${LOG_FILE}"
echo "==> Local erasure complete. Remaining steps (manual):" | tee -a "${LOG_FILE}"
echo "    1. Revoke tokens at IdP" | tee -a "${LOG_FILE}"
echo "    2. Purge external SIEM entries for ${USERNAME}" | tee -a "${LOG_FILE}"
echo "    3. Purge backup copies of audit logs" | tee -a "${LOG_FILE}"
echo "    4. Purge IdP-side audit logs" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "Erasure record written to: ${LOG_FILE}" | tee -a "${LOG_FILE}"
```

### 4.4 Article 17(3)(b) Exemption: Legal Compliance Retention

GDPR Art. 17(3)(b) states that the right to erasure does not apply where processing
is necessary "for compliance with a legal obligation which requires processing by
Union or Member State law to which the controller is subject."

In a prmana deployment, this exemption applies when audit logs are retained as
evidence for:

- **SOC 2 Type II audit requirements** — the audit trail is required to support the
  auditor's examination of CC7.2 (monitoring of controls) and CC7.3 (incident response).
- **PCI-DSS v4.0 Requirement 10.7** — audit logs covering cardholder data environment
  access must be retained for 1 year.
- **FedRAMP AU-11** — log retention is required by the authority operating the
  federal information system.
- **National law** (varies by jurisdiction) — some EU member states have specific
  retention requirements for security/audit logs in regulated sectors.

When invoking Art. 17(3)(b), the data controller must:

1. Document the specific legal obligation that requires retention.
2. Limit the retained data to what is strictly necessary for that obligation.
3. Inform the data subject of the exemption and the expected retention period.
4. Delete the data as soon as the retention obligation expires.

Work with your Data Protection Officer to document the legal basis for retention
and ensure it is reflected in your Record of Processing Activities (Art. 30).

---

## References

- Regulation (EU) 2016/679 of the European Parliament and of the Council (GDPR):
  - Art. 4(1) — definition of personal data
  - Art. 5(1)(e) — storage limitation principle
  - Art. 17(1) — right to erasure
  - Art. 17(3)(b) — exemption for legal compliance obligations
  - Art. 28(3)(f) — processor obligations including erasure
  - Art. 30 — records of processing activities
  Full text: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679

- NIST SP 800-88 Rev 1: Guidelines for Media Sanitization (December 2014).
  National Institute of Standards and Technology.
  §2.4 (Clear method), §2.5 (encryption as mitigation for CoW/SSD).
  https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final

- NIST SP 800-92: Guide to Computer Security Log Management (2006). NIST.
  https://csrc.nist.gov/publications/detail/sp/800-92/final

- PCI Security Standards Council. PCI DSS v4.0, Requirement 10.7 (March 2022).
  https://www.pcisecuritystandards.org/document_library/

- U.S. Department of Health and Human Services. HIPAA Security Rule.
  45 CFR § 164.530(j). https://www.hhs.gov/hipaa/for-professionals/security/index.html
