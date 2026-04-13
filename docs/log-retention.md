# Log Retention Guide for prmana

This document describes log retention requirements, output modes, centralized-logging
integration, and configuration guidance for prmana audit logs. It is intended for
system administrators, security operations teams, and compliance officers.

## Log Output Modes

prmana emits structured JSON audit events over three output channels, which can be
configured independently in `policy.yaml`:

| Mode | Channel | Default Destination | Suitable For |
|------|---------|---------------------|--------------|
| `syslog` | Linux syslog AUTH facility | `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL) | Low-overhead, integrated with system log infrastructure |
| `file` | Dedicated audit file | `/var/log/prmana-audit.log` | Compliance archiving, SIEM file-based ingestion |
| `stderr` | Standard error | journald / supervisor / container log driver | Container deployments, systemd-unit services |

All three modes can be enabled simultaneously. The `file` mode is recommended for
compliance deployments because it produces a self-contained, rotatable log file that
is independent of the system syslog configuration.

### Enabling File Mode

In `/etc/prmana/policy.yaml`:

```yaml
audit:
  output:
    - syslog       # PAM AUTH facility
    - file         # /var/log/prmana-audit.log
  file_path: /var/log/prmana-audit.log
```

The PAM module creates `/var/log/prmana-audit.log` on first write with mode
`0640` (root:adm). If the parent directory does not exist the module falls back to
syslog and logs a warning.

## Compliance Retention Periods

The table below maps regulatory frameworks to their minimum log retention requirements
with authoritative source references. **Review your legal counsel's guidance** before
applying these minimums — your specific agreement or certification scope may impose
stricter requirements.

| Framework | Minimum Retention | Immediately Available | Authoritative Source |
|-----------|------------------|----------------------|----------------------|
| SOC 2 Type II | 1 year | Full period | AICPA Trust Services Criteria CC7.2, CC7.3 (Monitoring of Controls) |
| PCI-DSS v4.0 | 1 year | Most recent 3 months | PCI-DSS v4.0 Requirement 10.7.1, 10.7.2 |
| HIPAA | 6 years | No minimum specified | 45 CFR § 164.530(j) — Policy/procedure retention period |
| GDPR | No minimum; storage minimization applies | N/A | GDPR Art. 5(1)(e) — Purpose limitation and storage limitation |
| FedRAMP | 1 year | Full period | NIST SP 800-53 Rev 5 AU-11 (Audit Record Retention) |
| ISO 27001:2022 | 3 years (typical) | No requirement specified | ISO/IEC 27001:2022 Annex A 8.15 (Logging) |

**Notes:**

- **GDPR** does not prescribe a minimum retention period; instead, it requires that
  personal data (including log entries containing usernames and IP addresses) be kept
  no longer than necessary for the stated purpose. For audit trails used to demonstrate
  security controls, GDPR Art. 17(3)(b) permits retention for legal compliance purposes.
  Coordinate with your Data Protection Officer to determine an appropriate period.

- **PCI-DSS v4.0** requires that the most recent three months of audit logs be
  "immediately available for analysis." The remaining nine months may be archived on
  secondary storage. See also the guidance in NIST SP 800-92 §4.4 on tiered log storage.

- **HIPAA** applies to covered entities and their business associates. The 6-year
  requirement in 45 CFR § 164.530(j) applies to written policies and procedures, not
  specifically to technical audit logs — but logs used as evidence of policy compliance
  should be retained for the same period. HIPAA Security Rule 45 CFR § 164.312(b)
  requires audit controls (hardware, software, and procedural mechanisms) but does not
  specify a log retention period. Many compliance programs treat 6 years as the working
  standard for all HIPAA-related records.

- **FedRAMP** AU-11 states: "Retain audit records for [Assignment: organization-defined
  time period] to provide support for after-the-fact investigations of security incidents
  and to meet regulatory and organizational information retention requirements."
  The most common FedRAMP baseline assignment is 1 year.

### Adjusting the Logrotate Configuration

The shipped `deploy/logrotate.d/prmana` uses `rotate 52` (52 weekly rotations = 1 year).
To meet HIPAA's 6-year working standard, change to `rotate 312` (52 weeks × 6 years):

```
/var/log/prmana-audit.log /var/log/prmana/*.log {
    weekly
    rotate 312          # 6 years — suitable for HIPAA
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || true
    endscript
}
```

For PCI-DSS, consider using `dateext` and offloading logs older than 3 months to
secondary (cold) storage while keeping the 1-year total:

```
/var/log/prmana-audit.log /var/log/prmana/*.log {
    weekly
    rotate 52
    dateext
    dateformat -%Y%m%d
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || true
    endscript
}
```

## Installing the Logrotate Configuration

```bash
# Install the shipped configuration
sudo cp deploy/logrotate.d/prmana /etc/logrotate.d/prmana

# Dry-run to verify syntax and which files will be rotated
sudo logrotate -d /etc/logrotate.d/prmana

# Force a rotation immediately (e.g., after initial deployment)
sudo logrotate -f /etc/logrotate.d/prmana
```

Logrotate runs automatically via cron (`/etc/cron.daily/logrotate`) or systemd timer
(`logrotate.timer`). No additional scheduling is required after installation.

### Checking That Rotation Is Working

```bash
# List rotated files (gzip-compressed copies)
ls -lh /var/log/prmana-audit.log*

# Verify logrotate state (last run date, file offset)
cat /var/lib/logrotate/status | grep prmana
```

## Centralized Logging Integration

### Splunk (HTTP Event Collector)

prmana emits newline-delimited JSON. Configure a Splunk Universal Forwarder monitor
input or use the rsyslog `omelasticsearch` / `omhttp` output module:

```ini
# /etc/rsyslog.d/60-prmana-splunk.conf
module(load="imfile")
module(load="omhttp")

input(type="imfile"
      File="/var/log/prmana-audit.log"
      Tag="prmana_audit"
      Ruleset="to_splunk")

ruleset(name="to_splunk") {
    action(type="omhttp"
           server="https://splunk-hec.example.com:8088"
           serverpath="/services/collector/event"
           httpheaderkey.Authorization="Splunk <HEC_TOKEN>"
           template="RSYSLOG_JSON")
}
```

Reference: Splunk Add-on for Syslog, HEC documentation at `docs.splunk.com`.

### Elastic Stack (Filebeat)

```yaml
# filebeat.yml (relevant excerpt)
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/prmana-audit.log
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      source: prmana
      log_type: audit

output.elasticsearch:
  hosts: ["https://elasticsearch:9200"]
  index: "prmana-audit-%{+yyyy.MM.dd}"
  ssl.certificate_authorities: ["/etc/filebeat/ca.crt"]
```

Reference: Elastic Filebeat Reference, §Configure Inputs (Log Input).

### Datadog

```yaml
# /etc/datadog-agent/conf.d/prmana.d/conf.yaml
logs:
  - type: file
    path: /var/log/prmana-audit.log
    service: prmana
    source: prmana
    log_processing_rules:
      - type: multi_line
        name: json_events
        pattern: '^\{'
```

Reference: Datadog Agent Log Collection documentation.

### AWS CloudWatch Logs

```json
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/prmana-audit.log",
            "log_group_name": "/prmana/audit",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
```

Add a CloudWatch Log Group retention policy of 365 days (SOC 2/PCI-DSS) or 2190 days
(HIPAA) using `aws logs put-retention-policy --log-group-name /prmana/audit
--retention-in-days 365`.

Reference: AWS CloudWatch Agent Configuration Reference.

## Structured Event Format

All prmana audit events are newline-delimited JSON. Key fields for SIEM queries:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO 8601 | Event time in UTC |
| `event_type` | string | e.g., `auth_success`, `auth_failure`, `auth_no_token` |
| `username` | string | Unix username of the authentication subject |
| `source_ip` | string | Client source IP address |
| `issuer` | string | OIDC issuer URL |
| `severity` | string | `INFO`, `WARN`, `ERROR`, `CRITICAL` |
| `category_uid` | int | OCSF Category — 3 = Identity & Access Management |
| `class_uid` | int | OCSF Class — 3002 = Authentication |
| `activity_id` | int | OCSF Activity — 1 = Logon, 2 = Logoff |
| `hmac` | string | HMAC-SHA-256 chain link (if tamper-evidence enabled) |

See `docs/observability.md` for the full event schema and OCSF field mapping.

## References

- NIST SP 800-92: Guide to Computer Security Log Management (2006). National Institute
  of Standards and Technology. https://csrc.nist.gov/publications/detail/sp/800-92/final
- NIST SP 800-53 Rev 5, Control AU-11: Audit Record Retention. NIST.
  https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- PCI Security Standards Council. PCI DSS v4.0, Requirement 10. March 2022.
  https://www.pcisecuritystandards.org/document_library/
- AICPA. 2017 Trust Services Criteria (with 2022 points of focus), CC7.2, CC7.3.
  https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustservices.html
- U.S. Department of Health and Human Services. HIPAA Security Rule. 45 CFR § 164.
  https://www.hhs.gov/hipaa/for-professionals/security/index.html
- Regulation (EU) 2016/679 (GDPR), Articles 5, 17. Official Journal of the European
  Union. https://gdpr-info.eu/
- FedRAMP Security Controls Baseline (High, Moderate, Low), AU-11.
  https://www.fedramp.gov/assets/resources/documents/FedRAMP_Security_Controls_Baseline.xlsx
