//! Phase 45: Access posture snapshots and evidence export.
//!
//! This module is intentionally local/export-first. It does not try to be a
//! dashboard or management plane. Instead, it turns the existing policy model
//! and structured audit trail into:
//!
//! - a deterministic host posture snapshot
//! - a filtered evidence bundle for audit/compliance review
//! - normalized event records suitable for later ingestion by a higher-level
//!   operations plane
//!
//! The design goal is to create a stable schema that can be reused later by a
//! fleet service without trapping the logic inside a one-off CLI.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;

use crate::audit::AuditEvent;
use crate::policy::config::{EnforcementMode, PolicyConfig, SudoPolicyAction};

/// Errors returned while building posture snapshots or evidence bundles.
#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("Policy load failed: {0}")]
    Policy(#[from] crate::policy::PolicyError),

    #[error("I/O error for {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Audit line {line_number} in {path} failed to parse: {reason}")]
    AuditParse {
        path: String,
        line_number: usize,
        reason: String,
    },

    #[error("Invalid RFC 3339 timestamp '{value}': {reason}")]
    InvalidTimestamp { value: String, reason: String },

    #[error("Serialization failed for {target}: {reason}")]
    Serialize { target: String, reason: String },
}

/// Severity for posture findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Critical,
}

/// A high-signal posture finding derived from policy state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureFinding {
    pub id: String,
    pub severity: FindingSeverity,
    pub message: String,
}

/// Per-issuer security posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerPostureSnapshot {
    pub issuer_url: String,
    pub client_id: String,
    pub dpop_enforcement: String,
    pub required_acr: Option<String>,
    pub attestation_enforcement: Option<String>,
    pub delegation_enabled: bool,
    pub expected_audience: Option<String>,
    pub jwks_cache_ttl_secs: u64,
}

/// Sudo privilege-policy posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SudoPostureSnapshot {
    pub default_action: String,
    pub dry_run: bool,
    pub grace_period_secs: u64,
    pub challenge_timeout_secs: u64,
    pub allowed_methods: Vec<String>,
    pub command_rule_count: usize,
    pub sudo_group_restriction_enabled: bool,
}

/// SSH login posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshLoginPostureSnapshot {
    pub require_oidc: bool,
    pub minimum_acr: Option<String>,
    pub max_auth_age: Option<i64>,
    pub login_group_restriction_enabled: bool,
}

/// Break-glass posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakGlassPostureSnapshot {
    pub enabled: bool,
    pub account_count: usize,
    pub requires: Option<String>,
    pub alert_on_use: bool,
}

/// Security enforcement posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityModesPostureSnapshot {
    pub dpop_required: String,
    pub jti_enforcement: String,
    pub groups_enforcement: String,
    pub step_up_require_id_token: bool,
}

/// Local host posture snapshot derived from `policy.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPostureSnapshot {
    pub generated_at: String,
    pub module_version: String,
    pub policy_path: String,
    pub policy_sha256: String,
    pub host_classification: String,
    pub issuer_count: usize,
    pub issuers: Vec<IssuerPostureSnapshot>,
    pub ssh_login: SshLoginPostureSnapshot,
    pub sudo: SudoPostureSnapshot,
    pub break_glass: BreakGlassPostureSnapshot,
    pub security_modes: SecurityModesPostureSnapshot,
    pub findings: Vec<PostureFinding>,
}

/// Filters applied when exporting evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceFilter {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub event_types: BTreeSet<String>,
}

/// Normalized audit record used by exports and later aggregation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEventRecord {
    pub timestamp: String,
    pub event: String,
    pub severity_id: u8,
    pub user: Option<String>,
    pub host: Option<String>,
    pub command: Option<String>,
    pub session_id: Option<String>,
    pub method: Option<String>,
    pub policy_action: Option<String>,
    pub matched_rule: Option<String>,
    pub source_ip: Option<String>,
    pub oidc_acr: Option<String>,
    pub serving_issuer: Option<String>,
    pub failover_active: bool,
    pub reason: Option<String>,
}

/// Summary counts for an evidence export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub total_events: usize,
    pub distinct_users: usize,
    pub distinct_hosts: usize,
    pub event_type_counts: BTreeMap<String, usize>,
    pub break_glass_events: usize,
    pub failover_events: usize,
    pub failover_active_logins: usize,
    pub privilege_policy_denies: usize,
    pub privilege_policy_dry_run_hits: usize,
    pub step_up_successes: usize,
    pub step_up_failures: usize,
}

/// Full evidence export bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExportBundle {
    pub generated_at: String,
    pub audit_log_path: String,
    pub filter: EvidenceFilterSummary,
    pub posture: Option<HostPostureSnapshot>,
    pub summary: EvidenceSummary,
    pub events: Vec<EvidenceEventRecord>,
}

/// Serialized form of the filter used for an evidence export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFilterSummary {
    pub from: Option<String>,
    pub to: Option<String>,
    pub event_types: Vec<String>,
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn mode_string(mode: EnforcementMode) -> String {
    match mode {
        EnforcementMode::Strict => "strict",
        EnforcementMode::Warn => "warn",
        EnforcementMode::Disabled => "disabled",
    }
    .to_string()
}

pub fn parse_rfc3339_to_utc(value: &str) -> Result<DateTime<Utc>, EvidenceError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| EvidenceError::InvalidTimestamp {
            value: value.to_string(),
            reason: e.to_string(),
        })
}

fn compute_policy_sha256(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    hex::encode(digest)
}

/// Load a policy file and derive a local posture snapshot from its effective state.
pub fn load_host_posture_snapshot(
    policy_path: &Path,
) -> Result<HostPostureSnapshot, EvidenceError> {
    let mut bytes = Vec::new();
    File::open(policy_path)
        .map_err(|source| EvidenceError::Io {
            path: policy_path.display().to_string(),
            source,
        })?
        .read_to_end(&mut bytes)
        .map_err(|source| EvidenceError::Io {
            path: policy_path.display().to_string(),
            source,
        })?;

    let policy = PolicyConfig::load_from(policy_path)?;
    let modes = policy.effective_security_modes();

    let issuers: Vec<IssuerPostureSnapshot> = policy
        .issuers
        .iter()
        .map(|issuer| IssuerPostureSnapshot {
            issuer_url: issuer.issuer_url.clone(),
            client_id: issuer.client_id.clone(),
            dpop_enforcement: mode_string(issuer.dpop_enforcement),
            required_acr: issuer
                .acr_mapping
                .as_ref()
                .and_then(|mapping| mapping.required_acr.clone()),
            attestation_enforcement: issuer
                .attestation
                .as_ref()
                .map(|cfg| mode_string(cfg.enforcement)),
            delegation_enabled: issuer.delegation.is_some(),
            expected_audience: issuer.expected_audience.clone(),
            jwks_cache_ttl_secs: issuer.jwks_cache_ttl_secs,
        })
        .collect();

    let mut findings = Vec::new();

    if policy.sudo.dry_run {
        findings.push(PostureFinding {
            id: "sudo_policy_dry_run".to_string(),
            severity: FindingSeverity::Warning,
            message: "Phase 44 sudo privilege policy is in dry-run mode; decisions are logged but not enforced.".to_string(),
        });
    }

    match modes.dpop_required {
        EnforcementMode::Strict => {}
        EnforcementMode::Warn => findings.push(PostureFinding {
            id: "global_dpop_warn".to_string(),
            severity: FindingSeverity::Warning,
            message: "Global DPoP enforcement is warn, not strict.".to_string(),
        }),
        EnforcementMode::Disabled => findings.push(PostureFinding {
            id: "global_dpop_disabled".to_string(),
            severity: FindingSeverity::Critical,
            message: "Global DPoP enforcement is disabled.".to_string(),
        }),
    }

    for issuer in &issuers {
        match issuer.dpop_enforcement.as_str() {
            "warn" => findings.push(PostureFinding {
                id: format!("issuer_dpop_warn:{}", issuer.issuer_url),
                severity: FindingSeverity::Warning,
                message: format!(
                    "Issuer {} uses DPoP warn mode instead of strict.",
                    issuer.issuer_url
                ),
            }),
            "disabled" => findings.push(PostureFinding {
                id: format!("issuer_dpop_disabled:{}", issuer.issuer_url),
                severity: FindingSeverity::Critical,
                message: format!(
                    "Issuer {} has DPoP enforcement disabled.",
                    issuer.issuer_url
                ),
            }),
            _ => {}
        }
    }

    if policy.break_glass.enabled {
        findings.push(PostureFinding {
            id: "break_glass_enabled".to_string(),
            severity: FindingSeverity::Info,
            message: "Break-glass access is enabled; monitor BREAK_GLASS_AUTH events closely."
                .to_string(),
        });
    }

    if !policy.sudo.sudo_groups.is_empty() {
        findings.push(PostureFinding {
            id: "sudo_group_restriction_enabled".to_string(),
            severity: FindingSeverity::Info,
            message: "Sudo group restrictions are enabled.".to_string(),
        });
    }

    Ok(HostPostureSnapshot {
        generated_at: now_rfc3339(),
        module_version: env!("CARGO_PKG_VERSION").to_string(),
        policy_path: policy_path.display().to_string(),
        policy_sha256: compute_policy_sha256(&bytes),
        host_classification: format!("{:?}", policy.host.classification).to_lowercase(),
        issuer_count: policy.issuers.len(),
        issuers,
        ssh_login: SshLoginPostureSnapshot {
            require_oidc: policy.ssh_login.require_oidc,
            minimum_acr: policy.ssh_login.minimum_acr.clone(),
            max_auth_age: policy.ssh_login.max_auth_age,
            login_group_restriction_enabled: !policy.ssh_login.login_groups.is_empty(),
        },
        sudo: SudoPostureSnapshot {
            default_action: match policy.default_sudo_action() {
                SudoPolicyAction::Allow => "allow",
                SudoPolicyAction::StepUp => "step_up",
                SudoPolicyAction::Deny => "deny",
            }
            .to_string(),
            dry_run: policy.sudo.dry_run,
            grace_period_secs: policy.sudo.grace_period_secs,
            challenge_timeout_secs: policy.sudo.challenge_timeout,
            allowed_methods: policy
                .sudo
                .allowed_methods
                .iter()
                .map(|m| format!("{m:?}").to_lowercase())
                .collect(),
            command_rule_count: policy.sudo.commands.len(),
            sudo_group_restriction_enabled: !policy.sudo.sudo_groups.is_empty(),
        },
        break_glass: BreakGlassPostureSnapshot {
            enabled: policy.break_glass.enabled,
            account_count: policy.break_glass.accounts.len()
                + usize::from(policy.break_glass.local_account.is_some()),
            requires: policy.break_glass.requires.clone(),
            alert_on_use: policy.break_glass.alert_on_use,
        },
        security_modes: SecurityModesPostureSnapshot {
            dpop_required: mode_string(modes.dpop_required),
            jti_enforcement: mode_string(modes.jti_enforcement),
            groups_enforcement: mode_string(modes.groups_enforcement),
            step_up_require_id_token: modes.step_up_require_id_token,
        },
        findings,
    })
}

fn normalize_audit_event(event: AuditEvent) -> EvidenceEventRecord {
    let severity_id = event.ocsf_fields().severity_id as u8;
    match event {
        AuditEvent::SshLoginSuccess {
            timestamp,
            session_id,
            user,
            source_ip,
            host,
            oidc_acr,
            serving_issuer,
            failover_active,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "SSH_LOGIN_SUCCESS".to_string(),
            severity_id,
            user: Some(user),
            host: Some(host),
            command: None,
            session_id: Some(session_id),
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip,
            oidc_acr,
            serving_issuer,
            failover_active,
            reason: None,
        },
        AuditEvent::SshLoginFailed {
            timestamp,
            user,
            source_ip,
            host,
            reason,
        } => EvidenceEventRecord {
            timestamp,
            event: "SSH_LOGIN_FAILED".to_string(),
            severity_id,
            user,
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: Some(reason),
        },
        AuditEvent::TokenValidationFailed {
            timestamp,
            user,
            source_ip,
            host,
            reason,
            oidc_issuer,
        } => EvidenceEventRecord {
            timestamp,
            event: "TOKEN_VALIDATION_FAILED".to_string(),
            severity_id,
            user,
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip,
            oidc_acr: None,
            serving_issuer: oidc_issuer,
            failover_active: false,
            reason: Some(reason),
        },
        AuditEvent::UserNotFound {
            timestamp,
            username,
            host,
        } => EvidenceEventRecord {
            timestamp,
            event: "USER_NOT_FOUND".to_string(),
            severity_id,
            user: Some(username),
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: None,
        },
        AuditEvent::PrivilegePolicyDecision {
            timestamp,
            user,
            command,
            host,
            policy_action,
            matched_rule,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "PRIVILEGE_POLICY_DECISION".to_string(),
            severity_id,
            user: Some(user),
            host: Some(host),
            command: Some(command),
            session_id: None,
            method: None,
            policy_action: Some(policy_action),
            matched_rule,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: None,
        },
        AuditEvent::StepUpInitiated {
            timestamp,
            user,
            command,
            host,
            method,
            policy_action,
            matched_rule,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "STEP_UP_INITIATED".to_string(),
            severity_id,
            user: Some(user),
            host: Some(host),
            command,
            session_id: None,
            method: Some(method),
            policy_action,
            matched_rule,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: None,
        },
        AuditEvent::StepUpSuccess {
            timestamp,
            user,
            command,
            host,
            method,
            session_id,
            oidc_acr,
            policy_action,
            matched_rule,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "STEP_UP_SUCCESS".to_string(),
            severity_id,
            user: Some(user),
            host: Some(host),
            command,
            session_id: Some(session_id),
            method: Some(method),
            policy_action,
            matched_rule,
            source_ip: None,
            oidc_acr,
            serving_issuer: None,
            failover_active: false,
            reason: None,
        },
        AuditEvent::StepUpFailed {
            timestamp,
            user,
            command,
            host,
            method,
            reason,
            policy_action,
            matched_rule,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "STEP_UP_FAILED".to_string(),
            severity_id,
            user: Some(user),
            host: Some(host),
            command,
            session_id: None,
            method: Some(method),
            policy_action,
            matched_rule,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: Some(reason),
        },
        AuditEvent::BreakGlassAuth {
            timestamp,
            username,
            source_ip,
            host,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "BREAK_GLASS_AUTH".to_string(),
            severity_id,
            user: Some(username),
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: None,
        },
        AuditEvent::SessionOpened {
            timestamp,
            session_id,
            username,
            client_ip,
            host,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "SESSION_OPENED".to_string(),
            severity_id,
            user: Some(username),
            host: Some(host),
            command: None,
            session_id: Some(session_id),
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: client_ip,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: None,
        },
        AuditEvent::SessionClosed {
            timestamp,
            session_id,
            username,
            host,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "SESSION_CLOSED".to_string(),
            severity_id,
            user: Some(username),
            host: Some(host),
            command: None,
            session_id: Some(session_id),
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: None,
        },
        AuditEvent::TokenRevoked {
            timestamp,
            session_id,
            username,
            host,
            reason,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "TOKEN_REVOKED".to_string(),
            severity_id,
            user: Some(username),
            host: Some(host),
            command: None,
            session_id: Some(session_id),
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason,
        },
        AuditEvent::IntrospectionFailed {
            timestamp,
            username,
            host,
            reason,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "INTROSPECTION_FAILED".to_string(),
            severity_id,
            user: username,
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: Some(reason),
        },
        AuditEvent::AuthNoToken {
            timestamp,
            username,
            source_ip,
            host,
        } => EvidenceEventRecord {
            timestamp,
            event: "AUTH_NO_TOKEN".to_string(),
            severity_id,
            user: Some(username),
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: None,
        },
        AuditEvent::SessionCloseFailed {
            timestamp,
            session_id,
            username,
            host,
            reason,
        } => EvidenceEventRecord {
            timestamp,
            event: "SESSION_CLOSE_FAILED".to_string(),
            severity_id,
            user: Some(username),
            host: Some(host),
            command: None,
            session_id: Some(session_id),
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: Some(reason),
        },
        AuditEvent::IssuerDegraded {
            timestamp,
            issuer_url,
            host,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "ISSUER_DEGRADED".to_string(),
            severity_id,
            user: None,
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: Some(issuer_url),
            failover_active: false,
            reason: None,
        },
        AuditEvent::IssuerRecovered {
            timestamp,
            issuer_url,
            host,
        } => EvidenceEventRecord {
            timestamp,
            event: "ISSUER_RECOVERED".to_string(),
            severity_id,
            user: None,
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: Some(issuer_url),
            failover_active: false,
            reason: None,
        },
        AuditEvent::JtiReplayDetected {
            timestamp,
            user,
            source_ip,
            host,
            token_type,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "JTI_REPLAY_DETECTED".to_string(),
            severity_id,
            user,
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: Some(token_type),
        },
        AuditEvent::JtiStoreDegraded {
            timestamp,
            host,
            reason,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "JTI_STORE_DEGRADED".to_string(),
            severity_id,
            user: None,
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: Some(reason),
        },
        AuditEvent::TokenExchangeAccepted {
            timestamp,
            session_id,
            username,
            exchanger,
            host,
            ..
        } => EvidenceEventRecord {
            timestamp,
            event: "TOKEN_EXCHANGE_ACCEPTED".to_string(),
            severity_id,
            user: Some(username),
            host: Some(host),
            command: None,
            session_id: Some(session_id),
            method: None,
            policy_action: None,
            matched_rule: Some(exchanger),
            source_ip: None,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: None,
        },
        AuditEvent::TokenExchangeRejected {
            timestamp,
            username,
            exchanger,
            reason,
            host,
        } => EvidenceEventRecord {
            timestamp,
            event: "TOKEN_EXCHANGE_REJECTED".to_string(),
            severity_id,
            user: Some(username),
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: Some(exchanger),
            source_ip: None,
            oidc_acr: None,
            serving_issuer: None,
            failover_active: false,
            reason: Some(reason),
        },
        AuditEvent::IdpFailoverActivated {
            timestamp,
            failed_issuer,
            secondary_issuer,
            host,
            reason,
        } => EvidenceEventRecord {
            timestamp,
            event: "IDP_FAILOVER_ACTIVATED".to_string(),
            severity_id,
            user: None,
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: Some(format!("{failed_issuer} -> {secondary_issuer}")),
            failover_active: true,
            reason: Some(reason),
        },
        AuditEvent::IdpFailoverRecovered {
            timestamp,
            recovered_issuer,
            previous_active_issuer,
            host,
        } => EvidenceEventRecord {
            timestamp,
            event: "IDP_FAILOVER_RECOVERED".to_string(),
            severity_id,
            user: None,
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: Some(format!("{previous_active_issuer} -> {recovered_issuer}")),
            failover_active: false,
            reason: None,
        },
        AuditEvent::IdpFailoverExhausted {
            timestamp,
            primary_issuer,
            secondary_issuer,
            host,
            last_error,
        } => EvidenceEventRecord {
            timestamp,
            event: "IDP_FAILOVER_EXHAUSTED".to_string(),
            severity_id,
            user: None,
            host: Some(host),
            command: None,
            session_id: None,
            method: None,
            policy_action: None,
            matched_rule: None,
            source_ip: None,
            oidc_acr: None,
            serving_issuer: Some(format!("{primary_issuer} -> {secondary_issuer}")),
            failover_active: true,
            reason: Some(last_error),
        },
    }
}

fn record_matches_filter(
    record: &EvidenceEventRecord,
    filter: &EvidenceFilter,
) -> Result<bool, EvidenceError> {
    if !filter.event_types.is_empty() && !filter.event_types.contains(&record.event) {
        return Ok(false);
    }

    let ts = parse_rfc3339_to_utc(&record.timestamp)?;
    if let Some(from) = filter.from {
        if ts < from {
            return Ok(false);
        }
    }
    if let Some(to) = filter.to {
        if ts > to {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Build a filtered evidence bundle from a JSON-lines audit log file.
pub fn build_evidence_export_bundle(
    audit_log_path: &Path,
    filter: &EvidenceFilter,
    posture: Option<HostPostureSnapshot>,
) -> Result<EvidenceExportBundle, EvidenceError> {
    let file = File::open(audit_log_path).map_err(|source| EvidenceError::Io {
        path: audit_log_path.display().to_string(),
        source,
    })?;

    let mut records = Vec::new();
    for (line_number, line_result) in BufReader::new(file).lines().enumerate() {
        let line_number = line_number + 1;
        let line = line_result.map_err(|source| EvidenceError::Io {
            path: audit_log_path.display().to_string(),
            source,
        })?;

        if line.trim().is_empty() {
            continue;
        }

        let event: AuditEvent =
            serde_json::from_str(&line).map_err(|e| EvidenceError::AuditParse {
                path: audit_log_path.display().to_string(),
                line_number,
                reason: e.to_string(),
            })?;
        let record = normalize_audit_event(event);
        if record_matches_filter(&record, filter)? {
            records.push(record);
        }
    }

    let mut distinct_users = HashSet::new();
    let mut distinct_hosts = HashSet::new();
    let mut event_type_counts = BTreeMap::new();
    let mut break_glass_events = 0;
    let mut failover_events = 0;
    let mut failover_active_logins = 0;
    let mut privilege_policy_denies = 0;
    let mut privilege_policy_dry_run_hits = 0;
    let mut step_up_successes = 0;
    let mut step_up_failures = 0;

    for record in &records {
        *event_type_counts.entry(record.event.clone()).or_insert(0) += 1;
        if let Some(user) = &record.user {
            distinct_users.insert(user.clone());
        }
        if let Some(host) = &record.host {
            distinct_hosts.insert(host.clone());
        }

        match record.event.as_str() {
            "BREAK_GLASS_AUTH" => break_glass_events += 1,
            "IDP_FAILOVER_ACTIVATED" | "IDP_FAILOVER_RECOVERED" | "IDP_FAILOVER_EXHAUSTED" => {
                failover_events += 1
            }
            "STEP_UP_SUCCESS" => step_up_successes += 1,
            "STEP_UP_FAILED" => step_up_failures += 1,
            "SSH_LOGIN_SUCCESS" if record.failover_active => failover_active_logins += 1,
            "PRIVILEGE_POLICY_DECISION" => {
                if record.policy_action.as_deref() == Some("deny") {
                    privilege_policy_denies += 1;
                }
            }
            _ => {}
        }

        if record.event == "PRIVILEGE_POLICY_DECISION" && record.reason.is_none() {
            // dry_run is not part of the normalized row to keep the CSV shape flat
            // and stable; infer it by parsing the raw event again would add a second
            // log pass. Instead, count from the line-level event-type map only when
            // the JSON row carried `dry_run=true` in its text representation.
        }
    }

    // Second pass for dry-run policy hits: preserve correctness even though the
    // normalized flat row intentionally omits low-signal booleans.
    let file = File::open(audit_log_path).map_err(|source| EvidenceError::Io {
        path: audit_log_path.display().to_string(),
        source,
    })?;
    for (line_number, line_result) in BufReader::new(file).lines().enumerate() {
        let line_number = line_number + 1;
        let line = line_result.map_err(|source| EvidenceError::Io {
            path: audit_log_path.display().to_string(),
            source,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let event: AuditEvent =
            serde_json::from_str(&line).map_err(|e| EvidenceError::AuditParse {
                path: audit_log_path.display().to_string(),
                line_number,
                reason: e.to_string(),
            })?;
        if let AuditEvent::PrivilegePolicyDecision {
            dry_run, timestamp, ..
        } = event
        {
            let synthetic = EvidenceEventRecord {
                timestamp,
                event: "PRIVILEGE_POLICY_DECISION".to_string(),
                severity_id: 0,
                user: None,
                host: None,
                command: None,
                session_id: None,
                method: None,
                policy_action: None,
                matched_rule: None,
                source_ip: None,
                oidc_acr: None,
                serving_issuer: None,
                failover_active: false,
                reason: None,
            };
            if dry_run && record_matches_filter(&synthetic, filter)? {
                privilege_policy_dry_run_hits += 1;
            }
        }
    }

    Ok(EvidenceExportBundle {
        generated_at: now_rfc3339(),
        audit_log_path: audit_log_path.display().to_string(),
        filter: EvidenceFilterSummary {
            from: filter.from.map(|dt| dt.to_rfc3339()),
            to: filter.to.map(|dt| dt.to_rfc3339()),
            event_types: filter.event_types.iter().cloned().collect(),
        },
        posture,
        summary: EvidenceSummary {
            total_events: records.len(),
            distinct_users: distinct_users.len(),
            distinct_hosts: distinct_hosts.len(),
            event_type_counts,
            break_glass_events,
            failover_events,
            failover_active_logins,
            privilege_policy_denies,
            privilege_policy_dry_run_hits,
            step_up_successes,
            step_up_failures,
        },
        events: records,
    })
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Render normalized evidence events as CSV.
pub fn render_evidence_events_csv(records: &[EvidenceEventRecord]) -> String {
    let mut out = String::from(
        "timestamp,event,severity_id,user,host,command,session_id,method,policy_action,matched_rule,source_ip,oidc_acr,serving_issuer,failover_active,reason\n",
    );

    for record in records {
        let row = [
            csv_escape(&record.timestamp),
            csv_escape(&record.event),
            record.severity_id.to_string(),
            csv_escape(record.user.as_deref().unwrap_or("")),
            csv_escape(record.host.as_deref().unwrap_or("")),
            csv_escape(record.command.as_deref().unwrap_or("")),
            csv_escape(record.session_id.as_deref().unwrap_or("")),
            csv_escape(record.method.as_deref().unwrap_or("")),
            csv_escape(record.policy_action.as_deref().unwrap_or("")),
            csv_escape(record.matched_rule.as_deref().unwrap_or("")),
            csv_escape(record.source_ip.as_deref().unwrap_or("")),
            csv_escape(record.oidc_acr.as_deref().unwrap_or("")),
            csv_escape(record.serving_issuer.as_deref().unwrap_or("")),
            record.failover_active.to_string(),
            csv_escape(record.reason.as_deref().unwrap_or("")),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }

    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn write_policy(contents: &str) -> (TempDir, PathBuf) {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("policy.yaml");
        std::fs::write(&path, contents).unwrap();
        (temp, path)
    }

    fn write_audit_log(lines: &[String]) -> (TempDir, PathBuf) {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("audit.log");
        std::fs::write(&path, lines.join("\n")).unwrap();
        (temp, path)
    }

    #[test]
    fn test_load_host_posture_snapshot_flags_risky_settings() {
        let (_temp, path) = write_policy(
            r#"
host:
  classification: critical
issuers:
  - issuer_url: "https://idp.example.com/realms/corp"
    client_id: "unix-oidc"
    dpop_enforcement: disabled
sudo:
  step_up_required: true
  default_action: step_up
  dry_run: true
break_glass:
  enabled: true
  accounts: ["breakglass"]
security_modes:
  dpop_required: warn
"#,
        );

        let snapshot = load_host_posture_snapshot(&path).unwrap();
        assert_eq!(snapshot.host_classification, "critical");
        assert_eq!(snapshot.sudo.default_action, "step_up");
        assert!(snapshot.sudo.dry_run);
        assert_eq!(snapshot.policy_sha256.len(), 64);
        assert!(snapshot
            .findings
            .iter()
            .any(|f| f.id == "sudo_policy_dry_run"));
        assert!(snapshot.findings.iter().any(|f| f.id == "global_dpop_warn"));
        assert!(snapshot
            .findings
            .iter()
            .any(|f| f.id.contains("issuer_dpop_disabled")));
    }

    #[test]
    fn test_policy_sha256_is_deterministic() {
        let bytes = b"sudo:\n  step_up_required: true\n";
        assert_eq!(compute_policy_sha256(bytes), compute_policy_sha256(bytes));
    }

    #[test]
    fn test_build_evidence_export_bundle_filters_by_event_and_time() {
        let lines = vec![
            AuditEvent::ssh_login_success("sess-1", "alice", None, None, None, None, None, None)
                .enriched_log_json(),
            AuditEvent::break_glass_auth("breakglass", Some("10.0.0.1"), true).enriched_log_json(),
            AuditEvent::step_up_success(
                "alice",
                Some("systemctl restart nginx"),
                "push",
                "sess-2",
                Some("urn:mfa"),
                Some(1_700_000_000),
                true,
                Some("service-restart"),
                Some("step_up"),
                Some("critical"),
                Some(300),
                false,
                false,
            )
            .enriched_log_json(),
        ];
        let (_temp, audit_path) = write_audit_log(&lines);

        let mut filter = EvidenceFilter::default();
        filter.event_types.insert("BREAK_GLASS_AUTH".to_string());

        let bundle = build_evidence_export_bundle(&audit_path, &filter, None).unwrap();
        assert_eq!(bundle.summary.total_events, 1);
        assert_eq!(bundle.summary.break_glass_events, 1);
        assert_eq!(bundle.events[0].event, "BREAK_GLASS_AUTH");
    }

    #[test]
    fn test_build_evidence_export_bundle_summarizes_phase45_signals() {
        let lines = vec![
            AuditEvent::privilege_policy_decision(
                "alice",
                "userdel alice",
                "deny",
                Some("destructive"),
                "critical",
                0,
                false,
                false,
            )
            .enriched_log_json(),
            AuditEvent::step_up_failed(
                "alice",
                Some("systemctl restart nginx"),
                "push",
                "timeout",
                None,
                Some("service-restart"),
                Some("step_up"),
                Some("critical"),
                Some(0),
                false,
            )
            .enriched_log_json(),
            AuditEvent::idp_failover_activated(
                "https://primary.example.com",
                "https://secondary.example.com",
                "timeout",
            )
            .enriched_log_json(),
        ];
        let (_temp, audit_path) = write_audit_log(&lines);

        let bundle =
            build_evidence_export_bundle(&audit_path, &EvidenceFilter::default(), None).unwrap();
        assert_eq!(bundle.summary.total_events, 3);
        assert_eq!(bundle.summary.privilege_policy_denies, 1);
        assert_eq!(bundle.summary.step_up_failures, 1);
        assert_eq!(bundle.summary.failover_events, 1);
    }

    #[test]
    fn test_render_evidence_events_csv_has_expected_headers() {
        let csv = render_evidence_events_csv(&[EvidenceEventRecord {
            timestamp: "2026-04-10T12:00:00Z".to_string(),
            event: "STEP_UP_SUCCESS".to_string(),
            severity_id: 1,
            user: Some("alice".to_string()),
            host: Some("host1".to_string()),
            command: Some("systemctl restart nginx".to_string()),
            session_id: Some("sess-1".to_string()),
            method: Some("push".to_string()),
            policy_action: Some("step_up".to_string()),
            matched_rule: Some("service-restart".to_string()),
            source_ip: None,
            oidc_acr: Some("urn:mfa".to_string()),
            serving_issuer: None,
            failover_active: false,
            reason: None,
        }]);

        assert!(csv.starts_with("timestamp,event,severity_id"));
        assert!(csv.contains("STEP_UP_SUCCESS"));
        assert!(csv.contains("service-restart"));
    }

    #[test]
    fn test_build_evidence_export_bundle_fails_on_malformed_line() {
        let (_temp, audit_path) = write_audit_log(&["not-json".to_string()]);
        let err = build_evidence_export_bundle(&audit_path, &EvidenceFilter::default(), None)
            .unwrap_err();
        assert!(matches!(err, EvidenceError::AuditParse { .. }));
    }
}
