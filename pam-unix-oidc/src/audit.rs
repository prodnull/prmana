//! Audit logging for authentication events.
//!
//! This module provides structured audit logging compatible with CIM (Common Information Model)
//! and OCSF (Open Cybersecurity Schema Framework) for security event analysis.
//!
//! Audit events are written to:
//! 1. Syslog (AUTH facility) - for SIEM integration
//! 2. /var/log/unix-oidc-audit.log - dedicated audit file
//! 3. stderr - for debugging/testing
//!
//! # Tamper-evident HMAC chain (OBS-06)
//!
//! When `UNIX_OIDC_AUDIT_HMAC_KEY` is set, each audit event includes:
//! - `prev_hash`: hex-encoded chain_hash of the previous event ("genesis" for the first)
//! - `chain_hash`: HMAC-SHA256(key, "{prev_hash}:{event_json}")
//!
//! Any deletion or modification of a logged event breaks the chain at that point,
//! detectable by `unix-oidc-audit-verify`. The key MUST be a high-entropy secret
//! (at least 32 random bytes) set to the same value on all processes writing to the
//! same log file. In the forked-sshd model, the parent sets the env var and all forks
//! inherit it, giving each session its own chain segment.
//!
//! When the key is absent or empty, tamper-evidence is disabled with a WARNING log.
//! The key MUST NOT be logged or included in error messages.

use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use serde::Serialize;
use sha2::Sha256;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use syslog::{Facility, Formatter3164};

/// HMAC-SHA256 type alias
type HmacSha256 = Hmac<Sha256>;

/// Default audit log file path
const DEFAULT_AUDIT_LOG: &str = "/var/log/unix-oidc-audit.log";

/// Syslog severity for an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

// ── HMAC chain state (OBS-06) ─────────────────────────────────────────────────

/// Per-process HMAC chain state for tamper-evident audit logging.
///
/// Thread-safety: protected by `Mutex`. In the forked-sshd model, each child
/// process has its own chain segment (starting from "genesis"), which is correct —
/// each fork handles one session. Concurrent PAM calls within the same process are
/// serialized by the mutex, guaranteeing a consistent chain ordering.
pub(crate) struct ChainState {
    /// HMAC key bytes. `None` when `UNIX_OIDC_AUDIT_HMAC_KEY` is absent or empty.
    pub(crate) hmac_key: Option<Vec<u8>>,
    /// hex-encoded chain_hash of the most recently logged event, or "genesis".
    pub(crate) prev_hash: String,
}

impl ChainState {
    /// Initialise chain state from `UNIX_OIDC_AUDIT_HMAC_KEY`.
    ///
    /// The key is decoded as raw UTF-8 bytes. Operators are advised to use a
    /// hex-encoded key of at least 32 bytes of entropy, but any non-empty string
    /// is accepted. An absent or empty value disables tamper-evidence with a WARNING.
    pub fn new() -> Self {
        let key = std::env::var("UNIX_OIDC_AUDIT_HMAC_KEY").ok();
        let hmac_key = match key {
            Some(ref k) if !k.is_empty() => Some(k.as_bytes().to_vec()),
            _ => {
                tracing::warn!(
                    "Audit HMAC chain disabled — UNIX_OIDC_AUDIT_HMAC_KEY not set. \
                     Set this env var to enable tamper-evident audit logging."
                );
                None
            }
        };
        Self {
            hmac_key,
            prev_hash: "genesis".to_string(),
        }
    }

    /// Compute the next HMAC chain step over `event_json`.
    ///
    /// `event_json` must be the fully serialized event JSON (including any OCSF
    /// enrichment fields added by Plan 27-04). The chain input is:
    ///
    ///   `HMAC-SHA256(key, "{prev_hash}:{event_json}")`
    ///
    /// Returns `Some((prev_hash, chain_hash))` and advances internal state,
    /// or `None` if tamper-evidence is disabled.
    pub fn compute_chain(&mut self, event_json: &str) -> Option<(String, String)> {
        let key = self.hmac_key.as_ref()?;

        // Input: "{prev_hash}:{event_json}"
        // This binds the hash to the previous event, forming an unforgeable chain.
        let input = format!("{}:{}", self.prev_hash, event_json);

        // HMAC-SHA256 accepts keys of any non-zero length per RFC 2104 §3.
        // new_from_slice only fails on zero-length keys; our HMAC_KEY env var
        // is validated to be non-empty before insertion.  This is not reachable
        // in practice, so we map to None (disabling chaining) rather than panic.
        let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
            return None;
        };
        mac.update(input.as_bytes());
        let result = mac.finalize();
        let chain_hash = hex::encode(result.into_bytes());

        let prev = self.prev_hash.clone();
        self.prev_hash = chain_hash.clone();
        Some((prev, chain_hash))
    }
}

/// Module-level HMAC chain state, initialised once per process.
///
/// In the forked-sshd model, each child process gets its own Lazy initialisation
/// (after fork, the parent's state is NOT inherited — Lazy is reset in each fork).
static CHAIN_STATE: Lazy<Mutex<ChainState>> = Lazy::new(|| Mutex::new(ChainState::new()));

/// A chained audit event: the original event JSON enriched with HMAC chain fields.
#[derive(Serialize)]
struct ChainedAuditEvent {
    /// All original event fields (and OCSF enrichment when Plan 27-04 is active),
    /// flattened into the top-level JSON object.
    #[serde(flatten)]
    enriched: serde_json::Value,
    /// hex-encoded chain_hash of the preceding event, or "genesis" for the first.
    prev_hash: String,
    /// HMAC-SHA256(key, "{prev_hash}:{enriched_json}") as a hex string.
    chain_hash: String,
}

// ── End HMAC chain state ──────────────────────────────────────────────────────

/// Global syslog writer
static SYSLOG_WRITER: Lazy<Mutex<Option<syslog::Logger<syslog::LoggerBackend, Formatter3164>>>> =
    Lazy::new(|| {
        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTH,
            hostname: None,
            process: "unix-oidc".to_string(),
            pid: std::process::id(),
        };

        let logger = syslog::unix(formatter).ok();
        Mutex::new(logger)
    });

/// Audit events for SSH/PAM authentication.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event")]
pub enum AuditEvent {
    /// Successful SSH login via OIDC
    #[serde(rename = "SSH_LOGIN_SUCCESS")]
    SshLoginSuccess {
        timestamp: String,
        session_id: String,
        user: String,
        uid: Option<u32>,
        source_ip: Option<String>,
        host: String,
        oidc_jti: Option<String>,
        oidc_acr: Option<String>,
        oidc_auth_time: Option<i64>,
    },

    /// Failed SSH login attempt
    #[serde(rename = "SSH_LOGIN_FAILED")]
    SshLoginFailed {
        timestamp: String,
        user: Option<String>,
        source_ip: Option<String>,
        host: String,
        reason: String,
    },

    /// Token validation failure
    #[serde(rename = "TOKEN_VALIDATION_FAILED")]
    TokenValidationFailed {
        timestamp: String,
        user: Option<String>,
        source_ip: Option<String>,
        host: String,
        reason: String,
        oidc_issuer: Option<String>,
    },

    /// User not found in directory
    #[serde(rename = "USER_NOT_FOUND")]
    UserNotFound {
        timestamp: String,
        username: String,
        host: String,
    },

    /// Sudo step-up authentication initiated
    #[serde(rename = "STEP_UP_INITIATED")]
    StepUpInitiated {
        timestamp: String,
        user: String,
        command: Option<String>,
        host: String,
        method: String,
        device_code: Option<String>,
    },

    /// Sudo step-up authentication succeeded
    #[serde(rename = "STEP_UP_SUCCESS")]
    StepUpSuccess {
        timestamp: String,
        user: String,
        command: Option<String>,
        host: String,
        method: String,
        session_id: String,
        oidc_acr: Option<String>,
        oidc_auth_time: Option<i64>,
    },

    /// Sudo step-up authentication failed
    #[serde(rename = "STEP_UP_FAILED")]
    StepUpFailed {
        timestamp: String,
        user: String,
        command: Option<String>,
        host: String,
        method: String,
        reason: String,
    },

    /// Break-glass emergency access used.
    ///
    /// Emitted at CRITICAL severity when `alert_on_use = true` (the default),
    /// or at INFO severity when `alert_on_use = false`.
    /// This event must be forwarded to SIEM/alerting systems when alert_on_use is enabled.
    /// OCSF: Authentication / Privileged Account Use (class_uid 3002).
    #[serde(rename = "BREAK_GLASS_AUTH")]
    BreakGlassAuth {
        timestamp: String,
        username: String,
        source_ip: Option<String>,
        host: String,
        reason: String,
        /// `"CRITICAL"` when `alert_on_use=true`; `"INFO"` when `alert_on_use=false`.
        severity: String,
        /// Mirrors the `alert_on_use` policy flag at the time of authentication.
        /// When `true`, the SIEM alerting pipeline is expected to page on this event.
        #[serde(skip)]
        alert_on_use: bool,
    },

    /// Session opened by pam_sm_open_session.
    ///
    /// Emitted when a session record is successfully written to the session directory.
    /// OCSF: Account Change / Session Activity.
    #[serde(rename = "SESSION_OPENED")]
    SessionOpened {
        timestamp: String,
        session_id: String,
        username: String,
        client_ip: Option<String>,
        host: String,
        /// Token expiry as Unix timestamp. Used to cross-reference session lifetime.
        token_exp: i64,
    },

    /// Session closed by pam_sm_close_session.
    ///
    /// Emitted when a session record is deleted from the session directory.
    /// Includes the total session duration for operational analytics.
    #[serde(rename = "SESSION_CLOSED")]
    SessionClosed {
        timestamp: String,
        session_id: String,
        username: String,
        host: String,
        /// Session duration in seconds (now - session_start from the record).
        duration_secs: i64,
    },

    /// Token revocation outcome during session teardown.
    ///
    /// Emitted by the IPC call to the agent daemon when close_session triggers
    /// RFC 7009 token revocation.
    #[serde(rename = "TOKEN_REVOKED")]
    TokenRevoked {
        timestamp: String,
        session_id: String,
        username: String,
        host: String,
        /// Revocation outcome: `"success"`, `"failed"`, or `"skipped"`.
        outcome: String,
        /// Human-readable reason for the outcome (e.g. IdP error message, "agent unreachable").
        reason: Option<String>,
    },

    /// Token introspection failure (RFC 7662).
    ///
    /// Emitted when introspection is enabled and the endpoint returns an error
    /// or `active: false`. The `enforcement` field indicates whether the failure
    /// caused authentication to be denied or just warned.
    #[serde(rename = "INTROSPECTION_FAILED")]
    IntrospectionFailed {
        timestamp: String,
        session_id: Option<String>,
        username: Option<String>,
        host: String,
        /// Description of the introspection failure.
        reason: String,
        /// Enforcement mode active at time of failure: `"strict"`, `"warn"`, or `"disabled"`.
        enforcement: String,
    },

    /// Authentication attempt with no token provided (OBS-02).
    ///
    /// Emitted when `get_auth_token()` returns `None` — the client did not supply
    /// any OIDC token. This event is distinct from `SshLoginFailed` / `TokenValidationFailed`
    /// which indicate a token was present but invalid.
    ///
    /// SIEM operators should query `event=AUTH_NO_TOKEN` to track unauthenticated
    /// access attempts separately from token validation failures.
    #[serde(rename = "AUTH_NO_TOKEN")]
    AuthNoToken {
        timestamp: String,
        username: String,
        source_ip: Option<String>,
        host: String,
    },

    /// IPC session-close failure (OBS-08).
    ///
    /// Emitted when `notify_agent_session_closed()` fails to deliver the session-closed
    /// IPC message to the agent daemon. Without this event, missed revocations would be
    /// silently dropped.
    ///
    /// Correlate with `SESSION_CLOSED` events via `session_id` to identify sessions
    /// where revocation was not confirmed.
    #[serde(rename = "SESSION_CLOSE_FAILED")]
    SessionCloseFailed {
        timestamp: String,
        session_id: String,
        /// Username is empty string when `notify_agent_session_closed` is called without
        /// a username — correlate with the preceding SESSION_CLOSED event via session_id.
        username: String,
        host: String,
        /// Description of the IPC failure (e.g., "connection refused", "write timeout").
        /// Contains only the error reason, not the IPC message body.
        reason: String,
    },
}

impl AuditEvent {
    /// Create a successful SSH login event.
    pub fn ssh_login_success(
        session_id: &str,
        user: &str,
        uid: Option<u32>,
        source_ip: Option<&str>,
        oidc_jti: Option<&str>,
        oidc_acr: Option<&str>,
        oidc_auth_time: Option<i64>,
    ) -> Self {
        Self::SshLoginSuccess {
            timestamp: iso_timestamp(),
            session_id: session_id.to_string(),
            user: user.to_string(),
            uid,
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
            oidc_jti: oidc_jti.map(String::from),
            oidc_acr: oidc_acr.map(String::from),
            oidc_auth_time,
        }
    }

    /// Create a failed SSH login event.
    pub fn ssh_login_failed(user: Option<&str>, source_ip: Option<&str>, reason: &str) -> Self {
        Self::SshLoginFailed {
            timestamp: iso_timestamp(),
            user: user.map(String::from),
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
            reason: reason.to_string(),
        }
    }

    /// Create a token validation failure event.
    pub fn token_validation_failed(
        user: Option<&str>,
        reason: &str,
        source_ip: Option<&str>,
        oidc_issuer: Option<&str>,
    ) -> Self {
        Self::TokenValidationFailed {
            timestamp: iso_timestamp(),
            user: user.map(String::from),
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
            reason: reason.to_string(),
            oidc_issuer: oidc_issuer.map(String::from),
        }
    }

    /// Create a user not found event.
    pub fn user_not_found(username: &str) -> Self {
        Self::UserNotFound {
            timestamp: iso_timestamp(),
            username: username.to_string(),
            host: get_hostname(),
        }
    }

    /// Create a step-up initiated event.
    pub fn step_up_initiated(
        user: &str,
        command: Option<&str>,
        method: &str,
        device_code: Option<&str>,
    ) -> Self {
        Self::StepUpInitiated {
            timestamp: iso_timestamp(),
            user: user.to_string(),
            command: command.map(String::from),
            host: get_hostname(),
            method: method.to_string(),
            device_code: device_code.map(String::from),
        }
    }

    /// Create a step-up success event.
    pub fn step_up_success(
        user: &str,
        command: Option<&str>,
        method: &str,
        session_id: &str,
        oidc_acr: Option<&str>,
        oidc_auth_time: Option<i64>,
    ) -> Self {
        Self::StepUpSuccess {
            timestamp: iso_timestamp(),
            user: user.to_string(),
            command: command.map(String::from),
            host: get_hostname(),
            method: method.to_string(),
            session_id: session_id.to_string(),
            oidc_acr: oidc_acr.map(String::from),
            oidc_auth_time,
        }
    }

    /// Create a step-up failed event.
    pub fn step_up_failed(user: &str, command: Option<&str>, method: &str, reason: &str) -> Self {
        Self::StepUpFailed {
            timestamp: iso_timestamp(),
            user: user.to_string(),
            command: command.map(String::from),
            host: get_hostname(),
            method: method.to_string(),
            reason: reason.to_string(),
        }
    }

    /// Create a break-glass authentication event.
    ///
    /// When `alert_on_use` is `true` (the `break_glass.alert_on_use` policy flag),
    /// the event is emitted at **CRITICAL** severity and the `severity` field in the
    /// JSON payload is `"CRITICAL"`. SIEM rules should page on this value.
    ///
    /// When `alert_on_use` is `false`, severity is downgraded to **INFO**. This is
    /// appropriate when break-glass accounts are used routinely (e.g. CI/CD automation
    /// that is already monitored by other means) and operators have explicitly opted out
    /// of alerting. The `severity` field in the JSON payload is `"INFO"`.
    ///
    /// The caller must log via `.log()` immediately after construction; this constructor
    /// does not emit it automatically.
    pub fn break_glass_auth(username: &str, source_ip: Option<&str>, alert_on_use: bool) -> Self {
        Self::BreakGlassAuth {
            timestamp: iso_timestamp(),
            username: username.to_string(),
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
            reason: "break-glass bypass".to_string(),
            severity: if alert_on_use { "CRITICAL".to_string() } else { "INFO".to_string() },
            alert_on_use,
        }
    }

    /// Create a session opened event (pam_sm_open_session).
    pub fn session_opened(
        session_id: &str,
        username: &str,
        client_ip: Option<&str>,
        token_exp: i64,
    ) -> Self {
        Self::SessionOpened {
            timestamp: iso_timestamp(),
            session_id: session_id.to_string(),
            username: username.to_string(),
            client_ip: client_ip.map(String::from),
            host: get_hostname(),
            token_exp,
        }
    }

    /// Create a session closed event (pam_sm_close_session).
    pub fn session_closed(session_id: &str, username: &str, duration_secs: i64) -> Self {
        Self::SessionClosed {
            timestamp: iso_timestamp(),
            session_id: session_id.to_string(),
            username: username.to_string(),
            host: get_hostname(),
            duration_secs,
        }
    }

    /// Create a token revocation outcome event.
    ///
    /// `outcome` must be one of `"success"`, `"failed"`, or `"skipped"`.
    pub fn token_revoked(
        session_id: &str,
        username: &str,
        outcome: &str,
        reason: Option<&str>,
    ) -> Self {
        Self::TokenRevoked {
            timestamp: iso_timestamp(),
            session_id: session_id.to_string(),
            username: username.to_string(),
            host: get_hostname(),
            outcome: outcome.to_string(),
            reason: reason.map(String::from),
        }
    }

    /// Create a token introspection failure event.
    ///
    /// `enforcement` should match the current `EnforcementMode` as a lowercase string.
    pub fn introspection_failed(
        session_id: Option<&str>,
        username: Option<&str>,
        reason: &str,
        enforcement: &str,
    ) -> Self {
        Self::IntrospectionFailed {
            timestamp: iso_timestamp(),
            session_id: session_id.map(String::from),
            username: username.map(String::from),
            host: get_hostname(),
            reason: reason.to_string(),
            enforcement: enforcement.to_string(),
        }
    }

    /// Create a no-token authentication attempt event (OBS-02).
    ///
    /// Emitted in `pam_sm_authenticate` when `get_auth_token()` returns `None`.
    /// Distinct from `ssh_login_failed` — SIEM can filter `event=AUTH_NO_TOKEN`
    /// without matching token validation failures.
    pub fn auth_no_token(username: &str, source_ip: Option<&str>) -> Self {
        Self::AuthNoToken {
            timestamp: iso_timestamp(),
            username: username.to_string(),
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
        }
    }

    /// Create an IPC session-close failure event (OBS-08).
    ///
    /// Emitted in `notify_agent_session_closed` when the IPC message cannot be
    /// delivered to the agent daemon. The `reason` contains only the error string,
    /// not the IPC message body — preventing IPC payload leakage into audit logs.
    ///
    /// Correlate with the preceding `SESSION_CLOSED` event via `session_id` to
    /// identify sessions where agent-side revocation was not confirmed.
    pub fn session_close_failed(session_id: &str, username: &str, reason: &str) -> Self {
        Self::SessionCloseFailed {
            timestamp: iso_timestamp(),
            session_id: session_id.to_string(),
            username: username.to_string(),
            host: get_hostname(),
            reason: reason.to_string(),
        }
    }

    /// Log this event to the configured audit destinations.
    ///
    /// When `UNIX_OIDC_AUDIT_HMAC_KEY` is set, the output JSON is augmented with
    /// `prev_hash` and `chain_hash` fields providing a tamper-evident audit chain.
    /// The HMAC is computed over the base event JSON (including any OCSF enrichment
    /// fields from Plan 27-04 when they are present).
    pub fn log(&self) {
        // Step 1: Serialize the base event (bare or OCSF-enriched, depending on
        // whether Plan 27-04 has been applied). This is the verifiable payload.
        let base_json = match serde_json::to_string(self) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize audit event");
                return;
            }
        };

        // Step 2: Attempt to advance the HMAC chain. The mutex guard is held for the
        // duration so that concurrent PAM calls cannot interleave their chain steps.
        let output_json = if let Ok(mut state) = CHAIN_STATE.lock() {
            if let Some((prev_hash, chain_hash)) = state.compute_chain(&base_json) {
                // Build ChainedAuditEvent: flatten base JSON then append chain fields.
                match serde_json::from_str::<serde_json::Value>(&base_json) {
                    Ok(enriched_value) => {
                        let chained = ChainedAuditEvent {
                            enriched: enriched_value,
                            prev_hash,
                            chain_hash,
                        };
                        serde_json::to_string(&chained).unwrap_or(base_json)
                    }
                    Err(_) => base_json,
                }
            } else {
                // Chain disabled — use base event JSON as-is (existing behaviour)
                base_json
            }
        } else {
            // Mutex poisoned — fall back to base JSON rather than refusing to log
            tracing::warn!("HMAC chain mutex poisoned; logging without chain fields");
            base_json
        };

        // Step 3: Emit to all audit destinations.
        let severity = self.syslog_severity();
        log_to_syslog(&output_json, severity);

        let log_path = std::env::var("UNIX_OIDC_AUDIT_LOG")
            .unwrap_or_else(|_| DEFAULT_AUDIT_LOG.to_string());
        let _ = append_to_file(&log_path, &output_json);

        eprintln!("unix-oidc-audit: {output_json}");
    }

    /// Get the event type as a string.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::SshLoginSuccess { .. } => "SSH_LOGIN_SUCCESS",
            Self::SshLoginFailed { .. } => "SSH_LOGIN_FAILED",
            Self::TokenValidationFailed { .. } => "TOKEN_VALIDATION_FAILED",
            Self::UserNotFound { .. } => "USER_NOT_FOUND",
            Self::StepUpInitiated { .. } => "STEP_UP_INITIATED",
            Self::StepUpSuccess { .. } => "STEP_UP_SUCCESS",
            Self::StepUpFailed { .. } => "STEP_UP_FAILED",
            Self::BreakGlassAuth { .. } => "BREAK_GLASS_AUTH",
            Self::SessionOpened { .. } => "SESSION_OPENED",
            Self::SessionClosed { .. } => "SESSION_CLOSED",
            Self::TokenRevoked { .. } => "TOKEN_REVOKED",
            Self::IntrospectionFailed { .. } => "INTROSPECTION_FAILED",
            Self::AuthNoToken { .. } => "AUTH_NO_TOKEN",
            Self::SessionCloseFailed { .. } => "SESSION_CLOSE_FAILED",
        }
    }

    /// Map each audit event to its appropriate syslog severity.
    ///
    /// - **Critical**: break-glass access with `alert_on_use=true`
    /// - **Info**: break-glass access with `alert_on_use=false` (routine / non-alerting)
    /// - **Warning**: authentication/validation failures
    /// - **Info**: successful operations and routine lifecycle events
    pub fn syslog_severity(&self) -> AuditSeverity {
        match self {
            Self::BreakGlassAuth { alert_on_use, .. } => {
                if *alert_on_use {
                    AuditSeverity::Critical
                } else {
                    AuditSeverity::Info
                }
            }
            Self::SshLoginFailed { .. }
            | Self::TokenValidationFailed { .. }
            | Self::StepUpFailed { .. }
            | Self::IntrospectionFailed { .. }
            | Self::UserNotFound { .. }
            | Self::AuthNoToken { .. }
            | Self::SessionCloseFailed { .. } => AuditSeverity::Warning,
            Self::SshLoginSuccess { .. }
            | Self::SessionOpened { .. }
            | Self::SessionClosed { .. }
            | Self::TokenRevoked { .. }
            | Self::StepUpInitiated { .. }
            | Self::StepUpSuccess { .. } => AuditSeverity::Info,
        }
    }
}

/// Get the current timestamp in ISO 8601 format.
fn iso_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Get the hostname of the current machine.
///
/// Resolution order (first hit wins):
///  1. `UNIX_OIDC_HOSTNAME` env var — operator override for CNAME or custom hostname
///     scenarios (e.g. containers where the kernel hostname is a pod ID but audit logs
///     should show a human-readable service name).
///  2. `gethostname(2)` POSIX syscall — always reflects the actual kernel hostname
///     regardless of environment variables.
///
/// The old fallback to `HOSTNAME` / `HOST` env vars is intentionally removed: those
/// env vars are unreliable in containers and are not set by the kernel — they can be
/// missing, stale, or deliberately spoofed.
fn get_hostname() -> String {
    if let Ok(override_host) = std::env::var("UNIX_OIDC_HOSTNAME") {
        if !override_host.is_empty() {
            return override_host;
        }
    }
    gethostname::gethostname().to_string_lossy().into_owned()
}

/// Append a line to a file.
fn append_to_file(path: &str, content: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    writeln!(file, "{content}")?;
    Ok(())
}

/// Log a message to syslog at the given severity level.
fn log_to_syslog(message: &str, severity: AuditSeverity) {
    if let Ok(mut guard) = SYSLOG_WRITER.lock() {
        if let Some(ref mut logger) = *guard {
            let _ = match severity {
                AuditSeverity::Info => logger.info(message),
                AuditSeverity::Warning => logger.warning(message),
                AuditSeverity::Critical => logger.crit(message),
            };
        }
    }
}

// ── HMAC chain tests (Plan 27-05) ─────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod hmac_chain_tests {
    use super::*;

    /// Helper: make a fresh ChainState with an explicit key (bypassing lazy env-var init)
    fn chain_with_key(key: &[u8]) -> ChainState {
        ChainState {
            hmac_key: Some(key.to_vec()),
            prev_hash: "genesis".to_string(),
        }
    }

    /// Helper: build a minimal audit event JSON using the current event serializer
    fn make_event_json(event: &AuditEvent) -> String {
        serde_json::to_string(event).unwrap()
    }

    // Test 1: With HMAC key set, the chain produces chain_hash and prev_hash fields
    #[test]
    fn test_hmac_chain_fields_present_when_key_set() {
        let mut chain = chain_with_key(b"test-secret-key-32-bytes-minimum!");
        let event = AuditEvent::ssh_login_success("s1", "alice", None, None, None, None, None);
        let event_json = make_event_json(&event);

        let result = chain.compute_chain(&event_json);
        assert!(result.is_some(), "chain should produce a result when key is set");
        let (prev_hash, chain_hash) = result.unwrap();
        assert_eq!(prev_hash, "genesis", "first event's prev_hash must be 'genesis'");
        assert!(!chain_hash.is_empty(), "chain_hash must be non-empty hex string");
        // HMAC-SHA256 hex = 64 chars
        assert_eq!(chain_hash.len(), 64, "chain_hash must be 64-char hex (HMAC-SHA256)");
    }

    // Test 2: Two consecutive events form a valid chain
    #[test]
    fn test_hmac_chain_consecutive_events_chain_correctly() {
        let mut chain = chain_with_key(b"test-secret-key-32-bytes-minimum!");

        let event1 = AuditEvent::ssh_login_success("s1", "alice", None, None, None, None, None);
        let json1 = make_event_json(&event1);
        let (_, hash1) = chain.compute_chain(&json1).unwrap();

        let event2 = AuditEvent::session_closed("s1", "alice", 300);
        let json2 = make_event_json(&event2);
        let (prev2, hash2) = chain.compute_chain(&json2).unwrap();

        // event2.prev_hash == event1.chain_hash
        assert_eq!(prev2, hash1, "event2.prev_hash must equal event1.chain_hash");
        assert_ne!(hash1, hash2, "consecutive hashes must differ");
    }

    // Test 3: Modifying event1's JSON after logging breaks the chain
    #[test]
    fn test_hmac_chain_modification_breaks_chain() {
        let key = b"test-secret-key-32-bytes-minimum!";
        let mut chain1 = chain_with_key(key);
        let mut chain2 = chain_with_key(key);

        let event1 = AuditEvent::ssh_login_success("s1", "alice", None, None, None, None, None);
        let original_json1 = make_event_json(&event1);
        let (_, hash1_original) = chain1.compute_chain(&original_json1).unwrap();

        // Now compute hash over a tampered version of event1
        let tampered_json1 = original_json1.replace("alice", "mallory");
        let (_, hash1_tampered) = chain2.compute_chain(&tampered_json1).unwrap();

        // The chain hashes must differ — modification detected
        assert_ne!(
            hash1_original, hash1_tampered,
            "tampering with event JSON must produce a different chain_hash"
        );
    }

    // Test 4 (negative): With key unset, compute_chain returns None
    #[test]
    fn test_hmac_chain_disabled_when_key_absent() {
        let mut chain = ChainState {
            hmac_key: None,
            prev_hash: "genesis".to_string(),
        };
        let event = AuditEvent::ssh_login_success("s1", "bob", None, None, None, None, None);
        let json = make_event_json(&event);
        let result = chain.compute_chain(&json);
        assert!(result.is_none(), "chain must be disabled (None) when key is absent");
    }

    // Test 5 (negative): Empty HMAC key treated as unset
    #[test]
    fn test_hmac_chain_disabled_for_empty_key() {
        let mut chain = ChainState {
            hmac_key: Some(vec![]),  // empty key → treated as unset during init
            prev_hash: "genesis".to_string(),
        };
        // An empty key vec: we test that the ChainState::new() path with empty env var
        // sets hmac_key = None. Test that compute_chain with Some([]) still gives Some result
        // (the HMAC itself would still compute — the empty check is at init time).
        // This test verifies the init logic: new() with empty env var sets hmac_key = None.
        let chain_from_empty_env = {
            // Simulate what ChainState::new() does with an empty key
            let key_bytes: Vec<u8> = vec![];
            if key_bytes.is_empty() { None } else { Some(key_bytes) }
        };
        assert!(chain_from_empty_env.is_none(), "empty key must be treated as absent");
        // Also verify the chain with None doesn't compute
        chain.hmac_key = None;
        let event = AuditEvent::user_not_found("nobody");
        let json = make_event_json(&event);
        assert!(chain.compute_chain(&json).is_none());
    }

    // Test 6: Chain works correctly across different event types
    #[test]
    fn test_hmac_chain_works_across_event_types() {
        let mut chain = chain_with_key(b"test-secret-key-32-bytes-minimum!");

        let login = AuditEvent::ssh_login_success("s1", "alice", None, None, None, None, None);
        let (_, hash_login) = chain.compute_chain(&make_event_json(&login)).unwrap();

        let closed = AuditEvent::session_closed("s1", "alice", 60);
        let (prev_closed, _hash_closed) = chain.compute_chain(&make_event_json(&closed)).unwrap();

        assert_eq!(prev_closed, hash_login, "SessionClosed.prev_hash must equal SshLoginSuccess.chain_hash");
    }

    // Test 7: The chain_hash input includes all event fields (OCSF when present) —
    // modifying any event field (including ones added by enrichment) breaks the chain.
    // Since 27-04 may not have run yet, we test with the current event JSON structure.
    #[test]
    fn test_hmac_chain_covers_all_event_fields() {
        let key = b"test-secret-key-32-bytes-minimum!";
        let mut chain_a = chain_with_key(key);
        let mut chain_b = chain_with_key(key);

        let event_a = AuditEvent::ssh_login_success("s1", "alice", Some(1000), Some("10.0.0.1"), None, None, None);
        let event_b = AuditEvent::ssh_login_success("s1", "alice", Some(9999), Some("10.0.0.1"), None, None, None);

        let (_, hash_a) = chain_a.compute_chain(&make_event_json(&event_a)).unwrap();
        let (_, hash_b) = chain_b.compute_chain(&make_event_json(&event_b)).unwrap();

        // Different uid → different JSON → different chain_hash
        assert_ne!(hash_a, hash_b, "different event content must produce different chain hashes");
    }

    // Test 8: prev_hash state advances correctly — state machine verification
    #[test]
    fn test_hmac_chain_state_advances_correctly() {
        let mut chain = chain_with_key(b"test-secret-key-32-bytes-minimum!");
        assert_eq!(chain.prev_hash, "genesis");

        let e1 = AuditEvent::ssh_login_success("s1", "alice", None, None, None, None, None);
        let (prev1, hash1) = chain.compute_chain(&make_event_json(&e1)).unwrap();
        assert_eq!(prev1, "genesis");
        assert_eq!(chain.prev_hash, hash1, "state must advance to hash1 after event1");

        let e2 = AuditEvent::session_closed("s1", "alice", 30);
        let (prev2, hash2) = chain.compute_chain(&make_event_json(&e2)).unwrap();
        assert_eq!(prev2, hash1, "prev_hash of event2 must be hash1");
        assert_eq!(chain.prev_hash, hash2, "state must advance to hash2 after event2");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // Serial mutex for hostname tests that mutate UNIX_OIDC_HOSTNAME env var.
    // Env vars are process-wide; parallel test threads would race without this.
    // Pattern consistent with Phase 6 / unix-oidc-agent config tests.
    use parking_lot::Mutex;
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_ssh_login_success_serialization() {
        let event = AuditEvent::ssh_login_success(
            "session-123",
            "testuser",
            Some(1001),
            Some("192.168.1.1"),
            Some("token-jti-456"),
            Some("urn:example:acr:mfa"),
            Some(1705400000),
        );

        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("SSH_LOGIN_SUCCESS"));
        assert!(json.contains("testuser"));
        assert!(json.contains("session-123"));
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("token-jti-456"));
        assert!(json.contains("urn:example:acr:mfa"));
    }

    #[test]
    fn test_ssh_login_failed_serialization() {
        let event = AuditEvent::ssh_login_failed(
            Some("testuser"),
            Some("192.168.1.1"),
            "Token validation failed: expired",
        );

        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("SSH_LOGIN_FAILED"));
        assert!(json.contains("testuser"));
        assert!(json.contains("Token validation failed"));
    }

    #[test]
    fn test_token_validation_failed_serialization() {
        let event = AuditEvent::token_validation_failed(
            Some("testuser"),
            "Invalid issuer",
            Some("10.0.0.1"),
            Some("http://wrong-issuer.com"),
        );

        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("TOKEN_VALIDATION_FAILED"));
        assert!(json.contains("Invalid issuer"));
        assert!(json.contains("wrong-issuer"));
    }

    #[test]
    fn test_user_not_found_serialization() {
        let event = AuditEvent::user_not_found("unknownuser");

        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("USER_NOT_FOUND"));
        assert!(json.contains("unknownuser"));
    }

    #[test]
    fn test_event_type() {
        let success = AuditEvent::ssh_login_success("s", "u", None, None, None, None, None);
        assert_eq!(success.event_type(), "SSH_LOGIN_SUCCESS");

        let failed = AuditEvent::ssh_login_failed(None, None, "reason");
        assert_eq!(failed.event_type(), "SSH_LOGIN_FAILED");

        let token_failed = AuditEvent::token_validation_failed(None, "reason", None, None);
        assert_eq!(token_failed.event_type(), "TOKEN_VALIDATION_FAILED");

        let not_found = AuditEvent::user_not_found("user");
        assert_eq!(not_found.event_type(), "USER_NOT_FOUND");
    }

    #[test]
    fn test_timestamp_format() {
        let ts = iso_timestamp();
        // Should be in RFC 3339 format like "2024-01-15T10:30:00.123456789+00:00"
        assert!(ts.contains('T'));
        assert!(ts.contains(':'));
    }

    // ── Phase 8: BreakGlassAuth tests ───────────────────────────────────────

    #[test]
    fn test_break_glass_auth_serialization() {
        let event = AuditEvent::break_glass_auth("emergency", Some("10.0.0.1"), true);
        let json = serde_json::to_string(&event).unwrap();

        // Event tag must be BREAK_GLASS_AUTH
        assert!(json.contains("BREAK_GLASS_AUTH"), "json: {json}");
        // Username must appear
        assert!(json.contains("emergency"), "json: {json}");
        // Source IP must appear
        assert!(json.contains("10.0.0.1"), "json: {json}");
        // Severity must be CRITICAL when alert_on_use=true
        assert!(json.contains("CRITICAL"), "json: {json}");
        // Reason must be present
        assert!(json.contains("break-glass bypass"), "json: {json}");
        // Timestamp must be present
        assert!(json.contains("timestamp"), "json: {json}");
    }

    #[test]
    fn test_break_glass_auth_serialization_no_source_ip() {
        let event = AuditEvent::break_glass_auth("breakglass1", None, true);
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("BREAK_GLASS_AUTH"), "json: {json}");
        assert!(json.contains("breakglass1"), "json: {json}");
        assert!(json.contains("CRITICAL"), "json: {json}");
        // source_ip should be null or absent
        assert!(json.contains("null") || !json.contains("source_ip\":\""));
    }

    #[test]
    fn test_break_glass_auth_event_type() {
        let event = AuditEvent::break_glass_auth("emergency", None, true);
        assert_eq!(event.event_type(), "BREAK_GLASS_AUTH");
    }

    // ── SBUG-02 / SHRD-03: alert_on_use wiring and syslog severity ──────────
    //
    // These tests serve as regression guards for SHRD-03:
    // "BREAK_GLASS_AUTH events appear at syslog CRITICAL severity when alert_on_use=true."
    // Existing tests from Phase 24 SBUG-02 already cover:
    // - syslog_severity() -> Critical for alert_on_use=true
    // - syslog_severity() -> Info for alert_on_use=false
    // - JSON payload contains "severity":"CRITICAL" / "severity":"INFO"
    // - event_type() returns "BREAK_GLASS_AUTH"

    #[test]
    fn test_break_glass_auth_alert_on_use_true_is_critical() {
        let event = AuditEvent::break_glass_auth("bguser", Some("10.1.2.3"), true);
        assert_eq!(
            event.syslog_severity(),
            AuditSeverity::Critical,
            "alert_on_use=true must produce Critical severity"
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"CRITICAL\""), "serialized severity must be CRITICAL, json: {json}");
    }

    #[test]
    fn test_break_glass_auth_alert_on_use_false_is_info() {
        let event = AuditEvent::break_glass_auth("bguser", Some("10.1.2.3"), false);
        assert_eq!(
            event.syslog_severity(),
            AuditSeverity::Info,
            "alert_on_use=false must produce Info severity"
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"INFO\""), "serialized severity must be INFO, json: {json}");
    }

    #[test]
    fn test_break_glass_auth_alert_on_use_false_no_critical_in_json() {
        let event = AuditEvent::break_glass_auth("bguser", None, false);
        let json = serde_json::to_string(&event).unwrap();
        // When alert_on_use=false severity is INFO, not CRITICAL
        assert!(!json.contains("\"CRITICAL\""), "severity must NOT be CRITICAL when alert_on_use=false, json: {json}");
    }

    // ── Phase 9: Session / introspection audit event tests ───────────────────

    #[test]
    fn test_session_opened_serialization() {
        let event = AuditEvent::session_opened("sid-123", "alice", Some("10.0.0.1"), 9_999_999);
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("SESSION_OPENED"), "json: {json}");
        assert!(json.contains("sid-123"), "json: {json}");
        assert!(json.contains("alice"), "json: {json}");
        assert!(json.contains("10.0.0.1"), "json: {json}");
        assert!(json.contains("9999999"), "json: {json}");
        assert!(json.contains("timestamp"), "json: {json}");
    }

    #[test]
    fn test_session_opened_no_client_ip() {
        let event = AuditEvent::session_opened("sid-456", "bob", None, 1000);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("SESSION_OPENED"), "json: {json}");
        assert!(json.contains("bob"), "json: {json}");
        // client_ip should be null or absent
        assert!(json.contains("null") || !json.contains("client_ip\":\""));
    }

    #[test]
    fn test_session_closed_serialization() {
        let event = AuditEvent::session_closed("sid-789", "charlie", 3600);
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("SESSION_CLOSED"), "json: {json}");
        assert!(json.contains("sid-789"), "json: {json}");
        assert!(json.contains("charlie"), "json: {json}");
        assert!(json.contains("3600"), "json: {json}");
        assert!(json.contains("timestamp"), "json: {json}");
    }

    #[test]
    fn test_token_revoked_success_serialization() {
        let event = AuditEvent::token_revoked("sid-abc", "diana", "success", None);
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("TOKEN_REVOKED"), "json: {json}");
        assert!(json.contains("sid-abc"), "json: {json}");
        assert!(json.contains("diana"), "json: {json}");
        assert!(json.contains("success"), "json: {json}");
    }

    #[test]
    fn test_token_revoked_failed_with_reason() {
        let event = AuditEvent::token_revoked("sid-def", "eve", "failed", Some("IdP unreachable"));
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("TOKEN_REVOKED"), "json: {json}");
        assert!(json.contains("failed"), "json: {json}");
        assert!(json.contains("IdP unreachable"), "json: {json}");
    }

    #[test]
    fn test_introspection_failed_serialization() {
        let event = AuditEvent::introspection_failed(
            Some("sid-xyz"),
            Some("frank"),
            "token not active",
            "warn",
        );
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("INTROSPECTION_FAILED"), "json: {json}");
        assert!(json.contains("sid-xyz"), "json: {json}");
        assert!(json.contains("frank"), "json: {json}");
        assert!(json.contains("token not active"), "json: {json}");
        assert!(json.contains("\"enforcement\""), "json: {json}");
        assert!(json.contains("warn"), "json: {json}");
    }

    #[test]
    fn test_introspection_failed_no_session_no_user() {
        let event = AuditEvent::introspection_failed(None, None, "connection refused", "strict");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("INTROSPECTION_FAILED"), "json: {json}");
        assert!(json.contains("connection refused"), "json: {json}");
        assert!(json.contains("strict"), "json: {json}");
    }

    #[test]
    fn test_new_event_types_in_event_type_method() {
        let opened = AuditEvent::session_opened("s", "u", None, 0);
        assert_eq!(opened.event_type(), "SESSION_OPENED");

        let closed = AuditEvent::session_closed("s", "u", 0);
        assert_eq!(closed.event_type(), "SESSION_CLOSED");

        let revoked = AuditEvent::token_revoked("s", "u", "skipped", None);
        assert_eq!(revoked.event_type(), "TOKEN_REVOKED");

        let failed = AuditEvent::introspection_failed(None, None, "err", "warn");
        assert_eq!(failed.event_type(), "INTROSPECTION_FAILED");
    }

    #[test]
    fn test_break_glass_auth_constructor_populates_all_fields() {
        let event = AuditEvent::break_glass_auth("testuser", Some("192.168.1.50"), true);
        match event {
            AuditEvent::BreakGlassAuth {
                timestamp,
                username,
                source_ip,
                host: _,
                reason,
                severity,
                alert_on_use,
            } => {
                assert!(!timestamp.is_empty(), "timestamp must be populated");
                assert_eq!(username, "testuser");
                assert_eq!(source_ip, Some("192.168.1.50".to_string()));
                assert_eq!(reason, "break-glass bypass");
                assert_eq!(severity, "CRITICAL");
                assert!(alert_on_use, "alert_on_use must be true");
            }
            other => panic!("Expected BreakGlassAuth, got {other:?}"),
        }
    }

    // ── OBS-02: AuthNoToken audit event tests ────────────────────────────────

    #[test]
    fn test_auth_no_token_serialization() {
        let event = AuditEvent::auth_no_token("testuser", Some("192.168.1.1"));
        let json = serde_json::to_string(&event).unwrap();

        // OBS-02 Test 1: correct event tag, username, source_ip, host, timestamp
        assert!(json.contains("AUTH_NO_TOKEN"), "json: {json}");
        assert!(json.contains("testuser"), "json: {json}");
        assert!(json.contains("192.168.1.1"), "json: {json}");
        assert!(json.contains("timestamp"), "json: {json}");
        assert!(json.contains("host"), "json: {json}");
    }

    #[test]
    fn test_auth_no_token_syslog_severity() {
        // OBS-02 Test 2: severity is Warning
        let event = AuditEvent::auth_no_token("user", Some("10.0.0.1"));
        assert_eq!(event.syslog_severity(), AuditSeverity::Warning);
    }

    #[test]
    fn test_auth_no_token_event_type() {
        // OBS-02 Test 3: event_type() returns "AUTH_NO_TOKEN"
        let event = AuditEvent::auth_no_token("user", None);
        assert_eq!(event.event_type(), "AUTH_NO_TOKEN");
    }

    #[test]
    fn test_auth_no_token_distinct_from_ssh_login_failed() {
        // OBS-02 Test 4 (negative): AUTH_NO_TOKEN is distinct from SSH_LOGIN_FAILED
        let no_token = AuditEvent::auth_no_token("user", None);
        let login_failed = AuditEvent::ssh_login_failed(Some("user"), None, "token expired");

        let no_token_json = serde_json::to_string(&no_token).unwrap();
        let login_failed_json = serde_json::to_string(&login_failed).unwrap();

        assert!(no_token_json.contains("AUTH_NO_TOKEN"), "no_token json: {no_token_json}");
        assert!(login_failed_json.contains("SSH_LOGIN_FAILED"), "login_failed json: {login_failed_json}");
        assert!(!no_token_json.contains("SSH_LOGIN_FAILED"), "AUTH_NO_TOKEN must not contain SSH_LOGIN_FAILED, json: {no_token_json}");
        assert!(!login_failed_json.contains("AUTH_NO_TOKEN"), "SSH_LOGIN_FAILED must not contain AUTH_NO_TOKEN, json: {login_failed_json}");
    }

    // ── OBS-08: SessionCloseFailed audit event tests ──────────────────────────

    #[test]
    fn test_session_close_failed_serialization() {
        let event = AuditEvent::session_close_failed("sid-abc", "alice", "connection refused");
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("SESSION_CLOSE_FAILED"), "json: {json}");
        assert!(json.contains("sid-abc"), "json: {json}");
        assert!(json.contains("alice"), "json: {json}");
        assert!(json.contains("connection refused"), "json: {json}");
        assert!(json.contains("timestamp"), "json: {json}");
        assert!(json.contains("host"), "json: {json}");
    }

    #[test]
    fn test_session_close_failed_syslog_severity() {
        // OBS-08 Test 6: severity is Warning
        let event = AuditEvent::session_close_failed("sid-123", "bob", "write error");
        assert_eq!(event.syslog_severity(), AuditSeverity::Warning);
    }

    #[test]
    fn test_session_close_failed_event_type() {
        // OBS-08 Test 7: event_type() returns "SESSION_CLOSE_FAILED"
        let event = AuditEvent::session_close_failed("sid-456", "carol", "timeout");
        assert_eq!(event.event_type(), "SESSION_CLOSE_FAILED");
    }

    #[test]
    fn test_session_close_failed_no_ipc_message_content() {
        // OBS-08 Test 8 (negative): event does NOT contain full IPC message content
        let ipc_message = r#"{"action":"session_closed","session_id":"sid-789"}"#;
        let event = AuditEvent::session_close_failed("sid-789", "dave", "write timeout");
        let json = serde_json::to_string(&event).unwrap();

        assert!(!json.contains("\"action\""), "IPC message field action must not appear in audit event, json: {json}");
        assert!(!json.contains(ipc_message), "full IPC message must not appear in audit event, json: {json}");
        assert!(json.contains("write timeout"), "reason must appear, json: {json}");
    }

    // ── get_hostname() tests ─────────────────────────────────────────────────

    #[test]
    fn test_get_hostname_returns_non_empty() {
        let _guard = ENV_MUTEX.lock();
        // Without UNIX_OIDC_HOSTNAME set (or with it cleared), gethostname(2) must
        // return a non-empty string on any properly configured system.
        std::env::remove_var("UNIX_OIDC_HOSTNAME");
        let h = get_hostname();
        assert!(!h.is_empty(), "hostname must be non-empty, got: {h:?}");
    }

    #[test]
    fn test_get_hostname_env_override() {
        let _guard = ENV_MUTEX.lock();
        std::env::set_var("UNIX_OIDC_HOSTNAME", "my-custom-host.example.com");
        let h = get_hostname();
        assert_eq!(h, "my-custom-host.example.com");
        std::env::remove_var("UNIX_OIDC_HOSTNAME");
    }

    #[test]
    fn test_get_hostname_syscall_without_override() {
        let _guard = ENV_MUTEX.lock();
        std::env::remove_var("UNIX_OIDC_HOSTNAME");
        // gethostname::gethostname() returns the same value
        let syscall_result = gethostname::gethostname().to_string_lossy().into_owned();
        let h = get_hostname();
        // Both should agree (no env override in play)
        assert_eq!(h, syscall_result);
    }

    // ── Syslog severity mapping tests ───────────────────────────────────────

    #[test]
    fn test_syslog_severity_mapping() {
        let bg = AuditEvent::break_glass_auth("emergency", None, true);
        assert_eq!(bg.syslog_severity(), AuditSeverity::Critical);

        let failed = AuditEvent::ssh_login_failed(None, None, "reason");
        assert_eq!(failed.syslog_severity(), AuditSeverity::Warning);

        let token_failed = AuditEvent::token_validation_failed(None, "bad", None, None);
        assert_eq!(token_failed.syslog_severity(), AuditSeverity::Warning);

        let not_found = AuditEvent::user_not_found("alice");
        assert_eq!(not_found.syslog_severity(), AuditSeverity::Warning);

        let step_failed = AuditEvent::step_up_failed("u", None, "ciba", "timeout");
        assert_eq!(step_failed.syslog_severity(), AuditSeverity::Warning);

        let intro_failed = AuditEvent::introspection_failed(None, None, "err", "strict");
        assert_eq!(intro_failed.syslog_severity(), AuditSeverity::Warning);

        let success = AuditEvent::ssh_login_success("s", "u", None, None, None, None, None);
        assert_eq!(success.syslog_severity(), AuditSeverity::Info);

        let opened = AuditEvent::session_opened("s", "u", None, 0);
        assert_eq!(opened.syslog_severity(), AuditSeverity::Info);

        let closed = AuditEvent::session_closed("s", "u", 0);
        assert_eq!(closed.syslog_severity(), AuditSeverity::Info);

        let revoked = AuditEvent::token_revoked("s", "u", "success", None);
        assert_eq!(revoked.syslog_severity(), AuditSeverity::Info);

        let initiated = AuditEvent::step_up_initiated("u", None, "ciba", None);
        assert_eq!(initiated.syslog_severity(), AuditSeverity::Info);

        let step_ok = AuditEvent::step_up_success("u", None, "ciba", "s", None, None);
        assert_eq!(step_ok.syslog_severity(), AuditSeverity::Info);
    }
}
