//! Audit logging for authentication events.
//!
//! This module provides structured audit logging compatible with CIM (Common Information Model)
//! and OCSF (Open Cybersecurity Schema Framework) for security event analysis.
//!
//! Audit events are written to:
//! 1. Syslog (AUTH facility) - for SIEM integration
//! 2. /var/log/unix-oidc-audit.log - dedicated audit file
//! 3. stderr - for debugging/testing

use once_cell::sync::Lazy;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use syslog::{Facility, Formatter3164};

/// Default audit log file path
const DEFAULT_AUDIT_LOG: &str = "/var/log/unix-oidc-audit.log";

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
    /// Emitted at CRITICAL severity whenever a break-glass account authenticates.
    /// This event must be forwarded to SIEM/alerting systems immediately.
    /// OCSF: Authentication / Privileged Account Use (class_uid 3002).
    #[serde(rename = "BREAK_GLASS_AUTH")]
    BreakGlassAuth {
        timestamp: String,
        username: String,
        source_ip: Option<String>,
        host: String,
        reason: String,
        /// Constant "CRITICAL" — break-glass use is always a critical event.
        severity: &'static str,
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
        oidc_issuer: Option<&str>,
    ) -> Self {
        Self::TokenValidationFailed {
            timestamp: iso_timestamp(),
            user: user.map(String::from),
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
    /// This event is always CRITICAL severity. The caller must ensure it is
    /// logged via `.log()` immediately after construction; this constructor
    /// does not emit it automatically.
    pub fn break_glass_auth(username: &str, source_ip: Option<&str>) -> Self {
        Self::BreakGlassAuth {
            timestamp: iso_timestamp(),
            username: username.to_string(),
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
            reason: "break-glass bypass".to_string(),
            severity: "CRITICAL",
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

    /// Log this event to the configured audit destinations.
    pub fn log(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            // 1. Log to syslog (AUTH facility)
            log_to_syslog(&json);

            // 2. Log to audit file (default or configured path)
            let log_path = std::env::var("UNIX_OIDC_AUDIT_LOG")
                .unwrap_or_else(|_| DEFAULT_AUDIT_LOG.to_string());
            let _ = append_to_file(&log_path, &json);

            // 3. Log to stderr for debugging/testing
            eprintln!("unix-oidc-audit: {}", json);
        }
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
        }
    }
}

/// Get the current timestamp in ISO 8601 format.
fn iso_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Get the hostname of the current machine.
fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Append a line to a file.
fn append_to_file(path: &str, content: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    writeln!(file, "{}", content)?;
    Ok(())
}

/// Log a message to syslog.
fn log_to_syslog(message: &str) {
    if let Ok(mut guard) = SYSLOG_WRITER.lock() {
        if let Some(ref mut logger) = *guard {
            // Use info level for audit events
            let _ = logger.info(message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let token_failed = AuditEvent::token_validation_failed(None, "reason", None);
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
        let event = AuditEvent::break_glass_auth("emergency", Some("10.0.0.1"));
        let json = serde_json::to_string(&event).unwrap();

        // Event tag must be BREAK_GLASS_AUTH
        assert!(json.contains("BREAK_GLASS_AUTH"), "json: {json}");
        // Username must appear
        assert!(json.contains("emergency"), "json: {json}");
        // Source IP must appear
        assert!(json.contains("10.0.0.1"), "json: {json}");
        // Severity must be CRITICAL
        assert!(json.contains("CRITICAL"), "json: {json}");
        // Reason must be present
        assert!(json.contains("break-glass bypass"), "json: {json}");
        // Timestamp must be present
        assert!(json.contains("timestamp"), "json: {json}");
    }

    #[test]
    fn test_break_glass_auth_serialization_no_source_ip() {
        let event = AuditEvent::break_glass_auth("breakglass1", None);
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("BREAK_GLASS_AUTH"), "json: {json}");
        assert!(json.contains("breakglass1"), "json: {json}");
        assert!(json.contains("CRITICAL"), "json: {json}");
        // source_ip should be null or absent
        assert!(json.contains("null") || !json.contains("source_ip\":\""));
    }

    #[test]
    fn test_break_glass_auth_event_type() {
        let event = AuditEvent::break_glass_auth("emergency", None);
        assert_eq!(event.event_type(), "BREAK_GLASS_AUTH");
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
        let event = AuditEvent::break_glass_auth("testuser", Some("192.168.1.50"));
        match event {
            AuditEvent::BreakGlassAuth {
                timestamp,
                username,
                source_ip,
                host: _,
                reason,
                severity,
            } => {
                assert!(!timestamp.is_empty(), "timestamp must be populated");
                assert_eq!(username, "testuser");
                assert_eq!(source_ip, Some("192.168.1.50".to_string()));
                assert_eq!(reason, "break-glass bypass");
                assert_eq!(severity, "CRITICAL");
            }
            other => panic!("Expected BreakGlassAuth, got {:?}", other),
        }
    }
}
