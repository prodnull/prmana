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
}
