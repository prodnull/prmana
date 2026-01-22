//! Approval provider trait and common types.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Status of an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Request is pending approval.
    Pending,
    /// Request has been approved.
    Approved,
    /// Request has been denied.
    Denied,
    /// Request has expired.
    Expired,
    /// An error occurred.
    Error,
}

/// A request for step-up approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique identifier for this approval request.
    pub request_id: String,
    /// The username requesting step-up.
    pub username: String,
    /// The command being executed (if available).
    pub command: Option<String>,
    /// Hostname where the request originated.
    pub hostname: String,
    /// Unix timestamp when the request was created.
    pub timestamp: i64,
    /// How long the request is valid (in seconds).
    pub timeout_seconds: u64,
    /// Additional context/metadata.
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

impl ApprovalRequest {
    /// Create a new approval request.
    pub fn new(username: &str, command: Option<&str>, timeout_seconds: u64) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let request_id = generate_request_id();
        let hostname = gethostname::gethostname().to_string_lossy().to_string();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            request_id,
            username: username.to_string(),
            command: command.map(|s| s.to_string()),
            hostname,
            timestamp,
            timeout_seconds,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Add metadata to the request.
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Response from an approval check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    /// The request ID this response is for.
    pub request_id: String,
    /// Current status of the approval.
    pub status: ApprovalStatus,
    /// Optional message to display to the user.
    pub message: Option<String>,
    /// Approver identifier (if approved).
    pub approver: Option<String>,
    /// Unix timestamp when the decision was made.
    pub decided_at: Option<i64>,
}

impl ApprovalResponse {
    /// Create a pending response.
    pub fn pending(request_id: &str) -> Self {
        Self {
            request_id: request_id.to_string(),
            status: ApprovalStatus::Pending,
            message: None,
            approver: None,
            decided_at: None,
        }
    }

    /// Create an approved response.
    pub fn approved(request_id: &str, approver: Option<&str>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            request_id: request_id.to_string(),
            status: ApprovalStatus::Approved,
            message: None,
            approver: approver.map(|s| s.to_string()),
            decided_at: Some(now),
        }
    }

    /// Create a denied response.
    pub fn denied(request_id: &str, message: Option<&str>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            request_id: request_id.to_string(),
            status: ApprovalStatus::Denied,
            message: message.map(|s| s.to_string()),
            approver: None,
            decided_at: Some(now),
        }
    }
}

/// Errors that can occur during approval.
#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("Request timed out")]
    Timeout,

    #[error("Request was denied: {0}")]
    Denied(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Approval cancelled")]
    Cancelled,
}

/// Trait for approval providers.
///
/// Implementations of this trait handle the approval workflow for step-up
/// authentication. Different providers can implement different mechanisms
/// (webhook, device flow, push notification, etc.).
pub trait ApprovalProvider: Send + Sync {
    /// Start a new approval request.
    ///
    /// Returns an `ApprovalRequest` that can be used to track the request.
    fn start_request(&self, request: ApprovalRequest) -> Result<ApprovalRequest, ApprovalError>;

    /// Check the status of an approval request.
    fn check_status(&self, request_id: &str) -> Result<ApprovalResponse, ApprovalError>;

    /// Poll for approval until complete or timeout.
    ///
    /// Default implementation polls `check_status` at the specified interval.
    fn poll_until_complete(
        &self,
        request: &ApprovalRequest,
        poll_interval: Duration,
    ) -> Result<ApprovalResponse, ApprovalError> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(request.timeout_seconds);

        loop {
            // Check if we've timed out
            if start.elapsed() > timeout {
                return Err(ApprovalError::Timeout);
            }

            // Check status
            let response = self.check_status(&request.request_id)?;

            match response.status {
                ApprovalStatus::Pending => {
                    // Still waiting, sleep and try again
                    std::thread::sleep(poll_interval);
                }
                ApprovalStatus::Approved => {
                    return Ok(response);
                }
                ApprovalStatus::Denied => {
                    return Err(ApprovalError::Denied(
                        response
                            .message
                            .unwrap_or_else(|| "Request denied".to_string()),
                    ));
                }
                ApprovalStatus::Expired => {
                    return Err(ApprovalError::Timeout);
                }
                ApprovalStatus::Error => {
                    return Err(ApprovalError::InvalidResponse(
                        response
                            .message
                            .unwrap_or_else(|| "Unknown error".to_string()),
                    ));
                }
            }
        }
    }

    /// Get a user-friendly description of this provider.
    fn description(&self) -> &str;
}

/// Generate a unique request ID.
fn generate_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("apr-{:x}", timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_request_creation() {
        let req = ApprovalRequest::new("testuser", Some("sudo rm -rf"), 300);
        assert!(req.request_id.starts_with("apr-"));
        assert_eq!(req.username, "testuser");
        assert_eq!(req.command, Some("sudo rm -rf".to_string()));
        assert_eq!(req.timeout_seconds, 300);
    }

    #[test]
    fn test_approval_request_with_metadata() {
        let req = ApprovalRequest::new("testuser", None, 300)
            .with_metadata("source_ip", "192.168.1.1")
            .with_metadata("tty", "/dev/pts/0");

        assert_eq!(
            req.metadata.get("source_ip"),
            Some(&"192.168.1.1".to_string())
        );
        assert_eq!(req.metadata.get("tty"), Some(&"/dev/pts/0".to_string()));
    }

    #[test]
    fn test_approval_response_pending() {
        let resp = ApprovalResponse::pending("apr-123");
        assert_eq!(resp.request_id, "apr-123");
        assert_eq!(resp.status, ApprovalStatus::Pending);
        assert!(resp.decided_at.is_none());
    }

    #[test]
    fn test_approval_response_approved() {
        let resp = ApprovalResponse::approved("apr-123", Some("admin"));
        assert_eq!(resp.status, ApprovalStatus::Approved);
        assert_eq!(resp.approver, Some("admin".to_string()));
        assert!(resp.decided_at.is_some());
    }

    #[test]
    fn test_approval_response_denied() {
        let resp = ApprovalResponse::denied("apr-123", Some("Policy violation"));
        assert_eq!(resp.status, ApprovalStatus::Denied);
        assert_eq!(resp.message, Some("Policy violation".to_string()));
    }

    #[test]
    fn test_approval_status_serialization() {
        let status = ApprovalStatus::Pending;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"pending\"");

        let status: ApprovalStatus = serde_json::from_str("\"approved\"").unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
    }
}
