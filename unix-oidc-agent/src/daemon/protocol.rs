//! JSON protocol for agent IPC

use crate::metrics::MetricsSnapshot;
use serde::{Deserialize, Serialize};

/// Request from client to agent
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum AgentRequest {
    /// Get token and proof for a target
    #[serde(rename = "get_proof")]
    GetProof {
        target: String,
        method: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    },

    /// Get current status
    #[serde(rename = "status")]
    Status,

    /// Get agent metrics
    #[serde(rename = "metrics")]
    Metrics {
        /// Output format: "json" (default) or "prometheus"
        #[serde(default)]
        format: MetricsFormat,
    },

    /// Trigger token refresh
    #[serde(rename = "refresh")]
    Refresh,

    /// Shutdown the daemon
    #[serde(rename = "shutdown")]
    Shutdown,
}

/// Output format for metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricsFormat {
    #[default]
    Json,
    Prometheus,
}

/// Response from agent to client
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum AgentResponse {
    #[serde(rename = "success")]
    Success(AgentResponseData),

    #[serde(rename = "error")]
    Error { message: String, code: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentResponseData {
    Proof {
        token: String,
        dpop_proof: String,
        expires_in: u64,
    },
    Status {
        logged_in: bool,
        username: Option<String>,
        thumbprint: Option<String>,
        token_expires: Option<i64>,
        /// Human-readable memory protection status (mlock availability).
        /// Set at daemon startup; None if the daemon has not been queried yet.
        #[serde(skip_serializing_if = "Option::is_none")]
        mlock_status: Option<String>,
        /// Active storage backend display name, e.g. "keyring (Secret Service)".
        /// Set at daemon startup; None if the daemon has not been queried yet.
        #[serde(skip_serializing_if = "Option::is_none")]
        storage_backend: Option<String>,
        /// Migration status after last startup, e.g. "migrated", "n/a".
        /// Set at daemon startup; None if the daemon has not been queried yet.
        #[serde(skip_serializing_if = "Option::is_none")]
        migration_status: Option<String>,
    },
    Metrics {
        /// Metrics data (JSON format)
        #[serde(flatten)]
        data: MetricsSnapshot,
    },
    MetricsText {
        /// Metrics in Prometheus text format
        text: String,
    },
    Refreshed {
        expires_in: u64,
    },
    Ok {},
}

impl AgentResponse {
    pub fn proof(token: String, dpop_proof: String, expires_in: u64) -> Self {
        Self::Success(AgentResponseData::Proof {
            token,
            dpop_proof,
            expires_in,
        })
    }

    pub fn status(
        logged_in: bool,
        username: Option<String>,
        thumbprint: Option<String>,
        token_expires: Option<i64>,
        mlock_status: Option<String>,
        storage_backend: Option<String>,
        migration_status: Option<String>,
    ) -> Self {
        Self::Success(AgentResponseData::Status {
            logged_in,
            username,
            thumbprint,
            token_expires,
            mlock_status,
            storage_backend,
            migration_status,
        })
    }

    pub fn ok() -> Self {
        Self::Success(AgentResponseData::Ok {})
    }

    pub fn refreshed(expires_in: u64) -> Self {
        Self::Success(AgentResponseData::Refreshed { expires_in })
    }

    pub fn metrics(data: MetricsSnapshot) -> Self {
        Self::Success(AgentResponseData::Metrics { data })
    }

    pub fn metrics_text(text: String) -> Self {
        Self::Success(AgentResponseData::MetricsText { text })
    }

    pub fn error(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
            code: code.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let req = AgentRequest::GetProof {
            target: "server.example.com".to_string(),
            method: "SSH".to_string(),
            nonce: Some("abc123".to_string()),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""action":"get_proof""#));
        assert!(json.contains(r#""target":"server.example.com""#));
    }

    #[test]
    fn test_request_deserialization() {
        let json = r#"{"action":"get_proof","target":"server.example.com","method":"SSH"}"#;
        let req: AgentRequest = serde_json::from_str(json).unwrap();

        match req {
            AgentRequest::GetProof {
                target,
                method,
                nonce,
            } => {
                assert_eq!(target, "server.example.com");
                assert_eq!(method, "SSH");
                assert!(nonce.is_none());
            }
            _ => panic!("Unexpected request type"),
        }
    }

    #[test]
    fn test_response_serialization() {
        let resp = AgentResponse::proof("token123".to_string(), "proof456".to_string(), 300);

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""status":"success""#));
        assert!(json.contains(r#""token":"token123""#));
    }

    #[test]
    fn test_error_response() {
        let resp = AgentResponse::error("Not logged in", "NOT_LOGGED_IN");

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""status":"error""#));
        assert!(json.contains(r#""code":"NOT_LOGGED_IN""#));
    }

    #[test]
    fn test_status_response() {
        let resp = AgentResponse::status(
            true,
            Some("alice".to_string()),
            Some("thumb123".to_string()),
            Some(1234567890),
            Some("mlock active".to_string()),
            Some("keyring (Secret Service)".to_string()),
            Some("migrated".to_string()),
        );

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""logged_in":true"#));
        assert!(json.contains(r#""username":"alice""#));
        assert!(json.contains(r#""mlock_status":"mlock active""#));
        assert!(json.contains(r#""storage_backend":"keyring (Secret Service)""#));
        assert!(json.contains(r#""migration_status":"migrated""#));
    }

    /// TDD: storage_backend field is omitted from JSON when None (skip_serializing_if).
    #[test]
    fn test_status_response_omits_storage_fields_when_none() {
        let resp = AgentResponse::status(
            false,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("storage_backend"), "storage_backend must be absent when None");
        assert!(!json.contains("migration_status"), "migration_status must be absent when None");
    }

    /// TDD: full JSON round-trip with all fields populated.
    #[test]
    fn test_status_response_round_trip_all_fields() {
        let resp = AgentResponse::status(
            true,
            Some("bob".to_string()),
            Some("fp-abc".to_string()),
            Some(9999999999),
            Some("mlock active".to_string()),
            Some("keyring (keyutils @u)".to_string()),
            Some("n/a".to_string()),
        );

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();

        if let AgentResponse::Success(AgentResponseData::Status {
            logged_in,
            username,
            storage_backend,
            migration_status,
            ..
        }) = parsed
        {
            assert!(logged_in);
            assert_eq!(username.as_deref(), Some("bob"));
            assert_eq!(storage_backend.as_deref(), Some("keyring (keyutils @u)"));
            assert_eq!(migration_status.as_deref(), Some("n/a"));
        } else {
            panic!("Expected Status response");
        }
    }
}
