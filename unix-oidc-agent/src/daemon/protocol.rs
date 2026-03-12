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

    /// Notify agent that a PAM session has been closed.
    ///
    /// Agent ACKs immediately with SessionAcknowledged; revocation and credential
    /// cleanup run in the background so that PAM pam_sm_close_session returns fast.
    ///
    /// RFC 7009: revocation is best-effort with 5s timeout; failure never blocks.
    #[serde(rename = "session_closed")]
    SessionClosed { session_id: String },

    /// PAM -> Agent: initiate CIBA step-up authentication.
    ///
    /// Agent spawns an async CIBA poll loop and returns StepUpPending immediately.
    /// PAM should then poll with StepUpResult at the returned poll_interval_secs.
    #[serde(rename = "step_up")]
    StepUp {
        username: String,
        command: String,
        hostname: String,
        /// "push" or "fido2" — determines acr_values sent to IdP
        method: String,
        /// Maximum seconds to wait before timing out; from policy, default 120
        timeout_secs: u64,
    },

    /// PAM -> Agent: poll for step-up result.
    ///
    /// Agent returns StepUpPending (still waiting), StepUpComplete, or StepUpTimedOut.
    #[serde(rename = "step_up_result")]
    StepUpResult { correlation_id: String },
}

impl AgentRequest {
    /// Return a short, stable name for the request variant.
    ///
    /// Used to populate the `command` field in the `ipc_request` tracing span
    /// after the request JSON has been parsed.  The names match the IPC wire
    /// format (`action` field) so they can be correlated with client logs.
    pub fn command_name(&self) -> &'static str {
        match self {
            AgentRequest::GetProof { .. } => "GetProof",
            AgentRequest::Status => "Status",
            AgentRequest::Metrics { .. } => "Metrics",
            AgentRequest::Refresh => "Refresh",
            AgentRequest::Shutdown => "Shutdown",
            AgentRequest::SessionClosed { .. } => "SessionClosed",
            AgentRequest::StepUp { .. } => "StepUp",
            AgentRequest::StepUpResult { .. } => "StepUpResult",
        }
    }
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
        /// Active signer backend, e.g. "software", "yubikey:9a", "tpm".
        /// Set at daemon startup from stored token metadata.
        #[serde(skip_serializing_if = "Option::is_none")]
        signer_type: Option<String>,
        /// True when the background auto-refresh task exhausted all retries.
        /// Operator signal: token will expire at natural lifetime; manual refresh or re-login required.
        /// Omitted from JSON when None (backward compat — callers that don't set this field are unaffected).
        #[serde(skip_serializing_if = "Option::is_none")]
        refresh_failed: Option<bool>,
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
    /// Step-up initiated — PAM should poll with StepUpResult at poll_interval_secs.
    ///
    /// `poll_interval_secs` is the required unique discriminant field for untagged serde.
    /// Placed BEFORE `Refreshed` because both have `expires_in`; serde must try
    /// StepUpPending first so it matches on `poll_interval_secs` before Refreshed claims
    /// any JSON object that has `expires_in`.
    ///
    /// Ordering contract:
    ///   StepUpPending → StepUpComplete → StepUpTimedOut →
    ///   Refreshed → SessionAcknowledged → Ok{}
    StepUpPending {
        correlation_id: String,
        expires_in: u64,
        poll_interval_secs: u64,
    },
    /// Step-up completed successfully — ACR validated (if required).
    ///
    /// `session_id` is the required discriminant field for untagged serde.
    StepUpComplete {
        acr: Option<String>,
        session_id: String,
    },
    /// Step-up failed or timed out.
    ///
    /// `reason` is the required discriminant field for untagged serde.
    StepUpTimedOut {
        reason: String,
        user_message: String,
    },
    Refreshed {
        expires_in: u64,
    },
    /// ACK for SessionClosed — sent immediately before background cleanup starts.
    ///
    /// Must appear before `Ok {}` in the untagged enum: `acknowledged: bool` serves as
    /// a required discriminant field that `Ok {}` does not have, so serde tries
    /// `SessionAcknowledged` first when deserializing `{"acknowledged":true}`.
    SessionAcknowledged {
        acknowledged: bool,
    },
    /// Generic success with no data fields.
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

    #[allow(clippy::too_many_arguments)]
    pub fn status(
        logged_in: bool,
        username: Option<String>,
        thumbprint: Option<String>,
        token_expires: Option<i64>,
        mlock_status: Option<String>,
        storage_backend: Option<String>,
        migration_status: Option<String>,
        signer_type: Option<String>,
    ) -> Self {
        Self::Success(AgentResponseData::Status {
            logged_in,
            username,
            thumbprint,
            token_expires,
            mlock_status,
            storage_backend,
            migration_status,
            signer_type,
            refresh_failed: None,
        })
    }

    /// Status response that includes the refresh_failed flag.
    ///
    /// Used by the daemon when it wants to surface auto-refresh failure to operators.
    #[allow(clippy::too_many_arguments)]
    pub fn status_with_refresh_failed(
        logged_in: bool,
        username: Option<String>,
        thumbprint: Option<String>,
        token_expires: Option<i64>,
        mlock_status: Option<String>,
        storage_backend: Option<String>,
        migration_status: Option<String>,
        signer_type: Option<String>,
        refresh_failed: bool,
    ) -> Self {
        Self::Success(AgentResponseData::Status {
            logged_in,
            username,
            thumbprint,
            token_expires,
            mlock_status,
            storage_backend,
            migration_status,
            signer_type,
            refresh_failed: Some(refresh_failed),
        })
    }

    /// ACK for SessionClosed — sent immediately, before background cleanup starts.
    pub fn session_acknowledged() -> Self {
        Self::Success(AgentResponseData::SessionAcknowledged { acknowledged: true })
    }

    /// Step-up initiated — PAM should poll at poll_interval_secs intervals.
    pub fn step_up_pending(
        correlation_id: String,
        expires_in: u64,
        poll_interval_secs: u64,
    ) -> Self {
        Self::Success(AgentResponseData::StepUpPending {
            correlation_id,
            expires_in,
            poll_interval_secs,
        })
    }

    /// Step-up completed successfully.
    pub fn step_up_complete(acr: Option<String>, session_id: String) -> Self {
        Self::Success(AgentResponseData::StepUpComplete { acr, session_id })
    }

    /// Step-up failed or timed out.
    pub fn step_up_timed_out(reason: impl Into<String>, user_message: impl Into<String>) -> Self {
        Self::Success(AgentResponseData::StepUpTimedOut {
            reason: reason.into(),
            user_message: user_message.into(),
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
            Some("software".to_string()),
        );

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""logged_in":true"#));
        assert!(json.contains(r#""username":"alice""#));
        assert!(json.contains(r#""mlock_status":"mlock active""#));
        assert!(json.contains(r#""storage_backend":"keyring (Secret Service)""#));
        assert!(json.contains(r#""migration_status":"migrated""#));
        assert!(json.contains(r#""signer_type":"software""#));
    }

    /// TDD: storage_backend field is omitted from JSON when None (skip_serializing_if).
    #[test]
    fn test_status_response_omits_storage_fields_when_none() {
        let resp = AgentResponse::status(false, None, None, None, None, None, None, None);

        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            !json.contains("storage_backend"),
            "storage_backend must be absent when None"
        );
        assert!(
            !json.contains("migration_status"),
            "migration_status must be absent when None"
        );
        assert!(
            !json.contains("signer_type"),
            "signer_type must be absent when None"
        );
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
            Some("yubikey:9a".to_string()),
        );

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();

        if let AgentResponse::Success(AgentResponseData::Status {
            logged_in,
            username,
            storage_backend,
            migration_status,
            signer_type,
            ..
        }) = parsed
        {
            assert!(logged_in);
            assert_eq!(username.as_deref(), Some("bob"));
            assert_eq!(storage_backend.as_deref(), Some("keyring (keyutils @u)"));
            assert_eq!(migration_status.as_deref(), Some("n/a"));
            assert_eq!(signer_type.as_deref(), Some("yubikey:9a"));
        } else {
            panic!("Expected Status response");
        }
    }

    /// TDD: signer_type field reported for hardware signers.
    #[test]
    fn test_status_response_hardware_signer_type() {
        let resp = AgentResponse::status(
            true,
            Some("alice".to_string()),
            Some("thumb123".to_string()),
            Some(1234567890),
            None,
            None,
            None,
            Some("yubikey:9a".to_string()),
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""signer_type":"yubikey:9a""#));
    }

    // --- TDD RED: SessionClosed IPC protocol ---

    /// SessionClosed request serializes with action=session_closed and session_id field.
    #[test]
    fn test_session_closed_request_serialization() {
        let req = AgentRequest::SessionClosed {
            session_id: "sess-abc-123".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains(r#""action":"session_closed""#),
            "expected action=session_closed in: {}",
            json
        );
        assert!(
            json.contains(r#""session_id":"sess-abc-123""#),
            "expected session_id in: {}",
            json
        );
    }

    /// SessionClosed request deserializes from JSON produced by PAM close_session.
    #[test]
    fn test_session_closed_request_deserialization() {
        let json = r#"{"action":"session_closed","session_id":"sess-xyz-789"}"#;
        let req: AgentRequest = serde_json::from_str(json).unwrap();
        match req {
            AgentRequest::SessionClosed { session_id } => {
                assert_eq!(session_id, "sess-xyz-789");
            }
            _ => panic!("Expected SessionClosed, got {:?}", req),
        }
    }

    /// SessionAcknowledged response serializes correctly with acknowledged=true discriminant.
    #[test]
    fn test_session_acknowledged_response_serialization() {
        let resp = AgentResponse::session_acknowledged();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""status":"success""#),
            "expected success status in: {}",
            json
        );
        assert!(
            json.contains(r#""acknowledged":true"#),
            "expected acknowledged=true discriminant in: {}",
            json
        );
        // Round-trip: must deserialize back to SessionAcknowledged, not Ok
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(
                parsed,
                AgentResponse::Success(AgentResponseData::SessionAcknowledged {
                    acknowledged: true
                })
            ),
            "expected SessionAcknowledged, got: {:?}",
            parsed
        );
    }

    /// Status response includes refresh_failed field when true.
    #[test]
    fn test_status_response_refresh_failed_present_when_true() {
        let resp = AgentResponse::status_with_refresh_failed(
            true,
            Some("alice".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            true,
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""refresh_failed":true"#),
            "expected refresh_failed in: {}",
            json
        );
    }

    /// Status response omits refresh_failed field when None (backward compat).
    #[test]
    fn test_status_response_refresh_failed_absent_when_none() {
        let resp = AgentResponse::status(false, None, None, None, None, None, None, None);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            !json.contains("refresh_failed"),
            "refresh_failed must be absent when None, got: {}",
            json
        );
    }

    // --- TDD RED: StepUp / StepUpResult IPC protocol ---

    /// StepUp request serializes as expected JSON with action=step_up.
    #[test]
    fn test_step_up_request_serialization() {
        let req = AgentRequest::StepUp {
            username: "alice".to_string(),
            command: "systemctl restart".to_string(),
            hostname: "prod-01".to_string(),
            method: "push".to_string(),
            timeout_secs: 120,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains(r#""action":"step_up""#),
            "expected action=step_up in: {}",
            json
        );
        assert!(
            json.contains(r#""username":"alice""#),
            "expected username in: {}",
            json
        );
        assert!(
            json.contains(r#""command":"systemctl restart""#),
            "expected command in: {}",
            json
        );
        assert!(
            json.contains(r#""hostname":"prod-01""#),
            "expected hostname in: {}",
            json
        );
        assert!(
            json.contains(r#""method":"push""#),
            "expected method in: {}",
            json
        );
        assert!(
            json.contains(r#""timeout_secs":120"#),
            "expected timeout_secs in: {}",
            json
        );
    }

    /// StepUp request deserializes from JSON produced by PAM.
    #[test]
    fn test_step_up_request_deserialization() {
        let json = r#"{"action":"step_up","username":"alice","command":"systemctl restart","hostname":"prod-01","method":"push","timeout_secs":120}"#;
        let req: AgentRequest = serde_json::from_str(json).unwrap();
        match req {
            AgentRequest::StepUp {
                username,
                command,
                hostname,
                method,
                timeout_secs,
            } => {
                assert_eq!(username, "alice");
                assert_eq!(command, "systemctl restart");
                assert_eq!(hostname, "prod-01");
                assert_eq!(method, "push");
                assert_eq!(timeout_secs, 120);
            }
            _ => panic!("Expected StepUp, got {:?}", req),
        }
    }

    /// StepUpResult request serializes with action=step_up_result and correlation_id.
    #[test]
    fn test_step_up_result_request_serialization() {
        let req = AgentRequest::StepUpResult {
            correlation_id: "uuid-here".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains(r#""action":"step_up_result""#),
            "expected action=step_up_result in: {}",
            json
        );
        assert!(
            json.contains(r#""correlation_id":"uuid-here""#),
            "expected correlation_id in: {}",
            json
        );
    }

    /// StepUpResult request deserializes from JSON.
    #[test]
    fn test_step_up_result_request_deserialization() {
        let json = r#"{"action":"step_up_result","correlation_id":"uuid-here"}"#;
        let req: AgentRequest = serde_json::from_str(json).unwrap();
        match req {
            AgentRequest::StepUpResult { correlation_id } => {
                assert_eq!(correlation_id, "uuid-here");
            }
            _ => panic!("Expected StepUpResult, got {:?}", req),
        }
    }

    /// StepUpPending response round-trips with required fields including poll_interval_secs.
    #[test]
    fn test_step_up_pending_response_round_trip() {
        let resp = AgentResponse::step_up_pending("uuid".to_string(), 120, 5);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""correlation_id":"uuid""#),
            "expected correlation_id in: {}",
            json
        );
        assert!(
            json.contains(r#""expires_in":120"#),
            "expected expires_in in: {}",
            json
        );
        assert!(
            json.contains(r#""poll_interval_secs":5"#),
            "expected poll_interval_secs in: {}",
            json
        );
        // Round-trip deserialization
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(
                parsed,
                AgentResponse::Success(AgentResponseData::StepUpPending {
                    ref correlation_id,
                    expires_in: 120,
                    poll_interval_secs: 5,
                }) if correlation_id == "uuid"
            ),
            "expected StepUpPending, got: {:?}",
            parsed
        );
    }

    /// StepUpComplete response round-trips with acr=None.
    #[test]
    fn test_step_up_complete_response_round_trip_no_acr() {
        let resp = AgentResponse::step_up_complete(None, "sess-123".to_string());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""session_id":"sess-123""#),
            "expected session_id in: {}",
            json
        );
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(
                parsed,
                AgentResponse::Success(AgentResponseData::StepUpComplete {
                    acr: None,
                    ref session_id,
                }) if session_id == "sess-123"
            ),
            "expected StepUpComplete with no acr, got: {:?}",
            parsed
        );
    }

    /// StepUpComplete response round-trips with acr=Some(url).
    #[test]
    fn test_step_up_complete_response_round_trip_with_acr() {
        let resp = AgentResponse::step_up_complete(
            Some("http://schemas.openid.net/phr".to_string()),
            "sess-456".to_string(),
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""session_id":"sess-456""#),
            "expected session_id in: {}",
            json
        );
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(
                parsed,
                AgentResponse::Success(AgentResponseData::StepUpComplete {
                    ref acr,
                    ref session_id,
                }) if acr.as_deref() == Some("http://schemas.openid.net/phr") && session_id == "sess-456"
            ),
            "expected StepUpComplete with acr, got: {:?}",
            parsed
        );
    }

    /// StepUpTimedOut response round-trips with reason and user_message fields.
    #[test]
    fn test_step_up_timed_out_response_round_trip() {
        let resp = AgentResponse::step_up_timed_out("timeout", "Approval window expired");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""reason":"timeout""#),
            "expected reason in: {}",
            json
        );
        assert!(
            json.contains(r#""user_message":"Approval window expired""#),
            "expected user_message in: {}",
            json
        );
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(
                parsed,
                AgentResponse::Success(AgentResponseData::StepUpTimedOut {
                    ref reason,
                    ref user_message,
                }) if reason == "timeout" && user_message == "Approval window expired"
            ),
            "expected StepUpTimedOut, got: {:?}",
            parsed
        );
    }

    /// Existing SessionAcknowledged/Ok ordering is preserved after adding StepUp variants.
    #[test]
    fn test_session_acknowledged_still_discriminates_from_ok_after_step_up_variants() {
        let resp = AgentResponse::session_acknowledged();
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(
                parsed,
                AgentResponse::Success(AgentResponseData::SessionAcknowledged {
                    acknowledged: true
                })
            ),
            "SessionAcknowledged must still parse correctly, got: {:?}",
            parsed
        );
    }
}
