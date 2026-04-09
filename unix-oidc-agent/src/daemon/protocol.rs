//! JSON protocol for agent IPC

use crate::metrics::MetricsSnapshot;
use serde::{Deserialize, Serialize};

/// Default HTTP method for DPoP proof binding in token exchange requests.
fn default_ssh_method() -> String {
    "SSH".to_string()
}

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
        /// Remote Unix username being authenticated (for per-user presence cache).
        /// When set, the hardware presence cache is scoped to this user+target pair.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        remote_user: Option<String>,
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
        /// Session ID of the parent SSH session that triggered sudo.
        ///
        /// Read from `UNIX_OIDC_SESSION_ID` env var in the PAM sudo path.
        /// Used for end-to-end audit correlation (OBS-3). Optional for backward
        /// compatibility — old PAM versions without this field deserialize as None.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        parent_session_id: Option<String>,
    },

    /// PAM -> Agent: poll for step-up result.
    ///
    /// Agent returns StepUpPending (still waiting), StepUpComplete, or StepUpTimedOut.
    #[serde(rename = "step_up_result")]
    StepUpResult { correlation_id: String },

    /// Perform RFC 8693 token exchange: exchange a subject token for a new
    /// token bound to this agent's DPoP key, targeting a different audience.
    ///
    /// Used for multi-hop SSH: a jump host exchanges the user's incoming token
    /// for a new token bound to the jump host's DPoP key.
    #[serde(rename = "exchange_token")]
    ExchangeToken {
        /// The subject token to exchange (the connecting user's access token).
        subject_token: String,
        /// Target audience for the exchanged token (next hop hostname).
        audience: String,
        /// HTTP method for DPoP proof binding. Default: "SSH".
        #[serde(default = "default_ssh_method")]
        method: String,
        /// Optional token endpoint override. When set, skips OIDC discovery and
        /// uses this URL directly. Plumbed from the CLI `--token-endpoint` flag.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        token_endpoint: Option<String>,
    },
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
            AgentRequest::ExchangeToken { .. } => "ExchangeToken",
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
    /// Token exchange response — new token bound to this agent's DPoP key.
    ///
    /// Discriminant field: `original_subject` (unique to this variant).
    ///
    /// ORDERING: Must appear BEFORE `Proof` in this enum. With `#[serde(untagged)]`,
    /// serde tries variants in declaration order. `Proof` and `ExchangedProof` share
    /// the same required base fields (`token`, `dpop_proof`, `expires_in`), so if
    /// `Proof` were first, serde would match it and silently drop `original_subject`
    /// and `delegation_depth`. By placing `ExchangedProof` first, serde matches it
    /// only when `original_subject` is present, then falls through to `Proof`.
    ExchangedProof {
        /// The exchanged access token.
        token: String,
        /// DPoP proof for the exchanged token (signed by this agent's key).
        dpop_proof: String,
        /// Seconds until the exchanged token expires.
        expires_in: u64,
        /// Original subject (user) from the subject_token's `sub` claim.
        original_subject: String,
        /// Delegation depth of the `act` chain in the exchanged token.
        delegation_depth: usize,
    },
    Proof {
        token: String,
        dpop_proof: String,
        expires_in: u64,
        /// How the hardware signer was authorized: "physical_touch", "cached", or "not_applicable".
        /// Allows the PAM module to emit the correct OCSF audit signal.
        #[serde(skip_serializing_if = "Option::is_none")]
        presence_type: Option<String>,
        /// TPM attestation evidence (ADR-018). Present when the signer is TPM-backed
        /// and attestation was successfully produced. JSON object with `certify_info`,
        /// `signature`, and `ak_public` fields (all base64url-encoded). The PAM module
        /// can verify this to enforce hardware-bound key requirements.
        #[serde(skip_serializing_if = "Option::is_none")]
        attestation: Option<serde_json::Value>,
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
        /// Hardware presence cache TTL in seconds. 0 = disabled.
        #[serde(skip_serializing_if = "Option::is_none")]
        presence_cache_ttl_secs: Option<u64>,
        /// Number of active (non-expired) entries in the presence cache.
        #[serde(skip_serializing_if = "Option::is_none")]
        presence_cache_active: Option<usize>,
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
        /// Parent SSH session ID echoed back from the agent for audit correlation.
        ///
        /// Matches the `parent_session_id` sent in the `StepUp` IPC request.
        /// Optional for backward compatibility — old agents that do not set this
        /// field will deserialize as None.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        parent_session_id: Option<String>,
        /// Raw ID token from the IdP's CIBA token response (D-12, Phase 30-02).
        ///
        /// New PAM versions validate the signature, issuer, audience, and ACR
        /// from this token directly (D-13 dual validation). Old PAM versions that
        /// do not read this field continue to work — the `default` attribute
        /// produces `None` for JSON that lacks the key (backward compat).
        ///
        /// The agent performs best-effort pre-validation before returning this token.
        /// PAM is the enforcement point and must validate independently.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        id_token: Option<String>,
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
    pub fn proof(
        token: String,
        dpop_proof: String,
        expires_in: u64,
        presence_type: Option<String>,
        attestation: Option<serde_json::Value>,
    ) -> Self {
        Self::Success(AgentResponseData::Proof {
            token,
            dpop_proof,
            expires_in,
            presence_type,
            attestation,
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
        presence_cache_ttl_secs: Option<u64>,
        presence_cache_active: Option<usize>,
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
            presence_cache_ttl_secs,
            presence_cache_active,
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
        presence_cache_ttl_secs: Option<u64>,
        presence_cache_active: Option<usize>,
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
            presence_cache_ttl_secs,
            presence_cache_active,
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
    pub fn step_up_complete(
        acr: Option<String>,
        session_id: String,
        parent_session_id: Option<String>,
        id_token: Option<String>,
    ) -> Self {
        Self::Success(AgentResponseData::StepUpComplete {
            acr,
            session_id,
            parent_session_id,
            id_token,
        })
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
            remote_user: None,
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
                ..
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
        let resp = AgentResponse::proof(
            "token123".to_string(),
            "proof456".to_string(),
            300,
            None,
            None,
        );

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
            Some(300),
            Some(0),
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
        let resp =
            AgentResponse::status(false, None, None, None, None, None, None, None, None, None);

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
            Some(300),
            Some(2),
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
            Some(300),
            Some(1),
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
            "expected action=session_closed in: {json}"
        );
        assert!(
            json.contains(r#""session_id":"sess-abc-123""#),
            "expected session_id in: {json}"
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
            _ => panic!("Expected SessionClosed, got {req:?}"),
        }
    }

    /// SessionAcknowledged response serializes correctly with acknowledged=true discriminant.
    #[test]
    fn test_session_acknowledged_response_serialization() {
        let resp = AgentResponse::session_acknowledged();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""status":"success""#),
            "expected success status in: {json}"
        );
        assert!(
            json.contains(r#""acknowledged":true"#),
            "expected acknowledged=true discriminant in: {json}"
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
            "expected SessionAcknowledged, got: {parsed:?}"
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
            None,
            None,
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""refresh_failed":true"#),
            "expected refresh_failed in: {json}"
        );
    }

    /// Status response omits refresh_failed field when None (backward compat).
    #[test]
    fn test_status_response_refresh_failed_absent_when_none() {
        let resp =
            AgentResponse::status(false, None, None, None, None, None, None, None, None, None);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            !json.contains("refresh_failed"),
            "refresh_failed must be absent when None, got: {json}"
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
            parent_session_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains(r#""action":"step_up""#),
            "expected action=step_up in: {json}"
        );
        assert!(
            json.contains(r#""username":"alice""#),
            "expected username in: {json}"
        );
        assert!(
            json.contains(r#""command":"systemctl restart""#),
            "expected command in: {json}"
        );
        assert!(
            json.contains(r#""hostname":"prod-01""#),
            "expected hostname in: {json}"
        );
        assert!(
            json.contains(r#""method":"push""#),
            "expected method in: {json}"
        );
        assert!(
            json.contains(r#""timeout_secs":120"#),
            "expected timeout_secs in: {json}"
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
                ..
            } => {
                assert_eq!(username, "alice");
                assert_eq!(command, "systemctl restart");
                assert_eq!(hostname, "prod-01");
                assert_eq!(method, "push");
                assert_eq!(timeout_secs, 120);
            }
            _ => panic!("Expected StepUp, got {req:?}"),
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
            "expected action=step_up_result in: {json}"
        );
        assert!(
            json.contains(r#""correlation_id":"uuid-here""#),
            "expected correlation_id in: {json}"
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
            _ => panic!("Expected StepUpResult, got {req:?}"),
        }
    }

    /// StepUpPending response round-trips with required fields including poll_interval_secs.
    #[test]
    fn test_step_up_pending_response_round_trip() {
        let resp = AgentResponse::step_up_pending("uuid".to_string(), 120, 5);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""correlation_id":"uuid""#),
            "expected correlation_id in: {json}"
        );
        assert!(
            json.contains(r#""expires_in":120"#),
            "expected expires_in in: {json}"
        );
        assert!(
            json.contains(r#""poll_interval_secs":5"#),
            "expected poll_interval_secs in: {json}"
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
            "expected StepUpPending, got: {parsed:?}"
        );
    }

    /// StepUpComplete response round-trips with acr=None.
    #[test]
    fn test_step_up_complete_response_round_trip_no_acr() {
        let resp = AgentResponse::step_up_complete(None, "sess-123".to_string(), None, None);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""session_id":"sess-123""#),
            "expected session_id in: {json}"
        );
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(
                parsed,
                AgentResponse::Success(AgentResponseData::StepUpComplete {
                    acr: None,
                    ref session_id,
                    ..
                }) if session_id == "sess-123"
            ),
            "expected StepUpComplete with no acr, got: {parsed:?}"
        );
    }

    /// StepUpComplete response round-trips with acr=Some(url).
    #[test]
    fn test_step_up_complete_response_round_trip_with_acr() {
        let resp = AgentResponse::step_up_complete(
            Some("http://schemas.openid.net/phr".to_string()),
            "sess-456".to_string(),
            None,
            None,
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""session_id":"sess-456""#),
            "expected session_id in: {json}"
        );
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(
                parsed,
                AgentResponse::Success(AgentResponseData::StepUpComplete {
                    ref acr,
                    ref session_id,
                    ..
                }) if acr.as_deref() == Some("http://schemas.openid.net/phr") && session_id == "sess-456"
            ),
            "expected StepUpComplete with acr, got: {parsed:?}"
        );
    }

    /// StepUpTimedOut response round-trips with reason and user_message fields.
    #[test]
    fn test_step_up_timed_out_response_round_trip() {
        let resp = AgentResponse::step_up_timed_out("timeout", "Approval window expired");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""reason":"timeout""#),
            "expected reason in: {json}"
        );
        assert!(
            json.contains(r#""user_message":"Approval window expired""#),
            "expected user_message in: {json}"
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
            "expected StepUpTimedOut, got: {parsed:?}"
        );
    }

    // --- TDD RED: parent_session_id threading in StepUp IPC protocol ---

    /// StepUp JSON without parent_session_id deserializes correctly — parent_session_id is None (backward compat).
    #[test]
    fn test_step_up_without_parent_session_id_backward_compat() {
        let json = r#"{"action":"step_up","username":"alice","command":"/usr/bin/ls","hostname":"prod-01","method":"push","timeout_secs":120}"#;
        let req: AgentRequest = serde_json::from_str(json).unwrap();
        match req {
            AgentRequest::StepUp {
                parent_session_id, ..
            } => {
                assert!(
                    parent_session_id.is_none(),
                    "parent_session_id must be None when absent in JSON (backward compat)"
                );
            }
            _ => panic!("Expected StepUp, got {req:?}"),
        }
    }

    /// StepUp JSON with parent_session_id deserializes correctly — parent_session_id is Some("abc-123").
    #[test]
    fn test_step_up_with_parent_session_id() {
        let json = r#"{"action":"step_up","username":"alice","command":"/usr/bin/ls","hostname":"prod-01","method":"push","timeout_secs":120,"parent_session_id":"abc-123"}"#;
        let req: AgentRequest = serde_json::from_str(json).unwrap();
        match req {
            AgentRequest::StepUp {
                parent_session_id, ..
            } => {
                assert_eq!(
                    parent_session_id.as_deref(),
                    Some("abc-123"),
                    "parent_session_id must be Some('abc-123') when present in JSON"
                );
            }
            _ => panic!("Expected StepUp, got {req:?}"),
        }
    }

    /// StepUpComplete JSON with parent_session_id serializes/deserializes correctly.
    #[test]
    fn test_step_up_complete_with_parent_session_id_round_trip() {
        let resp = AgentResponse::step_up_complete(
            Some("urn:mfa".to_string()),
            "sess-789".to_string(),
            Some("parent-sess-001".to_string()),
            None,
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains(r#""parent_session_id":"parent-sess-001""#),
            "expected parent_session_id in: {json}"
        );
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::Success(AgentResponseData::StepUpComplete {
                parent_session_id,
                session_id,
                ..
            }) => {
                assert_eq!(parent_session_id.as_deref(), Some("parent-sess-001"));
                assert_eq!(session_id, "sess-789");
            }
            _ => panic!("Expected StepUpComplete, got {parsed:?}"),
        }
    }

    /// StepUpComplete JSON without parent_session_id still deserializes (backward compat).
    #[test]
    fn test_step_up_complete_without_parent_session_id_backward_compat() {
        let json = r#"{"status":"success","acr":null,"session_id":"sess-456"}"#;
        let parsed: AgentResponse = serde_json::from_str(json).unwrap();
        match parsed {
            AgentResponse::Success(AgentResponseData::StepUpComplete {
                parent_session_id,
                session_id,
                ..
            }) => {
                assert!(
                    parent_session_id.is_none(),
                    "parent_session_id must be None when absent in JSON (backward compat)"
                );
                assert_eq!(session_id, "sess-456");
            }
            _ => panic!("Expected StepUpComplete, got {parsed:?}"),
        }
    }

    /// StepUpComplete still discriminates correctly against other untagged variants (session_id is discriminant).
    #[test]
    fn test_step_up_complete_still_discriminates_with_parent_session_id() {
        // With parent_session_id present, must still deserialize as StepUpComplete (not Ok or SessionAcknowledged)
        let resp = AgentResponse::step_up_complete(
            None,
            "sess-disc-test".to_string(),
            Some("parent-abc".to_string()),
            None,
        );
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(
                parsed,
                AgentResponse::Success(AgentResponseData::StepUpComplete {
                    ref session_id,
                    ..
                }) if session_id == "sess-disc-test"
            ),
            "StepUpComplete with parent_session_id must still discriminate correctly, got: {parsed:?}"
        );
    }

    // ── TDD RED: id_token field in StepUpComplete (Phase 30-02) ─────────────

    /// StepUpComplete with id_token=Some(token) serializes to JSON containing "id_token" key.
    #[test]
    fn test_step_up_complete_id_token_round_trip() {
        let raw_token = "eyJhbGciOiJSUzI1NiJ9.eyJhY3IiOiJ1cm46ZXhhbXBsZTptZmEifQ.sig";
        let resp = AgentResponse::step_up_complete(
            Some("urn:example:mfa".to_string()),
            "sess-123".to_string(),
            None,
            Some(raw_token.to_string()),
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("id_token"),
            "id_token must appear in JSON when Some, got: {json}"
        );
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::Success(AgentResponseData::StepUpComplete {
                id_token,
                session_id,
                ..
            }) => {
                assert_eq!(
                    id_token.as_deref(),
                    Some(raw_token),
                    "id_token must survive round-trip, got: {id_token:?}"
                );
                assert_eq!(session_id, "sess-123");
            }
            other => panic!("Expected StepUpComplete, got: {other:?}"),
        }
    }

    /// StepUpComplete with id_token=None serializes WITHOUT "id_token" key (skip_serializing_if).
    #[test]
    fn test_step_up_complete_no_id_token_omitted_from_json() {
        let resp = AgentResponse::step_up_complete(None, "sess-456".to_string(), None, None);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            !json.contains("id_token"),
            "id_token must be absent from JSON when None, got: {json}"
        );
    }

    /// JSON without id_token field must deserialize to StepUpComplete with id_token=None (backward compat).
    #[test]
    fn test_step_up_complete_no_id_token_backward_compat() {
        // Old-format JSON without id_token — old PAM/agent produced this
        let json = r#"{"status":"success","acr":"mfa","session_id":"sess-001"}"#;
        let parsed: AgentResponse = serde_json::from_str(json).unwrap();
        match parsed {
            AgentResponse::Success(AgentResponseData::StepUpComplete {
                id_token,
                session_id,
                ..
            }) => {
                assert!(
                    id_token.is_none(),
                    "id_token must be None when absent in JSON (backward compat), got: {id_token:?}"
                );
                assert_eq!(session_id, "sess-001");
            }
            other => panic!("Expected StepUpComplete, got: {other:?}"),
        }
    }

    // --- TDD: ExchangeToken IPC protocol (Phase 37-01 Task 4) ---

    #[test]
    fn test_exchange_token_request_roundtrip() {
        let req = AgentRequest::ExchangeToken {
            subject_token: "eyJhbGciOiJSUzI1NiJ9.test".into(),
            audience: "target-host-b".into(),
            method: "SSH".into(),
            token_endpoint: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""action":"exchange_token"#));
        // token_endpoint should be omitted when None
        assert!(!json.contains("token_endpoint"));
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::ExchangeToken {
                subject_token,
                audience,
                method,
                token_endpoint,
            } => {
                assert_eq!(subject_token, "eyJhbGciOiJSUzI1NiJ9.test");
                assert_eq!(audience, "target-host-b");
                assert_eq!(method, "SSH");
                assert!(token_endpoint.is_none());
            }
            _ => panic!("Expected ExchangeToken"),
        }
    }

    #[test]
    fn test_exchange_token_with_token_endpoint_override() {
        let json = r#"{"action":"exchange_token","subject_token":"tok","audience":"host","token_endpoint":"https://idp.example.com/token"}"#;
        let parsed: AgentRequest = serde_json::from_str(json).unwrap();
        match parsed {
            AgentRequest::ExchangeToken { token_endpoint, .. } => {
                assert_eq!(
                    token_endpoint.as_deref(),
                    Some("https://idp.example.com/token")
                );
            }
            _ => panic!("Expected ExchangeToken"),
        }
    }

    #[test]
    fn test_exchange_token_default_method() {
        let json = r#"{"action":"exchange_token","subject_token":"tok","audience":"host"}"#;
        let parsed: AgentRequest = serde_json::from_str(json).unwrap();
        match parsed {
            AgentRequest::ExchangeToken { method, .. } => {
                assert_eq!(method, "SSH");
            }
            _ => panic!("Expected ExchangeToken"),
        }
    }

    #[test]
    fn test_exchanged_proof_response_serde() {
        let data = AgentResponseData::ExchangedProof {
            token: "new-token".into(),
            dpop_proof: "new-proof".into(),
            expires_in: 300,
            original_subject: "alice@example.com".into(),
            delegation_depth: 1,
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("original_subject"));
        assert!(json.contains("alice@example.com"));
    }

    /// Verify untagged serde discrimination: ExchangedProof (with `original_subject`)
    /// must deserialize as ExchangedProof, not be swallowed by Proof.
    ///
    /// This test catches the ordering bug where `Proof` appeared before `ExchangedProof`
    /// in the enum and serde matched `Proof` first, silently dropping `original_subject`
    /// and `delegation_depth`.
    #[test]
    fn test_exchanged_proof_deserializes_as_exchanged_proof_not_proof() {
        let json = serde_json::json!({
            "token": "exchanged-tok",
            "dpop_proof": "exchanged-prf",
            "expires_in": 300,
            "original_subject": "alice@example.com",
            "delegation_depth": 2
        });
        let data: AgentResponseData = serde_json::from_value(json).unwrap();
        match data {
            AgentResponseData::ExchangedProof {
                original_subject,
                delegation_depth,
                ..
            } => {
                assert_eq!(original_subject, "alice@example.com");
                assert_eq!(delegation_depth, 2);
            }
            other => panic!(
                "Expected ExchangedProof, got {other:?} — \
                 check variant ordering in AgentResponseData"
            ),
        }
    }

    /// Proof (without `original_subject`) must still deserialize as Proof.
    #[test]
    fn test_proof_without_original_subject_deserializes_as_proof() {
        let json = serde_json::json!({
            "token": "plain-tok",
            "dpop_proof": "plain-prf",
            "expires_in": 60
        });
        let data: AgentResponseData = serde_json::from_value(json).unwrap();
        assert!(
            matches!(data, AgentResponseData::Proof { .. }),
            "Expected Proof, got {data:?}"
        );
    }

    // ── ADR-018: attestation evidence in Proof response ──────────────────

    #[test]
    fn test_proof_response_with_attestation() {
        let data = AgentResponseData::Proof {
            token: "tok".into(),
            dpop_proof: "proof".into(),
            expires_in: 300,
            presence_type: None,
            attestation: Some(serde_json::json!({
                "certify_info": "Y2VydA",
                "signature": "c2ln",
                "ak_public": "YWs"
            })),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("attestation"));
        assert!(json.contains("certify_info"));
    }

    #[test]
    fn test_proof_response_without_attestation_omits_field() {
        let data = AgentResponseData::Proof {
            token: "tok".into(),
            dpop_proof: "proof".into(),
            expires_in: 300,
            presence_type: None,
            attestation: None,
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(
            !json.contains("attestation"),
            "attestation should be omitted when None"
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
            "SessionAcknowledged must still parse correctly, got: {parsed:?}"
        );
    }
}
