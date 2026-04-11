//! Minimal subset of the prmana-agent IPC protocol types.
//!
//! These types MUST remain serde-compatible with the agent's protocol.rs.
//! Any change here must be mirrored in `prmana-agent/src/daemon/protocol.rs`
//! and vice versa.
//!
//! # Why duplicate rather than import?
//!
//! Importing `prmana-agent` as a library would pull in its full dependency tree
//! (keyring backends, TPM, SPIRE, CIBA, hardware signers) for a simple CLI tool.
//! The `protocol-only` feature refactor is deferred; this duplication keeps
//! the binary small and fast to compile.
//!
//! # Serde compatibility test
//!
//! `tests/integration.rs` round-trips request/response JSON through both
//! this module and a mock socket to verify compatibility.

use serde::{Deserialize, Serialize};

/// Request sent from prmana-kubectl to prmana-agent.
///
/// Only `GetKubectlCredential` is needed; other variants are listed for
/// documentation / future use but not constructed by this binary.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum AgentRequest {
    /// Get a kubectl exec-credential token for the specified cluster.
    ///
    /// Returns a bearer token scoped to audience `<cluster_id>.kube.prmana`.
    /// Token TTL: 10 minutes. No `cnf` claim (bearer-only).
    #[serde(rename = "get_kubectl_credential")]
    GetKubectlCredential {
        /// Cluster identifier used to form the audience `<cluster_id>.kube.prmana`.
        cluster_id: String,
    },
}

/// Successful response data from prmana-agent.
///
/// Only `KubectlCredential` is expected in this binary.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentResponseData {
    /// Kubectl exec credential — bearer token, no DPoP.
    ///
    /// Discriminant: `expires_at_unix` (unique field not present in other variants).
    KubectlCredential {
        /// Bearer token with audience `<cluster_id>.kube.prmana`.
        token: String,
        /// Unix timestamp (seconds) of token expiry (JWT `exp` claim).
        /// Subtract 30s to get `expirationTimestamp` for kubectl.
        expires_at_unix: i64,
    },
    /// Any other response data — treated as unexpected.
    Other(serde_json::Value),
}

/// Top-level response envelope from prmana-agent.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum AgentResponse {
    #[serde(rename = "success")]
    Success(AgentResponseData),

    #[serde(rename = "error")]
    Error { message: String, code: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that our serde representation matches the agent's wire format.
    #[test]
    fn test_get_kubectl_credential_request_wire_format() {
        let req = AgentRequest::GetKubectlCredential {
            cluster_id: "prod".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains(r#""action":"get_kubectl_credential""#),
            "wire format must use action=get_kubectl_credential: {json}"
        );
        assert!(
            json.contains(r#""cluster_id":"prod""#),
            "wire format must include cluster_id: {json}"
        );
    }

    /// Verify that the response parses correctly from agent wire JSON.
    #[test]
    fn test_kubectl_credential_response_parse() {
        let wire = r#"{"status":"success","token":"eyJ.test","expires_at_unix":1712000000}"#;
        let resp: AgentResponse = serde_json::from_str(wire).unwrap();
        match resp {
            AgentResponse::Success(AgentResponseData::KubectlCredential {
                token,
                expires_at_unix,
            }) => {
                assert_eq!(token, "eyJ.test");
                assert_eq!(expires_at_unix, 1_712_000_000);
            }
            other => panic!("Expected KubectlCredential, got {other:?}"),
        }
    }

    /// Error response parses correctly.
    #[test]
    fn test_error_response_parse() {
        let wire = r#"{"status":"error","message":"Not logged in","code":"NOT_LOGGED_IN"}"#;
        let resp: AgentResponse = serde_json::from_str(wire).unwrap();
        assert!(matches!(resp, AgentResponse::Error { .. }));
    }

    /// Security invariant: KubectlCredential response has no `cnf` field.
    #[test]
    fn test_no_cnf_in_kubectl_credential() {
        let resp_data = AgentResponseData::KubectlCredential {
            token: "bearer.token".to_string(),
            expires_at_unix: 1_712_000_000,
        };
        let json = serde_json::to_string(&resp_data).unwrap();
        assert!(
            !json.contains("cnf"),
            "KubectlCredential must not contain cnf: {json}"
        );
    }
}
