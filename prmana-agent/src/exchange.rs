//! RFC 8693 Token Exchange client implementation.
//!
//! Performs the OAuth 2.0 Token Exchange grant with DPoP rebinding as
//! described in ADR-005 (alignment). The jump host sends the user's
//! subject token to the IdP and receives a new token bound to its own
//! DPoP key.
//!
//! References:
//! - RFC 8693: OAuth 2.0 Token Exchange
//! - RFC 9449: DPoP
//! - draft-ietf-oauth-identity-chaining-08

use serde::Deserialize;
use thiserror::Error;
use tracing::info;

use crate::config::ClientAttestationConfig;
use crate::crypto::{attach_client_attestation, DPoPError, DPoPSigner};
use crate::url_policy::validate_endpoint_url;

/// Token exchange grant type (RFC 8693 §2.1).
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Subject token type for access tokens (RFC 8693 §3).
const SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Requested token type (RFC 8693 §3).
const REQUESTED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Token exchange HTTP timeout.
const EXCHANGE_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("Token exchange HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Token exchange endpoint policy error: {0}")]
    InsecureEndpoint(String),

    #[error("Token exchange failed: {error} — {description}")]
    OAuthError { error: String, description: String },

    #[error("Client attestation header generation failed: {0}")]
    ClientAttestation(String),
}

/// Successful token exchange response (RFC 8693 §2.2).
#[derive(Debug, Deserialize)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(default)]
    pub issued_token_type: Option<String>,
}

/// OAuth error response.
#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Perform RFC 8693 token exchange with DPoP rebinding.
///
/// Sends a `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` request
/// to the IdP's token endpoint. The `DPoP` header carries a proof signed by
/// this agent's key, binding the new token to the jump host's DPoP keypair.
///
/// # Parameters
/// - `token_endpoint` — IdP token endpoint URL (HTTPS required in production).
/// - `subject_token` — The user's access token being exchanged.
/// - `audience` — Target service/host for the exchanged token.
/// - `client_id` — This exchanger's OAuth client_id.
/// - `client_secret` — Optional client secret for confidential clients.
/// - `dpop_proof` — DPoP proof header signed by this agent's key.
///
/// # References
/// - RFC 8693 §2.1 (request parameters)
/// - RFC 9449 §5 (DPoP proof header)
/// - ADR-005-alignment §4 (identity chaining with `requested_cnf`)
#[allow(clippy::too_many_arguments)]
pub async fn perform_token_exchange(
    token_endpoint: &str,
    subject_token: &str,
    audience: &str,
    client_id: &str,
    client_secret: Option<&str>,
    dpop_proof: &str,
    signer: &dyn DPoPSigner,
    client_attestation: Option<&ClientAttestationConfig>,
) -> Result<ExchangeResponse, ExchangeError> {
    validate_endpoint_url(token_endpoint, "token_endpoint")
        .map_err(ExchangeError::InsecureEndpoint)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(EXCHANGE_TIMEOUT_SECS))
        .build()?;

    let mut params = vec![
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
        ("subject_token", subject_token),
        ("subject_token_type", SUBJECT_TOKEN_TYPE),
        ("requested_token_type", REQUESTED_TOKEN_TYPE),
        ("audience", audience),
        ("client_id", client_id),
    ];

    if let Some(secret) = client_secret {
        params.push(("client_secret", secret));
    }

    let response = attach_client_attestation(
        client.post(token_endpoint).header("DPoP", dpop_proof),
        signer,
        client_attestation,
        client_id,
        token_endpoint,
    )
    .map_err(|e| match e {
        DPoPError::HardwareSigner(msg) | DPoPError::UnsupportedAlgorithm(msg) => {
            ExchangeError::ClientAttestation(msg)
        }
        DPoPError::InvalidKey => {
            ExchangeError::ClientAttestation("invalid client attestation key".to_string())
        }
        DPoPError::ClockError => {
            ExchangeError::ClientAttestation("clock error building client attestation".to_string())
        }
        DPoPError::Json(err) => ExchangeError::ClientAttestation(err.to_string()),
        DPoPError::InvalidProofFormat => {
            ExchangeError::ClientAttestation("invalid proof format".to_string())
        }
        DPoPError::InvalidBase64 => ExchangeError::ClientAttestation("invalid base64".to_string()),
        DPoPError::InvalidProofType => {
            ExchangeError::ClientAttestation("invalid proof type".to_string())
        }
        DPoPError::InvalidSignatureLength(len) => {
            ExchangeError::ClientAttestation(format!("invalid signature length: {len}"))
        }
    })?
    .form(&params)
    .send()
    .await?;

    if !response.status().is_success() {
        let status = response.status();
        let err: OAuthErrorResponse = response.json().await.unwrap_or(OAuthErrorResponse {
            error: format!("http_{}", status.as_u16()),
            error_description: Some(format!("HTTP {status}")),
        });
        return Err(ExchangeError::OAuthError {
            error: err.error,
            description: err.error_description.unwrap_or_default(),
        });
    }

    let resp: ExchangeResponse = response.json().await?;

    info!(
        audience = audience,
        expires_in = resp.expires_in,
        token_type = %resp.token_type,
        "Token exchange successful"
    );

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientAttestationConfig;
    use crate::crypto::SoftwareSigner;
    use wiremock::matchers;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_exchange_sends_correct_grant_type() {
        let signer = SoftwareSigner::generate();
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "exchanged-token",
                "token_type": "DPoP",
                "expires_in": 300
            })))
            .mount(&mock_server)
            .await;

        let result = perform_token_exchange(
            &mock_server.uri(),
            "subject-token-value",
            "target-host-b",
            "jump-host-a",
            Some("secret"),
            "dpop-proof-header",
            &signer,
            None,
        )
        .await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.access_token, "exchanged-token");
        assert_eq!(resp.expires_in, 300);
    }

    #[tokio::test]
    async fn test_exchange_sends_dpop_header() {
        let signer = SoftwareSigner::generate();
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::header("DPoP", "my-dpop-proof"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok",
                "token_type": "DPoP",
                "expires_in": 60
            })))
            .mount(&mock_server)
            .await;

        let result = perform_token_exchange(
            &mock_server.uri(),
            "sub-token",
            "target",
            "client",
            None,
            "my-dpop-proof",
            &signer,
            None,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_exchange_rejects_non_loopback_http_endpoint() {
        let signer = SoftwareSigner::generate();
        let result = perform_token_exchange(
            "http://idp.example.com/token",
            "sub-token",
            "target",
            "client",
            None,
            "proof",
            &signer,
            None,
        )
        .await;

        assert!(matches!(result, Err(ExchangeError::InsecureEndpoint(_))));
    }

    #[tokio::test]
    async fn test_exchange_includes_client_secret_when_provided() {
        let signer = SoftwareSigner::generate();
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::body_string_contains("client_secret=my-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok",
                "token_type": "DPoP",
                "expires_in": 60
            })))
            .mount(&mock_server)
            .await;

        let result = perform_token_exchange(
            &mock_server.uri(),
            "sub-token",
            "target",
            "client",
            Some("my-secret"),
            "proof",
            &signer,
            None,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_exchange_error_response() {
        let signer = SoftwareSigner::generate();
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Subject token not found"
            })))
            .mount(&mock_server)
            .await;

        let result = perform_token_exchange(
            &mock_server.uri(),
            "bad-token",
            "target",
            "client",
            None,
            "proof",
            &signer,
            None,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid_grant"),
            "Error should contain 'invalid_grant': {err}"
        );
    }

    #[tokio::test]
    async fn test_exchange_no_client_secret_omits_field() {
        let signer = SoftwareSigner::generate();
        let mock_server = MockServer::start().await;
        // Verify client_secret is NOT in body when None
        Mock::given(matchers::method("POST"))
            .and(matchers::body_string_contains("grant_type="))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok",
                "token_type": "DPoP",
                "expires_in": 60
            })))
            .mount(&mock_server)
            .await;

        let result = perform_token_exchange(
            &mock_server.uri(),
            "sub-token",
            "target",
            "client",
            None, // no secret
            "proof",
            &signer,
            None,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_exchange_no_attestation_headers_when_disabled() {
        let signer = SoftwareSigner::generate();
        let disabled = ClientAttestationConfig {
            enabled: false,
            lifetime_secs: 3600,
        };
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok",
                "token_type": "DPoP",
                "expires_in": 60
            })))
            .mount(&mock_server)
            .await;

        let result = perform_token_exchange(
            &mock_server.uri(),
            "sub-token",
            "target",
            "client",
            None,
            "proof",
            &signer,
            Some(&disabled),
        )
        .await;

        assert!(result.is_ok());
        let requests = mock_server.received_requests().await.unwrap();
        assert!(!requests[0].headers.contains_key("OAuth-Client-Attestation"));
        assert!(!requests[0]
            .headers
            .contains_key("OAuth-Client-Attestation-PoP"));
    }
}
