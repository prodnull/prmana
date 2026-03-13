//! Types for OAuth 2.0 Device Authorization Grant.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error types for device flow operations.
#[derive(Debug, Error)]
pub enum DeviceFlowError {
    /// The authorization request is still pending user action.
    #[error("Authorization pending")]
    AuthorizationPending,

    /// The client is polling too fast; should slow down.
    #[error("Slow down: polling too fast")]
    SlowDown,

    /// The user denied the authorization request.
    #[error("Access denied by user")]
    AccessDenied,

    /// The device code has expired.
    #[error("Device code expired")]
    ExpiredToken,

    /// Network or HTTP error.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Invalid response from the server.
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Token validation failed.
    #[error("Token validation failed: {0}")]
    TokenValidation(String),

    /// Timeout waiting for user authentication.
    #[error("Timeout waiting for user authentication")]
    Timeout,

    /// Configuration error (e.g., IdP does not advertise a required endpoint).
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Response from the device authorization endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceAuthResponse {
    /// The device verification code.
    pub device_code: String,

    /// The end-user verification code displayed to the user.
    pub user_code: String,

    /// The URI the user should visit to authorize.
    pub verification_uri: String,

    /// Optional verification URI that includes the user_code.
    #[serde(default)]
    pub verification_uri_complete: Option<String>,

    /// Lifetime of the device_code in seconds.
    pub expires_in: u64,

    /// Minimum polling interval in seconds.
    #[serde(default = "default_interval")]
    pub interval: u64,
}

impl DeviceAuthResponse {
    /// Validate that verification URIs use the HTTPS scheme.
    ///
    /// RFC 9700 §2.5 requires TLS for all authorization server endpoints.
    /// A non-HTTPS verification URI could direct users to an insecure page
    /// where credentials are entered in the clear.
    ///
    /// `allow_http` should only be `true` when `test-mode` is enabled
    /// (local Keycloak development over HTTP).
    pub fn validate_uris(&self, allow_http: bool) -> Result<(), DeviceFlowError> {
        if !allow_http {
            if !self.verification_uri.starts_with("https://") {
                return Err(DeviceFlowError::InvalidResponse(format!(
                    "verification_uri must use HTTPS scheme, got: {}",
                    self.verification_uri
                        .split('/')
                        .take(3)
                        .collect::<Vec<_>>()
                        .join("/"),
                )));
            }
            if let Some(ref uri) = self.verification_uri_complete {
                if !uri.starts_with("https://") {
                    return Err(DeviceFlowError::InvalidResponse(
                        "verification_uri_complete must use HTTPS scheme".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn default_interval() -> u64 {
    5
}

/// Token response from the token endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,

    /// The token type (usually "Bearer").
    pub token_type: String,

    /// Lifetime of the access token in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,

    /// Optional refresh token.
    #[serde(default)]
    pub refresh_token: Option<String>,

    /// Optional ID token (for OIDC).
    #[serde(default)]
    pub id_token: Option<String>,

    /// Optional scope granted.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Error response from the token endpoint during polling.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenErrorResponse {
    /// The error code.
    pub error: String,

    /// Optional error description.
    #[serde(default)]
    pub error_description: Option<String>,
}

impl TokenErrorResponse {
    /// Convert to a DeviceFlowError.
    pub fn into_error(self) -> DeviceFlowError {
        match self.error.as_str() {
            "authorization_pending" => DeviceFlowError::AuthorizationPending,
            "slow_down" => DeviceFlowError::SlowDown,
            "access_denied" => DeviceFlowError::AccessDenied,
            "expired_token" => DeviceFlowError::ExpiredToken,
            _ => DeviceFlowError::InvalidResponse(format!(
                "{}: {}",
                self.error,
                self.error_description.unwrap_or_default()
            )),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_device_auth_response_deserialize() {
        let json = r#"{
            "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            "user_code": "ABCD-1234",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=ABCD-1234",
            "expires_in": 1800,
            "interval": 5
        }"#;

        let response: DeviceAuthResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.user_code, "ABCD-1234");
        assert_eq!(response.expires_in, 1800);
        assert_eq!(response.interval, 5);
    }

    #[test]
    fn test_device_auth_response_default_interval() {
        let json = r#"{
            "device_code": "abc123",
            "user_code": "ABCD-1234",
            "verification_uri": "https://example.com/device",
            "expires_in": 1800
        }"#;

        let response: DeviceAuthResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.interval, 5); // Default value
    }

    #[test]
    fn test_token_error_response_conversion() {
        let error = TokenErrorResponse {
            error: "authorization_pending".to_string(),
            error_description: None,
        };
        assert!(matches!(
            error.into_error(),
            DeviceFlowError::AuthorizationPending
        ));

        let error = TokenErrorResponse {
            error: "slow_down".to_string(),
            error_description: Some("Polling too fast".to_string()),
        };
        assert!(matches!(error.into_error(), DeviceFlowError::SlowDown));

        let error = TokenErrorResponse {
            error: "access_denied".to_string(),
            error_description: None,
        };
        assert!(matches!(error.into_error(), DeviceFlowError::AccessDenied));

        let error = TokenErrorResponse {
            error: "expired_token".to_string(),
            error_description: None,
        };
        assert!(matches!(error.into_error(), DeviceFlowError::ExpiredToken));
    }

    // --- URI scheme validation tests ---

    fn make_response(verification_uri: &str, complete: Option<&str>) -> DeviceAuthResponse {
        DeviceAuthResponse {
            device_code: "test-code".to_string(),
            user_code: "ABCD-1234".to_string(),
            verification_uri: verification_uri.to_string(),
            verification_uri_complete: complete.map(String::from),
            expires_in: 1800,
            interval: 5,
        }
    }

    #[test]
    fn test_validate_uris_accepts_https() {
        let resp = make_response("https://idp.example.com/device", None);
        assert!(resp.validate_uris(false).is_ok());
    }

    #[test]
    fn test_validate_uris_accepts_https_with_complete() {
        let resp = make_response(
            "https://idp.example.com/device",
            Some("https://idp.example.com/device?code=ABCD"),
        );
        assert!(resp.validate_uris(false).is_ok());
    }

    #[test]
    fn test_validate_uris_rejects_http() {
        let resp = make_response("http://idp.example.com/device", None);
        let err = resp.validate_uris(false).unwrap_err();
        assert!(
            matches!(err, DeviceFlowError::InvalidResponse(ref msg) if msg.contains("HTTPS")),
            "Expected HTTPS error, got: {err:?}"
        );
    }

    #[test]
    fn test_validate_uris_rejects_http_complete() {
        let resp = make_response(
            "https://idp.example.com/device",
            Some("http://idp.example.com/device?code=ABCD"),
        );
        let err = resp.validate_uris(false).unwrap_err();
        assert!(matches!(err, DeviceFlowError::InvalidResponse(_)));
    }

    #[test]
    fn test_validate_uris_rejects_custom_scheme() {
        let resp = make_response("myapp://callback", None);
        assert!(resp.validate_uris(false).is_err());
    }

    #[test]
    fn test_validate_uris_allows_http_in_test_mode() {
        let resp = make_response("http://localhost:8080/device", None);
        assert!(resp.validate_uris(true).is_ok());
    }
}
