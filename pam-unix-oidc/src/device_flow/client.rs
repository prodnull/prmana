//! Device flow client implementation.

use std::time::{Duration, Instant};

use reqwest::blocking::Client;

use crate::oidc::OidcDiscovery;

use super::types::{DeviceAuthResponse, DeviceFlowError, TokenErrorResponse, TokenResponse};

/// Client for OAuth 2.0 Device Authorization Grant.
#[derive(Debug)]
pub struct DeviceFlowClient {
    http_client: Client,
    device_authorization_endpoint: String,
    token_endpoint: String,
    client_id: String,
    client_secret: Option<String>,
}

impl DeviceFlowClient {
    /// Create a device flow client from OIDC discovery metadata.
    ///
    /// This is the IdP-agnostic constructor (STP-06). It reads
    /// `device_authorization_endpoint` and `token_endpoint` directly from the
    /// OIDC discovery document rather than constructing Keycloak-specific paths.
    ///
    /// Returns `DeviceFlowError::ConfigError` when the IdP does not advertise
    /// a `device_authorization_endpoint` in its discovery document — per RFC 8628 §3.1
    /// this field is required for Device Authorization Grant support.
    ///
    /// Prefer this constructor for all non-Keycloak deployments.
    pub fn from_discovery(
        discovery: &OidcDiscovery,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<Self, DeviceFlowError> {
        let device_endpoint = discovery
            .device_authorization_endpoint
            .as_deref()
            .ok_or_else(|| {
                DeviceFlowError::ConfigError(
                    "IdP does not advertise device_authorization_endpoint in OIDC discovery \
                     (RFC 8628 §3.1); device flow is not supported by this IdP"
                        .to_string(),
                )
            })?;

        Self::with_endpoints(
            device_endpoint,
            &discovery.token_endpoint,
            client_id,
            client_secret,
        )
    }

    /// Create a new device flow client using Keycloak-specific endpoint paths.
    ///
    /// **Deprecated for non-Keycloak deployments.** Use `from_discovery()` instead,
    /// which reads endpoints from the OIDC discovery document and works with any
    /// RFC 8628-compliant IdP (Auth0, Okta, Azure AD, Google, etc.).
    ///
    /// Returns an error if the HTTP client cannot be constructed (e.g., invalid TLS
    /// configuration). Propagating errors here prevents a panic in the PAM module.
    ///
    /// # Arguments
    /// * `issuer_url` - The OIDC issuer URL (will append Keycloak-specific endpoint paths)
    /// * `client_id` - The OAuth client ID
    /// * `client_secret` - Optional client secret for confidential clients
    pub fn new(
        issuer_url: &str,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<Self, DeviceFlowError> {
        let base = issuer_url.trim_end_matches('/');

        Ok(Self {
            http_client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| {
                    DeviceFlowError::NetworkError(format!("Failed to create HTTP client: {e}"))
                })?,
            device_authorization_endpoint: format!("{base}/protocol/openid-connect/auth/device"),
            token_endpoint: format!("{base}/protocol/openid-connect/token"),
            client_id: client_id.to_string(),
            client_secret: client_secret.map(String::from),
        })
    }

    /// Create a client with explicit endpoints (for non-standard IdPs).
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn with_endpoints(
        device_authorization_endpoint: &str,
        token_endpoint: &str,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<Self, DeviceFlowError> {
        Ok(Self {
            http_client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| {
                    DeviceFlowError::NetworkError(format!("Failed to create HTTP client: {e}"))
                })?,
            device_authorization_endpoint: device_authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.map(String::from),
        })
    }

    /// Start the device authorization flow.
    ///
    /// Returns the device authorization response containing the user code
    /// and verification URI that should be displayed to the user.
    pub fn start_authorization(
        &self,
        scope: Option<&str>,
        acr_values: Option<&str>,
    ) -> Result<DeviceAuthResponse, DeviceFlowError> {
        let mut params = vec![("client_id", self.client_id.as_str())];

        if let Some(secret) = &self.client_secret {
            params.push(("client_secret", secret.as_str()));
        }

        let scope_value = scope.unwrap_or("openid");
        params.push(("scope", scope_value));

        if let Some(acr) = acr_values {
            params.push(("acr_values", acr));
        }

        let response = self
            .http_client
            .post(&self.device_authorization_endpoint)
            .form(&params)
            .send()
            .map_err(|e| DeviceFlowError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(DeviceFlowError::InvalidResponse(format!(
                "HTTP {status}: {body}"
            )));
        }

        response
            .json::<DeviceAuthResponse>()
            .map_err(|e| DeviceFlowError::InvalidResponse(e.to_string()))
    }

    /// Poll for the token after user authentication.
    ///
    /// This function blocks until the user completes authentication,
    /// the device code expires, or the timeout is reached.
    ///
    /// # Arguments
    /// * `device_code` - The device code from the authorization response
    /// * `interval` - The polling interval in seconds
    /// * `timeout` - Maximum time to wait for user authentication
    pub fn poll_for_token(
        &self,
        device_code: &str,
        interval: u64,
        timeout: Duration,
    ) -> Result<TokenResponse, DeviceFlowError> {
        let start = Instant::now();
        let mut current_interval = Duration::from_secs(interval);

        loop {
            // Check timeout
            if start.elapsed() >= timeout {
                return Err(DeviceFlowError::Timeout);
            }

            // Wait before polling
            std::thread::sleep(current_interval);

            // Poll for token
            match self.request_token(device_code) {
                Ok(token) => return Ok(token),
                Err(DeviceFlowError::AuthorizationPending) => {
                    // Continue polling
                    continue;
                }
                Err(DeviceFlowError::SlowDown) => {
                    // Increase interval by 5 seconds as per RFC 8628
                    current_interval += Duration::from_secs(5);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Make a single token request.
    fn request_token(&self, device_code: &str) -> Result<TokenResponse, DeviceFlowError> {
        let mut params = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", self.client_id.as_str()),
        ];

        if let Some(secret) = &self.client_secret {
            params.push(("client_secret", secret.as_str()));
        }

        let response = self
            .http_client
            .post(&self.token_endpoint)
            .form(&params)
            .send()
            .map_err(|e| DeviceFlowError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            return response
                .json::<TokenResponse>()
                .map_err(|e| DeviceFlowError::InvalidResponse(e.to_string()));
        }

        // Parse error response
        let error_response = response
            .json::<TokenErrorResponse>()
            .map_err(|e| DeviceFlowError::InvalidResponse(e.to_string()))?;

        Err(error_response.into_error())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = DeviceFlowClient::new(
            "https://keycloak.example.com/realms/test",
            "unix-oidc",
            Some("secret"),
        )
        .unwrap();

        assert_eq!(
            client.device_authorization_endpoint,
            "https://keycloak.example.com/realms/test/protocol/openid-connect/auth/device"
        );
        assert_eq!(
            client.token_endpoint,
            "https://keycloak.example.com/realms/test/protocol/openid-connect/token"
        );
    }

    #[test]
    fn test_client_with_trailing_slash() {
        let client = DeviceFlowClient::new(
            "https://keycloak.example.com/realms/test/",
            "unix-oidc",
            None,
        )
        .unwrap();

        assert_eq!(
            client.device_authorization_endpoint,
            "https://keycloak.example.com/realms/test/protocol/openid-connect/auth/device"
        );
    }

    #[test]
    fn test_client_with_explicit_endpoints() {
        let client = DeviceFlowClient::with_endpoints(
            "https://auth.example.com/device",
            "https://auth.example.com/token",
            "my-client",
            None,
        )
        .unwrap();

        assert_eq!(
            client.device_authorization_endpoint,
            "https://auth.example.com/device"
        );
        assert_eq!(client.token_endpoint, "https://auth.example.com/token");
    }

    // --- TDD RED: from_discovery constructor ---

    /// Helper to build a minimal OidcDiscovery for device flow tests.
    #[cfg(test)]
    fn make_discovery(device_endpoint: Option<&str>) -> crate::oidc::OidcDiscovery {
        crate::oidc::OidcDiscovery {
            jwks_uri: "https://idp.example/jwks".to_string(),
            issuer: "https://idp.example".to_string(),
            token_endpoint: "https://idp.example/token".to_string(),
            device_authorization_endpoint: device_endpoint.map(str::to_string),
            backchannel_authentication_endpoint: None,
            backchannel_token_delivery_modes_supported: None,
            revocation_endpoint: None,
        }
    }

    /// from_discovery reads device_authorization_endpoint from OidcDiscovery.
    #[test]
    fn test_from_discovery_uses_discovery_endpoints() {
        let discovery = make_discovery(Some("https://idp.example/device"));
        let client = DeviceFlowClient::from_discovery(&discovery, "my-client", None).unwrap();
        assert_eq!(
            client.device_authorization_endpoint,
            "https://idp.example/device"
        );
        assert_eq!(client.token_endpoint, "https://idp.example/token");
        assert_eq!(client.client_id, "my-client");
    }

    /// from_discovery returns an error when device_authorization_endpoint is absent.
    #[test]
    fn test_from_discovery_errors_when_no_device_endpoint() {
        let discovery = make_discovery(None);
        let result = DeviceFlowClient::from_discovery(&discovery, "my-client", None);
        assert!(
            result.is_err(),
            "Expected error when device_authorization_endpoint is absent"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, DeviceFlowError::ConfigError(_)),
            "Expected ConfigError, got: {err:?}"
        );
    }

    /// from_discovery with client secret stores it.
    #[test]
    fn test_from_discovery_with_client_secret() {
        let discovery = make_discovery(Some("https://idp.example/device"));
        let client =
            DeviceFlowClient::from_discovery(&discovery, "my-client", Some("s3cr3t")).unwrap();
        assert_eq!(client.client_secret.as_deref(), Some("s3cr3t"));
    }
}
