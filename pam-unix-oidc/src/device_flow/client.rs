//! Device flow client implementation.

use std::time::{Duration, Instant};

use reqwest::blocking::Client;

use super::types::{DeviceAuthResponse, DeviceFlowError, TokenErrorResponse, TokenResponse};

/// Client for OAuth 2.0 Device Authorization Grant.
pub struct DeviceFlowClient {
    http_client: Client,
    device_authorization_endpoint: String,
    token_endpoint: String,
    client_id: String,
    client_secret: Option<String>,
}

impl DeviceFlowClient {
    /// Create a new device flow client.
    ///
    /// # Arguments
    /// * `issuer_url` - The OIDC issuer URL (will append standard endpoints)
    /// * `client_id` - The OAuth client ID
    /// * `client_secret` - Optional client secret for confidential clients
    pub fn new(issuer_url: &str, client_id: &str, client_secret: Option<&str>) -> Self {
        let base = issuer_url.trim_end_matches('/');

        Self {
            http_client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            device_authorization_endpoint: format!("{}/protocol/openid-connect/auth/device", base),
            token_endpoint: format!("{}/protocol/openid-connect/token", base),
            client_id: client_id.to_string(),
            client_secret: client_secret.map(String::from),
        }
    }

    /// Create a client with explicit endpoints (for non-standard IdPs).
    pub fn with_endpoints(
        device_authorization_endpoint: &str,
        token_endpoint: &str,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Self {
        Self {
            http_client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            device_authorization_endpoint: device_authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.map(String::from),
        }
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
                "HTTP {}: {}",
                status, body
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
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = DeviceFlowClient::new(
            "https://keycloak.example.com/realms/test",
            "unix-oidc",
            Some("secret"),
        );

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
        );

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
        );

        assert_eq!(
            client.device_authorization_endpoint,
            "https://auth.example.com/device"
        );
        assert_eq!(client.token_endpoint, "https://auth.example.com/token");
    }
}
