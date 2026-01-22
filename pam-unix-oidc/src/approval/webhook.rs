//! Webhook-based approval provider.
//!
//! This provider sends HTTP requests to a configured webhook URL for approval decisions.
//! It supports:
//! - POST to start a new approval request
//! - GET to check status of an existing request
//!
//! ## Webhook API
//!
//! ### Start Request (POST)
//!
//! Request body:
//! ```json
//! {
//!   "request_id": "apr-abc123",
//!   "username": "alice",
//!   "command": "sudo systemctl restart nginx",
//!   "hostname": "server.example.com",
//!   "timestamp": 1705400000,
//!   "timeout_seconds": 300,
//!   "metadata": {}
//! }
//! ```
//!
//! Response body:
//! ```json
//! {
//!   "request_id": "apr-abc123",
//!   "status": "pending",
//!   "message": null,
//!   "approver": null,
//!   "decided_at": null
//! }
//! ```
//!
//! ### Check Status (GET)
//!
//! URL: `{webhook_url}/{request_id}`
//!
//! Response body: Same as above with updated status.

use super::provider::{ApprovalError, ApprovalProvider, ApprovalRequest, ApprovalResponse};
use reqwest::blocking::Client;
use std::time::Duration;

/// Configuration for the webhook approval provider.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Base URL for the webhook endpoint.
    pub webhook_url: String,
    /// Optional authorization header value (e.g., "Bearer token123").
    pub auth_header: Option<String>,
    /// HTTP request timeout in seconds.
    pub timeout_seconds: u64,
    /// Whether to verify TLS certificates.
    pub verify_tls: bool,
}

impl WebhookConfig {
    /// Create a new webhook configuration.
    pub fn new(webhook_url: &str) -> Self {
        Self {
            webhook_url: webhook_url.trim_end_matches('/').to_string(),
            auth_header: None,
            timeout_seconds: 10,
            verify_tls: true,
        }
    }

    /// Set the authorization header.
    pub fn with_auth(mut self, auth_header: &str) -> Self {
        self.auth_header = Some(auth_header.to_string());
        self
    }

    /// Set the request timeout.
    pub fn with_timeout(mut self, timeout_seconds: u64) -> Self {
        self.timeout_seconds = timeout_seconds;
        self
    }

    /// Disable TLS verification (use only for testing!).
    pub fn with_insecure_tls(mut self) -> Self {
        self.verify_tls = false;
        self
    }

    /// Create configuration from environment variables.
    ///
    /// Environment variables:
    /// - `UNIX_OIDC_WEBHOOK_URL` (required): The webhook URL
    /// - `UNIX_OIDC_WEBHOOK_AUTH` (optional): Authorization header value
    /// - `UNIX_OIDC_WEBHOOK_TIMEOUT` (optional): Request timeout in seconds
    /// - `UNIX_OIDC_WEBHOOK_INSECURE` (optional): Set to "true" to disable TLS verification
    pub fn from_env() -> Result<Self, ApprovalError> {
        let webhook_url = std::env::var("UNIX_OIDC_WEBHOOK_URL")
            .map_err(|_| ApprovalError::ConfigError("UNIX_OIDC_WEBHOOK_URL not set".to_string()))?;

        let mut config = Self::new(&webhook_url);

        if let Ok(auth) = std::env::var("UNIX_OIDC_WEBHOOK_AUTH") {
            config = config.with_auth(&auth);
        }

        if let Ok(timeout_str) = std::env::var("UNIX_OIDC_WEBHOOK_TIMEOUT") {
            if let Ok(timeout) = timeout_str.parse() {
                config = config.with_timeout(timeout);
            }
        }

        if std::env::var("UNIX_OIDC_WEBHOOK_INSECURE")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            config = config.with_insecure_tls();
        }

        Ok(config)
    }
}

/// Webhook-based approval provider.
pub struct WebhookApprovalProvider {
    config: WebhookConfig,
    client: Client,
}

impl WebhookApprovalProvider {
    /// Create a new webhook approval provider.
    pub fn new(config: WebhookConfig) -> Result<Self, ApprovalError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()
            .map_err(|e| {
                ApprovalError::ConfigError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self { config, client })
    }

    /// Create from environment variables.
    pub fn from_env() -> Result<Self, ApprovalError> {
        let config = WebhookConfig::from_env()?;
        Self::new(config)
    }

    fn build_request(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> reqwest::blocking::RequestBuilder {
        let url = format!("{}{}", self.config.webhook_url, path);
        let mut builder = self.client.request(method, &url);

        if let Some(ref auth) = self.config.auth_header {
            builder = builder.header("Authorization", auth);
        }

        builder = builder.header("Content-Type", "application/json");
        builder = builder.header("User-Agent", "unix-oidc/0.1");

        builder
    }
}

impl ApprovalProvider for WebhookApprovalProvider {
    fn start_request(&self, request: ApprovalRequest) -> Result<ApprovalRequest, ApprovalError> {
        let response = self
            .build_request(reqwest::Method::POST, "/approve")
            .json(&request)
            .send()
            .map_err(|e| ApprovalError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(ApprovalError::NetworkError(format!(
                "Webhook returned HTTP {}: {}",
                status, body
            )));
        }

        // Parse response to validate it
        let _: ApprovalResponse = response
            .json()
            .map_err(|e| ApprovalError::InvalidResponse(e.to_string()))?;

        Ok(request)
    }

    fn check_status(&self, request_id: &str) -> Result<ApprovalResponse, ApprovalError> {
        let path = format!("/approve/{}", request_id);
        let response = self
            .build_request(reqwest::Method::GET, &path)
            .send()
            .map_err(|e| ApprovalError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(ApprovalError::NetworkError(format!(
                "Webhook returned HTTP {}: {}",
                status, body
            )));
        }

        let approval: ApprovalResponse = response
            .json()
            .map_err(|e| ApprovalError::InvalidResponse(e.to_string()))?;

        Ok(approval)
    }

    fn description(&self) -> &str {
        "Webhook approval"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_config_creation() {
        let config = WebhookConfig::new("https://example.com/api");
        assert_eq!(config.webhook_url, "https://example.com/api");
        assert!(config.auth_header.is_none());
        assert!(config.verify_tls);
    }

    #[test]
    fn test_webhook_config_with_auth() {
        let config = WebhookConfig::new("https://example.com/api")
            .with_auth("Bearer token123")
            .with_timeout(30);

        assert_eq!(config.auth_header, Some("Bearer token123".to_string()));
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_webhook_config_strips_trailing_slash() {
        let config = WebhookConfig::new("https://example.com/api/");
        assert_eq!(config.webhook_url, "https://example.com/api");
    }
}
