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
use secrecy::{ExposeSecret, SecretString};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Configuration for the webhook approval provider.
pub struct WebhookConfig {
    /// Base URL for the webhook endpoint.
    pub webhook_url: String,
    /// Optional authorization header value (e.g., "Bearer token123").
    pub auth_header: Option<String>,
    /// HTTP request timeout in seconds.
    pub timeout_seconds: u64,
    /// Whether to verify TLS certificates.
    pub verify_tls: bool,
    /// Optional HMAC-SHA256 shared secret for request signing.
    ///
    /// When set, outbound requests include:
    /// - `X-Unix-OIDC-Timestamp`: Unix timestamp (seconds) of the request
    /// - `X-Unix-OIDC-Signature`: HMAC-SHA256(secret, "{timestamp}.{body}") hex-encoded
    ///
    /// The timestamp is included in the signed payload to prevent replay attacks.
    pub hmac_secret: Option<SecretString>,
}

// Manual Clone because SecretString doesn't implement Clone
impl Clone for WebhookConfig {
    fn clone(&self) -> Self {
        Self {
            webhook_url: self.webhook_url.clone(),
            auth_header: self.auth_header.clone(),
            timeout_seconds: self.timeout_seconds,
            verify_tls: self.verify_tls,
            hmac_secret: self
                .hmac_secret
                .as_ref()
                .map(|s| SecretString::from(s.expose_secret().to_string())),
        }
    }
}

/// Custom Debug impl redacts auth_header and hmac_secret to prevent secret leakage in logs.
impl fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookConfig")
            .field("webhook_url", &self.webhook_url)
            .field(
                "auth_header",
                &self.auth_header.as_ref().map(|_| "[REDACTED]"),
            )
            .field("timeout_seconds", &self.timeout_seconds)
            .field("verify_tls", &self.verify_tls)
            .field(
                "hmac_secret",
                &self.hmac_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl WebhookConfig {
    /// Create a new webhook configuration.
    pub fn new(webhook_url: &str) -> Self {
        Self {
            webhook_url: webhook_url.trim_end_matches('/').to_string(),
            auth_header: None,
            timeout_seconds: 10,
            verify_tls: true,
            hmac_secret: None,
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

    /// Set the HMAC-SHA256 shared secret for request signing.
    pub fn with_hmac_secret(mut self, secret: &str) -> Self {
        self.hmac_secret = Some(SecretString::from(secret.to_string()));
        self
    }

    /// Disable TLS verification.
    ///
    /// Only available in test-mode builds. In production builds this method
    /// does not exist — preventing programmatic TLS bypass.
    #[cfg(feature = "test-mode")]
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

        if let Ok(secret) = std::env::var("UNIX_OIDC_WEBHOOK_HMAC_SECRET") {
            if !secret.is_empty() {
                config = config.with_hmac_secret(&secret);
            }
        }

        // Security: TLS verification bypass is only available in test-mode builds.
        // In production builds, this entire block is compiled out.
        #[cfg(feature = "test-mode")]
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
                ApprovalError::ConfigError(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self { config, client })
    }

    /// Create from environment variables.
    pub fn from_env() -> Result<Self, ApprovalError> {
        let config = WebhookConfig::from_env()?;
        Self::new(config)
    }

    /// Build a base request with common headers (auth, content-type, user-agent).
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

    /// Compute HMAC-SHA256 signature for the given body and attach headers.
    ///
    /// Signed payload format: `{unix_timestamp}.{body}`
    /// This binds the timestamp to the body, preventing replay with a different
    /// timestamp or body substitution with the same timestamp.
    fn sign_request(
        &self,
        mut builder: reqwest::blocking::RequestBuilder,
        body: &str,
    ) -> reqwest::blocking::RequestBuilder {
        if let Some(ref secret) = self.config.hmac_secret {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let signature = compute_hmac_signature(secret.expose_secret(), timestamp, body);

            builder = builder
                .header("X-Unix-OIDC-Timestamp", timestamp.to_string())
                .header("X-Unix-OIDC-Signature", signature);
        }
        builder
    }
}

/// Compute HMAC-SHA256("{timestamp}.{body}") and return hex-encoded digest.
///
/// Exposed for testing — callers should not use this directly.
pub(crate) fn compute_hmac_signature(secret: &str, timestamp: u64, body: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => unreachable!("HMAC-SHA256 accepts any key length"),
    };
    mac.update(format!("{timestamp}.{body}").as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

impl ApprovalProvider for WebhookApprovalProvider {
    fn start_request(&self, request: ApprovalRequest) -> Result<ApprovalRequest, ApprovalError> {
        let body = serde_json::to_string(&request)
            .map_err(|e| ApprovalError::ConfigError(format!("Failed to serialize request: {e}")))?;

        let builder = self.build_request(reqwest::Method::POST, "/approve");
        let builder = self.sign_request(builder, &body);

        let response = builder
            .body(body)
            .send()
            .map_err(|e| ApprovalError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(ApprovalError::NetworkError(format!(
                "Webhook returned HTTP {status}: {body}"
            )));
        }

        // Parse response to validate it
        let _: ApprovalResponse = response
            .json()
            .map_err(|e| ApprovalError::InvalidResponse(e.to_string()))?;

        Ok(request)
    }

    fn check_status(&self, request_id: &str) -> Result<ApprovalResponse, ApprovalError> {
        let path = format!("/approve/{request_id}");

        let builder = self.build_request(reqwest::Method::GET, &path);
        // GET requests have empty body — HMAC signs the empty string
        let builder = self.sign_request(builder, "");

        let response = builder
            .send()
            .map_err(|e| ApprovalError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(ApprovalError::NetworkError(format!(
                "Webhook returned HTTP {status}: {body}"
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
    use std::sync::Mutex;

    /// Serialize all env-var-dependent tests to prevent parallel interference.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

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

    #[test]
    fn test_webhook_config_debug_redacts_auth_header() {
        let config = WebhookConfig::new("https://example.com/api")
            .with_auth("Bearer super-secret-token-123");

        let debug_output = format!("{:?}", config);

        assert!(
            !debug_output.contains("super-secret-token-123"),
            "Debug output must not contain auth header value: {debug_output}"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output must show [REDACTED] for auth_header: {debug_output}"
        );
        assert!(
            debug_output.contains("example.com"),
            "Debug output should show webhook_url: {debug_output}"
        );
    }

    /// F-06 positive: default config from_env has verify_tls == true.
    #[test]
    fn test_webhook_config_default_tls_enabled() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Set only the required env var; leave UNIX_OIDC_WEBHOOK_INSECURE unset.
        let _url_guard = TempEnvGuard::set("UNIX_OIDC_WEBHOOK_URL", "https://example.com/hook");
        let _insecure_guard = TempEnvGuard::remove("UNIX_OIDC_WEBHOOK_INSECURE");
        let _hmac_guard = TempEnvGuard::remove("UNIX_OIDC_WEBHOOK_HMAC_SECRET");

        let config = WebhookConfig::from_env().unwrap();
        assert!(
            config.verify_tls,
            "verify_tls must default to true when UNIX_OIDC_WEBHOOK_INSECURE is unset"
        );
    }

    /// F-06 negative: in non-test-mode builds, setting UNIX_OIDC_WEBHOOK_INSECURE=true
    /// does NOT disable TLS verification (the env var is ignored).
    #[cfg(not(feature = "test-mode"))]
    #[test]
    fn test_webhook_insecure_env_ignored_without_test_mode() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _url_guard = TempEnvGuard::set("UNIX_OIDC_WEBHOOK_URL", "https://example.com/hook");
        let _insecure_guard = TempEnvGuard::set("UNIX_OIDC_WEBHOOK_INSECURE", "true");
        let _hmac_guard = TempEnvGuard::remove("UNIX_OIDC_WEBHOOK_HMAC_SECRET");

        let config = WebhookConfig::from_env().unwrap();
        assert!(
            config.verify_tls,
            "verify_tls must remain true even when UNIX_OIDC_WEBHOOK_INSECURE=true \
             in non-test-mode builds"
        );
    }

    /// F-06 test-mode: setting UNIX_OIDC_WEBHOOK_INSECURE=true disables TLS verification.
    #[cfg(feature = "test-mode")]
    #[test]
    fn test_webhook_insecure_env_disables_tls_in_test_mode() {
        let _url_guard = TempEnvGuard::set("UNIX_OIDC_WEBHOOK_URL", "https://example.com/hook");
        let _insecure_guard = TempEnvGuard::set("UNIX_OIDC_WEBHOOK_INSECURE", "true");

        let config = WebhookConfig::from_env().unwrap();
        assert!(
            !config.verify_tls,
            "verify_tls must be false when UNIX_OIDC_WEBHOOK_INSECURE=true in test-mode"
        );
    }

    // ── HMAC signing tests ───────────────────────────────────────────────────

    #[test]
    fn test_hmac_signature_deterministic() {
        let sig1 = compute_hmac_signature("my-secret", 1700000000, r#"{"foo":"bar"}"#);
        let sig2 = compute_hmac_signature("my-secret", 1700000000, r#"{"foo":"bar"}"#);
        assert_eq!(sig1, sig2, "Same inputs must produce same HMAC");
    }

    #[test]
    fn test_hmac_signature_changes_with_timestamp() {
        let sig1 = compute_hmac_signature("my-secret", 1700000000, r#"{"foo":"bar"}"#);
        let sig2 = compute_hmac_signature("my-secret", 1700000001, r#"{"foo":"bar"}"#);
        assert_ne!(
            sig1, sig2,
            "Different timestamps must produce different HMACs"
        );
    }

    #[test]
    fn test_hmac_signature_changes_with_body() {
        let sig1 = compute_hmac_signature("my-secret", 1700000000, r#"{"foo":"bar"}"#);
        let sig2 = compute_hmac_signature("my-secret", 1700000000, r#"{"foo":"baz"}"#);
        assert_ne!(sig1, sig2, "Different bodies must produce different HMACs");
    }

    #[test]
    fn test_hmac_signature_changes_with_secret() {
        let sig1 = compute_hmac_signature("secret-a", 1700000000, r#"{"foo":"bar"}"#);
        let sig2 = compute_hmac_signature("secret-b", 1700000000, r#"{"foo":"bar"}"#);
        assert_ne!(sig1, sig2, "Different secrets must produce different HMACs");
    }

    #[test]
    fn test_hmac_signature_is_64_hex_chars() {
        // SHA-256 produces 32 bytes = 64 hex characters.
        let sig = compute_hmac_signature("my-secret", 1700000000, "body");
        assert_eq!(sig.len(), 64, "HMAC-SHA256 hex must be 64 characters");
        assert!(
            sig.chars().all(|c| c.is_ascii_hexdigit()),
            "Signature must be valid hex: {sig}"
        );
    }

    #[test]
    fn test_hmac_debug_redacts_secret() {
        let config =
            WebhookConfig::new("https://example.com/api").with_hmac_secret("super-secret-hmac-key");

        let debug_output = format!("{:?}", config);
        assert!(
            !debug_output.contains("super-secret-hmac-key"),
            "Debug must not contain HMAC secret: {debug_output}"
        );
    }

    #[test]
    fn test_hmac_secret_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _url_guard = TempEnvGuard::set("UNIX_OIDC_WEBHOOK_URL", "https://example.com/hook");
        let _insecure_guard = TempEnvGuard::remove("UNIX_OIDC_WEBHOOK_INSECURE");
        let _hmac_guard = TempEnvGuard::set("UNIX_OIDC_WEBHOOK_HMAC_SECRET", "env-secret");

        let config = WebhookConfig::from_env().unwrap();
        assert!(
            config.hmac_secret.is_some(),
            "hmac_secret must be populated from env"
        );
        assert_eq!(
            config.hmac_secret.as_ref().unwrap().expose_secret(),
            "env-secret"
        );
    }

    #[test]
    fn test_hmac_secret_empty_env_ignored() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _url_guard = TempEnvGuard::set("UNIX_OIDC_WEBHOOK_URL", "https://example.com/hook");
        let _insecure_guard = TempEnvGuard::remove("UNIX_OIDC_WEBHOOK_INSECURE");
        let _hmac_guard = TempEnvGuard::set("UNIX_OIDC_WEBHOOK_HMAC_SECRET", "");

        let config = WebhookConfig::from_env().unwrap();
        assert!(
            config.hmac_secret.is_none(),
            "empty HMAC secret env var must not set hmac_secret"
        );
    }
}

/// RAII guard for temporarily setting/removing environment variables in tests.
/// Restores the original value on drop.
#[cfg(test)]
struct TempEnvGuard {
    key: String,
    original: Option<String>,
}

#[cfg(test)]
impl TempEnvGuard {
    fn set(key: &str, value: &str) -> Self {
        let original = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self {
            key: key.to_string(),
            original,
        }
    }

    fn remove(key: &str) -> Self {
        let original = std::env::var(key).ok();
        std::env::remove_var(key);
        Self {
            key: key.to_string(),
            original,
        }
    }
}

#[cfg(test)]
impl Drop for TempEnvGuard {
    fn drop(&mut self) {
        match &self.original {
            Some(val) => std::env::set_var(&self.key, val),
            None => std::env::remove_var(&self.key),
        }
    }
}
