//! Configuration management for the agent.
//!
//! Uses figment (https://docs.rs/figment) for layered configuration loading:
//!   1. Compiled-in defaults (AgentConfig::default())
//!   2. YAML config file (if present)
//!   3. Environment variables prefixed with UNIX_OIDC_ (double-underscore separates nested keys)
//!   4. Legacy env var UNIX_OIDC_JWKS_CACHE_TTL (for backward compat)
//!
//! Reference: figment docs, Figment::from() + Yaml + Env providers.

use figment::{
    providers::{Env, Format, Serialized, Yaml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Operator-tunable timeout and skew parameters.
///
/// All values represent seconds unless the field name specifies otherwise.
/// Defaults mirror the hardcoded constants that previously existed in the code:
///   - jwks_http_timeout_secs  → replaced `HTTP_TIMEOUT_SECS = 10` in jwks.rs
///   - device_flow_http_timeout_secs → replaced hardcoded `30` in main.rs device flow
///   - clock_skew_future_secs  → replaced hardcoded `5` in dpop.rs future-proof check
///   - clock_skew_staleness_secs → replaced `CLOCK_SKEW_TOLERANCE = 60` in validation.rs
///   - jwks_cache_ttl_secs     → replaced `DEFAULT_CACHE_TTL_SECS = 300` in jwks.rs
///   - ipc_idle_timeout_secs   → IPC connection idle timeout for the agent daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutsConfig {
    /// HTTP request timeout for JWKS fetching (seconds). Must be > 0.
    #[serde(default = "default_jwks_http_timeout")]
    pub jwks_http_timeout_secs: u64,

    /// HTTP request timeout for device flow and token refresh (seconds). Must be > 0.
    #[serde(default = "default_device_flow_http_timeout")]
    pub device_flow_http_timeout_secs: u64,

    /// Clock skew tolerance for DPoP proofs issued in the future (seconds).
    /// Must be <= clock_skew_staleness_secs.
    #[serde(default = "default_clock_skew_future")]
    pub clock_skew_future_secs: u64,

    /// Maximum age of DPoP proofs and clock skew tolerance for token expiration (seconds).
    /// Must be >= clock_skew_future_secs.
    #[serde(default = "default_clock_skew_staleness")]
    pub clock_skew_staleness_secs: u64,

    /// JWKS cache TTL (seconds). Must be >= jwks_http_timeout_secs.
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl_secs: u64,

    /// IPC connection idle timeout for the agent daemon (seconds).
    #[serde(default = "default_ipc_idle_timeout")]
    pub ipc_idle_timeout_secs: u64,
}

fn default_jwks_http_timeout() -> u64 {
    10
}
fn default_device_flow_http_timeout() -> u64 {
    30
}
fn default_clock_skew_future() -> u64 {
    5
}
fn default_clock_skew_staleness() -> u64 {
    60
}
fn default_jwks_cache_ttl() -> u64 {
    300
}
fn default_ipc_idle_timeout() -> u64 {
    60
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            jwks_http_timeout_secs: default_jwks_http_timeout(),
            device_flow_http_timeout_secs: default_device_flow_http_timeout(),
            clock_skew_future_secs: default_clock_skew_future(),
            clock_skew_staleness_secs: default_clock_skew_staleness(),
            jwks_cache_ttl_secs: default_jwks_cache_ttl(),
            ipc_idle_timeout_secs: default_ipc_idle_timeout(),
        }
    }
}

impl TimeoutsConfig {
    /// Validate that all timeout combinations are sensible.
    ///
    /// Rules:
    /// - `jwks_http_timeout_secs` must be > 0 (a zero timeout means "never connect")
    /// - `device_flow_http_timeout_secs` must be > 0
    /// - `jwks_cache_ttl_secs` must be >= `jwks_http_timeout_secs` (cache must outlive
    ///   a single fetch so the TTL is actually useful)
    /// - `clock_skew_future_secs` must be <= `clock_skew_staleness_secs` (accepting proofs
    ///   from further in the future than we accept from the past makes no security sense)
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.jwks_http_timeout_secs == 0 {
            return Err(ConfigError::Validation(
                "jwks_http_timeout_secs must be > 0".to_string(),
            ));
        }
        if self.device_flow_http_timeout_secs == 0 {
            return Err(ConfigError::Validation(
                "device_flow_http_timeout_secs must be > 0".to_string(),
            ));
        }
        if self.jwks_cache_ttl_secs < self.jwks_http_timeout_secs {
            return Err(ConfigError::Validation(format!(
                "jwks_cache_ttl_secs ({}) must be >= jwks_http_timeout_secs ({})",
                self.jwks_cache_ttl_secs, self.jwks_http_timeout_secs
            )));
        }
        if self.clock_skew_future_secs > self.clock_skew_staleness_secs {
            return Err(ConfigError::Validation(format!(
                "clock_skew_future_secs ({}) must be <= clock_skew_staleness_secs ({})",
                self.clock_skew_future_secs, self.clock_skew_staleness_secs
            )));
        }
        Ok(())
    }
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// OIDC issuer URL
    #[serde(default = "default_issuer")]
    pub issuer: String,

    /// OIDC client ID
    #[serde(default = "default_client_id")]
    pub client_id: String,

    /// Socket path for daemon
    #[serde(default)]
    pub socket_path: Option<PathBuf>,

    /// Cryptographic algorithm settings
    #[serde(default)]
    pub crypto: CryptoConfig,

    /// Operator-tunable timeout and clock-skew parameters
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
}

fn default_issuer() -> String {
    String::new()
}

fn default_client_id() -> String {
    "unix-oidc-agent".to_string()
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            issuer: default_issuer(),
            client_id: default_client_id(),
            socket_path: None,
            crypto: CryptoConfig::default(),
            timeouts: TimeoutsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoConfig {
    /// Enable PQC (ML-DSA-65) in addition to ES256
    #[serde(default)]
    pub enable_pqc: bool,
}

impl AgentConfig {
    /// Load configuration from environment variables (legacy path, kept for backward compat).
    pub fn from_env() -> Result<Self, ConfigError> {
        let issuer = std::env::var("OIDC_ISSUER")
            .map_err(|_| ConfigError::MissingEnvVar("OIDC_ISSUER".to_string()))?;

        let client_id = std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| default_client_id());

        let socket_path = std::env::var("UNIX_OIDC_SOCKET").ok().map(PathBuf::from);

        Ok(Self {
            issuer,
            client_id,
            socket_path,
            crypto: CryptoConfig::default(),
            timeouts: TimeoutsConfig::default(),
        })
    }

    /// Load configuration from a file (legacy path, kept for backward compat).
    ///
    /// Prefer `load_from_path()` which uses figment for layered loading.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Self = serde_yaml::from_str(&content)?;
        config.timeouts.validate()?;
        Ok(config)
    }

    /// Get the default config file path.
    pub fn default_config_path() -> PathBuf {
        let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from("~/.config"));
        config_dir.join("unix-oidc").join("config.yaml")
    }

    /// Load from a specific path using figment layered loading.
    ///
    /// Layer order (later layers override earlier):
    /// 1. Compiled-in defaults
    /// 2. YAML file at `path` (if it exists)
    /// 3. `UNIX_OIDC_TIMEOUTS__*` env vars (double-underscore for nested keys)
    /// 4. `UNIX_OIDC_JWKS_CACHE_TTL` (legacy direct override for backward compat)
    pub fn load_from_path(path: &std::path::Path) -> Result<Self, ConfigError> {
        let mut figment = Figment::from(Serialized::defaults(AgentConfig::default()));

        if path.exists() {
            figment = figment.merge(Yaml::file(path));
        }

        // UNIX_OIDC_TIMEOUTS__FIELD_NAME → config.timeouts.field_name
        // UNIX_OIDC_ISSUER → config.issuer (etc.)
        figment = figment.merge(Env::prefixed("UNIX_OIDC_").split("__"));

        let mut config: Self = figment
            .extract()
            .map_err(|e| ConfigError::Figment(e.to_string()))?;

        // Legacy backward-compat: UNIX_OIDC_JWKS_CACHE_TTL overrides jwks_cache_ttl_secs.
        // This env var predates the UNIX_OIDC_TIMEOUTS__ namespace.
        if let Ok(val) = std::env::var("UNIX_OIDC_JWKS_CACHE_TTL") {
            let ttl: u64 = val.parse().map_err(|_| {
                ConfigError::Validation(format!(
                    "UNIX_OIDC_JWKS_CACHE_TTL must be a positive integer, got: {val}"
                ))
            })?;
            config.timeouts.jwks_cache_ttl_secs = ttl;
        }

        config.timeouts.validate()?;
        Ok(config)
    }

    /// Load from default locations with figment layered loading (file first, then env).
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from_path(&Self::default_config_path())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Configuration load error: {0}")]
    Figment(String),
    #[error("Configuration validation error: {0}")]
    Validation(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    // Serial mutex for tests that mutate env vars (ENV_MUTEX pattern from Phase 6)
    use parking_lot::Mutex;
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_config_from_yaml() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(
            &config_path,
            r#"
issuer: https://idp.example.com/realms/corp
client_id: my-agent
crypto:
  enable_pqc: true
"#,
        )
        .unwrap();

        let config = AgentConfig::from_file(&config_path).unwrap();

        assert_eq!(config.issuer, "https://idp.example.com/realms/corp");
        assert_eq!(config.client_id, "my-agent");
        assert!(config.crypto.enable_pqc);
    }

    #[test]
    fn test_config_defaults() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(
            &config_path,
            r#"
issuer: https://idp.example.com
"#,
        )
        .unwrap();

        let config = AgentConfig::from_file(&config_path).unwrap();

        assert_eq!(config.client_id, "unix-oidc-agent");
        assert!(!config.crypto.enable_pqc);
    }

    // --- TimeoutsConfig tests ---

    #[test]
    fn test_timeouts_default_values() {
        let t = TimeoutsConfig::default();
        assert_eq!(t.jwks_http_timeout_secs, 10);
        assert_eq!(t.device_flow_http_timeout_secs, 30);
        assert_eq!(t.clock_skew_future_secs, 5);
        assert_eq!(t.clock_skew_staleness_secs, 60);
        assert_eq!(t.jwks_cache_ttl_secs, 300);
        assert_eq!(t.ipc_idle_timeout_secs, 60);
    }

    #[test]
    fn test_timeouts_validate_rejects_zero_jwks_http() {
        let mut t = TimeoutsConfig::default();
        t.jwks_http_timeout_secs = 0;
        assert!(t.validate().is_err());
    }

    #[test]
    fn test_timeouts_validate_rejects_zero_device_flow() {
        let mut t = TimeoutsConfig::default();
        t.device_flow_http_timeout_secs = 0;
        assert!(t.validate().is_err());
    }

    #[test]
    fn test_timeouts_validate_rejects_cache_ttl_less_than_http_timeout() {
        let mut t = TimeoutsConfig::default();
        t.jwks_http_timeout_secs = 20;
        t.jwks_cache_ttl_secs = 15; // less than http timeout
        assert!(t.validate().is_err());
    }

    #[test]
    fn test_timeouts_validate_rejects_skew_future_greater_than_staleness() {
        let mut t = TimeoutsConfig::default();
        t.clock_skew_future_secs = 90;
        t.clock_skew_staleness_secs = 60; // less than future skew
        assert!(t.validate().is_err());
    }

    #[test]
    fn test_timeouts_validate_passes_valid_config() {
        let t = TimeoutsConfig::default();
        assert!(t.validate().is_ok());
    }

    #[test]
    fn test_agent_config_load_from_yaml_with_timeouts() {
        let _guard = ENV_MUTEX.lock();
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(
            &config_path,
            r#"
issuer: https://idp.example.com
timeouts:
  jwks_http_timeout_secs: 20
  jwks_cache_ttl_secs: 600
"#,
        )
        .unwrap();

        // Temporarily clear env vars that could interfere
        env::remove_var("UNIX_OIDC_JWKS_CACHE_TTL");
        env::remove_var("UNIX_OIDC_TIMEOUTS__JWKS_HTTP_TIMEOUT_SECS");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert_eq!(config.timeouts.jwks_http_timeout_secs, 20);
        assert_eq!(config.timeouts.jwks_cache_ttl_secs, 600);
    }

    #[test]
    fn test_agent_config_load_without_timeouts_uses_defaults() {
        let _guard = ENV_MUTEX.lock();
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(
            &config_path,
            r#"
issuer: https://idp.example.com
"#,
        )
        .unwrap();

        env::remove_var("UNIX_OIDC_JWKS_CACHE_TTL");
        env::remove_var("UNIX_OIDC_TIMEOUTS__JWKS_HTTP_TIMEOUT_SECS");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert_eq!(config.timeouts.jwks_http_timeout_secs, 10);
        assert_eq!(config.timeouts.jwks_cache_ttl_secs, 300);
    }

    #[test]
    fn test_unix_oidc_jwks_cache_ttl_env_override() {
        let _guard = ENV_MUTEX.lock();
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(&config_path, "issuer: https://idp.example.com\n").unwrap();

        env::set_var("UNIX_OIDC_JWKS_CACHE_TTL", "900");
        env::remove_var("UNIX_OIDC_TIMEOUTS__JWKS_HTTP_TIMEOUT_SECS");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert_eq!(config.timeouts.jwks_cache_ttl_secs, 900);

        env::remove_var("UNIX_OIDC_JWKS_CACHE_TTL");
    }

    #[test]
    fn test_unix_oidc_timeouts_nested_env_override() {
        let _guard = ENV_MUTEX.lock();
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(&config_path, "issuer: https://idp.example.com\n").unwrap();

        env::remove_var("UNIX_OIDC_JWKS_CACHE_TTL");
        env::set_var("UNIX_OIDC_TIMEOUTS__JWKS_HTTP_TIMEOUT_SECS", "25");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert_eq!(config.timeouts.jwks_http_timeout_secs, 25);

        env::remove_var("UNIX_OIDC_TIMEOUTS__JWKS_HTTP_TIMEOUT_SECS");
    }
}
