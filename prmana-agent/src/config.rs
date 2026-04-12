//! Configuration management for the agent.
//!
//! Uses figment (<https://docs.rs/figment>) for layered configuration loading:
//!   1. Compiled-in defaults (AgentConfig::default())
//!   2. YAML config file (if present)
//!   3. Environment variables prefixed with PRMANA_ (double-underscore separates nested keys)
//!   4. Legacy env var PRMANA_JWKS_CACHE_TTL (for backward compat)
//!
//! Reference: figment docs, Figment::from() + Yaml + Env providers.

use figment::{
    providers::{Env, Format, Serialized, Yaml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::failover::FailoverPairConfig;

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

    /// Session expiry sweep interval (seconds).
    ///
    /// The background sweep task removes expired and corrupt session records from
    /// `/run/prmana/sessions/` at this interval.  Minimum 60s to prevent
    /// unnecessary I/O on systems with many sessions.
    ///
    /// Reference: SES-09 (session expiry sweep requirement).
    #[serde(default = "default_sweep_interval")]
    pub sweep_interval_secs: u64,
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
fn default_sweep_interval() -> u64 {
    300
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
            sweep_interval_secs: default_sweep_interval(),
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
        // Minimum 60s prevents excessive I/O thrashing on active servers.
        if self.sweep_interval_secs < 60 {
            return Err(ConfigError::Validation(format!(
                "sweep_interval_secs ({}) must be >= 60",
                self.sweep_interval_secs
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

    /// OAuth client attestation header configuration.
    #[serde(default)]
    pub client_attestation: ClientAttestationConfig,

    /// Failover pairs for primary/secondary OIDC issuer redundancy (Phase 41).
    ///
    /// Each pair references two issuer URLs. The agent uses active-passive failover:
    /// availability failures on the primary trigger automatic switch to the secondary.
    /// Recovery is lazy and cooldown-based — no background probing.
    #[serde(default)]
    pub failover_pairs: Vec<FailoverPairConfig>,
}

fn default_issuer() -> String {
    String::new()
}

fn default_client_id() -> String {
    "prmana-agent".to_string()
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            issuer: default_issuer(),
            client_id: default_client_id(),
            socket_path: None,
            crypto: CryptoConfig::default(),
            timeouts: TimeoutsConfig::default(),
            client_attestation: ClientAttestationConfig::default(),
            failover_pairs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAttestationConfig {
    /// Enable draft OAuth client-attestation headers on token endpoint requests.
    #[serde(default)]
    pub enabled: bool,

    /// Lifetime of the long-lived OAuth-Client-Attestation JWT in seconds.
    #[serde(default = "default_client_attestation_lifetime_secs")]
    pub lifetime_secs: u64,
}

fn default_client_attestation_lifetime_secs() -> u64 {
    86_400
}

impl Default for ClientAttestationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lifetime_secs: default_client_attestation_lifetime_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoConfig {
    /// Enable PQC (ML-DSA-65) in addition to ES256
    #[serde(default)]
    pub enable_pqc: bool,

    /// Hardware presence cache TTL in seconds.
    ///
    /// When a hardware signer (YubiKey, TPM) successfully generates a DPoP proof
    /// via physical touch, subsequent requests for the same `(remote_user, target)`
    /// within this TTL are signed automatically without re-triggering the hardware
    /// presence requirement.
    ///
    /// Default: 300 (5 minutes). Set to 0 to disable caching (every request
    /// requires a fresh touch).
    #[serde(default = "default_presence_cache_ttl")]
    pub presence_cache_ttl_secs: u64,
}

fn default_presence_cache_ttl() -> u64 {
    300
}

impl AgentConfig {
    /// Load configuration from environment variables (legacy path, kept for backward compat).
    pub fn from_env() -> Result<Self, ConfigError> {
        let issuer = std::env::var("OIDC_ISSUER")
            .map_err(|_| ConfigError::MissingEnvVar("OIDC_ISSUER".to_string()))?;

        let client_id = std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| default_client_id());

        let socket_path = std::env::var("PRMANA_SOCKET").ok().map(PathBuf::from);

        Ok(Self {
            issuer,
            client_id,
            socket_path,
            crypto: CryptoConfig::default(),
            timeouts: TimeoutsConfig::default(),
            client_attestation: ClientAttestationConfig::default(),
            failover_pairs: Vec::new(),
        })
    }

    /// Load configuration from a file (legacy path, kept for backward compat).
    ///
    /// Prefer `load_from_path()` which uses figment for layered loading.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        config.timeouts.validate()?;
        Ok(config)
    }

    /// Get the default config file path.
    pub fn default_config_path() -> PathBuf {
        let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from("~/.config"));
        config_dir.join("prmana").join("config.yaml")
    }

    /// Load from a specific path using figment layered loading.
    ///
    /// Layer order (later layers override earlier):
    /// 1. Compiled-in defaults
    /// 2. YAML file at `path` (if it exists)
    /// 3. `PRMANA_TIMEOUTS__*` env vars (double-underscore for nested keys)
    /// 4. `PRMANA_JWKS_CACHE_TTL` (legacy direct override for backward compat)
    pub fn load_from_path(path: &std::path::Path) -> Result<Self, ConfigError> {
        let mut figment = Figment::from(Serialized::defaults(AgentConfig::default()));

        if path.exists() {
            figment = figment.merge(Yaml::file(path));
        }

        // PRMANA_TIMEOUTS__FIELD_NAME → config.timeouts.field_name
        // PRMANA_ISSUER → config.issuer (etc.)
        figment = figment.merge(Env::prefixed("PRMANA_").split("__"));

        let mut config: Self = figment
            .extract()
            .map_err(|e| ConfigError::Figment(e.to_string()))?;

        // Legacy backward-compat: PRMANA_JWKS_CACHE_TTL overrides jwks_cache_ttl_secs.
        // This env var predates the PRMANA_TIMEOUTS__ namespace.
        if let Ok(val) = std::env::var("PRMANA_JWKS_CACHE_TTL") {
            let ttl: u64 = val.parse().map_err(|_| {
                ConfigError::Validation(format!(
                    "PRMANA_JWKS_CACHE_TTL must be a positive integer, got: {val}"
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

        assert_eq!(config.client_id, "prmana-agent");
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
        let t = TimeoutsConfig {
            jwks_http_timeout_secs: 0,
            ..TimeoutsConfig::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn test_timeouts_validate_rejects_zero_device_flow() {
        let t = TimeoutsConfig {
            device_flow_http_timeout_secs: 0,
            ..TimeoutsConfig::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn test_timeouts_validate_rejects_cache_ttl_less_than_http_timeout() {
        let t = TimeoutsConfig {
            jwks_http_timeout_secs: 20,
            jwks_cache_ttl_secs: 15, // less than http timeout
            ..TimeoutsConfig::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn test_timeouts_validate_rejects_skew_future_greater_than_staleness() {
        let t = TimeoutsConfig {
            clock_skew_future_secs: 90,
            clock_skew_staleness_secs: 60, // less than future skew
            ..TimeoutsConfig::default()
        };
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
        env::remove_var("PRMANA_JWKS_CACHE_TTL");
        env::remove_var("PRMANA_TIMEOUTS__JWKS_HTTP_TIMEOUT_SECS");

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

        env::remove_var("PRMANA_JWKS_CACHE_TTL");
        env::remove_var("PRMANA_TIMEOUTS__JWKS_HTTP_TIMEOUT_SECS");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert_eq!(config.timeouts.jwks_http_timeout_secs, 10);
        assert_eq!(config.timeouts.jwks_cache_ttl_secs, 300);
        assert!(!config.client_attestation.enabled);
        assert_eq!(config.client_attestation.lifetime_secs, 86_400);
    }

    #[test]
    fn test_prmana_jwks_cache_ttl_env_override() {
        let _guard = ENV_MUTEX.lock();
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(&config_path, "issuer: https://idp.example.com\n").unwrap();

        env::set_var("PRMANA_JWKS_CACHE_TTL", "900");
        env::remove_var("PRMANA_TIMEOUTS__JWKS_HTTP_TIMEOUT_SECS");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert_eq!(config.timeouts.jwks_cache_ttl_secs, 900);

        env::remove_var("PRMANA_JWKS_CACHE_TTL");
    }

    #[test]
    fn test_prmana_timeouts_nested_env_override() {
        let _guard = ENV_MUTEX.lock();
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(&config_path, "issuer: https://idp.example.com\n").unwrap();

        env::remove_var("PRMANA_JWKS_CACHE_TTL");
        env::set_var("PRMANA_TIMEOUTS__JWKS_HTTP_TIMEOUT_SECS", "25");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert_eq!(config.timeouts.jwks_http_timeout_secs, 25);

        env::remove_var("PRMANA_TIMEOUTS__JWKS_HTTP_TIMEOUT_SECS");
    }

    #[test]
    fn test_client_attestation_config_from_yaml() {
        let _guard = ENV_MUTEX.lock();
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(
            &config_path,
            r#"
issuer: https://idp.example.com
client_attestation:
  enabled: true
  lifetime_secs: 7200
"#,
        )
        .unwrap();

        env::remove_var("PRMANA_CLIENT_ATTESTATION__ENABLED");
        env::remove_var("PRMANA_CLIENT_ATTESTATION__LIFETIME_SECS");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert!(config.client_attestation.enabled);
        assert_eq!(config.client_attestation.lifetime_secs, 7200);
    }

    #[test]
    fn test_client_attestation_env_override() {
        let _guard = ENV_MUTEX.lock();
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(&config_path, "issuer: https://idp.example.com\n").unwrap();

        env::set_var("PRMANA_CLIENT_ATTESTATION__ENABLED", "true");
        env::set_var("PRMANA_CLIENT_ATTESTATION__LIFETIME_SECS", "1234");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert!(config.client_attestation.enabled);
        assert_eq!(config.client_attestation.lifetime_secs, 1234);

        env::remove_var("PRMANA_CLIENT_ATTESTATION__ENABLED");
        env::remove_var("PRMANA_CLIENT_ATTESTATION__LIFETIME_SECS");
    }

    #[test]
    fn test_failover_pairs_from_yaml() {
        let _guard = ENV_MUTEX.lock();
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(
            &config_path,
            r#"
issuer: https://idp.example.com
failover_pairs:
  - primary_issuer_url: "https://primary.example.com/realms/corp"
    secondary_issuer_url: "https://secondary.example.com/realms/corp"
    request_timeout_secs: 15
    cooldown_secs: 120
"#,
        )
        .unwrap();

        env::remove_var("PRMANA_FAILOVER_PAIRS");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert_eq!(config.failover_pairs.len(), 1);
        assert_eq!(
            config.failover_pairs[0].primary_issuer_url,
            "https://primary.example.com/realms/corp"
        );
        assert_eq!(
            config.failover_pairs[0].secondary_issuer_url,
            "https://secondary.example.com/realms/corp"
        );
        assert_eq!(config.failover_pairs[0].request_timeout_secs, 15);
        assert_eq!(config.failover_pairs[0].cooldown_secs, 120);
    }

    #[test]
    fn test_failover_pairs_defaults_when_absent() {
        let _guard = ENV_MUTEX.lock();
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(&config_path, "issuer: https://idp.example.com\n").unwrap();

        env::remove_var("PRMANA_FAILOVER_PAIRS");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert!(config.failover_pairs.is_empty());
    }

    #[test]
    fn test_failover_pairs_default_timeout_and_cooldown() {
        let _guard = ENV_MUTEX.lock();
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        std::fs::write(
            &config_path,
            r#"
issuer: https://idp.example.com
failover_pairs:
  - primary_issuer_url: "https://primary.example.com"
    secondary_issuer_url: "https://secondary.example.com"
"#,
        )
        .unwrap();

        env::remove_var("PRMANA_FAILOVER_PAIRS");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert_eq!(config.failover_pairs.len(), 1);
        assert_eq!(config.failover_pairs[0].request_timeout_secs, 10);
        assert_eq!(config.failover_pairs[0].cooldown_secs, 60);
    }
}
