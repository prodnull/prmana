//! Configuration management for the agent

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// OIDC issuer URL
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
}

fn default_client_id() -> String {
    "unix-oidc-agent".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoConfig {
    /// Enable PQC (ML-DSA-65) in addition to ES256
    #[serde(default)]
    pub enable_pqc: bool,
}

impl AgentConfig {
    /// Load configuration from environment variables
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
        })
    }

    /// Load configuration from a file
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Get the default config file path
    pub fn default_config_path() -> PathBuf {
        let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from("~/.config"));
        config_dir.join("unix-oidc").join("config.yaml")
    }

    /// Load from default locations (file first, then env)
    pub fn load() -> Result<Self, ConfigError> {
        let config_path = Self::default_config_path();

        if config_path.exists() {
            Self::from_file(&config_path)
        } else {
            Self::from_env()
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
}
