//! SCIM service configuration.

use serde::{Deserialize, Serialize};

/// SCIM service configuration loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScimConfig {
    /// Listen address. Default: "127.0.0.1:9443".
    pub listen_addr: String,
    /// OIDC issuer URL for validating Bearer tokens.
    pub oidc_issuer: String,
    /// Expected audience for Bearer tokens.
    pub oidc_audience: String,
    /// Default login shell for new users.
    pub default_shell: String,
    /// Whether to create home directories. Default: true.
    pub create_home: bool,
}

impl Default for ScimConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9443".to_string(),
            oidc_issuer: String::new(),
            oidc_audience: "unix-oidc-scim".to_string(),
            default_shell: "/bin/bash".to_string(),
            create_home: true,
        }
    }
}
