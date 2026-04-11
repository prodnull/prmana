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
    /// Required scope/role value for privileged SCIM operations.
    ///
    /// The auth layer accepts this value from common IdP claim shapes:
    /// `scope`, `scp`, top-level `roles`, `realm_access.roles`, and
    /// `resource_access[oidc_audience].roles`.
    pub required_entitlement: String,
    /// JWKS cache TTL in seconds. Default: 300.
    pub jwks_cache_ttl_secs: u64,
    /// Default login shell for new users.
    pub default_shell: String,
    /// Whether to create home directories. Default: true.
    pub create_home: bool,
    /// Persistent SCIM state file used to keep the `{userName} <-> SCIM id`
    /// mapping across restarts.
    pub state_file: String,
    /// Skip system commands (useradd/userdel). For testing only.
    /// Production deployments MUST leave this false.
    #[serde(default)]
    pub dry_run: bool,
}

impl Default for ScimConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9443".to_string(),
            oidc_issuer: String::new(),
            oidc_audience: "prmana-scim".to_string(),
            required_entitlement: "scim:provision".to_string(),
            jwks_cache_ttl_secs: 300,
            default_shell: "/bin/bash".to_string(),
            create_home: true,
            state_file: "/var/lib/prmana/scim-users.json".to_string(),
            dry_run: false,
        }
    }
}
