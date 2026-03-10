//! Policy configuration types and loading.
//!
//! Uses figment (layered configuration) for YAML + environment-variable overrides.
//! Environment variable override pattern: UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT
//! (double-underscore maps to nested struct fields per figment's `split("__")`).

use figment::{
    providers::{Env, Format, Serialized, Yaml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

use super::rules::StepUpMethod;

/// Check if test mode is explicitly enabled.
/// Security: Only accepts explicit "true" or "1" values, not just presence of the variable.
fn is_test_mode_enabled() -> bool {
    std::env::var("UNIX_OIDC_TEST_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Failed to read policy file: {0}")]
    ReadError(#[from] std::io::Error),

    /// Returned when the config file cannot be parsed or a field value is invalid.
    /// Changed from `#[from] serde_yaml::Error` to `String` because figment errors
    /// are not serde_yaml errors — figment provides its own error type.
    #[error("Failed to parse policy: {0}")]
    ParseError(String),

    #[error("Policy file not found: {0}")]
    NotFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

// ── Enforcement mode ─────────────────────────────────────────────────────────

/// Enforcement level for configurable security checks (Issue #10).
///
/// - `strict`   — reject the authentication attempt when the check fails
/// - `warn`     — log a warning and allow authentication to proceed (v1.0 default for most checks)
/// - `disabled` — skip the check entirely (not recommended for production)
///
/// Invalid strings cause a [`PolicyError::ParseError`] at config-load time so that
/// operator typos (e.g. `"strct"`) are never silently treated as `warn`.
///
/// Serde impls are hand-rolled (not derived) so that:
/// - `Deserialize` rejects unknown strings with an error rather than falling
///   back silently (no `#[serde(other)]`).
/// - `Serialize` round-trips identically to the lowercase YAML representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    Strict,
    #[default]
    Warn,
    Disabled,
}

impl serde::Serialize for EnforcementMode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            EnforcementMode::Strict => "strict",
            EnforcementMode::Warn => "warn",
            EnforcementMode::Disabled => "disabled",
        })
    }
}

impl<'de> serde::de::Deserialize<'de> for EnforcementMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = EnforcementMode;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(r#"one of "strict", "warn", or "disabled""#)
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<EnforcementMode, E> {
                match v {
                    "strict" => Ok(EnforcementMode::Strict),
                    "warn" => Ok(EnforcementMode::Warn),
                    "disabled" => Ok(EnforcementMode::Disabled),
                    other => Err(E::unknown_variant(
                        other,
                        &["strict", "warn", "disabled"],
                    )),
                }
            }
        }
        d.deserialize_str(Visitor)
    }
}

// ── ACR configuration ─────────────────────────────────────────────────────────

/// Authentication Context Reference (ACR) enforcement configuration.
#[derive(Debug, Clone, Serialize)]
#[serde(default)]
pub struct AcrConfig {
    /// How strictly to enforce the ACR claim. Default: `warn` (log and allow).
    pub enforcement: EnforcementMode,
    /// Minimum required ACR level string, e.g. `"urn:example:acr:mfa"`. Default: `None`.
    pub minimum_level: Option<String>,
}

impl Default for AcrConfig {
    fn default() -> Self {
        Self {
            enforcement: EnforcementMode::Warn,
            minimum_level: None,
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for AcrConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(default)]
        struct Raw {
            enforcement: EnforcementMode,
            minimum_level: Option<String>,
        }
        impl Default for Raw {
            fn default() -> Self {
                Self {
                    enforcement: EnforcementMode::Warn,
                    minimum_level: None,
                }
            }
        }
        let r = Raw::deserialize(d)?;
        Ok(AcrConfig {
            enforcement: r.enforcement,
            minimum_level: r.minimum_level,
        })
    }
}

// ── Security modes ────────────────────────────────────────────────────────────

/// Configurable enforcement modes for security checks (Issue #10).
///
/// When the `security_modes` section is absent from `policy.yaml`, this struct
/// is not instantiated — `PolicyConfig::security_modes` will be `None`.  Call
/// [`PolicyConfig::effective_security_modes`] to get the correct defaults in
/// both the v1.0 and v2.0 cases.
///
/// Default values match v1.0 code behavior exactly, ensuring a zero-behavior-change
/// upgrade for operators who do not add the new section.
#[derive(Debug, Clone, Serialize)]
#[serde(default)]
pub struct SecurityModes {
    /// JTI replay-prevention enforcement. Default: `warn` (some IdPs omit JTI).
    pub jti_enforcement: EnforcementMode,
    /// DPoP token binding enforcement. Default: `strict` (binding is critical).
    pub dpop_required: EnforcementMode,
    /// AMR (Authentication Methods References) claim enforcement. Default: `disabled`.
    pub amr_enforcement: EnforcementMode,
    /// ACR (Authentication Context Reference) configuration.
    pub acr: AcrConfig,
}

impl Default for SecurityModes {
    fn default() -> Self {
        Self {
            jti_enforcement: EnforcementMode::Warn,
            dpop_required: EnforcementMode::Strict,
            amr_enforcement: EnforcementMode::Disabled,
            acr: AcrConfig::default(),
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for SecurityModes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(default)]
        struct Raw {
            jti_enforcement: EnforcementMode,
            dpop_required: EnforcementMode,
            amr_enforcement: EnforcementMode,
            acr: AcrConfig,
        }
        impl Default for Raw {
            fn default() -> Self {
                let s = SecurityModes::default();
                Self {
                    jti_enforcement: s.jti_enforcement,
                    dpop_required: s.dpop_required,
                    amr_enforcement: s.amr_enforcement,
                    acr: s.acr,
                }
            }
        }
        let r = Raw::deserialize(d)?;
        Ok(SecurityModes {
            jti_enforcement: r.jti_enforcement,
            dpop_required: r.dpop_required,
            amr_enforcement: r.amr_enforcement,
            acr: r.acr,
        })
    }
}

// ── Cache configuration ───────────────────────────────────────────────────────

/// Operational tuning for caches (JTI replay cache, etc.).
///
/// Separate from `SecurityModes` because changing cache sizes is operational
/// tuning, not a security-policy change.
#[derive(Debug, Clone, Serialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Maximum number of JTI entries in the replay-prevention cache.
    /// See CLAUDE.md §JWKS Caching Security. Default: 100,000.
    pub jti_max_entries: usize,
    /// How often (in seconds) expired JTI entries are swept from the cache.
    /// Default: 300 seconds (5 minutes).
    pub jti_cleanup_interval_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            jti_max_entries: 100_000,
            jti_cleanup_interval_secs: 300,
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for CacheConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(default)]
        struct Raw {
            jti_max_entries: usize,
            jti_cleanup_interval_secs: u64,
        }
        impl Default for Raw {
            fn default() -> Self {
                let c = CacheConfig::default();
                Self {
                    jti_max_entries: c.jti_max_entries,
                    jti_cleanup_interval_secs: c.jti_cleanup_interval_secs,
                }
            }
        }
        let r = Raw::deserialize(d)?;
        Ok(CacheConfig {
            jti_max_entries: r.jti_max_entries,
            jti_cleanup_interval_secs: r.jti_cleanup_interval_secs,
        })
    }
}

// ── Existing config types ─────────────────────────────────────────────────────

/// Host classification for determining authentication requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HostClassification {
    /// Standard hosts with basic MFA requirements
    #[default]
    Standard,
    /// Elevated hosts with stricter requirements
    Elevated,
    /// Critical hosts with maximum security
    Critical,
}

/// SSH login configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SshConfig {
    /// Whether OIDC authentication is required
    pub require_oidc: bool,
    /// Minimum ACR level required
    pub minimum_acr: Option<String>,
    /// Maximum age of auth_time in seconds (re-auth if older)
    pub max_auth_age: Option<i64>,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            require_oidc: true,
            minimum_acr: None,
            max_auth_age: Some(3600), // 1 hour default
        }
    }
}

/// Sudo configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SudoConfig {
    /// Whether step-up authentication is required
    pub step_up_required: bool,
    /// Allowed step-up methods
    pub allowed_methods: Vec<StepUpMethod>,
    /// Timeout for step-up challenge in seconds
    pub challenge_timeout: u64,
    /// Command-specific rules
    #[serde(default)]
    pub commands: Vec<CommandRule>,
}

impl Default for SudoConfig {
    fn default() -> Self {
        Self {
            step_up_required: true,
            allowed_methods: vec![StepUpMethod::DeviceFlow],
            challenge_timeout: 60,
            commands: Vec::new(),
        }
    }
}

/// Rule for specific sudo commands.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandRule {
    /// Glob pattern for matching commands
    pub pattern: String,
    /// Whether step-up is required for this command
    pub step_up_required: bool,
}

/// Break-glass configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BreakGlassConfig {
    /// Whether break-glass is enabled
    pub enabled: bool,
    /// Local account for break-glass access
    pub local_account: Option<String>,
    /// Authentication method (yubikey_otp)
    pub requires: Option<String>,
    /// Whether to send alerts on break-glass use
    pub alert_on_use: bool,
}

impl Default for BreakGlassConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            local_account: None,
            requires: None,
            alert_on_use: true,
        }
    }
}

/// Host-level configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HostConfig {
    /// Host classification
    pub classification: HostClassification,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            classification: HostClassification::Standard,
        }
    }
}

// ── PolicyConfig ──────────────────────────────────────────────────────────────

/// Complete policy configuration.
///
/// Loaded via figment from `/etc/unix-oidc/policy.yaml` with optional
/// environment-variable overrides (prefix `UNIX_OIDC_`, double-underscore nesting).
///
/// `security_modes` is `Option<SecurityModes>` so that figment can distinguish
/// between "section absent" (v1.0 file → `None`) and "section present" (v2.0 → `Some`).
/// Use [`Self::effective_security_modes`] to get the correct enforcement config.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct PolicyConfig {
    /// Host-level configuration
    pub host: HostConfig,
    /// SSH login configuration
    pub ssh_login: SshConfig,
    /// Sudo configuration
    pub sudo: SudoConfig,
    /// Break-glass configuration
    pub break_glass: BreakGlassConfig,
    /// Security enforcement modes (v2.0+). Absent in v1.0 files.
    pub security_modes: Option<SecurityModes>,
    /// Cache tuning parameters.
    pub cache: CacheConfig,
}

impl PolicyConfig {
    /// Load policy from the default location.
    pub fn load() -> Result<Self, PolicyError> {
        Self::load_from("/etc/unix-oidc/policy.yaml")
    }

    /// Load policy from a specific path using figment (YAML + env overrides).
    ///
    /// Environment variable override pattern (double-underscore for nesting):
    /// - `UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT=strict`
    /// - `UNIX_OIDC_SECURITY_MODES__DPOP_REQUIRED=warn`
    /// - `UNIX_OIDC_CACHE__JTI_MAX_ENTRIES=50000`
    ///
    /// Only `security_modes` and `cache` env keys are recognized to prevent
    /// unrelated `UNIX_OIDC_*` vars (e.g. `UNIX_OIDC_TEST_MODE`) from causing
    /// spurious config-parse errors.
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(PolicyError::NotFound(path.display().to_string()));
        }

        let config: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::file(path))
            .merge(
                Env::prefixed("UNIX_OIDC_")
                    .split("__")
                    .only(&["security_modes", "cache"]),
            )
            .extract()
            .map_err(|e| PolicyError::ParseError(e.to_string()))?;

        // Emit v1.0-migration notice so operators know to add the new section.
        if config.security_modes.is_none() {
            tracing::info!(
                "Loaded policy.yaml without security_modes section \
                 — using v1.0 defaults. See docs for v2.0 configuration."
            );
        }

        Ok(config)
    }

    /// Load policy from environment variables (for testing / runtime override).
    ///
    /// Priority:
    /// 1. `UNIX_OIDC_POLICY_FILE` — path to a YAML file
    /// 2. `UNIX_OIDC_POLICY_YAML` — inline YAML string
    /// 3. `UNIX_OIDC_TEST_MODE=true|1` — return `Default::default()`
    /// 4. Default file location `/etc/unix-oidc/policy.yaml`
    pub fn from_env() -> Result<Self, PolicyError> {
        // Check for test policy file path
        if let Ok(path) = std::env::var("UNIX_OIDC_POLICY_FILE") {
            return Self::load_from(&path);
        }

        // Check for inline YAML config
        if let Ok(yaml) = std::env::var("UNIX_OIDC_POLICY_YAML") {
            let config: PolicyConfig =
                Figment::from(Serialized::defaults(PolicyConfig::default()))
                    .merge(Yaml::string(&yaml))
                    .merge(
                        Env::prefixed("UNIX_OIDC_")
                            .split("__")
                            .only(&["security_modes", "cache"]),
                    )
                    .extract()
                    .map_err(|e| PolicyError::ParseError(e.to_string()))?;
            return Ok(config);
        }

        // Return default policy for test mode
        // Security: Requires explicit "true" or "1", not just any value.
        if is_test_mode_enabled() {
            return Ok(Self::default());
        }

        // Try loading from default location
        Self::load()
    }

    /// Return the effective [`SecurityModes`] for this policy.
    ///
    /// If the `security_modes` section was absent from the YAML (v1.0 file),
    /// returns [`SecurityModes::default()`] which exactly matches v1.0 behavior.
    pub fn effective_security_modes(&self) -> SecurityModes {
        self.security_modes.clone().unwrap_or_default()
    }

    /// Check if a command matches any pattern that requires step-up.
    pub fn command_requires_step_up(&self, command: &str) -> bool {
        // If no command rules, use the default sudo config
        if self.sudo.commands.is_empty() {
            return self.sudo.step_up_required;
        }

        // Check command rules in order
        for rule in &self.sudo.commands {
            if pattern_matches(&rule.pattern, command) {
                return rule.step_up_required;
            }
        }

        // Default to the sudo config setting
        self.sudo.step_up_required
    }
}

// ── Glob pattern matching ─────────────────────────────────────────────────────

/// Simple glob pattern matching (supports * wildcard).
fn pattern_matches(pattern: &str, text: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('*').collect();

    if pattern_parts.len() == 1 {
        // No wildcards, exact match
        return pattern == text;
    }

    let mut pos = 0;
    for (i, part) in pattern_parts.iter().enumerate() {
        if part.is_empty() {
            // Empty part means * at start or end, or ** - matches anything
            continue;
        }

        if i == 0 {
            // First part must match at start
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == pattern_parts.len() - 1 {
            // Last non-empty part must match at end (if pattern doesn't end with *)
            // But if pattern ends with *, the last part will be empty
            if !text[pos..].ends_with(part) {
                return false;
            }
        } else {
            // Middle parts must be found in order
            if let Some(found_pos) = text[pos..].find(part) {
                pos += found_pos + part.len();
            } else {
                return false;
            }
        }
    }

    // If the last pattern part is empty (pattern ends with *),
    // we've already matched everything we need
    true
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── New-type tests ──────────────────────────────────────────────────────

    #[test]
    fn test_enforcement_mode_defaults() {
        // EnforcementMode::default() must be Warn (v1.0 behavior for JTI)
        assert_eq!(EnforcementMode::default(), EnforcementMode::Warn);
    }

    #[test]
    fn test_security_modes_defaults() {
        let modes = SecurityModes::default();
        assert_eq!(modes.jti_enforcement, EnforcementMode::Warn);
        assert_eq!(modes.dpop_required, EnforcementMode::Strict);
        assert_eq!(modes.amr_enforcement, EnforcementMode::Disabled);
        assert_eq!(modes.acr.enforcement, EnforcementMode::Warn);
        assert!(modes.acr.minimum_level.is_none());
    }

    #[test]
    fn test_cache_config_defaults() {
        let cache = CacheConfig::default();
        assert_eq!(cache.jti_max_entries, 100_000);
        assert_eq!(cache.jti_cleanup_interval_secs, 300);
    }

    #[test]
    fn test_v1_yaml_loads_with_defaults() {
        // A v1.0 policy.yaml (no security_modes section) must load without error
        // and produce None for security_modes (triggering v1.0-compat path).
        let yaml = r#"
host:
  classification: standard
ssh_login:
  require_oidc: true
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("v1.0 yaml should load");

        assert!(
            policy.security_modes.is_none(),
            "v1.0 yaml must produce security_modes=None"
        );
        // effective_security_modes() must still return correct defaults
        let modes = policy.effective_security_modes();
        assert_eq!(modes.jti_enforcement, EnforcementMode::Warn);
        assert_eq!(modes.dpop_required, EnforcementMode::Strict);
    }

    #[test]
    fn test_v2_yaml_overrides_security_modes() {
        let yaml = r#"
security_modes:
  jti_enforcement: strict
  dpop_required: warn
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("v2.0 yaml should load");

        let modes = policy.effective_security_modes();
        assert_eq!(modes.jti_enforcement, EnforcementMode::Strict);
        assert_eq!(modes.dpop_required, EnforcementMode::Warn);
    }

    #[test]
    fn test_invalid_enforcement_mode_rejected() {
        let yaml = r#"
security_modes:
  jti_enforcement: strct
"#;
        let result: Result<PolicyConfig, _> =
            Figment::from(Serialized::defaults(PolicyConfig::default()))
                .merge(Yaml::string(yaml))
                .extract();

        assert!(result.is_err(), "Invalid mode string must cause load failure");
    }

    #[test]
    fn test_cache_section_overrides_defaults() {
        let yaml = r#"
cache:
  jti_max_entries: 50000
  jti_cleanup_interval_secs: 600
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("cache yaml should load");

        assert_eq!(policy.cache.jti_max_entries, 50_000);
        assert_eq!(policy.cache.jti_cleanup_interval_secs, 600);
    }

    #[test]
    fn test_env_var_override_jti_enforcement() {
        // UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT=strict overrides YAML
        let yaml = r#"
security_modes:
  jti_enforcement: warn
"#;
        // Safety: test-only env var manipulation; tests run sequentially within this module
        std::env::set_var("UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT", "strict");
        let result: Result<PolicyConfig, _> =
            Figment::from(Serialized::defaults(PolicyConfig::default()))
                .merge(Yaml::string(yaml))
                .merge(Env::prefixed("UNIX_OIDC_").split("__"))
                .extract();
        std::env::remove_var("UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT");

        let policy = result.expect("env override should succeed");
        assert_eq!(
            policy.effective_security_modes().jti_enforcement,
            EnforcementMode::Strict
        );
    }

    #[test]
    fn test_unknown_env_vars_do_not_break_load() {
        // UNIX_OIDC_TEST_MODE is not a PolicyConfig field — figment must not error.
        // We use `.only()` filter on the env provider to prevent unknown key mapping.
        std::env::set_var("UNIX_OIDC_TEST_MODE", "true");
        let result: Result<PolicyConfig, _> =
            Figment::from(Serialized::defaults(PolicyConfig::default()))
                .merge(
                    Env::prefixed("UNIX_OIDC_")
                        .split("__")
                        .only(&["security_modes", "cache"]),
                )
                .extract();
        std::env::remove_var("UNIX_OIDC_TEST_MODE");

        assert!(result.is_ok(), "Unknown env vars must not break config load");
    }

    // ── Existing tests (backward compat) ────────────────────────────────────

    #[test]
    fn test_default_policy() {
        let policy = PolicyConfig::default();

        assert_eq!(policy.host.classification, HostClassification::Standard);
        assert!(policy.ssh_login.require_oidc);
        assert!(policy.sudo.step_up_required);
        assert_eq!(policy.sudo.challenge_timeout, 60);
    }

    #[test]
    fn test_parse_yaml_policy() {
        let yaml = r#"
host:
  classification: elevated

ssh_login:
  require_oidc: true
  minimum_acr: "urn:example:acr:mfa"
  max_auth_age: 1800

sudo:
  step_up_required: true
  allowed_methods:
    - device_flow
    - fido2
  challenge_timeout: 120
  commands:
    - pattern: "/usr/bin/systemctl restart *"
      step_up_required: true
    - pattern: "/usr/bin/less *"
      step_up_required: false
"#;

        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(policy.host.classification, HostClassification::Elevated);
        assert_eq!(
            policy.ssh_login.minimum_acr,
            Some("urn:example:acr:mfa".into())
        );
        assert_eq!(policy.ssh_login.max_auth_age, Some(1800));
        assert_eq!(policy.sudo.challenge_timeout, 120);
        assert_eq!(policy.sudo.commands.len(), 2);
    }

    #[test]
    fn test_pattern_matching() {
        // Exact match
        assert!(pattern_matches("/usr/bin/less", "/usr/bin/less"));
        assert!(!pattern_matches("/usr/bin/less", "/usr/bin/more"));

        // Trailing wildcard
        assert!(pattern_matches("/usr/bin/less *", "/usr/bin/less foo.txt"));
        assert!(pattern_matches("/usr/bin/less*", "/usr/bin/less")); // No space before *
        assert!(pattern_matches("/usr/bin/less*", "/usr/bin/less foo.txt")); // Also matches with args
        assert!(!pattern_matches("/usr/bin/less *", "/usr/bin/less")); // Space before * requires space in input
        assert!(!pattern_matches("/usr/bin/less *", "/usr/bin/more foo.txt"));

        // Leading wildcard
        assert!(pattern_matches("*.log", "/var/log/syslog.log"));
        assert!(!pattern_matches("*.log", "/var/log/syslog.txt"));

        // Middle wildcard
        assert!(pattern_matches("/usr/*/bin", "/usr/local/bin"));
        assert!(!pattern_matches("/usr/*/bin", "/opt/local/bin"));

        // Complex pattern
        assert!(pattern_matches(
            "/usr/bin/systemctl restart *",
            "/usr/bin/systemctl restart nginx"
        ));
    }

    #[test]
    fn test_command_requires_step_up() {
        let yaml = r#"
sudo:
  step_up_required: true
  commands:
    - pattern: "/usr/bin/systemctl restart *"
      step_up_required: true
    - pattern: "/usr/bin/less *"
      step_up_required: false
"#;

        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();

        // Matched by first rule - requires step-up
        assert!(policy.command_requires_step_up("/usr/bin/systemctl restart nginx"));

        // Matched by second rule - no step-up
        assert!(!policy.command_requires_step_up("/usr/bin/less /var/log/syslog"));

        // Not matched by any rule - uses default
        assert!(policy.command_requires_step_up("/usr/bin/rm -rf /"));
    }

    #[test]
    fn test_host_classification_parsing() {
        let yaml = "classification: critical";
        let host: HostConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(host.classification, HostClassification::Critical);

        let yaml = "classification: standard";
        let host: HostConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(host.classification, HostClassification::Standard);
    }
}
