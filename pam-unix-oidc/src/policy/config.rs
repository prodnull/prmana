//! Policy configuration types and loading.

use serde::Deserialize;
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

    #[error("Failed to parse policy YAML: {0}")]
    ParseError(#[from] serde_yaml::Error),

    #[error("Policy file not found: {0}")]
    NotFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Host classification for determining authentication requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
pub struct CommandRule {
    /// Glob pattern for matching commands
    pub pattern: String,
    /// Whether step-up is required for this command
    pub step_up_required: bool,
}

/// Break-glass configuration.
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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

/// Complete policy configuration.
#[derive(Debug, Clone, Deserialize, Default)]
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
}

impl PolicyConfig {
    /// Load policy from the default location.
    pub fn load() -> Result<Self, PolicyError> {
        Self::load_from("/etc/unix-oidc/policy.yaml")
    }

    /// Load policy from a specific path.
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(PolicyError::NotFound(path.display().to_string()));
        }

        let content = std::fs::read_to_string(path)?;
        let config: PolicyConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Load policy from environment variables (for testing).
    pub fn from_env() -> Result<Self, PolicyError> {
        // Check for test policy file path
        if let Ok(path) = std::env::var("UNIX_OIDC_POLICY_FILE") {
            return Self::load_from(&path);
        }

        // Check for inline YAML config
        if let Ok(yaml) = std::env::var("UNIX_OIDC_POLICY_YAML") {
            let config: PolicyConfig = serde_yaml::from_str(&yaml)?;
            return Ok(config);
        }

        // Return default policy for test mode
        // Security: Requires explicit "true" or "1", not just any value
        if is_test_mode_enabled() {
            return Ok(Self::default());
        }

        // Try loading from default location
        Self::load()
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

#[cfg(test)]
mod tests {
    use super::*;

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
