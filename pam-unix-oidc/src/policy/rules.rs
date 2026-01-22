//! Policy rules for determining authentication actions.

use serde::Deserialize;

use super::config::{HostClassification, PolicyConfig};

/// Authentication action determined by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAction {
    /// Allow access without additional authentication
    Allow,
    /// Deny access
    Deny,
    /// Require step-up authentication
    StepUp,
}

/// Methods for step-up authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpMethod {
    /// OAuth 2.0 Device Authorization Grant
    #[default]
    DeviceFlow,
    /// Push notification (e.g., MS Authenticator)
    Push,
    /// FIDO2/WebAuthn
    Fido2,
}

/// Policy rules engine for evaluating authentication requirements.
pub struct PolicyRules<'a> {
    policy: &'a PolicyConfig,
}

impl<'a> PolicyRules<'a> {
    pub fn new(policy: &'a PolicyConfig) -> Self {
        Self { policy }
    }

    /// Check if SSH login requires OIDC authentication.
    ///
    /// Returns the minimum ACR level required, or None if OIDC not required.
    pub fn check_ssh_login(&self) -> Option<SshLoginRequirements> {
        if !self.policy.ssh_login.require_oidc {
            return None;
        }

        let minimum_acr = self.get_minimum_acr_for_classification();

        Some(SshLoginRequirements {
            minimum_acr,
            max_auth_age: self.policy.ssh_login.max_auth_age,
        })
    }

    /// Check if sudo command requires step-up authentication.
    ///
    /// Returns the step-up requirements, or None if step-up not required.
    pub fn check_sudo(&self, command: &str) -> Option<SudoStepUpRequirements> {
        if !self.policy.command_requires_step_up(command) {
            return None;
        }

        Some(SudoStepUpRequirements {
            allowed_methods: self.policy.sudo.allowed_methods.clone(),
            timeout: self.policy.sudo.challenge_timeout,
            minimum_acr: self.get_minimum_acr_for_classification(),
        })
    }

    /// Get the minimum ACR level based on host classification.
    fn get_minimum_acr_for_classification(&self) -> Option<String> {
        // First check if explicitly configured
        if self.policy.ssh_login.minimum_acr.is_some() {
            return self.policy.ssh_login.minimum_acr.clone();
        }

        // Otherwise, derive from host classification
        match self.policy.host.classification {
            HostClassification::Standard => None,
            HostClassification::Elevated => Some("urn:example:acr:mfa".to_string()),
            HostClassification::Critical => Some("urn:example:acr:phishing-resistant".to_string()),
        }
    }
}

/// SSH login requirements.
#[derive(Debug, Clone)]
pub struct SshLoginRequirements {
    /// Minimum ACR level required
    pub minimum_acr: Option<String>,
    /// Maximum age of auth_time in seconds
    pub max_auth_age: Option<i64>,
}

/// Sudo step-up requirements.
#[derive(Debug, Clone)]
pub struct SudoStepUpRequirements {
    /// Allowed step-up methods
    pub allowed_methods: Vec<StepUpMethod>,
    /// Timeout for the step-up challenge in seconds
    pub timeout: u64,
    /// Minimum ACR level for the step-up token
    pub minimum_acr: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> PolicyConfig {
        let yaml = r#"
host:
  classification: elevated

ssh_login:
  require_oidc: true
  max_auth_age: 3600

sudo:
  step_up_required: true
  allowed_methods:
    - device_flow
  challenge_timeout: 60
  commands:
    - pattern: "/usr/bin/less *"
      step_up_required: false
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn test_ssh_login_requirements() {
        let policy = test_policy();
        let rules = PolicyRules::new(&policy);

        let req = rules.check_ssh_login().unwrap();
        assert_eq!(req.minimum_acr, Some("urn:example:acr:mfa".to_string()));
        assert_eq!(req.max_auth_age, Some(3600));
    }

    #[test]
    fn test_sudo_step_up_required() {
        let policy = test_policy();
        let rules = PolicyRules::new(&policy);

        // Command that requires step-up (default)
        let req = rules
            .check_sudo("/usr/bin/systemctl restart nginx")
            .unwrap();
        assert_eq!(req.allowed_methods, vec![StepUpMethod::DeviceFlow]);
        assert_eq!(req.timeout, 60);

        // Command that doesn't require step-up
        let req = rules.check_sudo("/usr/bin/less /var/log/syslog");
        assert!(req.is_none());
    }

    #[test]
    fn test_ssh_not_required() {
        let yaml = r#"
ssh_login:
  require_oidc: false
"#;
        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let rules = PolicyRules::new(&policy);

        assert!(rules.check_ssh_login().is_none());
    }

    #[test]
    fn test_classification_acr_mapping() {
        // Standard classification - no ACR required
        let yaml = r#"
host:
  classification: standard
ssh_login:
  require_oidc: true
"#;
        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let rules = PolicyRules::new(&policy);
        assert!(rules.check_ssh_login().unwrap().minimum_acr.is_none());

        // Critical classification - phishing-resistant required
        let yaml = r#"
host:
  classification: critical
ssh_login:
  require_oidc: true
"#;
        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let rules = PolicyRules::new(&policy);
        assert_eq!(
            rules.check_ssh_login().unwrap().minimum_acr,
            Some("urn:example:acr:phishing-resistant".to_string())
        );
    }
}
