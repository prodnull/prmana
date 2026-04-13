//! Policy rules for determining authentication actions.

use super::config::PolicyConfig;

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

    /// Get the minimum ACR level based on host classification.
    fn get_minimum_acr_for_classification(&self) -> Option<String> {
        // First check if explicitly configured
        if self.policy.ssh_login.minimum_acr.is_some() {
            return self.policy.ssh_login.minimum_acr.clone();
        }

        // Otherwise, derive from host classification
        use super::config::HostClassification;
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_policy() -> PolicyConfig {
        let yaml = r#"
host:
  classification: elevated

ssh_login:
  require_oidc: true
  max_auth_age: 3600
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
