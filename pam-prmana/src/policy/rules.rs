//! Policy rules for determining authentication actions.

use serde::{Deserialize, Serialize};

use super::config::{CommandRule, HostClassification, PolicyConfig, SudoPolicyAction};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
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
    /// Returns the full policy decision, including matched-rule metadata and
    /// step-up requirements when the action is `step_up`.
    pub fn evaluate_sudo(&self, command: &str) -> SudoPolicyDecision {
        let host_classification = self.policy.host.classification;
        let matched_rule = self
            .policy
            .sudo
            .commands
            .iter()
            .find(|rule| self.rule_matches(rule, command, host_classification));

        let action = matched_rule
            .map(CommandRule::effective_action)
            .unwrap_or_else(|| self.policy.default_sudo_action());

        let required_acr = matched_rule
            .and_then(|rule| rule.required_acr.clone())
            .or_else(|| self.get_minimum_acr_for_classification());

        let grace_period_secs = matched_rule
            .and_then(|rule| rule.grace_period_secs)
            .unwrap_or(self.policy.sudo.grace_period_secs);

        let matched_rule_name = matched_rule
            .and_then(|rule| rule.name.clone())
            .or_else(|| matched_rule.map(|rule| rule.pattern.clone()));

        let step_up = (action == SudoPolicyAction::StepUp).then(|| SudoStepUpRequirements {
            allowed_methods: self.policy.sudo.allowed_methods.clone(),
            timeout: self.policy.sudo.challenge_timeout,
            method_timeouts: self.policy.sudo.method_timeouts.clone(),
            poll_interval_secs: self.policy.sudo.poll_interval_secs,
            minimum_acr: required_acr.clone(),
            grace_period_secs,
        });

        SudoPolicyDecision {
            action,
            matched_rule_name,
            host_classification,
            grace_period_secs,
            dry_run: self.policy.sudo.dry_run,
            step_up,
        }
    }

    fn rule_matches(
        &self,
        rule: &CommandRule,
        command: &str,
        host_classification: HostClassification,
    ) -> bool {
        if let Some(required_host_class) = rule.host_classification {
            let required: HostClassification = required_host_class.into();
            if required != host_classification {
                return false;
            }
        }

        super::config::pattern_matches(&rule.pattern, command)
    }

    /// Compatibility wrapper that preserves the pre-Phase-44 API shape for
    /// older callers/tests. New code should use `evaluate_sudo`.
    pub fn check_sudo(&self, command: &str) -> Option<SudoStepUpRequirements> {
        self.evaluate_sudo(command).step_up
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
    /// Default timeout for the step-up challenge in seconds
    pub timeout: u64,
    /// Per-method timeout overrides (Phase 36-01).
    pub method_timeouts: super::config::MethodTimeouts,
    /// CIBA/device-flow poll interval in seconds (Phase 36-01).
    pub poll_interval_secs: u64,
    /// Minimum ACR level for the step-up token
    pub minimum_acr: Option<String>,
    /// Time-bounded elevation window for reusing a recent successful step-up.
    pub grace_period_secs: u64,
}

/// Result of evaluating sudo policy for a specific command.
#[derive(Debug, Clone)]
pub struct SudoPolicyDecision {
    /// Final policy action for the command.
    pub action: SudoPolicyAction,
    /// Rule identifier used for audit/explain output.
    pub matched_rule_name: Option<String>,
    /// Effective host classification used during evaluation.
    pub host_classification: HostClassification,
    /// Grace window that would apply to this decision when action = `step_up`.
    pub grace_period_secs: u64,
    /// Whether the decision is observational only and should fall back to the
    /// legacy boolean behavior.
    pub dry_run: bool,
    /// Step-up requirements when action = `step_up`.
    pub step_up: Option<SudoStepUpRequirements>,
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
        assert_eq!(req.grace_period_secs, 0);

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

    #[test]
    fn test_evaluate_sudo_deny_and_host_class_filtering() {
        let yaml = r#"
host:
  classification: critical
sudo:
  step_up_required: true
  grace_period_secs: 90
  commands:
    - name: destructive-prod
      pattern: "/usr/bin/rm -rf *"
      action: deny
      host_classification: critical
    - name: read-only
      pattern: "/usr/bin/less *"
      action: allow
"#;
        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let rules = PolicyRules::new(&policy);

        let deny = rules.evaluate_sudo("/usr/bin/rm -rf /tmp/x");
        assert_eq!(deny.action, SudoPolicyAction::Deny);
        assert_eq!(deny.matched_rule_name.as_deref(), Some("destructive-prod"));
        assert!(deny.step_up.is_none());

        let allow = rules.evaluate_sudo("/usr/bin/less /var/log/syslog");
        assert_eq!(allow.action, SudoPolicyAction::Allow);
        assert_eq!(allow.matched_rule_name.as_deref(), Some("read-only"));
        assert!(allow.step_up.is_none());
    }

    #[test]
    fn test_evaluate_sudo_required_acr_and_grace_override() {
        let yaml = r#"
host:
  classification: elevated
sudo:
  step_up_required: true
  grace_period_secs: 300
  commands:
    - name: restart
      pattern: "/usr/bin/systemctl restart *"
      action: step_up
      required_acr: "urn:example:acr:phr"
      grace_period_secs: 30
"#;
        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let rules = PolicyRules::new(&policy);

        let decision = rules.evaluate_sudo("/usr/bin/systemctl restart nginx");
        assert_eq!(decision.action, SudoPolicyAction::StepUp);
        assert_eq!(decision.grace_period_secs, 30);
        let step_up = decision.step_up.expect("step-up required");
        assert_eq!(step_up.minimum_acr.as_deref(), Some("urn:example:acr:phr"));
        assert_eq!(step_up.grace_period_secs, 30);
    }
}
