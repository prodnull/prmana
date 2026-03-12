//! Break-glass fallback integration test (INT-03)
//!
//! Validates that the break-glass code path:
//! - Returns correct determination for configured accounts
//! - Works independently of OIDC availability
//! - Applies only to explicitly configured accounts

use pam_unix_oidc::policy::config::PolicyConfig;

/// Verify is_break_glass_user logic via PolicyConfig deserialization.
///
/// This is a code-level integration test — we cannot invoke PAM module
/// entry points directly from Rust tests (they require a live PAM handle),
/// but we can verify the policy parsing and break-glass account matching
/// that gates the IGNORE return path.
#[test]
fn test_break_glass_policy_parsing_and_account_matching() {
    let yaml = r#"
issuer: "https://idp.example.com"
client_id: "unix-oidc"
break_glass:
  enabled: true
  accounts:
    - breakglass
    - emergency-admin
"#;

    let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();

    // Break-glass is enabled
    assert!(policy.break_glass.enabled);

    // Configured accounts match
    assert!(policy
        .break_glass
        .accounts
        .contains(&"breakglass".to_string()));
    assert!(policy
        .break_glass
        .accounts
        .contains(&"emergency-admin".to_string()));

    // Non-configured accounts don't match
    assert!(!policy
        .break_glass
        .accounts
        .contains(&"normaluser".to_string()));
    assert!(!policy.break_glass.accounts.contains(&"root".to_string()));
}

/// Verify break-glass is disabled when not configured.
#[test]
fn test_break_glass_disabled_by_default() {
    let yaml = r#"
issuer: "https://idp.example.com"
client_id: "unix-oidc"
"#;

    let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();

    // Break-glass defaults to disabled
    assert!(!policy.break_glass.enabled);
    assert!(policy.break_glass.accounts.is_empty());
}

/// Verify break-glass enabled but empty accounts list matches nothing.
#[test]
fn test_break_glass_enabled_but_empty_accounts() {
    let yaml = r#"
issuer: "https://idp.example.com"
client_id: "unix-oidc"
break_glass:
  enabled: true
  accounts: []
"#;

    let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(policy.break_glass.enabled);
    assert!(policy.break_glass.accounts.is_empty());
}

/// Verify v1.0 backward-compatible local_account field.
#[test]
fn test_break_glass_v1_local_account_compat() {
    let yaml = r#"
issuer: "https://idp.example.com"
client_id: "unix-oidc"
break_glass:
  enabled: true
  local_account: "legacyadmin"
"#;

    let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(policy.break_glass.enabled);
    assert_eq!(
        policy.break_glass.local_account.as_deref(),
        Some("legacyadmin")
    );
}

/// Verify that the OIDC issuer being unreachable doesn't prevent
/// policy loading (policy is local YAML, not network-dependent).
#[test]
fn test_policy_loads_with_unreachable_issuer() {
    // This simulates the break-glass scenario: IdP is down, but
    // the PAM module can still load its local policy config.
    let yaml = r#"
issuer: "http://127.0.0.1:1/unreachable"
client_id: "unix-oidc"
break_glass:
  enabled: true
  accounts:
    - breakglass
"#;

    let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(policy.break_glass.enabled);
    assert!(policy
        .break_glass
        .accounts
        .contains(&"breakglass".to_string()));
}
