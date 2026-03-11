//! Static injectivity analysis for username transform pipelines.
//!
//! A transform pipeline is *injective* when no two distinct input values produce
//! the same output username.  A non-injective pipeline can allow two users with
//! different identities to authenticate as the same Unix account, which is a
//! security concern.
//!
//! This module provides [`validate_collision_safety`] which returns a list of
//! warning messages for potentially non-injective configurations.  An empty
//! return value means no collisions were detected.
//!
//! # Current heuristics
//!
//! - `strip_domain` alone: non-injective when the claim covers multiple domains
//!   (e.g. `alice@corp.com` and `alice@evil.com` both map to `"alice"`).
//! - `regex`: inherently non-injective in general (the capture group may match
//!   overlapping strings from different inputs), so we emit an advisory warning.
//! - `lowercase`: injective within a single character set; no warning emitted.

use crate::policy::config::{IdentityConfig, TransformConfig};

/// Analyse an [`IdentityConfig`] for potentially non-injective transform pipelines.
///
/// Returns a `Vec<String>` of human-readable warning messages.  An empty vec
/// means no collision risk was detected.  Warnings are advisory — they do not
/// prevent the configuration from loading.
///
/// Warnings should be emitted at `tracing::warn!` level during daemon startup.
pub fn validate_collision_safety(config: &IdentityConfig) -> Vec<String> {
    let mut warnings = Vec::new();

    let has_strip_domain = config
        .transforms
        .iter()
        .any(|t| matches!(t, TransformConfig::Simple(s) if s == "strip_domain"));

    let has_regex = config
        .transforms
        .iter()
        .any(|t| matches!(t, TransformConfig::Object { r#type, .. } if r#type == "regex"));

    // strip_domain is non-injective when the identity source spans multiple domains.
    // The only safe case is when a domain constraint is enforced externally (e.g.
    // the IdP is configured to issue tokens only for a single domain).  Since we
    // cannot verify that constraint here, we warn unconditionally.
    if has_strip_domain {
        warnings.push(
            "Identity transform 'strip_domain' is non-injective across multiple email domains: \
             'alice@corp.com' and 'alice@other.com' both map to 'alice'. \
             Ensure your IdP restricts token issuance to a single domain, or add a domain \
             constraint to your identity provider configuration."
                .to_string(),
        );
    }

    // regex captures can overlap for different inputs — emit an advisory.
    if has_regex {
        warnings.push(
            "Identity transform 'regex' may be non-injective: different input values can match \
             the same capture group output. Verify your pattern is injective for all expected \
             identity claim values."
                .to_string(),
        );
    }

    warnings
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::config::TransformConfig;

    fn config_with(claim: &str, transforms: Vec<TransformConfig>) -> IdentityConfig {
        IdentityConfig {
            username_claim: claim.to_string(),
            transforms,
        }
    }

    #[test]
    fn test_lowercase_alone_is_safe() {
        let config = config_with("email", vec![TransformConfig::Simple("lowercase".to_string())]);
        let warnings = validate_collision_safety(&config);
        assert!(
            warnings.is_empty(),
            "lowercase alone must produce no collision warning"
        );
    }

    #[test]
    fn test_strip_domain_alone_warns() {
        let config = config_with(
            "email",
            vec![TransformConfig::Simple("strip_domain".to_string())],
        );
        let warnings = validate_collision_safety(&config);
        assert!(
            !warnings.is_empty(),
            "strip_domain alone must emit a collision warning"
        );
        assert!(warnings[0].contains("strip_domain"));
    }

    #[test]
    fn test_strip_domain_and_lowercase_warns() {
        // strip_domain is still non-injective even when combined with lowercase
        let config = config_with(
            "email",
            vec![
                TransformConfig::Simple("strip_domain".to_string()),
                TransformConfig::Simple("lowercase".to_string()),
            ],
        );
        let warnings = validate_collision_safety(&config);
        assert!(!warnings.is_empty(), "strip_domain+lowercase must still warn");
    }

    #[test]
    fn test_regex_transform_warns_advisory() {
        let config = config_with(
            "email",
            vec![TransformConfig::Object {
                r#type: "regex".to_string(),
                pattern: r"^(?P<username>[a-z]+)@corp\.com$".to_string(),
            }],
        );
        let warnings = validate_collision_safety(&config);
        assert!(!warnings.is_empty(), "regex must emit an advisory warning");
        assert!(warnings.iter().any(|w| w.contains("regex")));
    }

    #[test]
    fn test_no_transforms_is_safe() {
        let config = config_with("preferred_username", vec![]);
        let warnings = validate_collision_safety(&config);
        assert!(
            warnings.is_empty(),
            "empty transform pipeline must produce no warnings"
        );
    }

    #[test]
    fn test_returns_multiple_warnings_when_both_strip_and_regex() {
        let config = config_with(
            "email",
            vec![
                TransformConfig::Simple("strip_domain".to_string()),
                TransformConfig::Object {
                    r#type: "regex".to_string(),
                    pattern: r"^(?P<username>[a-z]+)$".to_string(),
                },
            ],
        );
        let warnings = validate_collision_safety(&config);
        assert!(warnings.len() >= 2, "both strip_domain and regex should warn");
    }
}
