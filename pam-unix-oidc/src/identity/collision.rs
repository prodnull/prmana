//! Static injectivity analysis for username transform pipelines.
//!
//! A transform pipeline is *injective* when no two distinct input values produce
//! the same output username.  A non-injective pipeline can allow two users with
//! different identities to authenticate as the same Unix account, which is a
//! security concern.
//!
//! This module provides:
//! - [`check_collision_safety`] — hard-fail gatekeeper (returns `Err(CollisionError)` for
//!   non-injective pipelines; used in production auth paths).
//! - [`validate_collision_safety`] — advisory-only variant (returns `Vec<String>` warnings)
//!   retained for backward compatibility and tooling use.
//!
//! # Security invariant (IDN-03)
//!
//! The hard-fail path is unconditional and non-configurable — same class as signature
//! verification.  A non-injective pipeline allows two distinct IdP users to authenticate
//! as the same Unix account, which is a critical identity security flaw.
//!
//! # Current heuristics
//!
//! - `strip_domain` alone: non-injective when the claim covers multiple domains
//!   (e.g. `alice@corp.com` and `alice@evil.com` both map to `"alice"`).
//! - `regex`: inherently non-injective in general (the capture group may match
//!   overlapping strings from different inputs), so we emit an advisory warning.
//! - `lowercase`: injective within a single character set; no warning emitted.

use crate::policy::config::{IdentityConfig, TransformConfig};

// ── Error type ────────────────────────────────────────────────────────────────

/// Error returned by [`check_collision_safety`] when a non-injective transform pipeline
/// is detected.
///
/// The `reason` field names each offending transform so operators know exactly which
/// configuration knob to change.  This error is always a hard-fail — it is not
/// configurable and cannot be suppressed.
#[derive(Debug, thiserror::Error)]
#[error(
    "Non-injective username transform pipeline detected — potential identity collision: {reason}"
)]
pub struct CollisionError {
    /// Human-readable description naming the offending transform(s).
    pub reason: String,
}

// ── Hard-fail gatekeeper ──────────────────────────────────────────────────────

/// Analyse an [`IdentityConfig`] for potentially non-injective transform pipelines.
///
/// Returns `Err(CollisionError)` when the pipeline contains any transform that can map
/// two distinct identity claim values to the same Unix username.  Returns `Ok(())` when
/// the pipeline is safe (or empty).
///
/// # Security
///
/// This function is the IDN-03 gatekeeper.  Callers in the authentication path **must**
/// propagate `Err` immediately as a configuration error (`AuthError::Config`).  The
/// check is unconditional and non-configurable — same class as signature verification.
pub fn check_collision_safety(config: &IdentityConfig) -> Result<(), CollisionError> {
    let warnings = validate_collision_safety(config);
    if warnings.is_empty() {
        Ok(())
    } else {
        Err(CollisionError {
            reason: warnings.join("; "),
        })
    }
}

// ── Advisory variant (preserved for backward compat / tooling) ────────────────

/// Analyse an [`IdentityConfig`] for potentially non-injective transform pipelines.
///
/// Returns a `Vec<String>` of human-readable warning messages.  An empty vec
/// means no collision risk was detected.  Warnings are advisory — they do not
/// prevent the configuration from loading.
///
/// **Production auth paths must use [`check_collision_safety`] instead.**  This
/// function is retained for backward compatibility and may be used by tooling that
/// wants to surface warnings without hard-failing.
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
        let config = config_with(
            "email",
            vec![TransformConfig::Simple("lowercase".to_string())],
        );
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
        assert!(
            !warnings.is_empty(),
            "strip_domain+lowercase must still warn"
        );
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
        assert!(
            warnings.len() >= 2,
            "both strip_domain and regex should warn"
        );
    }

    // ── check_collision_safety tests ──────────────────────────────────────────

    #[test]
    fn check_strip_domain_returns_err_with_transform_name() {
        let config = config_with(
            "email",
            vec![TransformConfig::Simple("strip_domain".to_string())],
        );
        let result = check_collision_safety(&config);
        assert!(result.is_err(), "strip_domain must hard-fail");
        let err = result.unwrap_err();
        assert!(
            err.reason.contains("strip_domain"),
            "error must name 'strip_domain' but got: {}",
            err.reason
        );
    }

    #[test]
    fn check_regex_returns_err_with_transform_name() {
        let config = config_with(
            "email",
            vec![TransformConfig::Object {
                r#type: "regex".to_string(),
                pattern: r"^(?P<username>[a-z]+)@corp\.com$".to_string(),
            }],
        );
        let result = check_collision_safety(&config);
        assert!(result.is_err(), "regex must hard-fail");
        let err = result.unwrap_err();
        assert!(
            err.reason.contains("regex"),
            "error must name 'regex' but got: {}",
            err.reason
        );
    }

    #[test]
    fn check_both_strip_domain_and_regex_lists_both() {
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
        let result = check_collision_safety(&config);
        assert!(
            result.is_err(),
            "both strip_domain and regex must hard-fail"
        );
        let err = result.unwrap_err();
        assert!(
            err.reason.contains("strip_domain"),
            "error must mention strip_domain"
        );
        assert!(err.reason.contains("regex"), "error must mention regex");
    }

    #[test]
    fn check_lowercase_only_is_ok() {
        let config = config_with(
            "email",
            vec![TransformConfig::Simple("lowercase".to_string())],
        );
        let result = check_collision_safety(&config);
        assert!(
            result.is_ok(),
            "lowercase alone must not hard-fail: {:?}",
            result
        );
    }

    #[test]
    fn check_no_transforms_is_ok() {
        let config = config_with("preferred_username", vec![]);
        let result = check_collision_safety(&config);
        assert!(
            result.is_ok(),
            "empty transform pipeline must not hard-fail: {:?}",
            result
        );
    }

    #[test]
    fn check_collision_error_display_contains_detail() {
        let config = config_with(
            "email",
            vec![TransformConfig::Simple("strip_domain".to_string())],
        );
        let err = check_collision_safety(&config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Non-injective"),
            "error Display must mention Non-injective: {msg}"
        );
        assert!(
            msg.contains("strip_domain"),
            "error Display must name the offending transform: {msg}"
        );
    }
}
