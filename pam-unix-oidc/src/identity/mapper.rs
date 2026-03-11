//! Username extraction and transform pipeline.
//!
//! [`UsernameMapper`] extracts a claim from a JWT token and applies an ordered
//! sequence of transforms to produce the Unix username used for authentication.
//!
//! # Transform pipeline
//!
//! Transforms are applied in order.  Each transform receives the output of the
//! previous one.  If any transform produces an empty string the pipeline fails
//! with [`IdentityError::TransformFailed`].
//!
//! # Validation at config-load time
//!
//! [`UsernameMapper::from_config`] pre-compiles regular expressions and validates
//! that every regex pattern contains a `(?P<username>...)` named capture group.
//! Missing capture groups are caught here, not at authentication time, so
//! operator misconfiguration is surfaced immediately on startup.

use regex::Regex;
use thiserror::Error;

use crate::oidc::token::TokenClaims;
use crate::policy::config::{IdentityConfig, TransformConfig};

// ── Error type ─────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Missing required claim '{0}' in token")]
    MissingClaim(String),

    #[error("Transform failed to produce a username from value '{0}'")]
    TransformFailed(String),

    #[error("Invalid regex pattern '{0}': {1}")]
    InvalidRegex(String, String),

    #[error("Regex pattern '{0}' is missing required named capture group (?P<username>...)")]
    MissingCaptureGroup(String),

    #[error("Invalid username '{0}': {1}")]
    InvalidUsername(String, String),
}

// ── Transform enum ─────────────────────────────────────────────────────────────

/// A single transform step in the username mapping pipeline.
#[derive(Debug)]
pub enum UsernameTransform {
    /// Strip the domain suffix: `"alice@corp.com"` → `"alice"`.
    ///
    /// Splits on `@` and takes the first segment.  If the value contains no `@`
    /// it is returned unchanged.  If the first segment is empty (e.g. `"@corp.com"`)
    /// the transform returns `None`, causing a [`IdentityError::TransformFailed`].
    StripDomain,

    /// Lowercase the value: `"Alice"` → `"alice"`.
    Lowercase,

    /// Extract a substring using a compiled regex with a `(?P<username>...)` group.
    ///
    /// The pattern must contain exactly one named capture group called `username`.
    /// This is validated at [`UsernameMapper::from_config`] time.
    Regex(Regex),
}

impl UsernameTransform {
    /// Apply this transform to `input`, returning `Some(output)` on success or
    /// `None` when the transform cannot produce a valid result (e.g. no `@` after
    /// strip, no regex match).
    pub fn apply(&self, input: &str) -> Option<String> {
        match self {
            UsernameTransform::StripDomain => {
                // Split on '@'; take only the first segment.
                // "@corp.com" → first segment is "" → None (empty is invalid).
                let local = input.splitn(2, '@').next()?;
                if local.is_empty() {
                    None
                } else {
                    Some(local.to_string())
                }
            }
            UsernameTransform::Lowercase => Some(input.to_lowercase()),
            UsernameTransform::Regex(re) => {
                re.captures(input)
                    .and_then(|caps| caps.name("username"))
                    .map(|m| m.as_str().to_string())
            }
        }
    }
}

// ── UsernameMapper ─────────────────────────────────────────────────────────────

/// Extracts and transforms a username from OIDC token claims.
///
/// Constructed from [`IdentityConfig`] via [`Self::from_config`].  The mapper
/// pre-compiles any regular expressions so that authentication is not gated on
/// regex compilation at runtime.
pub struct UsernameMapper {
    /// The OIDC claim name to extract (e.g. `"preferred_username"` or `"email"`).
    pub(crate) claim: String,
    /// Ordered sequence of transforms applied to the raw claim value.
    pub(crate) transforms: Vec<UsernameTransform>,
}

impl std::fmt::Debug for UsernameMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsernameMapper")
            .field("claim", &self.claim)
            .field("transforms", &self.transforms)
            .finish()
    }
}

impl UsernameMapper {
    /// Build a [`UsernameMapper`] from an [`IdentityConfig`].
    ///
    /// Validates regex patterns (including the required `(?P<username>...)` group)
    /// at config-load time.  Returns [`IdentityError`] on the first invalid pattern.
    pub fn from_config(config: &IdentityConfig) -> Result<Self, IdentityError> {
        let mut transforms = Vec::with_capacity(config.transforms.len());

        for tc in &config.transforms {
            let transform = match tc {
                TransformConfig::Simple(s) => match s.as_str() {
                    "strip_domain" => UsernameTransform::StripDomain,
                    "lowercase" => UsernameTransform::Lowercase,
                    other => {
                        return Err(IdentityError::InvalidRegex(
                            other.to_string(),
                            "unknown simple transform (expected 'strip_domain' or 'lowercase')"
                                .to_string(),
                        ));
                    }
                },
                TransformConfig::Object { r#type, pattern } => {
                    if r#type != "regex" {
                        return Err(IdentityError::InvalidRegex(
                            r#type.clone(),
                            "unknown object transform type (only 'regex' is supported)".to_string(),
                        ));
                    }

                    // Security: validate (?P<username>...) presence BEFORE compiling.
                    // The regex crate's group-name lookup is done post-match; if the
                    // group is absent the mapper would silently return None for every
                    // input. Catching this at config-load time surfaces operator error.
                    if !pattern.contains("(?P<username>") {
                        return Err(IdentityError::MissingCaptureGroup(pattern.clone()));
                    }

                    let re = Regex::new(pattern).map_err(|e| {
                        IdentityError::InvalidRegex(pattern.clone(), e.to_string())
                    })?;

                    UsernameTransform::Regex(re)
                }
            };

            transforms.push(transform);
        }

        Ok(Self {
            claim: config.username_claim.clone(),
            transforms,
        })
    }

    /// Extract a claim from `claims` and apply all transforms in order.
    ///
    /// Returns the final username string on success.  Returns [`IdentityError`]
    /// if the claim is missing, a transform fails, or the resulting username
    /// fails basic sanity checks (empty, contains `\0` or `/`, exceeds 256 bytes).
    pub fn map(&self, claims: &TokenClaims) -> Result<String, IdentityError> {
        // 1. Extract the raw claim value.
        let raw = claims
            .get_claim_str(&self.claim)
            .ok_or_else(|| IdentityError::MissingClaim(self.claim.clone()))?;

        // 2. Apply each transform in order.
        let mut current = raw.clone();
        for transform in &self.transforms {
            current = transform
                .apply(&current)
                .ok_or_else(|| IdentityError::TransformFailed(raw.clone()))?;
        }

        // 3. Validate the final username.
        validate_username(&current)?;

        Ok(current)
    }
}

// ── Username validation ────────────────────────────────────────────────────────

/// Validate a candidate username against basic Unix sanity rules.
///
/// Rejects:
/// - Empty strings (transform pipeline produced nothing useful)
/// - Strings containing null bytes (C string terminator injection)
/// - Strings containing `/` (path traversal in home-dir construction)
/// - Strings exceeding 256 bytes (beyond POSIX `LOGIN_NAME_MAX` on Linux/macOS)
fn validate_username(username: &str) -> Result<(), IdentityError> {
    if username.is_empty() {
        return Err(IdentityError::InvalidUsername(
            username.to_string(),
            "username must not be empty".to_string(),
        ));
    }
    if username.contains('\0') {
        return Err(IdentityError::InvalidUsername(
            "[contains null byte]".to_string(),
            "username must not contain null bytes".to_string(),
        ));
    }
    if username.contains('/') {
        return Err(IdentityError::InvalidUsername(
            username.to_string(),
            "username must not contain '/'".to_string(),
        ));
    }
    if username.len() > 256 {
        return Err(IdentityError::InvalidUsername(
            format!("[{} bytes]", username.len()),
            "username exceeds 256-byte limit (POSIX LOGIN_NAME_MAX)".to_string(),
        ));
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::oidc::token::{StringOrVec, TokenClaims};

    /// Build a minimal `TokenClaims` with a given username and optional extra claims.
    fn make_claims(preferred_username: &str) -> TokenClaims {
        TokenClaims {
            sub: preferred_username.to_string(),
            preferred_username: preferred_username.to_string(),
            iss: "https://idp.example.com".to_string(),
            aud: StringOrVec::String("unix-oidc".to_string()),
            exp: 9_999_999_999,
            iat: 0,
            auth_time: None,
            acr: None,
            amr: None,
            jti: None,
            cnf: None,
            extra: std::collections::HashMap::new(),
        }
    }

    fn make_claims_with_email(preferred_username: &str, email: &str) -> TokenClaims {
        let mut claims = make_claims(preferred_username);
        claims
            .extra
            .insert("email".to_string(), serde_json::Value::String(email.to_string()));
        claims
    }

    fn make_config(claim: &str, transforms: &[&str]) -> IdentityConfig {
        IdentityConfig {
            username_claim: claim.to_string(),
            transforms: transforms
                .iter()
                .map(|t| TransformConfig::Simple(t.to_string()))
                .collect(),
        }
    }

    fn make_config_regex(claim: &str, pattern: &str) -> IdentityConfig {
        IdentityConfig {
            username_claim: claim.to_string(),
            transforms: vec![TransformConfig::Object {
                r#type: "regex".to_string(),
                pattern: pattern.to_string(),
            }],
        }
    }

    // ── StripDomain ─────────────────────────────────────────────────────────

    #[test]
    fn test_strip_domain_with_domain() {
        let t = UsernameTransform::StripDomain;
        assert_eq!(t.apply("alice@corp.com"), Some("alice".to_string()));
    }

    #[test]
    fn test_strip_domain_without_domain() {
        let t = UsernameTransform::StripDomain;
        // No @ → value unchanged (idempotent)
        assert_eq!(t.apply("alice"), Some("alice".to_string()));
    }

    #[test]
    fn test_strip_domain_leading_at_returns_none() {
        let t = UsernameTransform::StripDomain;
        // "@corp.com" → local part is "" → None
        assert_eq!(t.apply("@corp.com"), None);
    }

    // ── Lowercase ───────────────────────────────────────────────────────────

    #[test]
    fn test_lowercase_transforms() {
        let t = UsernameTransform::Lowercase;
        assert_eq!(t.apply("Alice"), Some("alice".to_string()));
        assert_eq!(t.apply("ALICE"), Some("alice".to_string()));
        assert_eq!(t.apply("alice"), Some("alice".to_string()));
    }

    // ── Regex ───────────────────────────────────────────────────────────────

    #[test]
    fn test_regex_with_named_group() {
        let re = Regex::new(r"^corp-(?P<username>[a-z0-9]+)").unwrap();
        let t = UsernameTransform::Regex(re);
        assert_eq!(t.apply("corp-alice-01"), Some("alice".to_string()));
    }

    #[test]
    fn test_regex_no_match_returns_none() {
        let re = Regex::new(r"^corp-(?P<username>[a-z0-9]+)").unwrap();
        let t = UsernameTransform::Regex(re);
        assert_eq!(t.apply("CORP-ALICE"), None);
    }

    // ── Pipeline chaining ───────────────────────────────────────────────────

    #[test]
    fn test_pipeline_strip_domain_then_lowercase() {
        let config = make_config("email", &["strip_domain", "lowercase"]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let claims = make_claims_with_email("", "Alice@CORP.COM");
        let result = mapper.map(&claims).unwrap();
        assert_eq!(result, "alice");
    }

    #[test]
    fn test_pipeline_no_transforms_uses_claim_as_is() {
        let config = make_config("preferred_username", &[]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let claims = make_claims("testuser");
        assert_eq!(mapper.map(&claims).unwrap(), "testuser");
    }

    // ── Missing claim ───────────────────────────────────────────────────────

    #[test]
    fn test_missing_claim_returns_error() {
        let config = make_config("email", &[]); // no email in claims
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let claims = make_claims("testuser"); // no email extra claim
        let result = mapper.map(&claims);
        assert!(matches!(result, Err(IdentityError::MissingClaim(_))));
    }

    // ── Transform failure ───────────────────────────────────────────────────

    #[test]
    fn test_transform_produces_empty_causes_error() {
        // "@corp.com" → strip_domain → "" → TransformFailed
        let config = make_config("email", &["strip_domain"]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let claims = make_claims_with_email("", "@corp.com");
        let result = mapper.map(&claims);
        assert!(
            matches!(result, Err(IdentityError::TransformFailed(_))),
            "expected TransformFailed, got {result:?}"
        );
    }

    // ── Username sanitization ───────────────────────────────────────────────

    #[test]
    fn test_null_byte_in_username_rejected() {
        let config = make_config("preferred_username", &[]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        // Inject null byte via the claim value
        let mut claims = make_claims("test\0user");
        claims.preferred_username = "test\0user".to_string();
        let result = mapper.map(&claims);
        assert!(
            matches!(result, Err(IdentityError::InvalidUsername(_, _))),
            "expected InvalidUsername, got {result:?}"
        );
    }

    #[test]
    fn test_slash_in_username_rejected() {
        let config = make_config("preferred_username", &[]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let mut claims = make_claims("alice/bob");
        claims.preferred_username = "alice/bob".to_string();
        let result = mapper.map(&claims);
        assert!(matches!(result, Err(IdentityError::InvalidUsername(_, _))));
    }

    #[test]
    fn test_overlong_username_rejected() {
        let long = "a".repeat(257);
        let config = make_config("preferred_username", &[]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let mut claims = make_claims(&long);
        claims.preferred_username = long.clone();
        let result = mapper.map(&claims);
        assert!(matches!(result, Err(IdentityError::InvalidUsername(_, _))));
    }

    #[test]
    fn test_username_at_exactly_256_bytes_is_accepted() {
        let exactly_256 = "a".repeat(256);
        let config = make_config("preferred_username", &[]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let mut claims = make_claims(&exactly_256);
        claims.preferred_username = exactly_256.clone();
        assert!(mapper.map(&claims).is_ok());
    }

    // ── Regex validation at config-load time ────────────────────────────────

    #[test]
    fn test_regex_without_named_group_rejected_at_config_load() {
        // Pattern does not contain (?P<username>...) → must fail at from_config
        let config = make_config_regex("email", r"^[a-z]+");
        let result = UsernameMapper::from_config(&config);
        assert!(
            matches!(result, Err(IdentityError::MissingCaptureGroup(_))),
            "expected MissingCaptureGroup, got {result:?}"
        );
    }

    #[test]
    fn test_invalid_regex_pattern_rejected_at_config_load() {
        // Syntactically invalid regex
        let config = make_config_regex("email", r"(?P<username>[unclosed");
        let result = UsernameMapper::from_config(&config);
        assert!(
            matches!(result, Err(IdentityError::InvalidRegex(_, _))),
            "expected InvalidRegex, got {result:?}"
        );
    }

    #[test]
    fn test_valid_regex_with_named_group_accepted() {
        let config = make_config_regex("sub", r"^corp-(?P<username>[a-z0-9]+)-\d+$");
        assert!(UsernameMapper::from_config(&config).is_ok());
    }

    // ── Adversarial tests ────────────────────────────────────────────────────

    #[test]
    fn test_regex_crate_handles_catastrophic_input_gracefully() {
        // The regex crate uses a finite automata engine with guaranteed O(n) matching
        // (no backtracking), so catastrophic backtracking is not possible.
        // This test verifies that a "ReDoS-style" pattern still completes quickly.
        let config = make_config_regex(
            "email",
            r"^(?P<username>[a-zA-Z0-9._%+\-]+)@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
        );
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let mut claims = make_claims("");
        // A long input that would cause catastrophic backtracking in PCRE
        let adversarial = "a".repeat(100) + "@corp.com";
        claims
            .extra
            .insert("email".to_string(), serde_json::Value::String(adversarial));
        // Should either succeed or fail gracefully, not hang
        let _result = mapper.map(&claims);
    }

    #[test]
    fn test_null_byte_in_extra_claim_rejected() {
        let config = make_config("email", &[]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let mut claims = make_claims("testuser");
        claims.extra.insert(
            "email".to_string(),
            serde_json::Value::String("alice\0evil@corp.com".to_string()),
        );
        let result = mapper.map(&claims);
        assert!(matches!(result, Err(IdentityError::InvalidUsername(_, _))));
    }

    // ── Unknown simple transform rejected ────────────────────────────────────

    #[test]
    fn test_unknown_simple_transform_rejected() {
        let config = make_config("preferred_username", &["upper_case"]); // not supported
        let result = UsernameMapper::from_config(&config);
        assert!(
            matches!(result, Err(IdentityError::InvalidRegex(_, _))),
            "expected InvalidRegex for unknown simple transform, got {result:?}"
        );
    }
}
