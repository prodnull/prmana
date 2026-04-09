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

use std::collections::HashMap;

use crate::oidc::token::TokenClaims;
use crate::policy::config::{IdentityConfig, SpiffeMappingConfig, TransformConfig};

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
                let local = input.split('@').next()?;
                if local.is_empty() {
                    None
                } else {
                    Some(local.to_string())
                }
            }
            UsernameTransform::Lowercase => Some(input.to_lowercase()),
            UsernameTransform::Regex(re) => re
                .captures(input)
                .and_then(|caps| caps.name("username"))
                .map(|m| m.as_str().to_string()),
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

                    let re = Regex::new(pattern)
                        .map_err(|e| IdentityError::InvalidRegex(pattern.clone(), e.to_string()))?;

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

/// Reserved/system account names that must never be mapped from OIDC claims
/// or SPIFFE IDs. An attacker who controls their IdP `preferred_username` or
/// SPIFFE path could otherwise map to a privileged local account.
///
/// This list covers accounts that exist by default on Linux (Ubuntu/RHEL) and
/// have elevated privileges or special capabilities. It is intentionally
/// conservative — false positives are acceptable because legitimate users
/// should never have these usernames in their IdP.
const RESERVED_USERNAMES: &[&str] = &[
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "gnats",
    "nobody",
    "systemd-network",
    "systemd-resolve",
    "messagebus",
    "sshd",
    "polkitd",
    "tss",
    // Service accounts
    "mysql",
    "postgres",
    "redis",
    "nginx",
    "apache",
    "http",
    "named",
    "dbus",
    "avahi",
    "colord",
    "geoclue",
    "pulse",
    "rtkit",
    "gdm",
    "lightdm",
    "sddm",
    // RHEL/Fedora specifics
    "adm",
    "shutdown",
    "halt",
    "operator",
    "ftp",
    "nfsnobody",
    "chrony",
    "unbound",
    "cockpit-ws",
    "cockpit-wsinstance",
    "sssd",
    "setroubleshoot",
    "pesign",
    "radvd",
    "rpc",
    "rpcuser",
    "ntp",
    "abrt",
];

/// Validate a candidate username against Unix sanity rules and reserved accounts.
///
/// Rejects:
/// - Empty strings (transform pipeline produced nothing useful)
/// - Strings containing null bytes (C string terminator injection)
/// - Strings containing `/` (path traversal in home-dir construction)
/// - Strings exceeding 256 bytes (beyond POSIX `LOGIN_NAME_MAX` on Linux/macOS)
/// - Reserved/system account names (privilege escalation via IdP claim control)
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
    // Security: reject reserved/system accounts to prevent privilege escalation
    // via attacker-controlled IdP claims or SPIFFE IDs mapping to root/daemon/etc.
    if RESERVED_USERNAMES.contains(&username) {
        return Err(IdentityError::InvalidUsername(
            username.to_string(),
            "reserved system account — OIDC/SPIFFE identity must not map to privileged accounts"
                .to_string(),
        ));
    }
    Ok(())
}

// ── SPIFFE username mapper (Phase 35) ─────────────────────────────────────────

/// Maps SPIFFE IDs (`spiffe://trust-domain/path/segments`) to Unix usernames.
///
/// Three strategies, evaluated in priority order:
/// 1. `static_map` — exact SPIFFE ID → username lookup
/// 2. `regex` — regex with `(?P<username>...)` capture group applied to the full SPIFFE ID
/// 3. `path_suffix` — last path segment of the SPIFFE ID
///
/// Constructed from [`SpiffeMappingConfig`] via [`Self::from_config`].
pub struct SpiffeUsernameMapper {
    strategy: SpiffeStrategy,
}

enum SpiffeStrategy {
    PathSuffix,
    Regex(Regex),
    StaticMap(HashMap<String, String>),
}

impl std::fmt::Debug for SpiffeUsernameMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.strategy {
            SpiffeStrategy::PathSuffix => f.write_str("SpiffeMapper(path_suffix)"),
            SpiffeStrategy::Regex(re) => write!(f, "SpiffeMapper(regex: {})", re.as_str()),
            SpiffeStrategy::StaticMap(m) => {
                write!(f, "SpiffeMapper(static_map: {} entries)", m.len())
            }
        }
    }
}

impl SpiffeUsernameMapper {
    /// Build a mapper from config. Validates regex patterns at load time.
    pub fn from_config(config: &SpiffeMappingConfig) -> Result<Self, IdentityError> {
        let strategy = match config.strategy.as_str() {
            "path_suffix" => SpiffeStrategy::PathSuffix,
            "regex" => {
                let pattern = config.pattern.as_deref().ok_or_else(|| {
                    IdentityError::InvalidRegex(
                        "regex".to_string(),
                        "spiffe_mapping.pattern is required when strategy is 'regex'".to_string(),
                    )
                })?;
                if !pattern.contains("(?P<username>") {
                    return Err(IdentityError::MissingCaptureGroup(pattern.to_string()));
                }
                let re = Regex::new(pattern)
                    .map_err(|e| IdentityError::InvalidRegex(pattern.to_string(), e.to_string()))?;
                SpiffeStrategy::Regex(re)
            }
            "static_map" => {
                if config.mappings.is_empty() {
                    return Err(IdentityError::InvalidRegex(
                        "static_map".to_string(),
                        "spiffe_mapping.mappings must not be empty for static_map strategy"
                            .to_string(),
                    ));
                }
                SpiffeStrategy::StaticMap(config.mappings.clone())
            }
            other => {
                return Err(IdentityError::InvalidRegex(
                    other.to_string(),
                    "unknown spiffe_mapping strategy (expected 'path_suffix', 'regex', or 'static_map')".to_string(),
                ));
            }
        };
        Ok(Self { strategy })
    }

    /// Returns `true` if `sub` looks like a SPIFFE ID.
    pub fn is_spiffe_id(sub: &str) -> bool {
        sub.starts_with("spiffe://")
    }

    /// Map a SPIFFE ID to a Unix username.
    ///
    /// The `sub` claim must start with `spiffe://`. Returns [`IdentityError`]
    /// if the mapping fails or the resulting username is invalid.
    pub fn map_spiffe_id(&self, spiffe_id: &str) -> Result<String, IdentityError> {
        let username = match &self.strategy {
            SpiffeStrategy::PathSuffix => {
                // spiffe://trust-domain/ns/prod/sa/my-agent → "my-agent"
                spiffe_id
                    .rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        IdentityError::TransformFailed(format!(
                            "SPIFFE ID has no path segments: {spiffe_id}"
                        ))
                    })?
                    .to_string()
            }
            SpiffeStrategy::Regex(re) => re
                .captures(spiffe_id)
                .and_then(|caps| caps.name("username"))
                .map(|m| m.as_str().to_string())
                .ok_or_else(|| {
                    IdentityError::TransformFailed(format!(
                        "SPIFFE ID did not match regex: {spiffe_id}"
                    ))
                })?,
            SpiffeStrategy::StaticMap(map) => map.get(spiffe_id).cloned().ok_or_else(|| {
                IdentityError::TransformFailed(format!("SPIFFE ID not in static map: {spiffe_id}"))
            })?,
        };

        validate_username(&username)?;
        Ok(username)
    }
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
            preferred_username: Some(preferred_username.to_string()),
            iss: "https://idp.example.com".to_string(),
            aud: StringOrVec::String("unix-oidc".to_string()),
            exp: 9_999_999_999,
            iat: 0,
            auth_time: None,
            acr: None,
            amr: None,
            jti: None,
            cnf: None,
            act: None,
            extra: std::collections::HashMap::new(),
        }
    }

    fn make_claims_with_email(preferred_username: &str, email: &str) -> TokenClaims {
        let mut claims = make_claims(preferred_username);
        claims.extra.insert(
            "email".to_string(),
            serde_json::Value::String(email.to_string()),
        );
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
        claims.preferred_username = Some("test\0user".to_string());
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
        claims.preferred_username = Some("alice/bob".to_string());
        let result = mapper.map(&claims);
        assert!(matches!(result, Err(IdentityError::InvalidUsername(_, _))));
    }

    #[test]
    fn test_reserved_username_root_rejected() {
        let config = make_config("preferred_username", &[]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let mut claims = make_claims("root");
        claims.preferred_username = Some("root".to_string());
        let result = mapper.map(&claims);
        assert!(
            matches!(result, Err(IdentityError::InvalidUsername(_, _))),
            "reserved account 'root' must be rejected: {result:?}"
        );
    }

    #[test]
    fn test_reserved_username_nobody_rejected() {
        let config = make_config("preferred_username", &[]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let mut claims = make_claims("nobody");
        claims.preferred_username = Some("nobody".to_string());
        let result = mapper.map(&claims);
        assert!(matches!(result, Err(IdentityError::InvalidUsername(_, _))));
    }

    #[test]
    fn test_non_reserved_username_accepted() {
        let config = make_config("preferred_username", &[]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let claims = make_claims("alice");
        assert!(mapper.map(&claims).is_ok());
    }

    #[test]
    fn test_overlong_username_rejected() {
        let long = "a".repeat(257);
        let config = make_config("preferred_username", &[]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let mut claims = make_claims(&long);
        claims.preferred_username = Some(long.clone());
        let result = mapper.map(&claims);
        assert!(matches!(result, Err(IdentityError::InvalidUsername(_, _))));
    }

    #[test]
    fn test_username_at_exactly_256_bytes_is_accepted() {
        let exactly_256 = "a".repeat(256);
        let config = make_config("preferred_username", &[]);
        let mapper = UsernameMapper::from_config(&config).unwrap();
        let mut claims = make_claims(&exactly_256);
        claims.preferred_username = Some(exactly_256.clone());
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

    // ── SPIFFE mapping tests (Phase 35) ─────────────────────────────────────

    mod spiffe {
        use super::*;
        use crate::policy::config::SpiffeMappingConfig;
        use std::collections::HashMap;

        #[test]
        fn test_is_spiffe_id() {
            assert!(SpiffeUsernameMapper::is_spiffe_id(
                "spiffe://example.com/ns/prod/sa/agent"
            ));
            assert!(!SpiffeUsernameMapper::is_spiffe_id(
                "https://idp.example.com"
            ));
            assert!(!SpiffeUsernameMapper::is_spiffe_id("alice@corp.com"));
        }

        #[test]
        fn test_path_suffix_extracts_last_segment() {
            let config = SpiffeMappingConfig::default(); // path_suffix
            let mapper = SpiffeUsernameMapper::from_config(&config).unwrap();
            assert_eq!(
                mapper
                    .map_spiffe_id("spiffe://example.com/ns/prod/sa/ml-agent")
                    .unwrap(),
                "ml-agent"
            );
        }

        #[test]
        fn test_path_suffix_simple_path() {
            let config = SpiffeMappingConfig::default();
            let mapper = SpiffeUsernameMapper::from_config(&config).unwrap();
            assert_eq!(
                mapper.map_spiffe_id("spiffe://td/my-workload").unwrap(),
                "my-workload"
            );
        }

        #[test]
        fn test_path_suffix_rejects_empty_path() {
            let config = SpiffeMappingConfig::default();
            let mapper = SpiffeUsernameMapper::from_config(&config).unwrap();
            // Trailing slash → last segment is empty
            let result = mapper.map_spiffe_id("spiffe://example.com/");
            assert!(result.is_err());
        }

        #[test]
        fn test_regex_extracts_username() {
            let config = SpiffeMappingConfig {
                strategy: "regex".to_string(),
                pattern: Some(r"spiffe://[^/]+/ns/[^/]+/sa/(?P<username>[a-z0-9-]+)".to_string()),
                mappings: HashMap::new(),
            };
            let mapper = SpiffeUsernameMapper::from_config(&config).unwrap();
            assert_eq!(
                mapper
                    .map_spiffe_id("spiffe://td/ns/prod/sa/etl-worker")
                    .unwrap(),
                "etl-worker"
            );
        }

        #[test]
        fn test_regex_rejects_non_matching() {
            let config = SpiffeMappingConfig {
                strategy: "regex".to_string(),
                pattern: Some(r"spiffe://prod\.example\.com/(?P<username>[a-z]+)".to_string()),
                mappings: HashMap::new(),
            };
            let mapper = SpiffeUsernameMapper::from_config(&config).unwrap();
            let result = mapper.map_spiffe_id("spiffe://staging.example.com/agent");
            assert!(result.is_err());
        }

        #[test]
        fn test_regex_missing_pattern_rejected() {
            let config = SpiffeMappingConfig {
                strategy: "regex".to_string(),
                pattern: None,
                mappings: HashMap::new(),
            };
            assert!(SpiffeUsernameMapper::from_config(&config).is_err());
        }

        #[test]
        fn test_regex_missing_capture_group_rejected() {
            let config = SpiffeMappingConfig {
                strategy: "regex".to_string(),
                pattern: Some(r"spiffe://[a-z]+/[a-z]+".to_string()),
                mappings: HashMap::new(),
            };
            assert!(SpiffeUsernameMapper::from_config(&config).is_err());
        }

        #[test]
        fn test_static_map_exact_lookup() {
            let mut mappings = HashMap::new();
            mappings.insert(
                "spiffe://td/ns/prod/sa/ml-agent".to_string(),
                "ml-agent".to_string(),
            );
            mappings.insert(
                "spiffe://td/ns/prod/sa/etl".to_string(),
                "etl-user".to_string(),
            );
            let config = SpiffeMappingConfig {
                strategy: "static_map".to_string(),
                pattern: None,
                mappings,
            };
            let mapper = SpiffeUsernameMapper::from_config(&config).unwrap();
            assert_eq!(
                mapper
                    .map_spiffe_id("spiffe://td/ns/prod/sa/ml-agent")
                    .unwrap(),
                "ml-agent"
            );
            assert_eq!(
                mapper.map_spiffe_id("spiffe://td/ns/prod/sa/etl").unwrap(),
                "etl-user"
            );
        }

        #[test]
        fn test_static_map_rejects_unknown_id() {
            let mut mappings = HashMap::new();
            mappings.insert("spiffe://td/known".to_string(), "user".to_string());
            let config = SpiffeMappingConfig {
                strategy: "static_map".to_string(),
                pattern: None,
                mappings,
            };
            let mapper = SpiffeUsernameMapper::from_config(&config).unwrap();
            assert!(mapper.map_spiffe_id("spiffe://td/unknown").is_err());
        }

        #[test]
        fn test_static_map_empty_rejected_at_config() {
            let config = SpiffeMappingConfig {
                strategy: "static_map".to_string(),
                pattern: None,
                mappings: HashMap::new(),
            };
            assert!(SpiffeUsernameMapper::from_config(&config).is_err());
        }

        #[test]
        fn test_unknown_strategy_rejected() {
            let config = SpiffeMappingConfig {
                strategy: "custom".to_string(),
                pattern: None,
                mappings: HashMap::new(),
            };
            assert!(SpiffeUsernameMapper::from_config(&config).is_err());
        }

        #[test]
        fn test_path_suffix_rejects_root() {
            let config = SpiffeMappingConfig::default();
            let mapper = SpiffeUsernameMapper::from_config(&config).unwrap();
            let result = mapper.map_spiffe_id("spiffe://evil.com/root");
            assert!(
                matches!(result, Err(IdentityError::InvalidUsername(_, _))),
                "SPIFFE path_suffix mapping to 'root' must be rejected: {result:?}"
            );
        }

        #[test]
        fn test_regex_rejects_sshd() {
            let config = SpiffeMappingConfig {
                strategy: "regex".to_string(),
                pattern: Some(r"spiffe://[^/]+/(?P<username>[a-z]+)".to_string()),
                mappings: HashMap::new(),
            };
            let mapper = SpiffeUsernameMapper::from_config(&config).unwrap();
            let result = mapper.map_spiffe_id("spiffe://evil.com/sshd");
            assert!(
                matches!(result, Err(IdentityError::InvalidUsername(_, _))),
                "SPIFFE regex mapping to 'sshd' must be rejected: {result:?}"
            );
        }

        #[test]
        fn test_mapped_username_validated() {
            // Static map returns a username with '/' → must be rejected
            let mut mappings = HashMap::new();
            mappings.insert("spiffe://td/evil".to_string(), "../../root".to_string());
            let config = SpiffeMappingConfig {
                strategy: "static_map".to_string(),
                pattern: None,
                mappings,
            };
            let mapper = SpiffeUsernameMapper::from_config(&config).unwrap();
            let result = mapper.map_spiffe_id("spiffe://td/evil");
            assert!(
                matches!(result, Err(IdentityError::InvalidUsername(_, _))),
                "path traversal username must be rejected: {result:?}"
            );
        }
    }
}
