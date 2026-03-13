//! JWT token validation with JWKS signature verification.

use crate::oidc::jwks::{JwksError, JwksProvider};
use crate::oidc::token::TokenClaims;
use crate::policy::config::EnforcementMode;
use crate::security::jti_cache::{global_jti_cache, JtiCheckResult};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Token error: {0}")]
    Token(#[from] crate::oidc::token::TokenError),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Token expired")]
    Expired,

    #[error("Invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer { expected: String, actual: String },

    #[error("Invalid audience")]
    InvalidAudience,

    #[error("ACR level insufficient: required {required}, got {actual:?}")]
    InsufficientAcr {
        required: String,
        actual: Option<String>,
    },

    #[error("Auth time too old: max age {max_age}s, actual age {actual_age}s")]
    AuthTimeTooOld { max_age: i64, actual_age: i64 },

    #[error("Missing auth_time claim but max_auth_age is configured")]
    MissingAuthTime,

    #[error("Failed to fetch JWKS: {0}")]
    JwksFetchError(#[from] JwksError),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Token replay detected: JTI '{jti}' was already used")]
    TokenReplay { jti: String },

    #[error("Token missing required JTI claim - replay protection cannot be enforced")]
    MissingJti,
}

#[derive(Debug, Clone)]
pub struct ValidationConfig {
    pub issuer: String,
    pub client_id: String,
    pub required_acr: Option<String>,
    pub max_auth_age: Option<i64>,
    /// JTI replay-prevention enforcement mode (Issue #10).
    ///
    /// - `Strict`   — tokens without JTI are rejected.
    /// - `Warn`     — tokens without JTI produce a warning but pass (v1.0 default behavior).
    /// - `Disabled` — JTI check is skipped entirely (replay protection unavailable).
    ///
    /// Replaces the old `UNIX_OIDC_DISABLE_JTI_CHECK` environment variable.
    /// Default: `Warn` to maintain exact v1.0 behavior.
    pub jti_enforcement: EnforcementMode,
    /// Clock skew tolerance for token expiration validation (seconds, default: 60).
    ///
    /// A token is accepted up to `clock_skew_tolerance_secs` seconds after its `exp`
    /// claim. This accommodates clock drift between the server and the IdP.
    ///
    /// Maps to `AgentConfig.timeouts.clock_skew_staleness_secs`.
    /// Default: 60 (matches the previous CLOCK_SKEW_TOLERANCE constant).
    pub clock_skew_tolerance_secs: i64,
}

impl ValidationConfig {
    pub fn from_env() -> Result<Self, ValidationError> {
        let issuer = std::env::var("OIDC_ISSUER")
            .map_err(|_| ValidationError::ConfigError("OIDC_ISSUER not set".into()))?;

        let client_id = std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| "unix-oidc".into());

        let required_acr = std::env::var("OIDC_REQUIRED_ACR").ok();

        let max_auth_age = std::env::var("OIDC_MAX_AUTH_AGE")
            .ok()
            .and_then(|s| s.parse().ok());

        // JTI enforcement defaults to Warn (v1.0 behavior: warn on missing JTI, allow).
        // Callers in auth.rs override this from PolicyConfig.effective_security_modes().
        let jti_enforcement = EnforcementMode::Warn;

        Ok(Self {
            issuer,
            client_id,
            required_acr,
            max_auth_age,
            jti_enforcement,
            // Default matches the previous CLOCK_SKEW_TOLERANCE constant (60s).
            // Callers wiring AgentConfig should pass clock_skew_staleness_secs.
            clock_skew_tolerance_secs: 60,
        })
    }
}

pub struct TokenValidator {
    config: ValidationConfig,
    jwks_provider: Arc<JwksProvider>,
    /// Skip signature verification (for testing only)
    skip_signature: bool,
}

impl TokenValidator {
    pub fn new(config: ValidationConfig) -> Self {
        let jwks_provider = Arc::new(JwksProvider::new(&config.issuer));
        Self {
            config,
            jwks_provider,
            skip_signature: false,
        }
    }

    /// Create validator with custom JWKS provider (for testing)
    pub fn with_jwks_provider(config: ValidationConfig, jwks_provider: Arc<JwksProvider>) -> Self {
        Self {
            config,
            jwks_provider,
            skip_signature: false,
        }
    }

    /// Create validator that skips signature verification (TEST MODE ONLY)
    ///
    /// # Safety
    /// This function is ONLY available when compiled with `--features test-mode`.
    /// Production builds MUST NOT include this feature.
    /// Using signature bypass in production is a critical security vulnerability.
    ///
    /// # Example
    /// ```ignore
    /// // Only works with: cargo build --features test-mode
    /// let validator = TokenValidator::new_insecure_for_testing(config);
    /// ```
    #[cfg(feature = "test-mode")]
    pub fn new_insecure_for_testing(config: ValidationConfig) -> Self {
        Self {
            config,
            jwks_provider: Arc::new(JwksProvider::new("http://localhost")),
            skip_signature: true,
        }
    }

    /// Validate a token and return the claims
    pub fn validate(&self, token: &str) -> Result<TokenClaims, ValidationError> {
        // Verify signature and decode claims
        let claims = if self.skip_signature {
            // Test mode - parse without signature verification
            // WARNING: This is insecure and should only be used for testing
            TokenClaims::from_token(token)?
        } else {
            // Production mode - verify signature using JWKS
            self.verify_and_decode(token)?
        };

        // Validate issuer
        if claims.iss != self.config.issuer {
            return Err(ValidationError::InvalidIssuer {
                expected: self.config.issuer.clone(),
                actual: claims.iss.clone(),
            });
        }

        // Validate audience
        if !claims.aud.contains(&self.config.client_id) {
            return Err(ValidationError::InvalidAudience);
        }

        // Validate expiration with clock skew tolerance.
        // clock_skew_tolerance_secs is operator-configurable (default 60s).
        let now = chrono::Utc::now().timestamp();
        if claims.exp + self.config.clock_skew_tolerance_secs < now {
            return Err(ValidationError::Expired);
        }

        // Check JTI for replay protection (Issue #10 — configurable enforcement).
        //
        // Disabled mode skips the cache lookup entirely to avoid unnecessary state.
        // Strict and Warn modes both record seen JTIs; they differ only in how
        // a *missing* JTI (no jti claim at all) is handled.
        if self.config.jti_enforcement != EnforcementMode::Disabled {
            // Calculate TTL for JTI cache based on token expiration
            let ttl_seconds =
                (claims.exp - now + self.config.clock_skew_tolerance_secs).max(0) as u64;

            let jti_result = global_jti_cache().check_and_record(
                claims.jti.as_deref(),
                claims.preferred_username.as_deref().unwrap_or("unknown"),
                ttl_seconds,
            );

            match jti_result {
                JtiCheckResult::Valid => {
                    // First use of this JTI — allow.
                }
                JtiCheckResult::Replay => {
                    // Token was already used — always reject regardless of mode.
                    // Replay detection is a hard-fail (CLAUDE.md §Security Check Decision Matrix).
                    return Err(ValidationError::TokenReplay {
                        jti: claims.jti.clone().unwrap_or_else(|| "unknown".to_string()),
                    });
                }
                JtiCheckResult::Missing => {
                    // Token has no JTI — behavior depends on enforcement mode.
                    match self.config.jti_enforcement {
                        EnforcementMode::Strict => {
                            tracing::warn!(
                                check = "jti",
                                mode = "strict",
                                username = %claims.preferred_username.as_deref().unwrap_or("unknown"),
                                "JTI missing — rejecting token (strict mode)"
                            );
                            return Err(ValidationError::MissingJti);
                        }
                        EnforcementMode::Warn => {
                            tracing::warn!(
                                check = "jti",
                                mode = "warn",
                                username = %claims.preferred_username.as_deref().unwrap_or("unknown"),
                                "Token missing JTI claim — allowing with warning (some IdPs omit JTI)"
                            );
                        }
                        EnforcementMode::Disabled => {
                            // Unreachable: Disabled is handled by the outer if-guard above.
                            // This arm exists to make the match exhaustive.
                        }
                    }
                }
            }
        }

        // Validate ACR if required
        if let Some(ref required_acr) = self.config.required_acr {
            match &claims.acr {
                Some(acr) if acr == required_acr => {}
                actual => {
                    return Err(ValidationError::InsufficientAcr {
                        required: required_acr.clone(),
                        actual: actual.clone(),
                    });
                }
            }
        }

        // Validate auth_time if max_auth_age is set
        if let Some(max_age) = self.config.max_auth_age {
            match claims.auth_time {
                Some(auth_time) => {
                    let age = now - auth_time;
                    // Apply clock skew tolerance to max_age check
                    if age > max_age + self.config.clock_skew_tolerance_secs {
                        return Err(ValidationError::AuthTimeTooOld {
                            max_age,
                            actual_age: age,
                        });
                    }
                }
                None => {
                    // When max_auth_age is configured, auth_time MUST be present
                    return Err(ValidationError::MissingAuthTime);
                }
            }
        }

        Ok(claims)
    }

    /// Verify JWT signature and decode claims
    fn verify_and_decode(&self, token: &str) -> Result<TokenClaims, ValidationError> {
        // Decode header to get kid and algorithm
        let header =
            decode_header(token).map_err(|e| ValidationError::InvalidSignature(e.to_string()))?;

        let algorithm = header.alg;

        // Get the key from JWKS
        let jwk = if let Some(kid) = &header.kid {
            self.jwks_provider.get_key(kid)?
        } else {
            // No kid in token - try the default key
            self.jwks_provider.get_default_key()?
        };

        // Security: Pin token header algorithm to JWKS-advertised algorithm.
        // Prevents algorithm substitution attacks where an attacker changes the
        // token header's `alg` to trick the verifier into using a weaker algorithm
        // or a different key type. Analogous to DPoP ES256 enforcement in dpop.rs.
        // See: docs/threat-model.md §7 Recommendation 4 (P1), closes R-8.
        if let Some(jwk_alg) = &jwk.common.key_algorithm {
            let jwk_alg_str = format!("{jwk_alg:?}");
            let header_alg_str = format!("{algorithm:?}");
            if jwk_alg_str != header_alg_str {
                tracing::warn!(
                    jwk_alg = %jwk_alg_str,
                    token_alg = %header_alg_str,
                    kid = ?header.kid,
                    "Algorithm mismatch: token header alg does not match JWKS-advertised alg"
                );
                return Err(ValidationError::UnsupportedAlgorithm(format!(
                    "Token header claims {header_alg_str} but JWKS key specifies {jwk_alg_str}"
                )));
            }
        }

        // Convert JWK to DecodingKey
        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|e| ValidationError::InvalidSignature(format!("Invalid JWK: {e}")))?;

        // Set up validation
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_issuer(&[&self.config.issuer]);
        // We do our own exp validation with clock skew tolerance below.
        validation.validate_exp = false;
        // Security: Validate nbf (not-before) to reject tokens issued for future use.
        // Uses jsonwebtoken's built-in nbf check which applies a default leeway.
        // See: docs/threat-model.md §7 Recommendation 5 (P1).
        validation.validate_nbf = true;

        // Decode and verify
        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)
            .map_err(|e| ValidationError::InvalidSignature(e.to_string()))?;

        Ok(token_data.claims)
    }

    pub fn config(&self) -> &ValidationConfig {
        &self.config
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::policy::config::EnforcementMode;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // Helper to create a test validator that skips signature verification.
    // Only available when compiled with --features test-mode.
    // Run tests with: cargo test --features test-mode
    #[cfg(feature = "test-mode")]
    fn test_validator(config: ValidationConfig) -> TokenValidator {
        TokenValidator::new_insecure_for_testing(config)
    }

    /// Base config for tests — issuer/client_id only, JTI disabled so the JTI
    /// cache state does not bleed between tests.
    #[cfg(feature = "test-mode")]
    fn base_config() -> ValidationConfig {
        ValidationConfig {
            issuer: "http://localhost:8080/realms/test".into(),
            client_id: "unix-oidc".into(),
            required_acr: None,
            max_auth_age: None,
            jti_enforcement: EnforcementMode::Disabled,
            clock_skew_tolerance_secs: 60,
        }
    }

    #[test]
    fn test_validation_config_from_env() {
        std::env::set_var("OIDC_ISSUER", "http://localhost:8080/realms/test");
        std::env::set_var("OIDC_CLIENT_ID", "unix-oidc");

        let config = ValidationConfig::from_env().unwrap();

        assert_eq!(config.issuer, "http://localhost:8080/realms/test");
        assert_eq!(config.client_id, "unix-oidc");
        // Default JTI enforcement is Warn (v1.0 behavior)
        assert_eq!(config.jti_enforcement, EnforcementMode::Warn);

        // Cleanup
        std::env::remove_var("OIDC_ISSUER");
        std::env::remove_var("OIDC_CLIENT_ID");
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn test_validate_expired_token() {
        let config = ValidationConfig {
            jti_enforcement: EnforcementMode::Disabled,
            ..base_config()
        };

        let validator = test_validator(config);

        // Token with exp in the past
        let token = create_expired_test_token();
        let result = validator.validate(&token);

        assert!(matches!(result, Err(ValidationError::Expired)));
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn test_validate_wrong_issuer() {
        let config = ValidationConfig {
            issuer: "http://localhost:8080/realms/correct".into(),
            jti_enforcement: EnforcementMode::Disabled,
            ..base_config()
        };

        let validator = test_validator(config);
        let token = create_valid_test_token();
        let result = validator.validate(&token);

        assert!(matches!(result, Err(ValidationError::InvalidIssuer { .. })));
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn test_validate_wrong_audience() {
        let config = ValidationConfig {
            client_id: "wrong-client".into(),
            jti_enforcement: EnforcementMode::Disabled,
            ..base_config()
        };

        let validator = test_validator(config);
        let token = create_valid_test_token();
        let result = validator.validate(&token);

        assert!(matches!(result, Err(ValidationError::InvalidAudience)));
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn test_validate_insufficient_acr() {
        let config = ValidationConfig {
            required_acr: Some("urn:example:acr:high".into()),
            jti_enforcement: EnforcementMode::Disabled,
            ..base_config()
        };

        let validator = test_validator(config);
        let token = create_valid_test_token(); // Has acr: "urn:example:acr:mfa"
        let result = validator.validate(&token);

        assert!(matches!(
            result,
            Err(ValidationError::InsufficientAcr { .. })
        ));
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn test_validate_valid_token() {
        let config = ValidationConfig {
            required_acr: Some("urn:example:acr:mfa".into()),
            jti_enforcement: EnforcementMode::Disabled,
            ..base_config()
        };

        let validator = test_validator(config);
        let token = create_valid_test_token();
        let result = validator.validate(&token);

        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.preferred_username.as_deref(), Some("testuser"));
    }

    // ── JTI enforcement mode tests ───────────────────────────────────────────

    /// Strict mode rejects a token with no JTI claim (MissingJti error).
    #[test]
    #[cfg(feature = "test-mode")]
    fn test_jti_strict_rejects_missing() {
        let config = ValidationConfig {
            jti_enforcement: EnforcementMode::Strict,
            ..base_config()
        };

        let validator = test_validator(config);
        let token = create_token_without_jti();
        let result = validator.validate(&token);

        assert!(
            matches!(result, Err(ValidationError::MissingJti)),
            "Strict mode must reject tokens without JTI, got: {result:?}"
        );
    }

    /// Warn mode allows a token with no JTI claim (authentication succeeds).
    #[test]
    #[cfg(feature = "test-mode")]
    fn test_jti_warn_allows_missing() {
        let config = ValidationConfig {
            jti_enforcement: EnforcementMode::Warn,
            ..base_config()
        };

        let validator = test_validator(config);
        let token = create_token_without_jti();
        let result = validator.validate(&token);

        assert!(
            result.is_ok(),
            "Warn mode must allow tokens without JTI (with warning), got: {result:?}"
        );
    }

    /// Disabled mode skips the JTI check entirely (authentication succeeds, no cache writes).
    #[test]
    #[cfg(feature = "test-mode")]
    fn test_jti_disabled_skips_check() {
        let config = ValidationConfig {
            jti_enforcement: EnforcementMode::Disabled,
            ..base_config()
        };

        let validator = test_validator(config);
        let token = create_token_without_jti();
        let result = validator.validate(&token);

        assert!(
            result.is_ok(),
            "Disabled mode must skip JTI check entirely, got: {result:?}"
        );
    }

    /// v1.0 default: Warn mode on missing JTI allows authentication.
    /// Replay (duplicate JTI) is always hard-rejected regardless of mode.
    #[test]
    #[cfg(feature = "test-mode")]
    fn test_v1_default_behavior() {
        // v1.0 default: Warn allows missing JTI
        let config = ValidationConfig {
            jti_enforcement: EnforcementMode::Warn,
            ..base_config()
        };

        let validator = test_validator(config);
        let token_no_jti = create_token_without_jti();

        // Missing JTI → must pass (v1.0 behavior)
        let result = validator.validate(&token_no_jti);
        assert!(
            result.is_ok(),
            "v1.0 default (Warn) must allow tokens without JTI"
        );

        // Replay of a *present* JTI → always rejected
        let token_with_jti = create_valid_test_token();
        let first = validator.validate(&token_with_jti);
        assert!(first.is_ok(), "First use of JTI must succeed");

        let second = validator.validate(&token_with_jti);
        assert!(
            matches!(second, Err(ValidationError::TokenReplay { .. })),
            "Replay of same JTI must be rejected even in Warn mode"
        );
    }

    // ── Token construction helpers ───────────────────────────────────────────

    #[allow(dead_code)]
    fn create_expired_test_token() -> String {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        // exp is in the past (2020)
        let payload = r#"{"sub":"testuser","preferred_username":"testuser","iss":"http://localhost:8080/realms/test","aud":"unix-oidc","exp":1577836800,"iat":1577836700}"#;

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        format!("{header_b64}.{payload_b64}.fake-signature")
    }

    #[allow(dead_code)]
    fn create_valid_test_token() -> String {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        // exp is far in the future (2030)
        let payload = r#"{"sub":"testuser","preferred_username":"testuser","iss":"http://localhost:8080/realms/test","aud":"unix-oidc","exp":1893456000,"iat":1705400000,"acr":"urn:example:acr:mfa","auth_time":1705400000,"jti":"test-token-id"}"#;

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        format!("{header_b64}.{payload_b64}.fake-signature")
    }

    /// Token without a JTI claim — used to test enforcement mode behavior.
    #[allow(dead_code)]
    fn create_token_without_jti() -> String {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        // No "jti" field in payload
        let payload = r#"{"sub":"testuser","preferred_username":"testuser","iss":"http://localhost:8080/realms/test","aud":"unix-oidc","exp":1893456000,"iat":1705400000,"acr":"urn:example:acr:mfa","auth_time":1705400000}"#;

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        format!("{header_b64}.{payload_b64}.fake-signature")
    }

    #[allow(dead_code)]
    fn create_token_without_auth_time() -> String {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        // Valid token but without auth_time claim
        let payload = r#"{"sub":"testuser","preferred_username":"testuser","iss":"http://localhost:8080/realms/test","aud":"unix-oidc","exp":1893456000,"iat":1705400000,"acr":"urn:example:acr:mfa","jti":"test-token-id"}"#;

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        format!("{header_b64}.{payload_b64}.fake-signature")
    }

    #[allow(dead_code)]
    fn create_token_with_old_auth_time() -> String {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        // auth_time is very old (year 2020)
        let payload = r#"{"sub":"testuser","preferred_username":"testuser","iss":"http://localhost:8080/realms/test","aud":"unix-oidc","exp":1893456000,"iat":1705400000,"acr":"urn:example:acr:mfa","auth_time":1577836800,"jti":"test-token-id"}"#;

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        format!("{header_b64}.{payload_b64}.fake-signature")
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn test_validate_missing_auth_time_with_max_auth_age() {
        let config = ValidationConfig {
            max_auth_age: Some(3600), // 1 hour
            jti_enforcement: EnforcementMode::Disabled,
            ..base_config()
        };

        let validator = test_validator(config);
        let token = create_token_without_auth_time();
        let result = validator.validate(&token);

        assert!(matches!(result, Err(ValidationError::MissingAuthTime)));
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn test_validate_auth_time_too_old() {
        let config = ValidationConfig {
            max_auth_age: Some(3600), // 1 hour
            jti_enforcement: EnforcementMode::Disabled,
            ..base_config()
        };

        let validator = test_validator(config);
        let token = create_token_with_old_auth_time();
        let result = validator.validate(&token);

        assert!(matches!(
            result,
            Err(ValidationError::AuthTimeTooOld { .. })
        ));
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn test_validate_valid_token_with_max_auth_age() {
        let config = ValidationConfig {
            max_auth_age: Some(86400 * 365 * 100), // 100 years
            jti_enforcement: EnforcementMode::Disabled,
            ..base_config()
        };

        let validator = test_validator(config);
        let token = create_valid_test_token();
        let result = validator.validate(&token);

        assert!(result.is_ok());
    }
}
