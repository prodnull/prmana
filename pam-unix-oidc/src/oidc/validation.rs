//! JWT token validation with JWKS signature verification.

use crate::oidc::jwks::{JwksError, JwksProvider};
use crate::oidc::token::TokenClaims;
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
    /// Whether to enforce JTI uniqueness (replay protection).
    /// When true, tokens with previously-seen JTI values are rejected.
    /// Default: true (enabled for security)
    pub enforce_jti: bool,
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

        // JTI enforcement is enabled by default; set UNIX_OIDC_DISABLE_JTI_CHECK=true to disable
        let enforce_jti = std::env::var("UNIX_OIDC_DISABLE_JTI_CHECK")
            .map(|v| v.to_lowercase() != "true")
            .unwrap_or(true);

        Ok(Self {
            issuer,
            client_id,
            required_acr,
            max_auth_age,
            enforce_jti,
        })
    }
}

/// Clock skew tolerance in seconds for time-based validations
const CLOCK_SKEW_TOLERANCE: i64 = 60;

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

        // Validate expiration with clock skew tolerance
        let now = chrono::Utc::now().timestamp();
        if claims.exp + CLOCK_SKEW_TOLERANCE < now {
            return Err(ValidationError::Expired);
        }

        // Check JTI for replay protection
        if self.config.enforce_jti {
            // Calculate TTL for JTI cache based on token expiration
            let ttl_seconds = (claims.exp - now + CLOCK_SKEW_TOLERANCE).max(0) as u64;

            let jti_result = global_jti_cache().check_and_record(
                claims.jti.as_deref(),
                &claims.preferred_username,
                ttl_seconds,
            );

            match jti_result {
                JtiCheckResult::Valid => {
                    // First use of this JTI - allow
                }
                JtiCheckResult::Replay => {
                    // This token was already used - reject
                    return Err(ValidationError::TokenReplay {
                        jti: claims.jti.clone().unwrap_or_else(|| "unknown".to_string()),
                    });
                }
                JtiCheckResult::Missing => {
                    // Token has no JTI - log warning but allow for now
                    // TODO(#10): Implement configurable JTI enforcement modes
                    // (strict/warn/disabled) for enterprise flexibility
                    tracing::warn!(
                        username = %claims.preferred_username,
                        "Token missing JTI claim - replay protection not available"
                    );
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
                    if age > max_age + CLOCK_SKEW_TOLERANCE {
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

        // Convert JWK to DecodingKey
        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|e| ValidationError::InvalidSignature(format!("Invalid JWK: {}", e)))?;

        // Set up validation
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_issuer(&[&self.config.issuer]);
        // We'll do our own time validation with clock skew
        validation.validate_exp = false;
        validation.validate_nbf = false;

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
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // Helper to create a test validator that skips signature verification.
    // Only available when compiled with --features test-mode.
    // Run tests with: cargo test --features test-mode
    #[cfg(feature = "test-mode")]
    fn test_validator(config: ValidationConfig) -> TokenValidator {
        TokenValidator::new_insecure_for_testing(config)
    }

    #[test]
    fn test_validation_config_from_env() {
        std::env::set_var("OIDC_ISSUER", "http://localhost:8080/realms/test");
        std::env::set_var("OIDC_CLIENT_ID", "unix-oidc");

        let config = ValidationConfig::from_env().unwrap();

        assert_eq!(config.issuer, "http://localhost:8080/realms/test");
        assert_eq!(config.client_id, "unix-oidc");

        // Cleanup
        std::env::remove_var("OIDC_ISSUER");
        std::env::remove_var("OIDC_CLIENT_ID");
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn test_validate_expired_token() {
        let config = ValidationConfig {
            issuer: "http://localhost:8080/realms/test".into(),
            client_id: "unix-oidc".into(),
            required_acr: None,
            max_auth_age: None,
            enforce_jti: false, // Disable for test
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
            client_id: "unix-oidc".into(),
            required_acr: None,
            max_auth_age: None,
            enforce_jti: false,
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
            issuer: "http://localhost:8080/realms/test".into(),
            client_id: "wrong-client".into(),
            required_acr: None,
            max_auth_age: None,
            enforce_jti: false,
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
            issuer: "http://localhost:8080/realms/test".into(),
            client_id: "unix-oidc".into(),
            required_acr: Some("urn:example:acr:high".into()),
            max_auth_age: None,
            enforce_jti: false,
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
            issuer: "http://localhost:8080/realms/test".into(),
            client_id: "unix-oidc".into(),
            required_acr: Some("urn:example:acr:mfa".into()),
            max_auth_age: None,
            enforce_jti: false,
        };

        let validator = test_validator(config);
        let token = create_valid_test_token();
        let result = validator.validate(&token);

        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.preferred_username, "testuser");
    }

    #[allow(dead_code)]
    fn create_expired_test_token() -> String {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        // exp is in the past (2020)
        let payload = r#"{"sub":"testuser","preferred_username":"testuser","iss":"http://localhost:8080/realms/test","aud":"unix-oidc","exp":1577836800,"iat":1577836700}"#;

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        format!("{}.{}.fake-signature", header_b64, payload_b64)
    }

    #[allow(dead_code)]
    fn create_valid_test_token() -> String {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        // exp is far in the future (2030)
        let payload = r#"{"sub":"testuser","preferred_username":"testuser","iss":"http://localhost:8080/realms/test","aud":"unix-oidc","exp":1893456000,"iat":1705400000,"acr":"urn:example:acr:mfa","auth_time":1705400000,"jti":"test-token-id"}"#;

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        format!("{}.{}.fake-signature", header_b64, payload_b64)
    }

    #[allow(dead_code)]
    fn create_token_without_auth_time() -> String {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        // Valid token but without auth_time claim
        let payload = r#"{"sub":"testuser","preferred_username":"testuser","iss":"http://localhost:8080/realms/test","aud":"unix-oidc","exp":1893456000,"iat":1705400000,"acr":"urn:example:acr:mfa","jti":"test-token-id"}"#;

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        format!("{}.{}.fake-signature", header_b64, payload_b64)
    }

    #[allow(dead_code)]
    fn create_token_with_old_auth_time() -> String {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        // auth_time is very old (year 2020)
        let payload = r#"{"sub":"testuser","preferred_username":"testuser","iss":"http://localhost:8080/realms/test","aud":"unix-oidc","exp":1893456000,"iat":1705400000,"acr":"urn:example:acr:mfa","auth_time":1577836800,"jti":"test-token-id"}"#;

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        format!("{}.{}.fake-signature", header_b64, payload_b64)
    }

    #[test]
    #[cfg(feature = "test-mode")]
    fn test_validate_missing_auth_time_with_max_auth_age() {
        let config = ValidationConfig {
            issuer: "http://localhost:8080/realms/test".into(),
            client_id: "unix-oidc".into(),
            required_acr: None,
            max_auth_age: Some(3600), // 1 hour
            enforce_jti: false,
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
            issuer: "http://localhost:8080/realms/test".into(),
            client_id: "unix-oidc".into(),
            required_acr: None,
            max_auth_age: Some(3600), // 1 hour
            enforce_jti: false,
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
            issuer: "http://localhost:8080/realms/test".into(),
            client_id: "unix-oidc".into(),
            required_acr: None,
            max_auth_age: Some(86400 * 365 * 100), // 100 years - token's auth_time will always be within this
            enforce_jti: false,
        };

        let validator = test_validator(config);
        let token = create_valid_test_token();
        let result = validator.validate(&token);

        assert!(result.is_ok());
    }
}
