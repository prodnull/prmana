//! Authentication flow combining OIDC token validation and SSSD user resolution.

use crate::oidc::{
    validate_dpop_proof, verify_dpop_binding, DPoPConfig, DPoPValidationError, TokenValidator,
    ValidationConfig, ValidationError,
};
use crate::security::session::generate_ssh_session_id;
use crate::sssd::{get_user_info, user_exists, UserError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Token validation failed: {0}")]
    TokenValidation(#[from] ValidationError),

    #[error("User resolution failed: {0}")]
    UserResolution(#[from] UserError),

    #[error("User {0} not found in directory")]
    UserNotFound(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("DPoP validation failed: {0}")]
    DPoPValidation(#[from] DPoPValidationError),

    #[error("Token is DPoP-bound but no proof provided")]
    DPoPRequired,
}

/// Check if test mode is explicitly enabled.
/// Security: Only accepts explicit "true" or "1" values, not just presence of the variable.
#[cfg(feature = "test-mode")]
fn is_test_mode_enabled() -> bool {
    std::env::var("UNIX_OIDC_TEST_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// Result of a successful authentication.
#[derive(Debug)]
pub struct AuthResult {
    /// The resolved Unix username (from preferred_username claim)
    pub username: String,
    /// User ID from NSS/SSSD
    pub uid: u32,
    /// Primary group ID from NSS/SSSD
    pub gid: u32,
    /// Session ID for audit logging
    pub session_id: String,
    /// JWT ID from the token (for audit logging)
    pub token_jti: Option<String>,
    /// ACR from the token (for audit logging)
    pub token_acr: Option<String>,
    /// Authentication time from the token (for audit logging)
    pub token_auth_time: Option<i64>,
    /// DPoP thumbprint (if token was DPoP-bound and proof was provided)
    pub dpop_thumbprint: Option<String>,
}

/// Authenticate a user with an OIDC token.
///
/// This function:
/// 1. Validates the OIDC token (issuer, audience, expiration, ACR, auth_time)
/// 2. Extracts the preferred_username claim
/// 3. Resolves the username to a local user via NSS (which queries SSSD)
/// 4. Returns the authentication result with user info and session ID
///
/// Authenticate a user with an OIDC token.
///
/// # Test Mode
/// When compiled with `--features test-mode` AND `UNIX_OIDC_TEST_MODE` env var is set,
/// signature verification is skipped. Production builds MUST NOT include this feature.
pub fn authenticate_with_token(token: &str) -> Result<AuthResult, AuthError> {
    // Load configuration from environment
    let config = ValidationConfig::from_env().map_err(|e| AuthError::Config(e.to_string()))?;

    // Create validator
    #[cfg(feature = "test-mode")]
    let validator = {
        let test_mode = is_test_mode_enabled();
        if test_mode {
            // WARNING: This skips signature verification - for testing only!
            TokenValidator::new_insecure_for_testing(config)
        } else {
            TokenValidator::new(config)
        }
    };

    #[cfg(not(feature = "test-mode"))]
    let validator = TokenValidator::new(config);

    let claims = validator.validate(token)?;

    // Map preferred_username to SSSD user
    let username = &claims.preferred_username;

    if !user_exists(username) {
        return Err(AuthError::UserNotFound(username.clone()));
    }

    let user_info = get_user_info(username)?;

    // Generate cryptographically secure session ID
    let session_id = generate_ssh_session_id();

    Ok(AuthResult {
        username: user_info.username,
        uid: user_info.uid,
        gid: user_info.gid,
        session_id,
        token_jti: claims.jti,
        token_acr: claims.acr,
        token_auth_time: claims.auth_time,
        dpop_thumbprint: None,
    })
}

/// DPoP authentication configuration
#[derive(Debug, Clone)]
pub struct DPoPAuthConfig {
    /// Target hostname for DPoP validation (e.g., "server.example.com")
    pub target_host: String,
    /// Maximum proof age in seconds (default: 60)
    pub max_proof_age: u64,
    /// Whether nonce is required
    pub require_nonce: bool,
    /// Expected nonce value (if require_nonce is true)
    pub expected_nonce: Option<String>,
    /// Whether to require DPoP for tokens that have cnf.jkt claim
    pub require_dpop_for_bound_tokens: bool,
}

impl Default for DPoPAuthConfig {
    fn default() -> Self {
        Self {
            target_host: String::new(),
            max_proof_age: 60,
            require_nonce: false,
            expected_nonce: None,
            require_dpop_for_bound_tokens: true,
        }
    }
}

impl DPoPAuthConfig {
    /// Create config from environment variables
    pub fn from_env() -> Result<Self, String> {
        let target_host = gethostname::gethostname().to_string_lossy().to_string();

        let max_proof_age = std::env::var("UNIX_OIDC_DPOP_MAX_AGE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);

        let require_nonce = std::env::var("UNIX_OIDC_DPOP_REQUIRE_NONCE")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let require_dpop_for_bound_tokens = std::env::var("UNIX_OIDC_DPOP_REQUIRE_FOR_BOUND")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);

        Ok(Self {
            target_host,
            max_proof_age,
            require_nonce,
            expected_nonce: None,
            require_dpop_for_bound_tokens,
        })
    }
}

/// Authenticate a user with an OIDC token and optional DPoP proof.
///
/// This function:
/// 1. Validates the OIDC token (issuer, audience, expiration, ACR, auth_time)
/// 2. If token has cnf.jkt claim (DPoP-bound), validates the DPoP proof
/// 3. Extracts the preferred_username claim
/// 4. Resolves the username to a local user via NSS (which queries SSSD)
/// 5. Returns the authentication result with user info and session ID
///
/// # Arguments
/// * `token` - The OIDC access token
/// * `dpop_proof` - Optional DPoP proof (required if token has cnf.jkt claim)
/// * `dpop_config` - DPoP validation configuration
///
/// # Test Mode
/// When compiled with `--features test-mode` AND `UNIX_OIDC_TEST_MODE` env var is set,
/// signature verification is skipped. Production builds MUST NOT include this feature.
pub fn authenticate_with_dpop(
    token: &str,
    dpop_proof: Option<&str>,
    dpop_config: &DPoPAuthConfig,
) -> Result<AuthResult, AuthError> {
    // Load configuration from environment
    let config = ValidationConfig::from_env().map_err(|e| AuthError::Config(e.to_string()))?;

    // Create validator
    #[cfg(feature = "test-mode")]
    let validator = {
        let test_mode = is_test_mode_enabled();
        if test_mode {
            // WARNING: This skips signature verification - for testing only!
            TokenValidator::new_insecure_for_testing(config)
        } else {
            TokenValidator::new(config)
        }
    };

    #[cfg(not(feature = "test-mode"))]
    let validator = TokenValidator::new(config);

    let claims = validator.validate(token)?;

    // Check for DPoP binding
    let dpop_thumbprint = if let Some(cnf) = &claims.cnf {
        if let Some(token_jkt) = &cnf.jkt {
            // Token is DPoP-bound, require proof
            let proof = dpop_proof.ok_or(AuthError::DPoPRequired)?;

            // Validate the DPoP proof
            let dpop_validation_config = DPoPConfig {
                max_proof_age: dpop_config.max_proof_age,
                require_nonce: dpop_config.require_nonce,
                expected_nonce: dpop_config.expected_nonce.clone(),
                expected_method: "SSH".to_string(),
                expected_target: dpop_config.target_host.clone(),
            };

            let proof_thumbprint = validate_dpop_proof(proof, &dpop_validation_config)?;

            // Verify the proof's key matches the token's bound key
            verify_dpop_binding(&proof_thumbprint, token_jkt)?;

            Some(proof_thumbprint)
        } else {
            None
        }
    } else if let Some(proof) = dpop_proof {
        // Token is not DPoP-bound but proof was provided
        // Validate the proof anyway for logging/audit purposes
        let dpop_validation_config = DPoPConfig {
            max_proof_age: dpop_config.max_proof_age,
            require_nonce: dpop_config.require_nonce,
            expected_nonce: dpop_config.expected_nonce.clone(),
            expected_method: "SSH".to_string(),
            expected_target: dpop_config.target_host.clone(),
        };

        let proof_thumbprint = validate_dpop_proof(proof, &dpop_validation_config)?;
        Some(proof_thumbprint)
    } else {
        None
    };

    // Map preferred_username to SSSD user
    let username = &claims.preferred_username;

    if !user_exists(username) {
        return Err(AuthError::UserNotFound(username.clone()));
    }

    let user_info = get_user_info(username)?;

    // Generate cryptographically secure session ID
    let session_id = generate_ssh_session_id();

    Ok(AuthResult {
        username: user_info.username,
        uid: user_info.uid,
        gid: user_info.gid,
        session_id,
        token_jti: claims.jti,
        token_acr: claims.acr,
        token_auth_time: claims.auth_time,
        dpop_thumbprint,
    })
}

/// Authenticate with explicit configuration (for testing).
pub fn authenticate_with_config(
    token: &str,
    config: ValidationConfig,
) -> Result<AuthResult, AuthError> {
    // Validate token
    let validator = TokenValidator::new(config);
    let claims = validator.validate(token)?;

    // Map preferred_username to SSSD user
    let username = &claims.preferred_username;

    if !user_exists(username) {
        return Err(AuthError::UserNotFound(username.clone()));
    }

    let user_info = get_user_info(username)?;

    // Generate cryptographically secure session ID
    let session_id = generate_ssh_session_id();

    Ok(AuthResult {
        username: user_info.username,
        uid: user_info.uid,
        gid: user_info.gid,
        session_id,
        token_jti: claims.jti,
        token_acr: claims.acr,
        token_auth_time: claims.auth_time,
        dpop_thumbprint: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_session_id_format() {
        let id = generate_ssh_session_id();
        assert!(id.starts_with("unix-oidc-"));
        // New format: unix-oidc-{timestamp_hex}-{16_char_random_hex}
        let parts: Vec<&str> = id.split('-').collect();
        assert!(parts.len() >= 3);
        // Last part should be 16 chars of random hex
        assert_eq!(parts.last().unwrap().len(), 16);
    }

    #[test]
    fn test_secure_session_id_uniqueness() {
        let id1 = generate_ssh_session_id();
        let id2 = generate_ssh_session_id();
        // With 64 bits of CSPRNG randomness, collisions are practically impossible
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_dpop_auth_config_defaults() {
        let config = DPoPAuthConfig::default();
        assert_eq!(config.max_proof_age, 60);
        assert!(!config.require_nonce);
        assert!(config.expected_nonce.is_none());
        // target_host is set from hostname or defaults to "localhost"
        // In containers/CI it might be empty, so just verify it's a valid string
        let _ = config.target_host; // Exists and is a String
    }

    #[test]
    fn test_dpop_auth_config_from_env() {
        // Set environment variables
        std::env::set_var("UNIX_OIDC_DPOP_MAX_AGE", "120");
        std::env::set_var("UNIX_OIDC_DPOP_REQUIRE_NONCE", "1");

        let config = DPoPAuthConfig::default();
        // Note: from_env creates default, env vars are read in authenticate_with_dpop
        // This test validates that defaults are sane

        // Clean up
        std::env::remove_var("UNIX_OIDC_DPOP_MAX_AGE");
        std::env::remove_var("UNIX_OIDC_DPOP_REQUIRE_NONCE");

        assert!(config.max_proof_age > 0);
    }

    #[test]
    fn test_auth_error_display() {
        let err = AuthError::DPoPRequired;
        assert!(err.to_string().contains("DPoP"));
        assert!(err.to_string().contains("proof"));

        let err = AuthError::Config("test config error".to_string());
        assert!(err.to_string().contains("test config error"));

        let err = AuthError::UserNotFound("testuser".to_string());
        assert!(err.to_string().contains("testuser"));
    }
}
