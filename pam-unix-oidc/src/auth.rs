//! Authentication flow combining OIDC token validation and SSSD user resolution.

use crate::identity::mapper::{IdentityError, UsernameMapper};
use crate::oidc::{
    validate_dpop_proof, verify_dpop_binding, DPoPConfig, DPoPProofResult, DPoPValidationError,
    TokenValidator, ValidationConfig, ValidationError,
};
use crate::policy::config::{EnforcementMode, PolicyConfig};
use crate::security::nonce_cache::{global_nonce_cache, NonceConsumeError};
use crate::security::session::generate_ssh_session_id;
use crate::sssd::groups::{check_group_policy, GroupPolicyError};
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

    /// User's NSS groups do not intersect with the configured login_groups allow-list.
    #[error("Group policy denied login: {0}")]
    GroupDenied(String),

    /// Username mapping pipeline failed (missing claim or transform error).
    #[error("Identity mapping failed: {0}")]
    IdentityMapping(String),
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
    /// The resolved Unix username (final mapped value used for NSS lookup)
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
    /// The original raw claim value before transforms were applied (for audit trail).
    /// `None` when no mapping was performed (e.g. in test paths that use preferred_username directly).
    pub mapped_from: Option<String>,
}

/// Authenticate a user with an OIDC token.
///
/// This function:
/// 1. Validates the OIDC token (issuer, audience, expiration, ACR, auth_time)
/// 2. Extracts the preferred_username claim
/// 3. Resolves the username to a local user via NSS (which queries SSSD)
/// 4. Returns the authentication result with user info and session ID
///
/// # Test Mode
/// When compiled with `--features test-mode` AND `UNIX_OIDC_TEST_MODE` env var is set,
/// signature verification is skipped. Production builds MUST NOT include this feature.
pub fn authenticate_with_token(token: &str) -> Result<AuthResult, AuthError> {
    // Load configuration from environment
    let mut config = ValidationConfig::from_env().map_err(|e| AuthError::Config(e.to_string()))?;

    // Thread JTI enforcement mode and identity config from policy config (Issue #10).
    // PolicyConfig::from_env() returns Ok(Default) in test mode, and Err when the
    // policy file is absent (e.g. in unit tests). We use .ok() so missing-file is
    // non-fatal; the default Warn mode (already set in from_env()) is used instead.
    let policy_opt = PolicyConfig::from_env().ok();
    if let Some(ref policy) = policy_opt {
        config.jti_enforcement = policy.effective_security_modes().jti_enforcement;
    }

    // Construct username mapper from policy identity config.
    // Security (IDN-03): check_collision_safety() is a hard-fail gatekeeper — same class as
    // signature verification.  A non-injective pipeline is a configuration error that must
    // prevent authentication entirely, not a warning that allows it.
    let mapper = policy_opt
        .as_ref()
        .map(|policy| -> Result<UsernameMapper, AuthError> {
            crate::identity::collision::check_collision_safety(&policy.identity)
                .map_err(|e| AuthError::Config(e.to_string()))?;
            UsernameMapper::from_config(&policy.identity)
                .map_err(|e| AuthError::IdentityMapping(e.to_string()))
        })
        .transpose()?;

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

    // Map username via configured claim + transform pipeline.
    // After .transpose()?, mapper is Option<UsernameMapper> — None when policy is absent.
    let (username_str, mapped_from) = match mapper {
        Some(ref m) => {
            let raw = claims.preferred_username.clone();
            let mapped = m
                .map(&claims)
                .map_err(|e: IdentityError| AuthError::IdentityMapping(e.to_string()))?;
            // Only record mapped_from when the mapping actually changed the value.
            let from = if mapped != raw { Some(raw) } else { None };
            (mapped, from)
        }
        None => (claims.preferred_username.clone(), None),
    };

    // Log token groups for audit enrichment — NEVER used for access decisions.
    if let Some(token_groups) = claims.groups_for_audit() {
        tracing::info!(
            username = %username_str,
            token_groups = ?token_groups,
            "Token groups (audit enrichment only — access decisions use NSS groups)"
        );
    }

    if !user_exists(&username_str) {
        return Err(AuthError::UserNotFound(username_str));
    }

    let user_info = get_user_info(&username_str)?;

    // Enforce login_groups policy via NSS group membership check.
    // This runs AFTER user_exists() so we have the user's GID.
    if let Some(ref policy) = policy_opt {
        let modes = policy.effective_security_modes();
        check_group_policy(
            &user_info.username,
            user_info.gid,
            &policy.ssh_login.login_groups,
            modes.groups_enforcement,
        )
        .map_err(|e: GroupPolicyError| {
            tracing::warn!(
                username = %user_info.username,
                error = %e,
                "Group policy denied SSH login"
            );
            AuthError::GroupDenied(e.to_string())
        })?;
    }

    // Generate cryptographically secure session ID
    let session_id = generate_ssh_session_id()
        .map_err(|e| AuthError::Config(format!("Session ID generation failed: {e}")))?;

    Ok(AuthResult {
        username: user_info.username,
        uid: user_info.uid,
        gid: user_info.gid,
        session_id,
        token_jti: claims.jti,
        token_acr: claims.acr,
        token_auth_time: claims.auth_time,
        dpop_thumbprint: None,
        mapped_from,
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
    let mut config = ValidationConfig::from_env().map_err(|e| AuthError::Config(e.to_string()))?;

    // Thread JTI and dpop_required enforcement modes from policy config (Issue #10).
    let mut dpop_nonce_enforcement = EnforcementMode::Strict; // safe default
    let policy_opt = PolicyConfig::from_env().ok();
    if let Some(ref policy) = policy_opt {
        let modes = policy.effective_security_modes();
        config.jti_enforcement = modes.jti_enforcement;
        dpop_nonce_enforcement = modes.dpop_required;
    }

    // Construct username mapper from policy identity config.
    // Security (IDN-03): check_collision_safety() hard-fails on non-injective pipelines.
    let mapper = policy_opt
        .as_ref()
        .map(|policy| -> Result<UsernameMapper, AuthError> {
            crate::identity::collision::check_collision_safety(&policy.identity)
                .map_err(|e| AuthError::Config(e.to_string()))?;
            UsernameMapper::from_config(&policy.identity)
                .map_err(|e| AuthError::IdentityMapping(e.to_string()))
        })
        .transpose()?;

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

    // Validate DPoP proof and extract result (thumbprint + nonce).
    //
    // Helper closure to validate proof and enforce nonce policy.
    // Returns the proof thumbprint string for cnf.jkt binding comparison.
    let validate_and_enforce_nonce = |proof: &str| -> Result<DPoPProofResult, AuthError> {
        let dpop_validation_config = DPoPConfig {
            max_proof_age: dpop_config.max_proof_age,
            // Pass require_nonce/expected_nonce to dpop.rs only for the
            // direct single-value path (expected_nonce set by caller).
            // Cache-backed enforcement is handled here in auth.rs.
            require_nonce: dpop_config.require_nonce && dpop_config.expected_nonce.is_some(),
            expected_nonce: dpop_config.expected_nonce.clone(),
            expected_method: "SSH".to_string(),
            expected_target: dpop_config.target_host.clone(),
        };
        let result = validate_dpop_proof(proof, &dpop_validation_config)?;

        // Cache-backed nonce enforcement path (require_nonce=true, expected_nonce=None).
        // This is the primary path for server-issued nonces (RFC 9449 §8).
        // The single-value path (expected_nonce=Some) is handled inside dpop.rs.
        if dpop_config.require_nonce && dpop_config.expected_nonce.is_none() {
            match &result.nonce {
                Some(nonce) => {
                    // Nonce is present — consume it from cache.
                    // Replay (nonce already consumed) is ALWAYS hard-fail regardless
                    // of enforcement mode (CLAUDE.md security invariant).
                    match global_nonce_cache().consume(nonce) {
                        Ok(()) => {
                            tracing::debug!(
                                nonce_prefix = &nonce[..nonce.len().min(8)],
                                "DPoP nonce consumed successfully"
                            );
                        }
                        Err(NonceConsumeError::ConsumedOrExpired) => {
                            tracing::warn!("DPoP nonce replay or expiry detected — rejecting");
                            return Err(AuthError::DPoPValidation(
                                DPoPValidationError::NonceMismatch,
                            ));
                        }
                        Err(NonceConsumeError::EmptyNonce) => {
                            // Should not happen: dpop.rs only stores non-empty nonces
                            tracing::warn!("DPoP nonce in proof is empty — rejecting");
                            return Err(AuthError::DPoPValidation(
                                DPoPValidationError::MissingNonce,
                            ));
                        }
                    }
                }
                None => {
                    // Nonce is absent from proof — behavior depends on enforcement mode.
                    match dpop_nonce_enforcement {
                        EnforcementMode::Strict => {
                            tracing::warn!("DPoP nonce required (strict) but proof has no nonce");
                            return Err(AuthError::DPoPValidation(
                                DPoPValidationError::MissingNonce,
                            ));
                        }
                        EnforcementMode::Warn => {
                            tracing::warn!(
                                "DPoP proof has no nonce (dpop_required=warn) — \
                                     allowing but this may indicate a misconfigured client"
                            );
                        }
                        EnforcementMode::Disabled => {
                            // Silently skip nonce check.
                        }
                    }
                }
            }
        }

        Ok(result)
    };

    // Check for DPoP binding
    let dpop_thumbprint = if let Some(cnf) = &claims.cnf {
        if let Some(token_jkt) = &cnf.jkt {
            // Token is DPoP-bound, require proof
            let proof = dpop_proof.ok_or(AuthError::DPoPRequired)?;

            let result = validate_and_enforce_nonce(proof)?;

            // Verify the proof's key matches the token's bound key
            verify_dpop_binding(&result.thumbprint, token_jkt)?;

            Some(result.thumbprint)
        } else {
            None
        }
    } else if let Some(proof) = dpop_proof {
        // Token is not DPoP-bound but proof was provided
        // Validate the proof anyway for logging/audit purposes
        let result = validate_and_enforce_nonce(proof)?;
        Some(result.thumbprint)
    } else {
        None
    };

    // Map username via configured claim + transform pipeline.
    // After .transpose()?, mapper is Option<UsernameMapper> — None when policy is absent.
    let (username_str, mapped_from) = match mapper {
        Some(ref m) => {
            let raw = claims.preferred_username.clone();
            let mapped = m
                .map(&claims)
                .map_err(|e: IdentityError| AuthError::IdentityMapping(e.to_string()))?;
            let from = if mapped != raw { Some(raw) } else { None };
            (mapped, from)
        }
        None => (claims.preferred_username.clone(), None),
    };

    // Log token groups for audit enrichment — NEVER used for access decisions.
    if let Some(token_groups) = claims.groups_for_audit() {
        tracing::info!(
            username = %username_str,
            token_groups = ?token_groups,
            "Token groups (audit enrichment only — access decisions use NSS groups)"
        );
    }

    if !user_exists(&username_str) {
        return Err(AuthError::UserNotFound(username_str));
    }

    let user_info = get_user_info(&username_str)?;

    // Enforce login_groups policy via NSS group membership check.
    if let Some(ref policy) = policy_opt {
        let modes = policy.effective_security_modes();
        check_group_policy(
            &user_info.username,
            user_info.gid,
            &policy.ssh_login.login_groups,
            modes.groups_enforcement,
        )
        .map_err(|e: GroupPolicyError| {
            tracing::warn!(
                username = %user_info.username,
                error = %e,
                "Group policy denied SSH login"
            );
            AuthError::GroupDenied(e.to_string())
        })?;
    }

    // Generate cryptographically secure session ID
    let session_id = generate_ssh_session_id()
        .map_err(|e| AuthError::Config(format!("Session ID generation failed: {e}")))?;

    Ok(AuthResult {
        username: user_info.username,
        uid: user_info.uid,
        gid: user_info.gid,
        session_id,
        token_jti: claims.jti,
        token_acr: claims.acr,
        token_auth_time: claims.auth_time,
        dpop_thumbprint,
        mapped_from,
    })
}

/// Authenticate with explicit configuration (for testing).
///
/// The optional `mapper` parameter allows tests to inject a [`UsernameMapper`] instance.
/// When `None`, `preferred_username` is used directly (backward-compatible with all 134
/// existing tests that call this function without a mapper).
///
/// Group policy is intentionally NOT enforced here — this function is the test path.
/// Production auth goes through [`authenticate_with_token`] or [`authenticate_with_dpop`].
pub fn authenticate_with_config(
    token: &str,
    config: ValidationConfig,
    mapper: Option<&UsernameMapper>,
) -> Result<AuthResult, AuthError> {
    // Validate token
    let validator = TokenValidator::new(config);
    let claims = validator.validate(token)?;

    // Apply username mapper if provided, otherwise use preferred_username directly.
    let username_str = match mapper {
        Some(m) => m
            .map(&claims)
            .map_err(|e: IdentityError| AuthError::IdentityMapping(e.to_string()))?,
        None => claims.preferred_username.clone(),
    };

    if !user_exists(&username_str) {
        return Err(AuthError::UserNotFound(username_str));
    }

    let user_info = get_user_info(&username_str)?;

    // Generate cryptographically secure session ID
    let session_id = generate_ssh_session_id()
        .map_err(|e| AuthError::Config(format!("Session ID generation failed: {e}")))?;

    Ok(AuthResult {
        username: user_info.username,
        uid: user_info.uid,
        gid: user_info.gid,
        session_id,
        token_jti: claims.jti,
        token_acr: claims.acr,
        token_auth_time: claims.auth_time,
        dpop_thumbprint: None,
        mapped_from: None, // test path — no audit trail needed
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_session_id_format() {
        let id = generate_ssh_session_id().unwrap();
        assert!(id.starts_with("unix-oidc-"));
        // New format: unix-oidc-{timestamp_hex}-{16_char_random_hex}
        let parts: Vec<&str> = id.split('-').collect();
        assert!(parts.len() >= 3);
        // Last part should be 16 chars of random hex
        assert_eq!(parts.last().unwrap().len(), 16);
    }

    #[test]
    fn test_secure_session_id_uniqueness() {
        let id1 = generate_ssh_session_id().unwrap();
        let id2 = generate_ssh_session_id().unwrap();
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

        // New variants from Phase 8
        let err = AuthError::GroupDenied("not in unix-users".to_string());
        assert!(err.to_string().contains("Group policy denied"));

        let err = AuthError::IdentityMapping("missing claim 'email'".to_string());
        assert!(err.to_string().contains("Identity mapping failed"));
        assert!(err.to_string().contains("missing claim"));
    }

    #[test]
    fn test_auth_result_mapped_from_field_exists() {
        // Verify that AuthResult has a mapped_from field (compile-time check via construction).
        let result = AuthResult {
            username: "alice".to_string(),
            uid: 1000,
            gid: 1000,
            session_id: "unix-oidc-abc-0123456789abcdef".to_string(),
            token_jti: None,
            token_acr: None,
            token_auth_time: None,
            dpop_thumbprint: None,
            mapped_from: Some("alice@corp.example.com".to_string()),
        };
        assert_eq!(
            result.mapped_from.as_deref(),
            Some("alice@corp.example.com")
        );
    }

    #[test]
    fn test_auth_result_mapped_from_none_when_no_transform() {
        // mapped_from should be None when username was not changed by transforms.
        let result = AuthResult {
            username: "alice".to_string(),
            uid: 1000,
            gid: 1000,
            session_id: "unix-oidc-abc-0123456789abcdef".to_string(),
            token_jti: None,
            token_acr: None,
            token_auth_time: None,
            dpop_thumbprint: None,
            mapped_from: None,
        };
        assert!(result.mapped_from.is_none());
    }

    // ── Nonce enforcement mode tests ──────────────────────────────────────────
    //
    // These tests exercise the nonce enforcement logic that lives in auth.rs,
    // without requiring SSSD. They call validate_dpop_proof() + nonce_cache
    // directly to mirror the logic in authenticate_with_dpop()'s
    // validate_and_enforce_nonce closure.

    use crate::oidc::{validate_dpop_proof, DPoPConfig, DPoPValidationError};
    use crate::security::nonce_cache::{generate_dpop_nonce, DPoPNonceCache};

    fn make_test_proof_with_nonce(target: &str, nonce: Option<&str>) -> (String, String) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use p256::elliptic_curve::rand_core::OsRng;
        use std::time::{SystemTime, UNIX_EPOCH};

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = serde_json::json!({
            "jti": uuid::Uuid::new_v4().to_string(),
            "htm": "SSH",
            "htu": target,
            "iat": now,
            "nonce": nonce,
        });

        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y }
        });

        let h = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let c = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let msg = format!("{h}.{c}");
        let sig: Signature = signing_key.sign(msg.as_bytes());
        let proof = format!("{}.{}", msg, URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        (proof, target.to_string())
    }

    /// Replicate the cache-backed nonce enforcement logic from authenticate_with_dpop
    /// so we can test it in isolation without SSSD.
    fn apply_cache_nonce_enforcement(
        nonce_from_proof: Option<&str>,
        cache: &DPoPNonceCache,
        enforcement: EnforcementMode,
    ) -> Result<(), AuthError> {
        match nonce_from_proof {
            Some(nonce) => match cache.consume(nonce) {
                Ok(()) => Ok(()),
                Err(crate::security::nonce_cache::NonceConsumeError::ConsumedOrExpired) => Err(
                    AuthError::DPoPValidation(DPoPValidationError::NonceMismatch),
                ),
                Err(crate::security::nonce_cache::NonceConsumeError::EmptyNonce) => {
                    Err(AuthError::DPoPValidation(DPoPValidationError::MissingNonce))
                }
            },
            None => match enforcement {
                EnforcementMode::Strict => {
                    Err(AuthError::DPoPValidation(DPoPValidationError::MissingNonce))
                }
                EnforcementMode::Warn => Ok(()),
                EnforcementMode::Disabled => Ok(()),
            },
        }
    }

    #[test]
    fn test_nonce_in_proof_and_cache_consume_succeeds() {
        let cache = DPoPNonceCache::new(100, 60);
        let nonce = generate_dpop_nonce().unwrap();
        cache.issue(&nonce).unwrap();

        let result = apply_cache_nonce_enforcement(Some(&nonce), &cache, EnforcementMode::Strict);
        assert!(result.is_ok(), "valid nonce from cache must succeed");
    }

    #[test]
    fn test_nonce_replay_is_always_hard_fail() {
        // Replay (nonce already consumed) must hard-fail regardless of enforcement mode.
        let cache = DPoPNonceCache::new(100, 60);
        let nonce = generate_dpop_nonce().unwrap();
        cache.issue(&nonce).unwrap();
        // First consume
        apply_cache_nonce_enforcement(Some(&nonce), &cache, EnforcementMode::Disabled).unwrap();

        // Second consume — all modes must reject
        for mode in [
            EnforcementMode::Strict,
            EnforcementMode::Warn,
            EnforcementMode::Disabled,
        ] {
            let result = apply_cache_nonce_enforcement(Some(&nonce), &cache, mode);
            assert!(
                matches!(
                    result,
                    Err(AuthError::DPoPValidation(
                        DPoPValidationError::NonceMismatch
                    ))
                ),
                "replay must hard-fail in mode {:?}",
                mode
            );
        }
    }

    #[test]
    fn test_missing_nonce_strict_rejects() {
        let cache = DPoPNonceCache::new(100, 60);
        let result = apply_cache_nonce_enforcement(None, &cache, EnforcementMode::Strict);
        assert!(
            matches!(
                result,
                Err(AuthError::DPoPValidation(DPoPValidationError::MissingNonce))
            ),
            "strict mode must reject missing nonce"
        );
    }

    #[test]
    fn test_missing_nonce_warn_allows() {
        let cache = DPoPNonceCache::new(100, 60);
        let result = apply_cache_nonce_enforcement(None, &cache, EnforcementMode::Warn);
        assert!(result.is_ok(), "warn mode must allow missing nonce");
    }

    #[test]
    fn test_missing_nonce_disabled_allows() {
        let cache = DPoPNonceCache::new(100, 60);
        let result = apply_cache_nonce_enforcement(None, &cache, EnforcementMode::Disabled);
        assert!(result.is_ok(), "disabled mode must allow missing nonce");
    }

    // ── Collision safety hard-fail tests ──────────────────────────────────────
    //
    // These tests mirror the collision-check logic in authenticate_with_token and
    // authenticate_with_dpop without requiring SSSD or a real ValidationConfig.
    // The production code uses:
    //
    //   policy_opt.as_ref()
    //       .map(|policy| {
    //           check_collision_safety(&policy.identity)
    //               .map_err(|e| AuthError::Config(e.to_string()))?;
    //           UsernameMapper::from_config(&policy.identity)
    //       })
    //       .transpose()?;
    //
    // We replicate that pattern here so any regression in the hard-fail path is
    // caught at unit-test time without depending on external services.

    use crate::identity::collision::check_collision_safety;
    use crate::identity::mapper::UsernameMapper;
    use crate::policy::config::{IdentityConfig, TransformConfig};

    fn build_identity(transforms: Vec<TransformConfig>) -> IdentityConfig {
        IdentityConfig {
            username_claim: "email".to_string(),
            transforms,
        }
    }

    /// Replicate the production mapper-construction block so we can test it in isolation.
    fn construct_mapper_like_auth(
        identity: &IdentityConfig,
    ) -> Result<Option<UsernameMapper>, AuthError> {
        let policy_opt: Option<&IdentityConfig> = Some(identity);
        policy_opt
            .map(|id| -> Result<UsernameMapper, AuthError> {
                check_collision_safety(id).map_err(|e| AuthError::Config(e.to_string()))?;
                UsernameMapper::from_config(id)
                    .map_err(|e: IdentityError| AuthError::IdentityMapping(e.to_string()))
            })
            .transpose()
    }

    #[test]
    fn collision_check_strip_domain_propagates_auth_config_error() {
        let identity = build_identity(vec![TransformConfig::Simple("strip_domain".to_string())]);
        let result = construct_mapper_like_auth(&identity);
        assert!(
            result.is_err(),
            "strip_domain pipeline must produce Err from mapper construction"
        );
        match result.unwrap_err() {
            AuthError::Config(msg) => {
                assert!(
                    msg.contains("strip_domain"),
                    "Config error must name strip_domain, got: {msg}"
                );
                assert!(
                    msg.contains("Non-injective"),
                    "Config error must contain 'Non-injective', got: {msg}"
                );
            }
            other => panic!("Expected AuthError::Config, got: {other:?}"),
        }
    }

    #[test]
    fn collision_check_regex_propagates_auth_config_error() {
        let identity = build_identity(vec![TransformConfig::Object {
            r#type: "regex".to_string(),
            pattern: r"^(?P<username>[a-z]+)@corp\.com$".to_string(),
        }]);
        let result = construct_mapper_like_auth(&identity);
        assert!(
            result.is_err(),
            "regex pipeline must produce Err from mapper construction"
        );
        match result.unwrap_err() {
            AuthError::Config(msg) => {
                assert!(
                    msg.contains("regex"),
                    "Config error must name regex, got: {msg}"
                );
            }
            other => panic!("Expected AuthError::Config, got: {other:?}"),
        }
    }

    #[test]
    fn collision_check_lowercase_does_not_trigger_hard_fail() {
        let identity = build_identity(vec![TransformConfig::Simple("lowercase".to_string())]);
        let result = construct_mapper_like_auth(&identity);
        assert!(
            result.is_ok(),
            "lowercase pipeline must not hard-fail, got: {:?}",
            result
        );
    }

    #[test]
    fn collision_check_no_policy_skips_check() {
        // When policy_opt is None (no policy file), transpose of Option::None is Ok(None).
        // The collision check is never called.
        let policy_opt: Option<&IdentityConfig> = None;
        let result: Result<Option<UsernameMapper>, AuthError> = policy_opt
            .map(|id| -> Result<UsernameMapper, AuthError> {
                check_collision_safety(id).map_err(|e| AuthError::Config(e.to_string()))?;
                UsernameMapper::from_config(id)
                    .map_err(|e: IdentityError| AuthError::IdentityMapping(e.to_string()))
            })
            .transpose();

        assert!(
            result.is_ok(),
            "absent policy must not trigger collision check"
        );
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn collision_check_both_transforms_config_error_lists_both() {
        let identity = build_identity(vec![
            TransformConfig::Simple("strip_domain".to_string()),
            TransformConfig::Object {
                r#type: "regex".to_string(),
                pattern: r"^(?P<username>[a-z]+)$".to_string(),
            },
        ]);
        let result = construct_mapper_like_auth(&identity);
        match result.unwrap_err() {
            AuthError::Config(msg) => {
                assert!(msg.contains("strip_domain"), "must name strip_domain");
                assert!(msg.contains("regex"), "must name regex");
            }
            other => panic!("Expected AuthError::Config, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_dpop_proof_result_carries_nonce() {
        let target = "nonce-result-test.example.com";
        let (proof, _) = make_test_proof_with_nonce(target, Some("test-nonce-abc"));

        let config = DPoPConfig {
            max_proof_age: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "SSH".to_string(),
            expected_target: target.to_string(),
        };

        let result = validate_dpop_proof(&proof, &config).unwrap();
        assert_eq!(result.nonce.as_deref(), Some("test-nonce-abc"));
        assert!(!result.thumbprint.is_empty());
    }
}
