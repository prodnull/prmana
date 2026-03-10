//! PAM module for OIDC authentication with SSSD user mapping.
//!
//! This PAM module authenticates users using OIDC tokens. The workflow is:
//! 1. User provides an OIDC token (via PAM conversation or environment variable in test mode)
//! 2. Token is validated against the configured OIDC issuer
//! 3. The `preferred_username` claim is extracted and verified to match the PAM_USER
//! 4. The username is verified to exist in SSSD
//! 5. If validation passes and user exists, authentication succeeds
//!
//! ## Environment Variables
//! - `OIDC_ISSUER` (required): The OIDC issuer URL
//! - `OIDC_CLIENT_ID` (optional): Expected audience, defaults to "unix-oidc"
//! - `OIDC_REQUIRED_ACR` (optional): Required ACR level for authentication
//! - `OIDC_MAX_AUTH_AGE` (optional): Maximum age in seconds for auth_time
//! - `UNIX_OIDC_TEST_MODE` (optional): Enable test mode (allows token from OIDC_TOKEN env var)
//! - `OIDC_TOKEN` (test mode only): The OIDC token to use for authentication

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod approval;
pub mod audit;
pub mod auth;
pub mod device_flow;
pub mod oidc;
pub mod policy;
pub mod security;
pub mod sssd;
pub mod sudo;
pub mod ui;

use audit::AuditEvent;
use auth::{authenticate_with_dpop, authenticate_with_token, AuthError, DPoPAuthConfig};
use policy::config::{EnforcementMode, PolicyConfig};
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamMsgStyle, PamServiceModule};
use security::nonce_cache::{generate_dpop_nonce, global_nonce_cache};
use security::rate_limit::global_rate_limiter;

struct PamUnixOidc;
pamsm::pam_module!(PamUnixOidc);

/// Check if test mode is explicitly enabled.
/// Security: Only accepts explicit "true" or "1" values, not just presence of the variable.
fn is_test_mode_enabled() -> bool {
    std::env::var("UNIX_OIDC_TEST_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

impl PamServiceModule for PamUnixOidc {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        // Check if we're in test mode (token from environment)
        // Security: Requires explicit "true" or "1", not just any value
        let test_mode = is_test_mode_enabled();

        // Get the PAM user (already set by the calling application)
        let pam_user = match pamh.get_cached_user() {
            Ok(Some(user)) => user.to_string_lossy().to_string(),
            Ok(None) | Err(_) => {
                // No user set yet, try to get it with prompting
                match pamh.get_user(None) {
                    Ok(Some(user)) => user.to_string_lossy().to_string(),
                    _ => return PamError::USER_UNKNOWN,
                }
            }
        };

        // Get source IP from PAM environment (PAM_RHOST) for rate limiting and audit
        let rhost_string: Option<String> = pamh
            .get_rhost()
            .ok()
            .flatten()
            .map(|s| s.to_string_lossy().to_string());
        let source_ip: Option<&str> = rhost_string.as_deref();

        // Check rate limiting before attempting authentication
        if let Err(e) = global_rate_limiter().check_allowed(&pam_user, source_ip) {
            AuditEvent::ssh_login_failed(
                Some(&pam_user),
                source_ip,
                &format!("Rate limited: {}", e),
            )
            .log();
            return PamError::AUTH_ERR;
        }

        // Determine DPoP enforcement mode from policy.
        // PolicyConfig::from_env() is non-fatal: missing policy file or test mode both
        // fall through to the default (Strict for dpop_required).
        let dpop_mode = PolicyConfig::from_env()
            .map(|p| p.effective_security_modes().dpop_required)
            .unwrap_or(EnforcementMode::Strict);

        // DPoP nonce challenge/response: two-round PAM conversation.
        //
        // Round 1 — Nonce delivery (PROMPT_ECHO_ON):
        //   Server generates a nonce, issues it to the cache, and delivers it to the
        //   client as "DPOP_NONCE:<value>". The SSH agent reads the prefix, extracts
        //   the nonce, and binds it into the next DPoP proof. The client responds with
        //   an empty string or acknowledgement — we ignore the response.
        //
        // Round 2 — Proof collection (PROMPT_ECHO_OFF):
        //   Server prompts for the DPoP proof. The agent sends the nonce-bound proof.
        //
        // This pattern implements RFC 9449 §8 server-issued nonce binding within the
        // PAM keyboard-interactive conversation framework.
        let dpop_proof: Option<String> = if dpop_mode != EnforcementMode::Disabled {
            match issue_and_deliver_nonce(&pamh) {
                Ok(nonce) => {
                    // Round 2: collect the DPoP proof.
                    // PROMPT_ECHO_OFF because the proof is a signed JWT — treat as secret.
                    match pamh.conv(Some("DPOP_PROOF: "), PamMsgStyle::PROMPT_ECHO_OFF) {
                        Ok(Some(p)) => {
                            let proof_str = p.to_string_lossy().to_string();
                            if proof_str.is_empty() {
                                // Client did not provide a proof; nonce was issued but won't
                                // be consumed. The cache TTL will evict it automatically.
                                tracing::warn!(
                                    nonce_prefix = &nonce[..nonce.len().min(8)],
                                    "DPoP proof conversation returned empty response"
                                );
                                None
                            } else {
                                Some(proof_str)
                            }
                        }
                        Ok(None) | Err(_) => {
                            tracing::warn!(
                                nonce_prefix = &nonce[..nonce.len().min(8)],
                                "DPoP proof collection via PAM conversation failed"
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    // Nonce delivery failed (CSPRNG or conversation error).
                    // Fall back to token-only path; strictness handled below.
                    tracing::warn!("DPoP nonce issuance failed: {}", e);
                    None
                }
            }
        } else {
            // DPoP mode is Disabled — skip nonce issuance entirely.
            None
        };

        // Get the authentication token
        let token = match get_auth_token(&pamh, test_mode) {
            Some(t) => t,
            None => {
                // Record as a failure for rate limiting purposes
                global_rate_limiter().record_failure(&pam_user, source_ip);
                return PamError::AUTH_ERR;
            }
        };

        // Choose authentication path based on DPoP mode and proof availability.
        //
        // - DPoP proof available: always use authenticate_with_dpop() regardless of mode.
        //   (If the client sent a proof, validate it — this catches misconfigured clients
        //   sending invalid proofs even in Warn/Disabled mode.)
        //
        // - DPoP proof unavailable + Strict: return AUTH_ERR (client must send proof).
        //
        // - DPoP proof unavailable + Warn/Disabled: fall back to token-only auth.
        //   authenticate_with_dpop() with dpop_proof=None also handles DPoP-bound tokens
        //   (cnf.jkt present) correctly via its internal DPoPRequired check.
        let auth_result = if dpop_proof.is_some() || dpop_mode == EnforcementMode::Strict {
            // DPoP path (strict or proof provided).
            let dpop_config = DPoPAuthConfig {
                target_host: gethostname::gethostname().to_string_lossy().to_string(),
                max_proof_age: 60,
                require_nonce: true,    // cache-backed nonce enforcement
                expected_nonce: None,   // None = cache path (auth.rs consumes from cache)
                require_dpop_for_bound_tokens: true,
            };
            authenticate_with_dpop(&token, dpop_proof.as_deref(), &dpop_config)
        } else {
            // Warn or Disabled with no proof — token-only fallback.
            authenticate_with_token(&token)
        };

        // Handle authentication result
        match auth_result {
            Ok(result) => {
                // Verify that the token's preferred_username matches the PAM user
                if result.username != pam_user {
                    global_rate_limiter().record_failure(&pam_user, source_ip);
                    AuditEvent::ssh_login_failed(
                        Some(&pam_user),
                        source_ip,
                        &format!(
                            "Username mismatch: PAM user '{}' != token user '{}'",
                            pam_user, result.username
                        ),
                    )
                    .log();
                    return PamError::AUTH_ERR;
                }

                // Record successful authentication for rate limiting
                global_rate_limiter().record_success(&pam_user, source_ip);

                // Log successful authentication
                AuditEvent::ssh_login_success(
                    &result.session_id,
                    &result.username,
                    Some(result.uid),
                    source_ip,
                    result.token_jti.as_deref(),
                    result.token_acr.as_deref(),
                    result.token_auth_time,
                )
                .log();

                PamError::SUCCESS
            }
            Err(e) => {
                // Record failure for rate limiting
                global_rate_limiter().record_failure(&pam_user, source_ip);

                // Log the failure
                let reason = e.to_string();
                match &e {
                    AuthError::UserNotFound(username) => {
                        AuditEvent::user_not_found(username).log();
                        PamError::USER_UNKNOWN
                    }
                    AuthError::TokenValidation(_) => {
                        AuditEvent::token_validation_failed(Some(&pam_user), &reason, source_ip)
                            .log();
                        PamError::AUTH_ERR
                    }
                    AuthError::UserResolution(_) => {
                        AuditEvent::ssh_login_failed(Some(&pam_user), source_ip, &reason).log();
                        PamError::USER_UNKNOWN
                    }
                    AuthError::Config(_) => {
                        AuditEvent::ssh_login_failed(Some(&pam_user), source_ip, &reason).log();
                        PamError::SERVICE_ERR
                    }
                    AuthError::DPoPValidation(_) => {
                        AuditEvent::token_validation_failed(
                            Some(&pam_user),
                            &format!("DPoP validation failed: {}", reason),
                            source_ip,
                        )
                        .log();
                        PamError::AUTH_ERR
                    }
                    AuthError::DPoPRequired => {
                        AuditEvent::token_validation_failed(
                            Some(&pam_user),
                            "DPoP proof required but not provided",
                            source_ip,
                        )
                        .log();
                        PamError::AUTH_ERR
                    }
                }
            }
        }
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn acct_mgmt(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn open_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn close_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn chauthtok(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }
}

/// Generate a DPoP nonce, issue it to the global cache, and deliver it to the
/// client via PAM keyboard-interactive conversation (PROMPT_ECHO_ON, round 1).
///
/// Returns the issued nonce string on success so the caller can reference it
/// for logging (the nonce itself is already in the cache; auth.rs will consume it).
///
/// # Errors
///
/// Returns a descriptive `String` on CSPRNG failure or PAM conversation error.
/// The caller is responsible for deciding whether to treat this as fatal based on
/// the current `dpop_required` enforcement mode.
fn issue_and_deliver_nonce(pamh: &Pam) -> Result<String, String> {
    // Generate 256-bit CSPRNG nonce (43-char base64url per RFC 9449 §8).
    let nonce = generate_dpop_nonce().map_err(|e| format!("CSPRNG unavailable: {e}"))?;

    // Register nonce in the global cache so auth.rs can consume it on the return trip.
    global_nonce_cache()
        .issue(&nonce)
        .map_err(|e| format!("Nonce issue failed: {e}"))?;

    // Round 1: deliver nonce via PAM PROMPT_ECHO_ON.
    //
    // The SSH agent on the client side reads the prompt, recognises the "DPOP_NONCE:"
    // prefix, extracts the nonce value, and binds it into the next DPoP proof.
    // The client response (an empty ack or the nonce itself) is ignored by the server.
    // PROMPT_ECHO_ON is used because this is not a secret — the nonce is a public
    // challenge value (RFC 9449 §8 explicitly allows nonces to be sent in the clear).
    let nonce_prompt = format!("DPOP_NONCE:{nonce}");
    match pamh.conv(Some(&nonce_prompt), PamMsgStyle::PROMPT_ECHO_ON) {
        Ok(_) => {
            tracing::debug!(
                nonce_prefix = &nonce[..nonce.len().min(8)],
                "DPoP nonce delivered via PAM conversation"
            );
        }
        Err(e) => {
            // Conversation failure: the nonce is now orphaned in the cache; it will be
            // evicted automatically when its TTL expires (60 s by default).
            return Err(format!("PAM conversation round 1 failed: {e:?}"));
        }
    }

    Ok(nonce)
}

/// Check if PAM environment token reading is explicitly enabled.
/// Security: Requires explicit opt-in to accept tokens from PAM environment.
fn is_pam_env_token_enabled() -> bool {
    std::env::var("UNIX_OIDC_ACCEPT_PAM_ENV")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// Get the authentication token from various sources.
///
/// Token sources (in priority order):
/// 1. OIDC_TOKEN environment variable (requires UNIX_OIDC_TEST_MODE=true)
/// 2. PAM environment variable OIDC_TOKEN (requires UNIX_OIDC_ACCEPT_PAM_ENV=true)
/// 3. Cached PAM authtok (password field)
/// 4. Interactive PAM conversation prompt
///
/// Note: PAM conversation has a ~512 byte buffer limit, which is insufficient
/// for JWT tokens (~1400+ bytes). For production use, pass tokens via environment
/// variables or use the unix-oidc-agent with SSH_ASKPASS.
fn get_auth_token(pamh: &Pam, test_mode: bool) -> Option<String> {
    // In test mode, allow token from process environment variable
    // Security: Requires explicit UNIX_OIDC_TEST_MODE=true
    if test_mode {
        // SECURITY WARNING: Log that test mode is active
        eprintln!(
            "unix-oidc: WARNING: UNIX_OIDC_TEST_MODE is enabled. \
             JWT signature verification may be skipped. \
             NEVER use this in production environments."
        );

        if let Ok(token) = std::env::var("OIDC_TOKEN") {
            if is_jwt(&token) {
                eprintln!(
                    "unix-oidc: SECURITY NOTICE: Accepting token from OIDC_TOKEN environment variable (test mode)."
                );
                return Some(token);
            }
        }
    }

    // Check PAM environment for OIDC_TOKEN (set by external mechanisms like pam_env)
    // Security: Requires explicit UNIX_OIDC_ACCEPT_PAM_ENV=true
    if is_pam_env_token_enabled() {
        // SECURITY WARNING: Log that this potentially dangerous mode is active
        eprintln!(
            "unix-oidc: WARNING: UNIX_OIDC_ACCEPT_PAM_ENV is enabled. \
             Tokens from PAM environment are accepted. \
             This may allow token injection if PAM environment is not fully trusted. \
             Only enable this in controlled environments."
        );

        if let Ok(Some(token)) = pamh.getenv("OIDC_TOKEN") {
            let token_str = token.to_string_lossy().to_string();
            if is_jwt(&token_str) {
                eprintln!(
                    "unix-oidc: SECURITY NOTICE: Accepting token from PAM environment variable. \
                     Ensure PAM environment source is trusted."
                );
                return Some(token_str);
            }
        }
    }

    // Try to get token from PAM authtok (password field)
    if let Ok(Some(token)) = pamh.get_cached_authtok() {
        let token_str = token.to_string_lossy().to_string();
        if is_jwt(&token_str) {
            return Some(token_str);
        }
    }

    // If no cached token, prompt for one using direct PAM conversation
    // Note: This has a ~512 byte buffer limit, which is insufficient for JWTs
    if let Ok(Some(token)) = pamh.conv(Some("OIDC Token: "), PamMsgStyle::PROMPT_ECHO_OFF) {
        let token_str = token.to_string_lossy().to_string();
        if is_jwt(&token_str) {
            return Some(token_str);
        }
        // Log warning about potential truncation if the input looks like a partial JWT
        if token_str.starts_with("eyJ") && token_str.len() > 500 {
            eprintln!(
                "unix-oidc: Warning: Token may be truncated ({} bytes). \
                 PAM conversation has a ~512 byte limit. \
                 Use OIDC_TOKEN environment variable for longer tokens.",
                token_str.len()
            );
        }
    }

    None
}

/// Check if a string looks like a JWT (three base64url parts separated by dots).
fn is_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    // All parts should be non-empty base64url strings
    parts.iter().all(|p| !p.is_empty() && is_base64url(p))
}

/// Check if a string is valid base64url.
fn is_base64url(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    // Mutex to ensure environment variable tests don't interfere with each other.
    // parking_lot::Mutex does not poison on panic, so .lock() returns the guard
    // directly without needing .unwrap().
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_is_jwt_valid() {
        assert!(is_jwt("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature"));
    }

    #[test]
    fn test_is_jwt_invalid() {
        assert!(!is_jwt("not-a-jwt"));
        assert!(!is_jwt("only.two"));
        assert!(!is_jwt("one.two.three.four"));
        assert!(!is_jwt(""));
    }

    #[test]
    fn test_is_base64url() {
        assert!(is_base64url("eyJhbGciOiJSUzI1NiJ9"));
        assert!(is_base64url("abc123_-"));
        assert!(!is_base64url("abc.def"));
        assert!(!is_base64url("abc=def"));
    }

    // =========================================================================
    // Security tests for UNIX_OIDC_TEST_MODE gating
    // =========================================================================

    #[test]
    fn test_test_mode_disabled_by_default() {
        let _guard = ENV_MUTEX.lock();
        std::env::remove_var("UNIX_OIDC_TEST_MODE");
        assert!(
            !is_test_mode_enabled(),
            "SECURITY: Test mode MUST be disabled by default"
        );
    }

    #[test]
    fn test_test_mode_enabled_with_true() {
        let _guard = ENV_MUTEX.lock();
        std::env::set_var("UNIX_OIDC_TEST_MODE", "true");
        assert!(is_test_mode_enabled());
        std::env::remove_var("UNIX_OIDC_TEST_MODE");
    }

    #[test]
    fn test_test_mode_enabled_with_1() {
        let _guard = ENV_MUTEX.lock();
        std::env::set_var("UNIX_OIDC_TEST_MODE", "1");
        assert!(is_test_mode_enabled());
        std::env::remove_var("UNIX_OIDC_TEST_MODE");
    }

    #[test]
    fn test_test_mode_not_enabled_with_other_values() {
        let _guard = ENV_MUTEX.lock();

        // Test various values that should NOT enable test mode
        for value in &["yes", "TRUE", "True", "enabled", "on", "0", "false", ""] {
            std::env::set_var("UNIX_OIDC_TEST_MODE", value);
            assert!(
                !is_test_mode_enabled(),
                "SECURITY: Test mode MUST NOT be enabled by value '{}'",
                value
            );
        }
        std::env::remove_var("UNIX_OIDC_TEST_MODE");
    }

    // =========================================================================
    // Security tests for UNIX_OIDC_ACCEPT_PAM_ENV gating
    // =========================================================================

    #[test]
    fn test_pam_env_token_disabled_by_default() {
        let _guard = ENV_MUTEX.lock();
        std::env::remove_var("UNIX_OIDC_ACCEPT_PAM_ENV");
        assert!(
            !is_pam_env_token_enabled(),
            "SECURITY: PAM environment token reading MUST be disabled by default"
        );
    }

    #[test]
    fn test_pam_env_token_enabled_with_true() {
        let _guard = ENV_MUTEX.lock();
        std::env::set_var("UNIX_OIDC_ACCEPT_PAM_ENV", "true");
        assert!(is_pam_env_token_enabled());
        std::env::remove_var("UNIX_OIDC_ACCEPT_PAM_ENV");
    }

    #[test]
    fn test_pam_env_token_enabled_with_1() {
        let _guard = ENV_MUTEX.lock();
        std::env::set_var("UNIX_OIDC_ACCEPT_PAM_ENV", "1");
        assert!(is_pam_env_token_enabled());
        std::env::remove_var("UNIX_OIDC_ACCEPT_PAM_ENV");
    }

    #[test]
    fn test_pam_env_token_not_enabled_with_other_values() {
        let _guard = ENV_MUTEX.lock();

        // Test various values that should NOT enable PAM env token reading
        for value in &["yes", "TRUE", "True", "enabled", "on", "0", "false", ""] {
            std::env::set_var("UNIX_OIDC_ACCEPT_PAM_ENV", value);
            assert!(
                !is_pam_env_token_enabled(),
                "SECURITY: PAM env token MUST NOT be enabled by value '{}'",
                value
            );
        }
        std::env::remove_var("UNIX_OIDC_ACCEPT_PAM_ENV");
    }

    // =========================================================================
    // Security invariant tests
    // =========================================================================

    #[test]
    fn test_security_invariant_both_modes_disabled_by_default() {
        let _guard = ENV_MUTEX.lock();

        // Clear all relevant environment variables
        std::env::remove_var("UNIX_OIDC_TEST_MODE");
        std::env::remove_var("UNIX_OIDC_ACCEPT_PAM_ENV");

        // CRITICAL SECURITY INVARIANT:
        // With no environment variables set, both token bypass mechanisms MUST be disabled
        assert!(
            !is_test_mode_enabled() && !is_pam_env_token_enabled(),
            "SECURITY CRITICAL: Default configuration MUST NOT allow any token bypass mechanisms"
        );
    }

    #[test]
    fn test_security_invariant_explicit_opt_in_required() {
        let _guard = ENV_MUTEX.lock();

        // Set variables to non-enabling values
        std::env::set_var("UNIX_OIDC_TEST_MODE", "false");
        std::env::set_var("UNIX_OIDC_ACCEPT_PAM_ENV", "no");

        // CRITICAL SECURITY INVARIANT:
        // Setting variables to non-"true"/non-"1" values MUST NOT enable bypass
        assert!(
            !is_test_mode_enabled(),
            "SECURITY: 'false' MUST NOT enable test mode"
        );
        assert!(
            !is_pam_env_token_enabled(),
            "SECURITY: 'no' MUST NOT enable PAM env token"
        );

        std::env::remove_var("UNIX_OIDC_TEST_MODE");
        std::env::remove_var("UNIX_OIDC_ACCEPT_PAM_ENV");
    }

    // =========================================================================
    // DPoP nonce issuance — unit tests for the new lib.rs infrastructure.
    //
    // issue_and_deliver_nonce() requires a live Pam handle (PAM conversation),
    // so we test its sub-components directly: generate_dpop_nonce() + the global
    // cache issue/consume cycle, and the DPoP mode determination logic.
    // =========================================================================

    use crate::security::nonce_cache::{generate_dpop_nonce, global_nonce_cache};

    #[test]
    fn test_dpop_nonce_issuance_and_consumption_roundtrip() {
        // Verify that a nonce generated and issued by lib.rs's issue path
        // can be consumed exactly once by auth.rs's consume path.
        let nonce = generate_dpop_nonce().unwrap();
        let cache = global_nonce_cache();

        cache.issue(&nonce).unwrap();
        assert!(
            cache.consume(&nonce).is_ok(),
            "nonce issued by lib.rs must be consumable by auth.rs"
        );
        // Second consume must fail (single-use invariant)
        assert!(
            cache.consume(&nonce).is_err(),
            "nonce must not be consumable a second time"
        );
    }

    #[test]
    fn test_nonce_format_matches_dpop_nonce_prefix() {
        // "DPOP_NONCE:<nonce>" must parse correctly: split at ':' gives exactly 2 parts.
        let nonce = generate_dpop_nonce().unwrap();
        let prompt = format!("DPOP_NONCE:{nonce}");
        let parts: Vec<&str> = prompt.splitn(2, ':').collect();
        assert_eq!(parts.len(), 2, "DPOP_NONCE prompt must split into exactly 2 parts");
        assert_eq!(parts[0], "DPOP_NONCE");
        assert_eq!(parts[1], nonce.as_str());
    }

    #[test]
    fn test_dpop_mode_default_is_strict_without_policy_file() {
        let _guard = ENV_MUTEX.lock();
        // With no policy file and no env var, PolicyConfig::from_env() returns Err
        // (default policy path /etc/unix-oidc/policy.yaml absent).
        // Our authenticate() code maps this to EnforcementMode::Strict (safe default).
        std::env::remove_var("UNIX_OIDC_POLICY_FILE");
        std::env::remove_var("UNIX_OIDC_POLICY_YAML");
        std::env::remove_var("UNIX_OIDC_TEST_MODE");

        let dpop_mode = PolicyConfig::from_env()
            .map(|p| p.effective_security_modes().dpop_required)
            .unwrap_or(EnforcementMode::Strict);

        assert_eq!(
            dpop_mode,
            EnforcementMode::Strict,
            "Default DPoP mode must be Strict when policy file is absent"
        );
    }

    #[test]
    fn test_dpop_mode_from_inline_yaml_disabled() {
        let _guard = ENV_MUTEX.lock();
        let yaml = "security_modes:\n  dpop_required: disabled\n";
        std::env::set_var("UNIX_OIDC_POLICY_YAML", yaml);

        let dpop_mode = PolicyConfig::from_env()
            .map(|p| p.effective_security_modes().dpop_required)
            .unwrap_or(EnforcementMode::Strict);

        std::env::remove_var("UNIX_OIDC_POLICY_YAML");
        assert_eq!(dpop_mode, EnforcementMode::Disabled);
    }

    #[test]
    fn test_dpop_mode_from_inline_yaml_warn() {
        let _guard = ENV_MUTEX.lock();
        let yaml = "security_modes:\n  dpop_required: warn\n";
        std::env::set_var("UNIX_OIDC_POLICY_YAML", yaml);

        let dpop_mode = PolicyConfig::from_env()
            .map(|p| p.effective_security_modes().dpop_required)
            .unwrap_or(EnforcementMode::Strict);

        std::env::remove_var("UNIX_OIDC_POLICY_YAML");
        assert_eq!(dpop_mode, EnforcementMode::Warn);
    }
}
