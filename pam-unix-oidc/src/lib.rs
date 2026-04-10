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
// Production code must use ? or explicit error handling — unwrap/expect can panic
// in PAM (locking users out). Test code is allowed to unwrap for clarity.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
// Security: Prevent accidental release builds with test-mode enabled.
// test-mode bypasses ALL signature verification — a critical vulnerability if shipped.
// See: docs/threat-model.md §7 Recommendation 1 (P0), CLAUDE.md §CRITICAL: Test Mode Security.
#[cfg(all(feature = "test-mode", not(debug_assertions)))]
compile_error!(
    "test-mode feature must not be enabled in release builds — \
     it disables JWT signature verification. \
     Build without --features test-mode for production."
);

pub mod approval;
pub mod audit;
pub mod auth;
pub mod ciba;
pub mod device_flow;
pub mod identity;
pub mod oidc;
pub mod otp;
pub mod policy;
pub mod security;
pub mod session;
pub mod sssd;
pub mod sudo;
pub mod ui;

use audit::AuditEvent;
use auth::{
    authenticate_multi_issuer, authenticate_with_dpop, authenticate_with_token, AuthError,
    DPoPAuthConfig,
};
use oidc::jwks::IssuerJwksRegistry;
use once_cell::sync::Lazy;
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamMsgStyle, PamServiceModule};
use policy::config::{EnforcementMode, PolicyConfig};
use secrecy::{ExposeSecret, SecretString};
use security::nonce_cache::{generate_dpop_nonce, global_nonce_cache};
use security::rate_limit::global_rate_limiter;

/// Module-level JWKS registry that persists across PAM authentication calls.
///
/// Using a static ensures that:
/// 1. JWKS cache entries are retained between PAM calls (one sshd process may handle
///    many authentications).
/// 2. Per-issuer JWKS providers are independent — fetching JWKS for issuer A does not
///    evict the cached keys for issuer B (MIDP-07).
///
/// Initialized lazily on first use via `Lazy<IssuerJwksRegistry>`.
static JWKS_REGISTRY: Lazy<IssuerJwksRegistry> = Lazy::new(IssuerJwksRegistry::new);

/// Return `true` if `pam_user` matches any configured break-glass account.
///
/// Checks both `break_glass.accounts` (v2.0) and `break_glass.local_account` (v1.0 compat).
fn is_break_glass_user(pam_user: &str, policy: &PolicyConfig) -> bool {
    policy.break_glass.accounts.iter().any(|a| a == pam_user)
        || policy
            .break_glass
            .local_account
            .as_deref()
            .map(|la| la == pam_user)
            .unwrap_or(false)
}

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
        // Bridge environment config to process env for downstream ValidationConfig::from_env().
        //
        // OpenSSH sshd sanitizes the forked child's process environment, stripping all
        // vars including OIDC_ISSUER. The PAM module's config readers use std::env::var()
        // (process env), so we must restore the vars from available sources.
        //
        // Source priority:
        //   1. Process env (already set) — highest, never overridden
        //   2. PAM env (set by pam_env.so readenv=1 from /etc/environment)
        //   3. /etc/environment direct parse — fallback if PAM env unavailable
        //
        // Security:
        //   - /etc/environment is root-owned (0644). An attacker who can modify it has root.
        //   - We only set vars NOT already in process env (explicit config wins).
        //   - Each sshd child is a separate fork; single-threaded during PAM auth.
        //   - Only OIDC-specific var names are bridged (allowlist, not passthrough).
        {
            let bridge_vars = [
                "OIDC_ISSUER",
                "OIDC_CLIENT_ID",
                "OIDC_REQUIRED_ACR",
                "OIDC_MAX_AUTH_AGE",
                "UNIX_OIDC_POLICY_PATH",
            ];

            // Try PAM env first (set by pam_env.so), then /etc/environment fallback.
            let mut etc_env_cache: Option<Vec<(String, String)>> = None;

            for var_name in &bridge_vars {
                if std::env::var(var_name).is_ok() {
                    continue; // Already in process env — don't override.
                }

                // Source 2: PAM environment
                let pam_val = pamh
                    .getenv(var_name)
                    .ok()
                    .flatten()
                    .map(|v| v.to_string_lossy().to_string())
                    .filter(|v| !v.is_empty());

                if let Some(val) = pam_val {
                    #[allow(unsafe_code)]
                    // SAFETY: sshd forks per connection; single-threaded during PAM auth.
                    unsafe {
                        std::env::set_var(var_name, &val)
                    };
                    continue;
                }

                // Source 3: Parse /etc/environment (lazy, read once)
                if etc_env_cache.is_none() {
                    etc_env_cache = Some(
                        std::fs::read_to_string("/etc/environment")
                            .unwrap_or_default()
                            .lines()
                            .filter_map(|line| {
                                let line = line.trim();
                                if line.is_empty() || line.starts_with('#') {
                                    return None;
                                }
                                let (k, v) = line.split_once('=')?;
                                // Strip optional quotes from value
                                let v = v.trim_matches('"').trim_matches('\'');
                                Some((k.to_string(), v.to_string()))
                            })
                            .collect(),
                    );
                }

                if let Some(ref entries) = etc_env_cache {
                    if let Some((_, val)) = entries.iter().find(|(k, _)| k == *var_name) {
                        #[allow(unsafe_code)]
                        // SAFETY: sshd forks per connection; single-threaded during PAM auth.
                        unsafe {
                            std::env::set_var(var_name, val)
                        };
                    }
                }
            }
        }

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

        // Break-glass bypass — MUST come before rate limiting, nonce issuance, and OIDC.
        //
        // Break-glass accounts bypass OIDC entirely: they are local accounts authenticated
        // by the downstream PAM stack (e.g. pam_unix.so with local password or YubiKey OTP).
        // Returning PAM_IGNORE here causes PAM to skip this module and continue to the next
        // auth provider in the stack, which handles the actual credential check.
        //
        // Security: We only bypass when break_glass.enabled is explicitly true AND the user
        // is in the configured accounts list. Disabled break-glass config = normal OIDC flow.
        if let Ok(policy) = PolicyConfig::from_env() {
            if policy.break_glass.enabled && is_break_glass_user(&pam_user, &policy) {
                // Phase 36-02: If `requires: yubikey_otp` is set, verify TOTP before bypass.
                // This adds a hardware-bound factor to break-glass access without any network call.
                if policy.break_glass.requires.as_deref() == Some("yubikey_otp") {
                    let otp_path = std::path::Path::new(otp::DEFAULT_OTP_SEEDS_PATH);
                    match otp::load_seeds(otp_path) {
                        Ok(store) => {
                            // Prompt for OTP code via PAM conversation.
                            let code = match pamh
                                .conv(Some("Break-glass OTP: "), PamMsgStyle::PROMPT_ECHO_OFF)
                            {
                                Ok(Some(c)) => c.to_string_lossy().to_string(),
                                _ => {
                                    tracing::warn!(
                                        username = %pam_user,
                                        "Break-glass OTP prompt failed or cancelled"
                                    );
                                    AuditEvent::ssh_login_failed(
                                        Some(&pam_user),
                                        source_ip,
                                        "break-glass OTP prompt failed",
                                    )
                                    .log();
                                    return PamError::AUTH_ERR;
                                }
                            };

                            if let Err(e) = otp::verify_totp(&pam_user, code.trim(), &store) {
                                tracing::warn!(
                                    username = %pam_user,
                                    error = %e,
                                    "Break-glass OTP verification failed"
                                );
                                AuditEvent::ssh_login_failed(
                                    Some(&pam_user),
                                    source_ip,
                                    &format!("break-glass OTP failed: {e}"),
                                )
                                .log();
                                return PamError::AUTH_ERR;
                            }

                            tracing::info!(
                                username = %pam_user,
                                "Break-glass OTP verified — proceeding with bypass"
                            );
                        }
                        Err(e) => {
                            // OTP seeds not found — log and deny. Operator configured
                            // yubikey_otp but didn't enroll seeds; fail closed.
                            tracing::error!(
                                username = %pam_user,
                                error = %e,
                                "Break-glass requires yubikey_otp but seed file is unavailable"
                            );
                            AuditEvent::ssh_login_failed(
                                Some(&pam_user),
                                source_ip,
                                &format!("break-glass OTP seed unavailable: {e}"),
                            )
                            .log();
                            return PamError::AUTH_ERR;
                        }
                    }
                }

                // Audit event — severity depends on alert_on_use policy flag (SBUG-02).
                // When alert_on_use=true (default), severity is CRITICAL so SIEM alerting fires.
                // When alert_on_use=false, severity is INFO (routine / non-alerting use).
                AuditEvent::break_glass_auth(&pam_user, source_ip, policy.break_glass.alert_on_use)
                    .log();
                return PamError::IGNORE;
            }
        }

        // Check rate limiting before attempting authentication
        if let Err(e) = global_rate_limiter().check_allowed(&pam_user, source_ip) {
            AuditEvent::ssh_login_failed(Some(&pam_user), source_ip, &format!("Rate limited: {e}"))
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
        let secret_token = match get_auth_token(&pamh, test_mode) {
            Some(t) => t,
            None => {
                // OBS-02: Emit AUTH_NO_TOKEN audit event — distinguishes "no token provided"
                // from "token present but invalid" in SIEM queries.
                AuditEvent::auth_no_token(&pam_user, source_ip).log();
                // Record as a failure for rate limiting purposes
                global_rate_limiter().record_failure(&pam_user, source_ip);
                return PamError::AUTH_ERR;
            }
        };
        // Expose the raw JWT for validation functions. The SecretString wrapper
        // ensures the token is never leaked via Debug/Display formatting.
        let token = secret_token.expose_secret();

        // Best-effort issuer extraction for forensic audit attribution (SBUG-01).
        //
        // We decode the JWT payload WITHOUT signature verification here — purely to
        // read the `iss` claim so that token_validation_failed audit events record the
        // correct issuer URL.  Full signature verification is performed subsequently.
        // If the token is malformed (not a valid JWT), we record None — the audit event
        // will have null oidc_issuer, which is honest: no issuer was identifiable.
        let token_issuer_for_audit: Option<String> =
            crate::auth::extract_iss_for_routing(token).ok();

        // Load policy once — used for both path selection and DPoP config.
        //
        // Multi-issuer path uses load_fresh() (MIDP-11 hot-reload): stats the config
        // file on each authentication attempt and re-parses only when the mtime changes.
        // On parse failure, the previous valid config is returned — never blocks auth.
        //
        // Legacy single-issuer path continues to use from_env().unwrap_or_default() for
        // backward compatibility; that path is deprecated and will not gain hot-reload.
        let policy_for_auth = PolicyConfig::load_fresh()
            .unwrap_or_else(|_| PolicyConfig::from_env().unwrap_or_default());

        // Choose authentication path:
        //
        // Multi-issuer path (Phase 21): When `issuers[]` is configured in policy.yaml,
        // dispatch to `authenticate_multi_issuer()` which applies per-issuer JWKS,
        // DPoP enforcement, and claim mapping. The DPoP nonce/proof collected above is
        // passed through verbatim; per-issuer enforcement decides whether to require it.
        //
        // Legacy single-issuer path: When `issuers[]` is empty, fall back to the
        // existing `authenticate_with_dpop()` / `authenticate_with_token()` paths.
        // Zero behavior change for existing single-issuer deployments.
        let auth_result = if !policy_for_auth.issuers.is_empty() {
            // Multi-issuer dispatch (MIDP-06).
            let dpop_config = DPoPAuthConfig {
                target_host: gethostname::gethostname().to_string_lossy().to_string(),
                require_nonce: true,
                expected_nonce: None,
                ..DPoPAuthConfig::from_policy(&policy_for_auth)
            };
            authenticate_multi_issuer(
                token,
                dpop_proof.as_deref(),
                &dpop_config,
                &policy_for_auth,
                &JWKS_REGISTRY,
            )
        } else if dpop_proof.is_some() || dpop_mode == EnforcementMode::Strict {
            // Legacy DPoP path (strict or proof provided).
            // Clock skew values come from PolicyConfig.timeouts (Phase 14-01).
            // Fall back to DPoPAuthConfig defaults if policy could not be loaded.
            let dpop_config = DPoPAuthConfig {
                target_host: gethostname::gethostname().to_string_lossy().to_string(),
                require_nonce: true,  // cache-backed nonce enforcement
                expected_nonce: None, // None = cache path (auth.rs consumes from cache)
                ..DPoPAuthConfig::from_policy(&policy_for_auth)
            };
            authenticate_with_dpop(token, dpop_proof.as_deref(), &dpop_config)
        } else {
            // Legacy: Warn or Disabled with no proof — token-only fallback.
            authenticate_with_token(token)
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

                // RFC 7662 Token Introspection — opt-in post-validation active-status check.
                //
                // Runs AFTER signature verification, issuer/audience checks, and DPoP validation.
                // Purpose: detect token revocation or account disablement at the IdP within the
                // cache TTL (default 60 s). Zero overhead when introspection.enabled = false.
                //
                // Enforcement follows IntrospectionConfig.enforcement (Warn / Strict):
                //   Ok(true)  — active; proceed to SUCCESS
                //   Ok(false) — inactive; Strict → AUTH_ERR, Warn → log and proceed
                //   Err(_)    — endpoint error; Strict → AUTH_ERR, Warn → fail-open and proceed
                if let Ok(policy) = PolicyConfig::from_env() {
                    if policy.introspection.enabled {
                        let client_id = std::env::var("OIDC_CLIENT_ID")
                            .unwrap_or_else(|_| "unix-oidc".to_string());
                        let introspect_result = oidc::introspection::introspect_token(
                            &policy.introspection,
                            token,
                            result.token_jti.as_deref(),
                            result.token_exp,
                            &client_id,
                            Some(&result.session_id),
                            Some(&result.username),
                        );

                        let enforcement = policy.introspection.enforcement;
                        match introspect_result {
                            Ok(true) => {
                                // Token is active — proceed normally.
                            }
                            Ok(false) => {
                                // Token reported as inactive (revoked or expired at IdP).
                                AuditEvent::introspection_failed(
                                    Some(&result.session_id),
                                    Some(&result.username),
                                    "Token is inactive (revoked or expired at IdP)",
                                    match enforcement {
                                        EnforcementMode::Strict => "strict",
                                        EnforcementMode::Warn => "warn",
                                        EnforcementMode::Disabled => "disabled",
                                    },
                                )
                                .log();
                                match enforcement {
                                    EnforcementMode::Strict => {
                                        global_rate_limiter().record_failure(&pam_user, source_ip);
                                        return PamError::AUTH_ERR;
                                    }
                                    EnforcementMode::Warn | EnforcementMode::Disabled => {
                                        // Fail-open: log already emitted above; proceed.
                                        tracing::warn!(
                                            username = %result.username,
                                            "Introspection reports token inactive; proceeding (warn mode)"
                                        );
                                    }
                                }
                            }
                            Err(oidc::introspection::IntrospectionError::NotConfigured) => {
                                // enabled=true but no endpoint URL — operator misconfiguration.
                                let enforcement_str = match enforcement {
                                    EnforcementMode::Strict => "strict",
                                    EnforcementMode::Warn => "warn",
                                    EnforcementMode::Disabled => "disabled",
                                };
                                tracing::warn!(
                                    username = %result.username,
                                    enforcement = %enforcement_str,
                                    "Introspection enabled but no endpoint configured"
                                );
                                if enforcement == EnforcementMode::Strict {
                                    AuditEvent::introspection_failed(
                                        Some(&result.session_id),
                                        Some(&result.username),
                                        "Introspection endpoint not configured",
                                        enforcement_str,
                                    )
                                    .log();
                                    return PamError::SERVICE_ERR;
                                }
                            }
                            Err(e) => {
                                // Network or parse error reaching the introspection endpoint.
                                // Audit event is already emitted inside introspect_token/do_introspect.
                                tracing::warn!(
                                    username = %result.username,
                                    error = %e,
                                    "Introspection endpoint error"
                                );
                                if enforcement == EnforcementMode::Strict {
                                    global_rate_limiter().record_failure(&pam_user, source_ip);
                                    return PamError::AUTH_ERR;
                                }
                                // Warn/Disabled: fail-open — log already emitted, proceed.
                            }
                        }
                    }
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
                    result.dpop_thumbprint.as_deref(),
                )
                .log();

                // Store session metadata in PAM environment for open_session / close_session.
                //
                // Session ID correlation:  authenticate() runs in the sshd auth worker;
                // open_session() runs in a separate sshd session worker.  PAM environment
                // variables (putenv/getenv) are the only reliable cross-fork channel
                // within a single PAM transaction.
                //
                // Security: Session correlation is best-effort; failure to set env vars is
                // logged at WARN but NEVER causes authentication to fail.
                if let Err(e) = pamh.putenv(&format!("UNIX_OIDC_SESSION_ID={}", result.session_id))
                {
                    tracing::warn!(error = ?e, "Failed to set UNIX_OIDC_SESSION_ID in PAM env");
                }
                if let Err(e) = pamh.putenv(&format!(
                    "UNIX_OIDC_TOKEN_JTI={}",
                    result.token_jti.as_deref().unwrap_or("")
                )) {
                    tracing::warn!(error = ?e, "Failed to set UNIX_OIDC_TOKEN_JTI in PAM env");
                }
                if let Err(e) = pamh.putenv(&format!("UNIX_OIDC_TOKEN_EXP={}", result.token_exp)) {
                    tracing::warn!(error = ?e, "Failed to set UNIX_OIDC_TOKEN_EXP in PAM env");
                }
                if let Err(e) = pamh.putenv(&format!("UNIX_OIDC_ISSUER={}", result.token_issuer)) {
                    tracing::warn!(error = ?e, "Failed to set UNIX_OIDC_ISSUER in PAM env");
                }

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
                        // SBUG-01: include the issuer extracted before the auth call.
                        AuditEvent::token_validation_failed(
                            Some(&pam_user),
                            &reason,
                            source_ip,
                            token_issuer_for_audit.as_deref(),
                        )
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
                        // SBUG-01: DPoP failures also attribute to the token's issuer.
                        AuditEvent::token_validation_failed(
                            Some(&pam_user),
                            &format!("DPoP validation failed: {reason}"),
                            source_ip,
                            token_issuer_for_audit.as_deref(),
                        )
                        .log();
                        PamError::AUTH_ERR
                    }
                    AuthError::DPoPRequired => {
                        // SBUG-01: attribute DPoP-required rejections to the token's issuer.
                        AuditEvent::token_validation_failed(
                            Some(&pam_user),
                            "DPoP proof required but not provided",
                            source_ip,
                            token_issuer_for_audit.as_deref(),
                        )
                        .log();
                        PamError::AUTH_ERR
                    }
                    AuthError::GroupDenied(_) => {
                        AuditEvent::ssh_login_failed(Some(&pam_user), source_ip, &reason).log();
                        PamError::AUTH_ERR
                    }
                    AuthError::IdentityMapping(_) => {
                        AuditEvent::ssh_login_failed(Some(&pam_user), source_ip, &reason).log();
                        PamError::AUTH_ERR
                    }
                    AuthError::UnknownIssuer(iss) => {
                        // SBUG-01: UnknownIssuer always has the issuer in the variant data.
                        tracing::warn!(issuer = %iss, "Token from unknown issuer — rejected");
                        AuditEvent::token_validation_failed(
                            Some(&pam_user),
                            &format!("Unknown issuer: {iss}"),
                            source_ip,
                            Some(iss.as_str()),
                        )
                        .log();
                        PamError::AUTH_ERR
                    }
                    AuthError::AttestationFailed(_) => {
                        // ADR-018: Hardware attestation verification failed.
                        AuditEvent::token_validation_failed(
                            Some(&pam_user),
                            &format!("Hardware attestation failed: {reason}"),
                            source_ip,
                            token_issuer_for_audit.as_deref(),
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

    fn open_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        // Retrieve session ID set by authenticate() via putenv.
        // If absent (e.g., non-OIDC PAM path), log WARN and return SUCCESS —
        // session tracking is best-effort and must never block legitimate logins.
        let session_id = match pamh.getenv("UNIX_OIDC_SESSION_ID") {
            Ok(Some(s)) => s.to_string_lossy().to_string(),
            Ok(None) => {
                tracing::warn!("UNIX_OIDC_SESSION_ID absent in PAM env; skipping session record");
                return PamError::SUCCESS;
            }
            Err(e) => {
                tracing::warn!(error = ?e, "Failed to read UNIX_OIDC_SESSION_ID from PAM env");
                return PamError::SUCCESS;
            }
        };

        // Retrieve PAM_USER (Unix username for this session)
        let username = match pamh
            .get_cached_user()
            .ok()
            .flatten()
            .map(|s| s.to_string_lossy().to_string())
            .or_else(|| {
                pamh.get_user(None)
                    .ok()
                    .flatten()
                    .map(|s| s.to_string_lossy().to_string())
            }) {
            Some(u) => u,
            None => {
                tracing::warn!(
                    "open_session: could not determine PAM user; skipping session record"
                );
                return PamError::SUCCESS;
            }
        };

        // Best-effort: read token metadata from PAM environment (set by authenticate()).
        let token_jti = pamh
            .getenv("UNIX_OIDC_TOKEN_JTI")
            .ok()
            .flatten()
            .map(|s| s.to_string_lossy().to_string())
            .filter(|s| !s.is_empty());

        let token_exp: i64 = pamh
            .getenv("UNIX_OIDC_TOKEN_EXP")
            .ok()
            .flatten()
            .and_then(|s| s.to_string_lossy().parse().ok())
            .unwrap_or(0);

        let issuer = pamh
            .getenv("UNIX_OIDC_ISSUER")
            .ok()
            .flatten()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        // Client IP from PAM_RHOST
        let client_ip: Option<String> = pamh
            .get_rhost()
            .ok()
            .flatten()
            .map(|s| s.to_string_lossy().to_string());

        // Load session config (use defaults on error — file may not exist in all deployments)
        let config = PolicyConfig::from_env().unwrap_or_default();
        let session_dir = &config.session.session_dir;

        // Ensure session directory exists with correct permissions
        if let Err(e) = crate::session::ensure_session_dir(session_dir) {
            tracing::warn!(
                error = %e,
                dir = %session_dir,
                "Failed to create session directory; skipping session record"
            );
            return PamError::SUCCESS;
        }

        // Build and write the session record
        let record = crate::session::SessionRecord {
            session_id: session_id.clone(),
            username: username.clone(),
            token_jti,
            token_exp,
            session_start: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            client_ip: client_ip.clone(),
            sshd_pid: std::process::id(),
            issuer,
        };

        if let Err(e) = crate::session::write_session_record(session_dir, &session_id, &record) {
            tracing::warn!(
                error = %e,
                session_id = %session_id,
                "Failed to write session record; session tracking unavailable"
            );
            // Continue — do not fail session open
        }

        // Emit SESSION_OPENED audit event
        AuditEvent::session_opened(
            &session_id,
            &username,
            client_ip.as_deref(),
            record.token_exp,
        )
        .log();

        PamError::SUCCESS
    }

    fn close_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        // Retrieve session ID set by authenticate() via putenv.
        // If absent, log WARN and return SUCCESS — session tracking is best-effort.
        let session_id = match pamh.getenv("UNIX_OIDC_SESSION_ID") {
            Ok(Some(s)) => s.to_string_lossy().to_string(),
            Ok(None) => {
                tracing::warn!("UNIX_OIDC_SESSION_ID absent in PAM env at session close");
                return PamError::SUCCESS;
            }
            Err(e) => {
                tracing::warn!(error = ?e, "Failed to read UNIX_OIDC_SESSION_ID from PAM env at close");
                return PamError::SUCCESS;
            }
        };

        let config = PolicyConfig::from_env().unwrap_or_default();
        let session_dir = &config.session.session_dir;

        // Delete the session record and retrieve it for audit / duration calculation
        let (username, duration_secs) =
            match crate::session::delete_session_record(session_dir, &session_id) {
                Ok(Some(record)) => {
                    let dur = crate::session::session_duration_secs(record.session_start);
                    (record.username, dur)
                }
                Ok(None) => {
                    // Record not found — session may have been cleaned up by other means
                    tracing::warn!(
                        session_id = %session_id,
                        "Session record not found on close; cannot compute duration"
                    );
                    // Still emit SessionClosed with empty username and 0 duration
                    (String::new(), 0i64)
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        session_id = %session_id,
                        "Failed to delete session record"
                    );
                    (String::new(), 0i64)
                }
            };

        // Emit SESSION_CLOSED audit event
        AuditEvent::session_closed(&session_id, &username, duration_secs).log();

        // Notify agent daemon of session close via Unix socket IPC.
        //
        // Best-effort: 2-second connect timeout. If the agent is unreachable or the
        // IPC fails for any reason, we log WARN and continue. Session teardown must
        // NEVER be blocked by agent availability.
        //
        // Protocol: send `{"action":"session_closed","session_id":"..."}` and read ACK.
        // This is a blocking call in the PAM module — no tokio, just std UnixStream.
        notify_agent_session_closed(&session_id);

        // INVARIANT: Always return SUCCESS — session teardown must never be blocked.
        PamError::SUCCESS
    }

    fn chauthtok(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }
}

/// Send a best-effort session-closed IPC notification to the agent daemon.
///
/// Connects to the agent's Unix domain socket and sends a JSON message:
/// `{"action":"session_closed","session_id":"<id>"}`.
///
/// This is intentionally blocking (std UnixStream, not tokio) because the PAM
/// module has no async runtime.  The connect timeout is 2 seconds.  Any error
/// is logged at WARN and silently ignored — the agent being unreachable is
/// a valid operational state (agent may not be running on every host).
///
/// The agent socket path follows the same convention used by the oidc-ssh-agent
/// CLI: `$XDG_RUNTIME_DIR/unix-oidc-agent.sock` falling back to
/// `/run/user/0/unix-oidc-agent.sock` (root).
fn notify_agent_session_closed(session_id: &str) {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    // Resolve agent socket path from UID, not environment variables.
    // Security (Codex finding 3): session-close runs as root; env vars are
    // user-influenced and could redirect root to a malicious socket.
    let socket_path = {
        #[cfg(feature = "test-mode")]
        if let Ok(path) = std::env::var("UNIX_OIDC_AGENT_SOCKET") {
            path
        } else {
            let uid = uzers::get_current_uid();
            format!("/run/user/{uid}/unix-oidc-agent.sock")
        }
        #[cfg(not(feature = "test-mode"))]
        {
            let uid = uzers::get_current_uid();
            format!("/run/user/{uid}/unix-oidc-agent.sock")
        }
    };

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error = %e,
                socket = %socket_path,
                session_id = %session_id,
                "Agent socket not reachable; session-closed IPC skipped"
            );
            // OBS-08: Emit SESSION_CLOSE_FAILED — missed revocations must not be silently dropped.
            // Username is empty: notify_agent_session_closed only receives session_id.
            // Correlate with the preceding SESSION_CLOSED event via session_id in SIEM.
            AuditEvent::session_close_failed(session_id, "", &format!("{e}")).log();
            return;
        }
    };

    // Set 2-second read/write timeout on the stream.
    if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(2))) {
        tracing::warn!(error = %e, "Failed to set read timeout on agent socket");
    }
    if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(2))) {
        tracing::warn!(error = %e, "Failed to set write timeout on agent socket");
    }

    let msg = serde_json::json!({
        "action": "session_closed",
        "session_id": session_id
    })
    .to_string();

    let mut stream = stream;
    if let Err(e) = stream.write_all(msg.as_bytes()) {
        tracing::warn!(
            error = %e,
            session_id = %session_id,
            "Failed to send session_closed IPC to agent"
        );
        // OBS-08: IPC write failure — revocation not delivered to agent.
        AuditEvent::session_close_failed(session_id, "", &format!("{e}")).log();
        return;
    }
    // Append newline so the agent's BufReader::read_line() returns immediately
    // instead of blocking until the 2s timeout expires (Phase 14-01 fix).
    if let Err(e) = stream.write_all(b"\n") {
        tracing::warn!(
            error = %e,
            session_id = %session_id,
            "Failed to send session_closed IPC newline to agent"
        );
        // OBS-08: Newline write failure — agent BufReader will not return; revocation unconfirmed.
        AuditEvent::session_close_failed(session_id, "", &format!("{e}")).log();
        return;
    }

    // Read ACK (up to 64 bytes; we don't care about the content, just that the agent responded)
    let mut ack = [0u8; 64];
    match stream.read(&mut ack) {
        Ok(0) | Err(_) => {
            // Agent closed connection or timed out — best-effort, acceptable
            tracing::debug!(session_id = %session_id, "Agent IPC ACK not received (best-effort)");
        }
        Ok(_) => {
            tracing::debug!(session_id = %session_id, "Agent session_closed IPC acknowledged");
        }
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
fn get_auth_token(pamh: &Pam, test_mode: bool) -> Option<SecretString> {
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
                return Some(SecretString::from(token));
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
                return Some(SecretString::from(token_str));
            }
        }
    }

    // Try to get token from PAM authtok (password field)
    if let Ok(Some(token)) = pamh.get_cached_authtok() {
        let token_str = token.to_string_lossy().to_string();
        if is_jwt(&token_str) {
            return Some(SecretString::from(token_str));
        }
    }

    // If no cached token, prompt for one using direct PAM conversation
    // Note: This has a ~512 byte buffer limit, which is insufficient for JWTs
    if let Ok(Some(token)) = pamh.conv(Some("OIDC Token: "), PamMsgStyle::PROMPT_ECHO_OFF) {
        let token_str = token.to_string_lossy().to_string();
        if is_jwt(&token_str) {
            return Some(SecretString::from(token_str));
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
                "SECURITY: Test mode MUST NOT be enabled by value '{value}'"
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
                "SECURITY: PAM env token MUST NOT be enabled by value '{value}'"
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
        assert_eq!(
            parts.len(),
            2,
            "DPOP_NONCE prompt must split into exactly 2 parts"
        );
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

    // Requires test-mode: UNIX_OIDC_POLICY_YAML is gated behind #[cfg(feature = "test-mode")]
    // per Codex finding 4 (env-policy injection prevention).
    #[cfg(feature = "test-mode")]
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

    #[cfg(feature = "test-mode")]
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

    // =========================================================================
    // Break-glass bypass tests
    // =========================================================================

    use figment::providers::Format as _;

    fn make_policy(yaml: &str) -> PolicyConfig {
        figment::Figment::from(figment::providers::Serialized::defaults(
            PolicyConfig::default(),
        ))
        .merge(figment::providers::Yaml::string(yaml))
        .extract()
        .unwrap()
    }

    #[test]
    fn test_is_break_glass_user_with_accounts_list() {
        let policy = make_policy(
            "break_glass:\n  enabled: true\n  accounts:\n    - breakglass1\n    - breakglass2\n",
        );
        assert!(is_break_glass_user("breakglass1", &policy));
        assert!(is_break_glass_user("breakglass2", &policy));
        assert!(!is_break_glass_user("regularuser", &policy));
    }

    #[test]
    fn test_is_break_glass_user_with_local_account_v1_compat() {
        // v1.0 backward compat: local_account field
        let policy = make_policy("break_glass:\n  enabled: true\n  local_account: emergency\n");
        assert!(is_break_glass_user("emergency", &policy));
        assert!(!is_break_glass_user("alice", &policy));
    }

    #[test]
    fn test_is_break_glass_user_false_when_disabled() {
        // Break-glass guard must not fire when enabled=false even if account matches.
        let policy =
            make_policy("break_glass:\n  enabled: false\n  accounts:\n    - breakglass1\n");
        // is_break_glass_user returns true (account is listed)...
        assert!(is_break_glass_user("breakglass1", &policy));
        // ...but the authenticate() guard checks policy.break_glass.enabled first,
        // so PAM_IGNORE is only returned when BOTH enabled=true AND user matches.
        assert!(!policy.break_glass.enabled);
    }

    #[test]
    fn test_is_break_glass_user_empty_accounts_returns_false() {
        // No accounts configured — no user should match.
        let policy = PolicyConfig::default();
        assert!(!is_break_glass_user("anyone", &policy));
        assert!(!is_break_glass_user("root", &policy));
    }

    #[test]
    fn test_is_break_glass_user_both_fields_honoured() {
        // Both local_account and accounts are in effect simultaneously.
        let policy = make_policy(
            "break_glass:\n  enabled: true\n  local_account: legacy\n  accounts:\n    - new1\n    - new2\n",
        );
        assert!(is_break_glass_user("legacy", &policy));
        assert!(is_break_glass_user("new1", &policy));
        assert!(is_break_glass_user("new2", &policy));
        assert!(!is_break_glass_user("notlisted", &policy));
    }

    // ── SessionClosed IPC newline test (Phase 14-01) ─────────────────────────
    // Requires test-mode: production builds derive socket path from UID,
    // not UNIX_OIDC_AGENT_SOCKET env var, so the test socket can't be reached.

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_notify_agent_session_closed_sends_newline_framed_json() {
        // Verify that notify_agent_session_closed writes JSON + '\n' so that the
        // agent's BufReader::read_line() returns immediately without blocking.
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;
        use std::path::PathBuf;

        // Bind a temp socket.
        let dir = std::env::temp_dir();
        let sock_path: PathBuf = dir.join(format!("oidc-test-{}.sock", std::process::id()));
        if sock_path.exists() {
            let _ = std::fs::remove_file(&sock_path);
        }
        let listener = UnixListener::bind(&sock_path).expect("bind test socket");

        // Spawn a thread to capture what the PAM sends.
        let sock_path_str = sock_path.to_str().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            let _guard = ENV_MUTEX.lock();
            std::env::set_var("UNIX_OIDC_AGENT_SOCKET", &sock_path_str);
            notify_agent_session_closed("test-session-id-123");
            std::env::remove_var("UNIX_OIDC_AGENT_SOCKET");
        });

        // Accept the connection and read a line (newline-framed).
        listener.set_nonblocking(false).ok();
        let (stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .ok();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("read_line must not block indefinitely");

        handle.join().ok();
        let _ = std::fs::remove_file(&sock_path);

        // The line must end with '\n' (the fix) and be valid JSON.
        assert!(
            line.ends_with('\n'),
            "IPC message must end with \\n for BufReader::read_line compatibility, got: {line:?}"
        );
        let trimmed = line.trim_end_matches('\n');
        assert!(
            trimmed.contains("session_closed"),
            "JSON must contain action=session_closed"
        );
        assert!(
            trimmed.contains("test-session-id-123"),
            "JSON must contain the session_id"
        );
    }

    // ── Multi-issuer dispatch tests (Phase 21, MIDP-06) ──────────────────────
    //
    // These tests verify that:
    // 1. The JWKS_REGISTRY static is accessible and non-empty after first use.
    // 2. The dispatch branching logic (issuers empty → legacy, non-empty → multi)
    //    works correctly via authenticate_multi_issuer() directly.
    // 3. UnknownIssuer is mapped to AUTH_ERR with an audit log in the PAM error handler.

    #[test]
    fn test_jwks_registry_static_is_accessible() {
        // The static JWKS_REGISTRY must be initializable and usable.
        // Calling get_or_init with a dummy URL should return an Arc<JwksProvider>.
        let provider = JWKS_REGISTRY.get_or_init("https://test.example.com", 300, 10);
        // A second call with the same issuer must return the same Arc.
        let provider2 = JWKS_REGISTRY.get_or_init("https://test.example.com", 300, 10);
        assert!(
            std::sync::Arc::ptr_eq(&provider, &provider2),
            "same issuer must return same Arc from static registry"
        );
    }

    #[test]
    fn test_multi_issuer_dispatch_requires_issuers_configured() {
        // With empty issuers[], authenticate_multi_issuer is NOT called.
        // This test verifies the branching condition: policy.issuers.is_empty().
        let policy = crate::policy::config::PolicyConfig::default();
        assert!(
            policy.issuers.is_empty(),
            "default PolicyConfig must have empty issuers[] (legacy mode)"
        );
    }

    // ── SBUG-01: oidc_issuer forensic attribution ─────────────────────────────
    //
    // These tests verify that token_issuer_for_audit is correctly populated from
    // the JWT payload, so that audit events carry the correct issuer URL rather
    // than None.  We test extract_iss_for_routing() (the extraction function used
    // by lib.rs before the auth call) and validate that TokenValidationFailed
    // events include oidc_issuer when the issuer is parseable.

    #[test]
    fn test_extract_iss_for_routing_parses_issuer() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT"}"#.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(
            format!(r#"{{"iss":"https://idp.example.com","sub":"alice","aud":"unix-oidc","exp":{exp},"iat":{now}}}"#,
                exp = now + 3600)
                .as_bytes(),
        );
        let token = format!("{header}.{payload}.dummysig");

        let iss = crate::auth::extract_iss_for_routing(&token).unwrap();
        assert_eq!(
            iss, "https://idp.example.com",
            "issuer must be extracted without trailing slash"
        );
    }

    #[test]
    fn test_extract_iss_for_routing_normalizes_trailing_slash() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT"}"#.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(
            format!(r#"{{"iss":"https://idp.example.com/","sub":"alice","aud":"unix-oidc","exp":{exp},"iat":{now}}}"#,
                exp = now + 3600)
                .as_bytes(),
        );
        let token = format!("{header}.{payload}.dummysig");

        let iss = crate::auth::extract_iss_for_routing(&token).unwrap();
        assert_eq!(
            iss, "https://idp.example.com",
            "trailing slash must be normalized"
        );
    }

    #[test]
    fn test_extract_iss_for_routing_returns_err_on_malformed_token() {
        let result = crate::auth::extract_iss_for_routing("not.a.valid-base64!token");
        assert!(result.is_err(), "malformed token must return Err");
    }

    #[test]
    fn test_token_validation_failed_audit_event_includes_issuer() {
        // Verify that AuditEvent::token_validation_failed correctly stores the issuer.
        // This is the audit constructor that lib.rs calls; SBUG-01 is that lib.rs was
        // passing None — we test the constructor correctly stores non-None values.
        let event = crate::audit::AuditEvent::token_validation_failed(
            Some("alice"),
            "Token expired",
            Some("10.0.0.1"),
            Some("https://idp.example.com"),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains("idp.example.com"),
            "token_validation_failed audit event must include the oidc_issuer, json: {json}"
        );
    }

    #[test]
    fn test_token_validation_failed_audit_event_with_none_issuer() {
        // When issuer is genuinely unknown (malformed token), oidc_issuer must be null.
        let event = crate::audit::AuditEvent::token_validation_failed(
            Some("alice"),
            "Token malformed",
            Some("10.0.0.1"),
            None,
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains("\"oidc_issuer\":null"),
            "null oidc_issuer must be serialized as null, json: {json}"
        );
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_multi_issuer_dispatch_unknown_issuer_via_authenticate_multi_issuer() {
        // Verify that authenticate_multi_issuer returns UnknownIssuer for an
        // unrecognized token issuer, matching the PAM AUTH_ERR mapping in lib.rs.
        use crate::auth::{authenticate_multi_issuer, AuthError, DPoPAuthConfig};
        use crate::oidc::jwks::IssuerJwksRegistry;
        use crate::policy::config::{EnforcementMode, IdentityConfig, IssuerConfig};

        // Build a minimal token with an issuer not in the config.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let exp = now + 3600;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT"}"#.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(
            format!(r#"{{"iss":"https://unknown.example.com","sub":"x","aud":"unix-oidc","exp":{exp},"iat":{now}}}"#)
                .as_bytes(),
        );
        let token = format!("{header}.{payload}.dummysig");

        let policy = crate::policy::config::PolicyConfig {
            issuers: vec![IssuerConfig {
                issuer_url: "https://known.example.com".to_string(),
                client_id: "unix-oidc".to_string(),
                dpop_enforcement: EnforcementMode::Strict,
                claim_mapping: IdentityConfig::default(),
                ..IssuerConfig::default()
            }],
            ..crate::policy::config::PolicyConfig::default()
        };

        let registry = IssuerJwksRegistry::new();
        let dpop_config = DPoPAuthConfig::default();
        let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
        assert!(
            matches!(result, Err(AuthError::UnknownIssuer(_))),
            "expected UnknownIssuer, got: {result:?}"
        );
    }

    /// F-08 positive: normal hex session_id produces valid JSON.
    #[test]
    fn test_session_closed_json_normal_id() {
        let session_id = "sudo-18d4f2a3b4c-a7f3e2d1c0b9a8f7";
        let msg = serde_json::json!({
            "action": "session_closed",
            "session_id": session_id
        })
        .to_string();

        let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(parsed["action"], "session_closed");
        assert_eq!(parsed["session_id"], session_id);
    }

    /// F-08 negative: session_id containing quotes/backslashes produces properly
    /// escaped JSON (no injection), not a broken JSON structure.
    #[test]
    fn test_session_closed_json_injection_prevented() {
        // An attacker-controlled session_id with JSON-breaking characters.
        let malicious_id = r#"evil","admin":true,"x":"#;
        let msg = serde_json::json!({
            "action": "session_closed",
            "session_id": malicious_id
        })
        .to_string();

        // Must parse as valid JSON with exactly 2 keys.
        let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(
            parsed.as_object().unwrap().len(),
            2,
            "JSON must have exactly 2 keys (no injected fields), got: {msg}"
        );
        // The malicious string must be the literal value, not parsed as JSON structure.
        assert_eq!(parsed["session_id"], malicious_id);
        // Verify no "admin" key was injected.
        assert!(parsed.get("admin").is_none(), "injected key must not exist");
    }
}
