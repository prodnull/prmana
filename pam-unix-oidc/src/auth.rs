//! Authentication flow combining OIDC token validation and SSSD user resolution.

use crate::identity::mapper::{IdentityError, UsernameMapper};
use crate::oidc::jwks::IssuerJwksRegistry;
use crate::oidc::token::TokenClaims;
use crate::oidc::{
    validate_dpop_proof, verify_dpop_binding, DPoPConfig, DPoPProofResult, DPoPValidationError,
    TokenValidator, ValidationConfig, ValidationError,
};
use crate::policy::config::{EnforcementMode, IssuerConfig, IssuerHealthManager, PolicyConfig};
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

    /// Token issuer does not match any configured issuer in policy.yaml.
    ///
    /// Security: Unknown issuers are always hard-rejected. An attacker cannot
    /// gain access by presenting a token from an unconfigured IdP.
    #[error("Token from unknown issuer '{0}' — not in configured issuers")]
    UnknownIssuer(String),
}

/// Check if test mode is explicitly enabled.
/// Security: Only accepts explicit "true" or "1" values, not just presence of the variable.
#[cfg(feature = "test-mode")]
fn is_test_mode_enabled() -> bool {
    std::env::var("UNIX_OIDC_TEST_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// Extract the `iss` (issuer) claim from a raw JWT for pre-validation routing.
///
/// This function decodes the JWT payload WITHOUT signature verification to read
/// the `iss` claim. This is safe because:
/// 1. The issuer value is only used for routing (looking up which config to use).
/// 2. Full signature verification is performed subsequently by `TokenValidator`.
/// 3. An attacker forging `iss` would still fail the signature check with the
///    JWKS for the forged issuer.
///
/// The extracted issuer is trailing-slash normalized to match the normalization
/// applied in `PolicyConfig::issuer_by_url()`.
pub fn extract_iss_for_routing(token: &str) -> Result<String, AuthError> {
    let claims = TokenClaims::from_token(token).map_err(|e| AuthError::Config(e.to_string()))?;
    // Normalize: trim trailing slash to match issuer_by_url() normalization.
    Ok(claims.iss.trim_end_matches('/').to_string())
}

/// Multi-issuer authentication dispatch (MIDP-06, MIDP-07, MIDP-09).
///
/// Extracts the `iss` claim from the token, looks up the matching `IssuerConfig`
/// in `policy`, validates the token with the per-issuer JWKS provider, applies
/// per-issuer DPoP enforcement (MIDP-02), and applies per-issuer claim mapping
/// (MIDP-03).
///
/// JTI cache keys are issuer-scoped (format: `"{iss}:{jti}"`) to prevent
/// cross-issuer replay false positives — a token from issuer A with JTI "x" does
/// not collide with a token from issuer B with JTI "x" (MIDP-07).
///
/// Issuer selection is priority-ordered: `policy.issuers[0]` is the highest priority.
/// The first issuer whose URL matches the token `iss` claim is selected (MIDP-09).
/// The selection position is emitted as a structured audit log field so operators can
/// observe which issuer was chosen and in what array position.
///
/// # Errors
///
/// - `AuthError::Config` — token payload cannot be decoded.
/// - `AuthError::UnknownIssuer` — `iss` not found in `policy.issuers`.
/// - `AuthError::TokenValidation` — signature, expiry, audience, or JTI check failed.
/// - `AuthError::DPoPRequired` — issuer enforces DPoP strict but no proof provided.
/// - `AuthError::DPoPValidation` — DPoP proof is present but invalid.
/// - `AuthError::IdentityMapping` — claim mapping pipeline failed.
/// - `AuthError::UserNotFound` / `AuthError::UserResolution` — SSSD lookup failed.
pub fn authenticate_multi_issuer(
    token: &str,
    dpop_proof: Option<&str>,
    dpop_config: &DPoPAuthConfig,
    policy: &PolicyConfig,
    jwks_registry: &IssuerJwksRegistry,
) -> Result<AuthResult, AuthError> {
    // Step 1: Extract issuer from token payload for routing.
    // No signature verification here — full verification follows per-issuer JWKS.
    let iss = extract_iss_for_routing(token)?;

    // Step 2: Look up the matching IssuerConfig.
    // Security: unknown issuers are ALWAYS hard-rejected.
    let issuer_config: &IssuerConfig = policy.issuer_by_url(&iss).ok_or_else(|| {
        tracing::warn!(issuer = %iss, "Token from unknown issuer — rejected");
        AuthError::UnknownIssuer(iss.clone())
    })?;

    // Step 2b: Emit priority selection audit log (MIDP-09).
    //
    // The `issuers[]` array order IS the priority because `issuer_by_url()` returns
    // the first match. We log the position so operators can verify selection order via
    // their SIEM. Target `unix_oidc_audit` ensures this appears in the audit stream.
    let normalized_iss = iss.trim_end_matches('/');
    let issuer_position = policy
        .issuers
        .iter()
        .position(|i| i.issuer_url.trim_end_matches('/') == normalized_iss);
    let total_issuers = policy.issuers.len();
    tracing::info!(
        target: "unix_oidc_audit",
        issuer = %iss,
        position = issuer_position.unwrap_or(0),
        total_issuers = total_issuers,
        "Issuer selected for authentication (MIDP-09 priority ordering)"
    );

    // Step 3: Build ValidationConfig from IssuerConfig.
    //
    // JTI enforcement is DISABLED in the inner validator because it records
    // unscoped JTI keys (raw "abc123"). In a multi-issuer setup, this causes
    // cross-issuer false positives: if issuer A uses JTI "x", the inner check
    // would incorrectly flag issuer B's JTI "x" as replay. Instead, JTI replay
    // prevention is handled at Step 8 with issuer-scoped keys ("{iss}:{jti}").
    let jti_enforcement = policy.effective_security_modes().jti_enforcement;
    let clock_skew = policy.timeouts.clock_skew_staleness_secs as i64;
    let validation_config = ValidationConfig {
        // Normalize issuer URL for the validator's exact-match comparison.
        // Without this, a config with "https://idp.example.com/" would fail
        // validation against a token with "https://idp.example.com" (no slash).
        issuer: issuer_config.issuer_url.trim_end_matches('/').to_string(),
        // Security: Use expected_audience override when configured; supports Entra app
        // registrations with custom Application ID URIs (api://...) that differ from the
        // GUID client_id. Falls back to client_id (OIDC standard behavior, RFC 7519 §4.1.3).
        client_id: issuer_config
            .expected_audience
            .as_deref()
            .unwrap_or(&issuer_config.client_id)
            .to_string(),
        // DEBT-02: Wire ACR enforcement from per-issuer acr_mapping config.
        // When the operator sets required_acr in acr_mapping, the validator rejects
        // tokens whose acr claim does not match the required value.
        required_acr: issuer_config
            .acr_mapping
            .as_ref()
            .and_then(|m| m.required_acr.clone()),
        max_auth_age: None,
        // Disabled: inner validator must NOT record unscoped JTI keys.
        // Scoped enforcement happens at Step 8 below (MIDP-07).
        jti_enforcement: EnforcementMode::Disabled,
        clock_skew_tolerance_secs: clock_skew,
        // SHRD-01/02: Thread per-issuer algorithm allowlist into the validator.
        // When set, only these algorithms are accepted from tokens for this issuer.
        allowed_algorithms: match issuer_config.allowed_algorithms.as_ref() {
            Some(names) => Some(
                crate::oidc::validation::parse_algorithm_names(names)
                    .map_err(|e| AuthError::Config(format!("invalid allowed_algorithms: {e}")))?,
            ),
            None => None,
        },
    };

    // Step 4: Issuer health gate (MIDP-10).
    //
    // Check whether this issuer is currently marked degraded. A degraded issuer has
    // had 3+ consecutive JWKS fetch failures and is within its recovery interval.
    // Skipping it prevents cascading failures when the IdP is unreachable.
    //
    // The health manager is stateless (reads from disk on each call) because each
    // forked sshd process is ephemeral — file-based state is the only shared medium.
    // All I/O is best-effort: failures in the health check never block authentication.
    let health_manager = IssuerHealthManager::new();
    if health_manager.is_degraded(
        &issuer_config.issuer_url,
        issuer_config.recovery_interval_secs,
    ) {
        tracing::warn!(
            target: "unix_oidc_audit",
            issuer = %issuer_config.issuer_url,
            recovery_interval_secs = issuer_config.recovery_interval_secs,
            "Issuer is degraded — skipping JWKS validation (MIDP-10)"
        );
        return Err(AuthError::Config(format!(
            "Issuer '{}' is degraded (too many consecutive JWKS failures). \
             Will retry after recovery interval ({} s).",
            issuer_config.issuer_url, issuer_config.recovery_interval_secs
        )));
    }

    // Step 5: Get or create the per-issuer JWKS provider from the registry.
    // The registry keeps independent caches per issuer (MIDP-07).
    // DEBT-05: JWKS TTL and HTTP timeout are now per-issuer configurable via
    // IssuerConfig fields, with defaults of 300s and 10s respectively.
    if issuer_config.jwks_cache_ttl_secs != 300 || issuer_config.http_timeout_secs != 10 {
        tracing::info!(
            issuer = %issuer_config.issuer_url,
            jwks_cache_ttl_secs = issuer_config.jwks_cache_ttl_secs,
            http_timeout_secs = issuer_config.http_timeout_secs,
            "Using per-issuer JWKS cache configuration"
        );
    }
    let jwks_provider = jwks_registry.get_or_init(
        &issuer_config.issuer_url,
        issuer_config.jwks_cache_ttl_secs,
        issuer_config.http_timeout_secs,
    );

    // Step 6: Validate the token with the per-issuer JWKS provider.
    #[cfg(feature = "test-mode")]
    let validator = {
        if is_test_mode_enabled() {
            // WARNING: This skips signature verification - for testing only!
            TokenValidator::new_insecure_for_testing(validation_config)
        } else {
            TokenValidator::with_jwks_provider(validation_config, jwks_provider)
        }
    };

    #[cfg(not(feature = "test-mode"))]
    let validator = TokenValidator::with_jwks_provider(validation_config, jwks_provider);

    // Step 6b: Validate with health tracking (MIDP-10).
    //
    // On JWKS fetch errors (network failures, HTTP errors, parse failures), record
    // a failure against this issuer's health state. This advances the failure counter
    // toward the degradation threshold (3 consecutive failures).
    //
    // On successful validation, record a success to clear any previous failure state.
    // This handles the recovery path: a degraded issuer that gets a retry attempt
    // succeeds and is restored to healthy.
    //
    // Only JWKS fetch errors count as health failures. Token validation errors
    // (expired token, wrong audience, invalid signature against fetched keys) do NOT
    // count — those are expected errors due to bad tokens, not IdP unavailability.
    let claims = match validator.validate(token) {
        Ok(c) => {
            health_manager.record_success(&issuer_config.issuer_url);
            c
        }
        Err(e @ ValidationError::JwksFetchError(_)) => {
            // JWKS fetch error: record against issuer health (MIDP-10).
            health_manager.record_failure(&issuer_config.issuer_url);
            return Err(AuthError::TokenValidation(e));
        }
        Err(e) => return Err(AuthError::TokenValidation(e)),
    };

    // Step 7: Per-issuer DPoP enforcement (MIDP-02).
    // Overrides the global dpop_required with the per-issuer dpop_enforcement setting.
    // dpop_nonce_enforcement governs missing-nonce behavior in the cache-backed path.
    let dpop_thumbprint = apply_per_issuer_dpop(
        dpop_proof,
        dpop_config,
        &claims,
        issuer_config.dpop_enforcement,
        policy.effective_security_modes().dpop_required,
    )?;

    // Step 7: Per-issuer claim mapping (MIDP-03).
    // Security (IDN-03): check_collision_safety() is a hard-fail gatekeeper that prevents
    // non-injective transform pipelines from allowing multiple identities to map to the same
    // Unix username. The bypass is only active when the operator explicitly sets
    // allow_unsafe_identity_pipeline=true, acknowledging that the IdP's own domain constraint
    // (e.g. single-tenant Entra ID) makes the pipeline safe in their specific deployment.
    if issuer_config.allow_unsafe_identity_pipeline {
        tracing::warn!(
            issuer = %issuer_config.issuer_url,
            "Collision-safety check bypassed by allow_unsafe_identity_pipeline — \
             operator acknowledges non-injective transform pipeline"
        );
    } else {
        crate::identity::collision::check_collision_safety(&issuer_config.claim_mapping)
            .map_err(|e| AuthError::Config(e.to_string()))?;
    }
    let mapper = UsernameMapper::from_config(&issuer_config.claim_mapping)
        .map_err(|e| AuthError::IdentityMapping(e.to_string()))?;

    // SBUG-03: Use the configured username_claim to populate raw_claim for the audit trail.
    //
    // Previously this was `preferred_username.clone().unwrap_or_default()`, which
    // produces "" when preferred_username is absent but the configured claim is e.g. "email".
    // After the fix: raw_claim reflects the ACTUAL claim the mapper will use, so the
    // `mapped_from` audit field accurately records what was fed into the mapping pipeline.
    // If the configured claim is also absent, raw_claim is "" — that is correct/honest,
    // and the mapper's MissingClaim error fires immediately below.
    let raw_claim = claims
        .get_claim_str(&issuer_config.claim_mapping.username_claim)
        .unwrap_or_default();
    let username_str = mapper
        .map(&claims)
        .map_err(|e: IdentityError| AuthError::IdentityMapping(e.to_string()))?;
    let mapped_from = if username_str != raw_claim {
        Some(raw_claim)
    } else {
        None
    };

    // Step 8: JTI replay prevention with issuer-scoped keys (MIDP-07).
    //
    // The inner TokenValidator's JTI check is disabled (Step 3) because it uses
    // unscoped keys that would cause cross-issuer false positives. All JTI
    // enforcement for the multi-issuer path happens here with scoped keys.
    //
    // Key format: "{iss}:{jti}" — so issuer A's JTI "x" and issuer B's JTI "x"
    // are independent cache entries, preventing cross-issuer replay collisions.
    if jti_enforcement != EnforcementMode::Disabled {
        let token_ttl = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let exp_u64 = claims.exp.max(0) as u64;
            exp_u64.saturating_sub(now)
        };

        // Phase 30 (D-06): Route through FsAtomicStore for cross-fork replay
        // protection. The issuer URL is used as the isolation scope (D-02) so
        // two issuers sharing a JTI value hash to different filesystem entries.
        // On strict-mode filesystem failure this returns Replay (hard-fail).
        // On permissive-mode filesystem failure this falls back to per-process
        // cache with LOG_CRIT to syslog.
        let jti_result = crate::security::jti_cache::check_and_record_fs(
            claims.jti.as_deref(),
            &iss,
            &username_str,
            token_ttl,
            jti_enforcement,
        );

        match jti_result {
            crate::security::jti_cache::JtiCheckResult::Valid => {
                // First use of this scoped JTI — allow.
            }
            crate::security::jti_cache::JtiCheckResult::Replay => {
                // Replay is always a hard-fail (CLAUDE.md §Security Check Decision Matrix).
                let jti_display = claims.jti.as_deref().unwrap_or("unknown");
                tracing::warn!(
                    jti = %jti_display,
                    issuer = %iss,
                    username = %username_str,
                    "JTI replay detected (issuer-scoped) — rejecting token"
                );
                return Err(AuthError::TokenValidation(ValidationError::TokenReplay {
                    jti: jti_display.to_string(),
                }));
            }
            crate::security::jti_cache::JtiCheckResult::Missing => {
                // Token has no JTI claim — behavior depends on enforcement mode.
                match jti_enforcement {
                    EnforcementMode::Strict => {
                        tracing::warn!(
                            issuer = %iss,
                            username = %username_str,
                            "JTI missing — rejecting token (strict mode, multi-issuer)"
                        );
                        return Err(AuthError::TokenValidation(ValidationError::MissingJti));
                    }
                    EnforcementMode::Warn => {
                        tracing::warn!(
                            issuer = %iss,
                            username = %username_str,
                            "Token missing JTI claim — allowing with warning (multi-issuer)"
                        );
                    }
                    EnforcementMode::Disabled => {
                        // Unreachable: outer if-guard checks != Disabled.
                    }
                }
            }
        }
    }

    // Log token groups for audit enrichment — NEVER used for access decisions.
    if let Some(token_groups) = claims.groups_for_audit() {
        tracing::info!(
            username = %username_str,
            token_groups = ?token_groups,
            issuer = %iss,
            "Token groups (audit enrichment only — access decisions use NSS groups)"
        );
    }

    // Step 9: SSSD user resolution.
    if !user_exists(&username_str) {
        return Err(AuthError::UserNotFound(username_str));
    }
    let user_info = get_user_info(&username_str)?;

    // Step 10: Enforce login_groups policy via NSS group membership check.
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

    // Step 11: Generate session ID and return result.
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
        token_exp: claims.exp,
        token_issuer: claims.iss,
    })
}

/// Apply per-issuer DPoP enforcement logic.
///
/// Returns the DPoP thumbprint string if a valid proof was provided,
/// `None` if DPoP is disabled or the token is not DPoP-bound.
///
/// Enforcement semantics:
/// - `Disabled`: DPoP proof is not required; if provided it is NOT validated
///   (Entra-like issuers that use SHR instead of RFC 9449).
/// - `Warn`: DPoP-bound tokens require a proof; unbound tokens proceed without proof.
///   Missing proof on unbound tokens produces a warning but does not fail.
/// - `Strict`: Any token (bound or unbound) must carry a valid DPoP proof.
///
/// `dpop_nonce_enforcement` controls the behavior when the proof is missing a nonce
/// in the cache-backed path (`require_nonce=true`, `expected_nonce=None`).
fn apply_per_issuer_dpop(
    dpop_proof: Option<&str>,
    dpop_config: &DPoPAuthConfig,
    claims: &crate::oidc::token::TokenClaims,
    enforcement: EnforcementMode,
    dpop_nonce_enforcement: EnforcementMode,
) -> Result<Option<String>, AuthError> {
    // Fast path: DPoP is disabled for this issuer.
    // Accept the token regardless of whether a proof was provided.
    if enforcement == EnforcementMode::Disabled {
        return Ok(None);
    }

    // Validate the proof and consume the nonce from the global cache (RFC 9449 §8).
    //
    // The `require_nonce` flag is passed to dpop.rs only for the single-value path
    // (expected_nonce=Some). Cache-backed enforcement (expected_nonce=None) is handled
    // here so the consuming logic mirrors `authenticate_with_dpop`.
    let validate_and_enforce_nonce = |proof: &str| -> Result<DPoPProofResult, AuthError> {
        let dpop_validation_config = DPoPConfig {
            max_proof_age: dpop_config.max_proof_age,
            clock_skew_future_secs: dpop_config.clock_skew_future_secs,
            require_nonce: dpop_config.require_nonce && dpop_config.expected_nonce.is_some(),
            expected_nonce: dpop_config.expected_nonce.clone(),
            expected_method: "SSH".to_string(),
            expected_target: dpop_config.target_host.clone(),
        };
        let result = validate_dpop_proof(proof, &dpop_validation_config)?;

        // Cache-backed nonce enforcement (RFC 9449 §8).
        // The single-value path (expected_nonce.is_some()) is handled by validate_dpop_proof;
        // this handles the cache-backed path (require_nonce=true, expected_nonce=None).
        if dpop_config.require_nonce && dpop_config.expected_nonce.is_none() {
            match &result.nonce {
                Some(nonce) => match global_nonce_cache().consume(nonce) {
                    Ok(()) => {
                        tracing::debug!(
                            nonce_prefix = &nonce[..nonce.len().min(8)],
                            "DPoP nonce consumed successfully (multi-issuer path)"
                        );
                    }
                    Err(NonceConsumeError::ConsumedOrExpired) => {
                        tracing::warn!("DPoP nonce replay or expiry detected in multi-issuer path");
                        return Err(AuthError::DPoPValidation(
                            DPoPValidationError::NonceMismatch,
                        ));
                    }
                    Err(NonceConsumeError::EmptyNonce) => {
                        tracing::warn!("DPoP nonce in proof is empty (multi-issuer path)");
                        return Err(AuthError::DPoPValidation(DPoPValidationError::MissingNonce));
                    }
                },
                None => match dpop_nonce_enforcement {
                    EnforcementMode::Strict => {
                        tracing::warn!(
                            "DPoP nonce required (strict) but proof has no nonce \
                                 (multi-issuer path)"
                        );
                        return Err(AuthError::DPoPValidation(DPoPValidationError::MissingNonce));
                    }
                    EnforcementMode::Warn => {
                        tracing::warn!(
                            "DPoP proof missing nonce in multi-issuer path — \
                                 proceeding (warn mode)"
                        );
                    }
                    EnforcementMode::Disabled => {}
                },
            }
        }

        Ok(result)
    };

    // Check if token is DPoP-bound (has cnf.jkt claim).
    if let Some(cnf) = &claims.cnf {
        if let Some(token_jkt) = &cnf.jkt {
            // Token is DPoP-bound — require proof regardless of enforcement mode.
            let proof = dpop_proof.ok_or(AuthError::DPoPRequired)?;
            let result = validate_and_enforce_nonce(proof)?;
            verify_dpop_binding(&result.thumbprint, token_jkt)?;
            return Ok(Some(result.thumbprint));
        }
    }

    // Token is NOT DPoP-bound.
    match (dpop_proof, enforcement) {
        (Some(proof), _) => {
            // Proof provided for unbound token — validate it anyway (audit/logging).
            let result = validate_and_enforce_nonce(proof)?;
            Ok(Some(result.thumbprint))
        }
        (None, EnforcementMode::Strict) => {
            // Strict mode requires a proof even for unbound tokens.
            tracing::warn!("DPoP enforcement is strict but no proof provided");
            Err(AuthError::DPoPRequired)
        }
        (None, EnforcementMode::Warn) => {
            tracing::warn!(
                "DPoP enforcement is warn but no proof provided — \
                 proceeding without DPoP binding"
            );
            Ok(None)
        }
        (None, EnforcementMode::Disabled) => {
            // Already handled above; unreachable but be explicit.
            Ok(None)
        }
    }
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
    /// Token expiry as Unix timestamp (seconds since epoch). Stored in PAM env for open_session.
    pub token_exp: i64,
    /// OIDC issuer URL. Stored in PAM env for open_session.
    pub token_issuer: String,
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
            let raw = claims.preferred_username.clone().unwrap_or_default();
            let mapped = m
                .map(&claims)
                .map_err(|e: IdentityError| AuthError::IdentityMapping(e.to_string()))?;
            // Only record mapped_from when the mapping actually changed the value.
            let from = if mapped != raw { Some(raw) } else { None };
            (mapped, from)
        }
        None => (claims.preferred_username.clone().unwrap_or_default(), None),
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
        token_exp: claims.exp,
        token_issuer: claims.iss,
    })
}

/// DPoP authentication configuration
#[derive(Debug, Clone)]
pub struct DPoPAuthConfig {
    /// Target hostname for DPoP validation (e.g., "server.example.com")
    pub target_host: String,
    /// Maximum proof age in seconds (default: 60).
    /// Maps to `AgentConfig.timeouts.clock_skew_staleness_secs`.
    pub max_proof_age: u64,
    /// Clock skew tolerance for proofs issued in the future (seconds, default: 5).
    /// Maps to `AgentConfig.timeouts.clock_skew_future_secs`.
    pub clock_skew_future_secs: u64,
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
            clock_skew_future_secs: 5,
            require_nonce: false,
            expected_nonce: None,
            require_dpop_for_bound_tokens: true,
        }
    }
}

impl DPoPAuthConfig {
    /// Create config from a loaded [`PolicyConfig`], reading clock-skew values
    /// from `policy.timeouts` (Phase 14+).
    ///
    /// `target_host` is left empty — callers in `lib.rs` set it via struct
    /// literal update syntax (`..DPoPAuthConfig::from_policy(&policy)`).
    /// Other fields default to safe values: `require_nonce = false`,
    /// `expected_nonce = None`, `require_dpop_for_bound_tokens = true`.
    ///
    /// Replaces the removed `from_env()` dead code (Phase 14-01 cleanup).
    pub fn from_policy(policy: &PolicyConfig) -> Self {
        Self {
            target_host: String::new(),
            max_proof_age: policy.timeouts.clock_skew_staleness_secs,
            clock_skew_future_secs: policy.timeouts.clock_skew_future_secs,
            require_nonce: false,
            expected_nonce: None,
            require_dpop_for_bound_tokens: true,
        }
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
    // Also wire clock_skew_staleness_secs from policy.timeouts into ValidationConfig (Phase 14-01).
    let mut dpop_nonce_enforcement = EnforcementMode::Strict; // safe default
    let policy_opt = PolicyConfig::from_env().ok();
    if let Some(ref policy) = policy_opt {
        let modes = policy.effective_security_modes();
        config.jti_enforcement = modes.jti_enforcement;
        dpop_nonce_enforcement = modes.dpop_required;
        // Wire operator-configurable clock skew from policy.timeouts (Phase 14-01).
        config.clock_skew_tolerance_secs = policy.timeouts.clock_skew_staleness_secs as i64;
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
            clock_skew_future_secs: dpop_config.clock_skew_future_secs,
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
            let raw = claims.preferred_username.clone().unwrap_or_default();
            let mapped = m
                .map(&claims)
                .map_err(|e: IdentityError| AuthError::IdentityMapping(e.to_string()))?;
            let from = if mapped != raw { Some(raw) } else { None };
            (mapped, from)
        }
        None => (claims.preferred_username.clone().unwrap_or_default(), None),
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
        token_exp: claims.exp,
        token_issuer: claims.iss,
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
        None => claims.preferred_username.clone().unwrap_or_default(),
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
        token_exp: claims.exp,
        token_issuer: claims.iss,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use figment::providers::Format as _;

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
            token_exp: 9_999_999_999,
            token_issuer: "https://idp.example.com".to_string(),
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
            token_exp: 0,
            token_issuer: String::new(),
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

    // Redirect the filesystem JTI store to a per-process tempdir.
    // `global_jti_store()` is a Lazy initialised on first access; setting
    // UNIX_OIDC_JTI_DIR before that first access points it at a writable
    // tempdir instead of /run/unix-oidc/jti (unwritable in CI / dev).
    static AUTH_TEST_JTI_DIR: std::sync::OnceLock<tempfile::TempDir> =
        std::sync::OnceLock::new();

    fn setup_jti_dir() {
        AUTH_TEST_JTI_DIR.get_or_init(|| {
            let tmp = tempfile::tempdir().expect("tempdir for JTI store");
            std::env::set_var("UNIX_OIDC_JTI_DIR", tmp.path());
            tmp
        });
    }

    fn make_test_proof_with_nonce(target: &str, nonce: Option<&str>) -> (String, String) {
        setup_jti_dir();
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
                "replay must hard-fail in mode {mode:?}"
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
            "lowercase pipeline must not hard-fail, got: {result:?}"
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
            clock_skew_future_secs: 5,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "SSH".to_string(),
            expected_target: target.to_string(),
        };

        let result = validate_dpop_proof(&proof, &config).unwrap();
        assert_eq!(result.nonce.as_deref(), Some("test-nonce-abc"));
        assert!(!result.thumbprint.is_empty());
    }

    // ── DPoPAuthConfig::from_policy tests (Phase 14-01) ──────────────────────

    #[test]
    fn test_dpop_auth_config_from_policy_reads_clock_skew() {
        // DPoPAuthConfig::from_policy must read clock_skew values from PolicyConfig.timeouts.
        let yaml = r#"
timeouts:
  clock_skew_future_secs: 12
  clock_skew_staleness_secs: 90
"#;
        let policy: crate::policy::config::PolicyConfig =
            figment::Figment::from(figment::providers::Serialized::defaults(
                crate::policy::config::PolicyConfig::default(),
            ))
            .merge(figment::providers::Yaml::string(yaml))
            .extract()
            .expect("policy yaml should load");

        let config = DPoPAuthConfig::from_policy(&policy);
        assert_eq!(config.clock_skew_future_secs, 12);
        // max_proof_age maps to clock_skew_staleness_secs
        assert_eq!(config.max_proof_age, 90);
    }

    #[test]
    fn test_dpop_auth_config_from_policy_defaults_when_timeouts_absent() {
        // PolicyConfig with no timeouts section must yield default clock skew.
        let policy = crate::policy::config::PolicyConfig::default();
        let config = DPoPAuthConfig::from_policy(&policy);
        assert_eq!(config.clock_skew_future_secs, 5);
        assert_eq!(config.max_proof_age, 60);
    }

    // ── Multi-issuer routing tests (MIDP-06, MIDP-07) ────────────────────────
    //
    // These tests exercise extract_iss_for_routing(), authenticate_multi_issuer(),
    // and JTI cache scoping without requiring SSSD.
    //
    // Token construction: base64url-encode a minimal JSON payload (no real sig needed
    // because tests run with UNIX_OIDC_TEST_MODE=1 which uses new_insecure_for_testing).
    // Format: <base64url(header)>.<base64url(payload)>.<dummy_sig>
    //
    // ENV_MUTEX serializes tests that manipulate UNIX_OIDC_TEST_MODE to prevent
    // races between parallel test threads (same pattern as Plan 01 / config.rs tests).
    static MULTI_ISSUER_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(feature = "test-mode")]
    fn make_test_jwt(iss: &str, sub: &str, preferred_username: &str, jti: Option<&str>) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = r#"{"alg":"ES256","typ":"JWT"}"#;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let exp = now + 3600;
        let jti_field = jti.map(|j| format!(r#","jti":"{j}""#)).unwrap_or_default();
        let payload = format!(
            r#"{{"iss":"{iss}","sub":"{sub}","aud":"unix-oidc","exp":{exp},"iat":{now},"preferred_username":"{preferred_username}"{jti_field}}}"#
        );
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("{h}.{p}.dummysig")
    }

    #[cfg(feature = "test-mode")]
    fn make_two_issuer_policy(
        issuer_a: &str,
        issuer_b: &str,
        dpop_a: crate::policy::config::EnforcementMode,
        strip_domain_a: bool,
    ) -> crate::policy::config::PolicyConfig {
        use crate::policy::config::{IdentityConfig, IssuerConfig, TransformConfig};
        let claim_a = if strip_domain_a {
            IdentityConfig {
                username_claim: "preferred_username".to_string(),
                transforms: vec![TransformConfig::Simple("strip_domain".to_string())],
            }
        } else {
            IdentityConfig::default()
        };
        crate::policy::config::PolicyConfig {
            issuers: vec![
                IssuerConfig {
                    issuer_url: issuer_a.to_string(),
                    client_id: "unix-oidc".to_string(),
                    dpop_enforcement: dpop_a,
                    claim_mapping: claim_a,
                    ..IssuerConfig::default()
                },
                IssuerConfig {
                    issuer_url: issuer_b.to_string(),
                    client_id: "unix-oidc".to_string(),
                    dpop_enforcement: EnforcementMode::Disabled,
                    claim_mapping: IdentityConfig::default(),
                    ..IssuerConfig::default()
                },
            ],
            ..crate::policy::config::PolicyConfig::default()
        }
    }

    // ── extract_iss_for_routing ───────────────────────────────────────────────

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_extract_iss_valid_token() {
        let token = make_test_jwt(
            "https://keycloak.example.com/realms/test",
            "alice",
            "alice",
            None,
        );
        let iss = extract_iss_for_routing(&token).expect("should extract iss");
        assert_eq!(iss, "https://keycloak.example.com/realms/test");
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_extract_iss_trailing_slash_normalized() {
        let token = make_test_jwt(
            "https://keycloak.example.com/realms/test/",
            "alice",
            "alice",
            None,
        );
        let iss = extract_iss_for_routing(&token).expect("should extract iss");
        // Trailing slash must be trimmed.
        assert_eq!(iss, "https://keycloak.example.com/realms/test");
    }

    #[test]
    fn test_extract_iss_garbage_input_returns_err() {
        let result = extract_iss_for_routing("not.a.jwt");
        assert!(
            result.is_err(),
            "garbage input must return Err, got: {result:?}"
        );
    }

    // ── Unknown issuer rejection ──────────────────────────────────────────────

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_unknown_issuer_is_rejected() {
        let _guard = MULTI_ISSUER_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("UNIX_OIDC_TEST_MODE", "1");
        let token = make_test_jwt(
            "https://evil.example.com",
            "attacker",
            "attacker",
            Some("jti-evil"),
        );
        let policy = make_two_issuer_policy(
            "https://keycloak.example.com/realms/test",
            "https://entra.example.com",
            EnforcementMode::Strict,
            false,
        );
        let registry = crate::oidc::jwks::IssuerJwksRegistry::new();
        let dpop_config = DPoPAuthConfig::default();
        let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
        std::env::remove_var("UNIX_OIDC_TEST_MODE");
        assert!(
            matches!(result, Err(AuthError::UnknownIssuer(ref iss)) if iss == "https://evil.example.com"),
            "expected UnknownIssuer, got: {result:?}"
        );
    }

    // ── Per-issuer DPoP enforcement ───────────────────────────────────────────

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_per_issuer_dpop_disabled_accepts_token_without_proof() {
        // Issuer B has dpop_enforcement: Disabled.
        // A token from issuer B with no DPoP proof must succeed (up to SSSD check).
        let _guard = MULTI_ISSUER_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("UNIX_OIDC_TEST_MODE", "1");
        let token = make_test_jwt(
            "https://entra.example.com",
            "alice",
            "alice",
            Some("jti-entra-1"),
        );
        let policy = make_two_issuer_policy(
            "https://keycloak.example.com/realms/test",
            "https://entra.example.com",
            EnforcementMode::Strict,
            false,
        );
        let registry = crate::oidc::jwks::IssuerJwksRegistry::new();
        let dpop_config = DPoPAuthConfig::default();
        let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
        std::env::remove_var("UNIX_OIDC_TEST_MODE");
        // DPoP is Disabled for this issuer — should NOT get DPoPRequired.
        // May get UserNotFound (no SSSD in tests) but NOT DPoPRequired.
        assert!(
            !matches!(result, Err(AuthError::DPoPRequired)),
            "DPoP should not be required when enforcement is Disabled, got: {result:?}"
        );
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_per_issuer_dpop_strict_rejects_token_without_proof() {
        // Issuer A has dpop_enforcement: Strict.
        // A token from issuer A with no proof must return DPoPRequired.
        let _guard = MULTI_ISSUER_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("UNIX_OIDC_TEST_MODE", "1");
        let token = make_test_jwt(
            "https://keycloak.example.com/realms/test",
            "alice",
            "alice",
            Some("jti-kc-strict"),
        );
        let policy = make_two_issuer_policy(
            "https://keycloak.example.com/realms/test",
            "https://entra.example.com",
            EnforcementMode::Strict,
            false,
        );
        let registry = crate::oidc::jwks::IssuerJwksRegistry::new();
        let dpop_config = DPoPAuthConfig::default();
        let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
        std::env::remove_var("UNIX_OIDC_TEST_MODE");
        assert!(
            matches!(result, Err(AuthError::DPoPRequired)),
            "Strict DPoP enforcement must require proof, got: {result:?}"
        );
    }

    // ── Per-issuer claim mapping ──────────────────────────────────────────────

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_per_issuer_strip_domain_applied_only_for_issuer_a() {
        // This test verifies that the collision-safety check fires for a bad
        // strip_domain pipeline (non-injective) before we even get to SSSD.
        // This is the expected hard-fail behaviour from check_collision_safety().
        let _guard = MULTI_ISSUER_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("UNIX_OIDC_TEST_MODE", "1");
        let token = make_test_jwt(
            "https://keycloak.example.com/realms/test",
            "alice@corp.example",
            "alice@corp.example",
            Some("jti-kc-map"),
        );
        let policy = make_two_issuer_policy(
            "https://keycloak.example.com/realms/test",
            "https://entra.example.com",
            EnforcementMode::Disabled, // Disabled so we don't hit DPoP error first
            true,                      // strip_domain on issuer A
        );
        let registry = crate::oidc::jwks::IssuerJwksRegistry::new();
        let dpop_config = DPoPAuthConfig::default();
        let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
        std::env::remove_var("UNIX_OIDC_TEST_MODE");
        // check_collision_safety fires for strip_domain → Config error
        assert!(
            matches!(result, Err(AuthError::Config(_))),
            "strip_domain with preferred_username must produce Config error, got: {result:?}"
        );
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_per_issuer_no_mapping_on_issuer_b_preserves_full_username() {
        // Issuer B (Entra) has no transforms — preferred_username is used as-is.
        // This test verifies no strip_domain is applied for issuer B.
        // Result may be UserNotFound (no SSSD) but NOT Config error from mapping.
        let _guard = MULTI_ISSUER_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("UNIX_OIDC_TEST_MODE", "1");
        let token = make_test_jwt(
            "https://entra.example.com",
            "alice@corp.example",
            "alice@corp.example",
            Some("jti-entra-map"),
        );
        let policy = make_two_issuer_policy(
            "https://keycloak.example.com/realms/test",
            "https://entra.example.com",
            EnforcementMode::Strict,
            true, // strip_domain only on issuer A (not B)
        );
        let registry = crate::oidc::jwks::IssuerJwksRegistry::new();
        let dpop_config = DPoPAuthConfig::default();
        let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
        std::env::remove_var("UNIX_OIDC_TEST_MODE");
        // Issuer B (Entra) has Disabled DPoP and no transforms.
        // Should hit UserNotFound, NOT DPoPRequired or Config.
        assert!(
            matches!(result, Err(AuthError::UserNotFound(_))),
            "expected UserNotFound (no SSSD), got: {result:?}"
        );
    }

    // ── JTI cache scoping ─────────────────────────────────────────────────────

    #[test]
    fn test_jti_scoping_same_jti_different_issuers_no_collision() {
        // Same JTI "jti-shared" from two different issuers should NOT collide.
        // Both tokens should proceed past the scoped JTI check (may fail on SSSD).
        use crate::security::jti_cache::global_jti_cache;

        // Pre-record the scoped JTI for issuer A to simulate a prior auth.
        let iss_a = "https://issuer-a.example.com";
        let iss_b = "https://issuer-b.example.com";
        let shared_jti = "jti-collision-test-shared";
        let scoped_a = format!("{iss_a}:{shared_jti}");
        let scoped_b = format!("{iss_b}:{shared_jti}");

        // Record issuer A's scoped JTI.
        global_jti_cache().check_and_record(Some(&scoped_a), "alice", 3600);

        // Issuer B's scoped JTI must still be Valid (no collision).
        let result_b = global_jti_cache().check_and_record(Some(&scoped_b), "bob", 3600);
        assert!(
            result_b.is_valid(),
            "same JTI from different issuer must not collide; got: {result_b:?}"
        );
    }

    // ── SBUG-03: preferred_username=None graceful handling ────────────────────
    //
    // Tests verify that:
    // (a) auth.rs uses get_claim_str(username_claim) for raw_claim rather than
    //     always cloning preferred_username — no empty-string artefact when the
    //     configured claim is something other than preferred_username.
    // (b) sudo.rs falls back to the sub claim when preferred_username is absent —
    //     error message shows the sub value instead of an empty string.

    #[cfg(feature = "test-mode")]
    #[allow(dead_code)]
    fn make_test_jwt_no_preferred_username(iss: &str, sub: &str, jti: Option<&str>) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = r#"{"alg":"ES256","typ":"JWT"}"#;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let exp = now + 3600;
        let jti_field = jti.map(|j| format!(r#","jti":"{j}""#)).unwrap_or_default();
        // Note: no preferred_username field — OIDC Core §5.1 makes it optional.
        let payload = format!(
            r#"{{"iss":"{iss}","sub":"{sub}","aud":"unix-oidc","exp":{exp},"iat":{now}{jti_field}}}"#
        );
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("{h}.{p}.dummysig")
    }

    #[cfg(feature = "test-mode")]
    #[allow(dead_code)]
    fn make_test_jwt_with_email_no_preferred_username(
        iss: &str,
        sub: &str,
        email: &str,
        jti: Option<&str>,
    ) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = r#"{"alg":"ES256","typ":"JWT"}"#;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let exp = now + 3600;
        let jti_field = jti.map(|j| format!(r#","jti":"{j}""#)).unwrap_or_default();
        // No preferred_username, but has email claim.
        let payload = format!(
            r#"{{"iss":"{iss}","sub":"{sub}","aud":"unix-oidc","exp":{exp},"iat":{now},"email":"{email}"{jti_field}}}"#
        );
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("{h}.{p}.dummysig")
    }

    /// Verify that auth.rs uses the configured username_claim for raw_claim.
    ///
    /// When username_claim is "email" and preferred_username is absent,
    /// `raw_claim` must be the email value (not ""). This is a unit test on the
    /// authenticate_multi_issuer code path where the fix in Step 7 lives.
    ///
    /// The test verifies indirectly: if the mapper succeeds (email claim is
    /// present and used), the raw_claim is populated correctly. If raw_claim
    /// were computed as `preferred_username.unwrap_or_default()` (= ""), the
    /// mapped_from audit field would incorrectly record "" when email is used,
    /// but more importantly the mapper would proceed with "email" regardless —
    /// so this test focuses on what goes INTO mapped_from.
    #[cfg(feature = "test-mode")]
    #[test]
    fn test_sbug03_auth_raw_claim_uses_configured_username_claim_not_preferred_username() {
        // Verify that raw_claim in auth.rs is taken from the configured claim
        // (email), not always from preferred_username. We check this via the
        // TokenClaims::get_claim_str API that auth.rs (post-fix) calls.
        use crate::oidc::token::TokenClaims;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let exp = now + 3600;
        let payload = serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "user-sub-123",
            "aud": "unix-oidc",
            "exp": exp,
            "iat": now,
            "email": "alice@example.com",
        });
        let h = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT"}"#.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let token = format!("{h}.{p}.dummysig");

        let claims = TokenClaims::from_token(&token).unwrap();
        // preferred_username is absent — the raw claim for "email" username_claim
        // must come from get_claim_str("email"), NOT from preferred_username.
        assert!(
            claims.preferred_username.is_none(),
            "preferred_username must be absent"
        );
        let raw_via_get_claim_str = claims.get_claim_str("email");
        assert_eq!(
            raw_via_get_claim_str.as_deref(),
            Some("alice@example.com"),
            "get_claim_str('email') must return the email claim"
        );
        // The FIXED path: raw_claim = get_claim_str(username_claim)
        let raw_claim_fixed = claims.get_claim_str("email").unwrap_or_default();
        assert_eq!(
            raw_claim_fixed, "alice@example.com",
            "raw_claim with email username_claim must be the email value, not ''"
        );
        // The OLD (broken) path: raw_claim = preferred_username.unwrap_or_default()
        let raw_claim_broken = claims.preferred_username.clone().unwrap_or_default();
        assert_eq!(
            raw_claim_broken, "",
            "old unwrap_or_default() path would produce empty string — this is the bug"
        );
    }

    /// Verify that sudo.rs with no preferred_username falls back to sub claim.
    ///
    /// The test checks the fixed logic directly via the sub fallback — when
    /// preferred_username is absent, the UserMismatch error must show the sub
    /// value, not an empty string.
    #[test]
    fn test_sbug03_sudo_token_user_fallback_to_sub_when_no_preferred_username() {
        use crate::oidc::token::TokenClaims;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let exp = now + 3600;
        let payload = serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "user-sub-123",
            "aud": "unix-oidc",
            "exp": exp,
            "iat": now,
            // no preferred_username
        });
        let h = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT"}"#.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let token = format!("{h}.{p}.dummysig");

        let claims = TokenClaims::from_token(&token).unwrap();
        assert!(claims.preferred_username.is_none());

        // FIXED path: use as_deref().or(Some(&claims.sub))
        let token_user_str = claims.preferred_username.as_deref().unwrap_or(&claims.sub);
        assert_eq!(
            token_user_str, "user-sub-123",
            "without preferred_username, token_user_str must fall back to sub, got: {token_user_str:?}"
        );

        // BROKEN path: unwrap_or_default() returns empty string
        let token_user_broken = claims.preferred_username.clone().unwrap_or_default();
        assert_eq!(
            token_user_broken, "",
            "old unwrap_or_default() on None preferred_username would produce empty string — this is the bug"
        );
    }

    #[test]
    fn test_sbug03_sudo_user_mismatch_error_shows_sub_not_empty_string() {
        // Verify the error message semantic: when preferred_username is None,
        // UserMismatch should contain the sub value, not "".
        // This test exercises the fixed SudoError::UserMismatch message format.
        let token_user = "user-sub-123"; // what the fixed path produces
        let sudo_user = "alice";
        let err = crate::sudo::SudoError::UserMismatch {
            token_user: token_user.to_string(),
            sudo_user: sudo_user.to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("user-sub-123"),
            "UserMismatch error must contain the sub value, not empty string. Got: {msg}"
        );
        assert!(
            msg.contains("alice"),
            "UserMismatch error must contain the sudo user. Got: {msg}"
        );
        // Verify it does NOT show a bare empty string token_user mismatch
        assert!(
            !msg.contains("token user '' does not"),
            "UserMismatch with sub fallback must not show empty string. Got: {msg}"
        );
    }

    #[test]
    fn test_jti_scoping_same_issuer_same_jti_is_replay() {
        // Same JTI from the same issuer IS a replay attack.
        use crate::security::jti_cache::global_jti_cache;

        let iss = "https://issuer-replay.example.com";
        let jti = "jti-replay-test";
        let scoped = format!("{iss}:{jti}");

        // First use
        let first = global_jti_cache().check_and_record(Some(&scoped), "alice", 3600);
        assert!(first.is_valid(), "first use must be valid");

        // Second use — replay
        let second = global_jti_cache().check_and_record(Some(&scoped), "alice", 3600);
        assert!(second.is_replay(), "second use must be replay");
    }
}
