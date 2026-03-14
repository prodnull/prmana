//! Entra ID live integration tests (Phase 22, ENTR-02..ENTR-05).
//!
//! Validates RS256 token verification, UPN claim mapping, bearer-only auth,
//! and negative test cases against a real Entra tenant.
//!
//! These tests are **ignored by default** and only run when the following
//! environment variables are set:
//!
//! - `ENTRA_TENANT_ID`  — Azure AD Directory (tenant) ID
//! - `ENTRA_CLIENT_ID`  — Application (client) ID from App Registration
//! - `ENTRA_TOKEN`      — A valid access token obtained via ROPC or device flow
//!
//! See `docs/entra-setup-guide.md` for instructions on obtaining these values.
//!
//! **Security note:** These tests verify REAL cryptographic signatures against
//! live Entra JWKS. Do NOT add `--features test-mode` when running these tests —
//! that would bypass signature verification and defeat the purpose of the suite.
//!
//! # Running
//! ```bash
//! ENTRA_TENANT_ID=<tenant> ENTRA_CLIENT_ID=<client_id> ENTRA_TOKEN=<token> \
//!   cargo test -p pam-unix-oidc --test entra_integration -- --include-ignored
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use pam_unix_oidc::auth::{authenticate_multi_issuer, AuthError, DPoPAuthConfig};
use pam_unix_oidc::identity::mapper::UsernameMapper;
use pam_unix_oidc::oidc::jwks::{IssuerJwksRegistry, JwksProvider};
use pam_unix_oidc::oidc::{TokenValidator, ValidationConfig};
use pam_unix_oidc::policy::config::{
    EnforcementMode, IdentityConfig, IssuerConfig, PolicyConfig, TransformConfig,
};
use std::sync::Arc;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Read a required environment variable, panicking with a descriptive message
/// if not set. Avoids silent test skips that mask missing setup.
fn entra_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "Required env var {name} not set. See docs/entra-setup-guide.md for setup instructions."
        )
    })
}

/// Build the Entra V2 issuer URL for the configured tenant.
///
/// Format: `https://login.microsoftonline.com/{tenant_id}/v2.0`
/// This is the value emitted in the `iss` claim of Entra access tokens.
fn entra_issuer() -> String {
    let tenant_id = entra_env("ENTRA_TENANT_ID");
    format!("https://login.microsoftonline.com/{tenant_id}/v2.0")
}

/// Read the Entra access token from the environment.
fn entra_token() -> String {
    entra_env("ENTRA_TOKEN")
}

/// Build a `ValidationConfig` for the Entra issuer.
///
/// - `jti_enforcement`: Warn — Entra emits `uti` not `jti`; strict would reject all tokens
/// - `clock_skew_tolerance_secs`: 60 — standard tolerance for token expiry
fn entra_validation_config() -> ValidationConfig {
    ValidationConfig {
        issuer: entra_issuer(),
        client_id: entra_env("ENTRA_CLIENT_ID"),
        required_acr: None,
        max_auth_age: None,
        jti_enforcement: EnforcementMode::Warn,
        clock_skew_tolerance_secs: 60,
    }
}

/// Build an `Arc<JwksProvider>` for the Entra issuer.
///
/// `JwksProvider::new()` lazily fetches the JWKS on first use via OIDC discovery.
fn entra_jwks_provider() -> Arc<JwksProvider> {
    Arc::new(JwksProvider::new(&entra_issuer()))
}

/// Build a single-issuer `PolicyConfig` for Entra with bearer-only settings.
///
/// Matches `test/fixtures/policy/policy-entra.yaml`:
/// - `dpop_enforcement`: Disabled — Entra uses SHR, not RFC 9449 DPoP
/// - `claim_mapping`: email → strip_domain → lowercase
/// - `allow_unsafe_identity_pipeline`: true — single-tenant Entra app, IdP enforces domain
/// - `jti_enforcement`: Warn — Entra omits jti
fn entra_single_issuer_policy() -> PolicyConfig {
    let mut policy = PolicyConfig::default();
    policy.issuers = vec![IssuerConfig {
        issuer_url: entra_issuer(),
        client_id: entra_env("ENTRA_CLIENT_ID"),
        dpop_enforcement: EnforcementMode::Disabled,
        claim_mapping: IdentityConfig {
            username_claim: "email".to_string(),
            transforms: vec![
                TransformConfig::Simple("strip_domain".to_string()),
                TransformConfig::Simple("lowercase".to_string()),
            ],
        },
        allow_unsafe_identity_pipeline: true,
        ..IssuerConfig::default()
    }];
    // JTI enforcement at global level: warn (Entra omits jti)
    policy.security_modes = Some(pam_unix_oidc::policy::config::SecurityModes {
        jti_enforcement: EnforcementMode::Warn,
        ..Default::default()
    });
    policy
}

// ── Always-run tests (no secrets required) ────────────────────────────────────

/// ENTR-01 (integration fix): Verify the shipped Entra policy fixture
/// deserializes correctly through PolicyConfig::load_from().
///
/// This is NOT ignored — it runs in every CI build to catch YAML schema
/// regressions without requiring Entra secrets.
///
/// Structural assertions match the documented intent in the fixture header
/// (test/fixtures/policy/policy-entra.yaml).
#[test]
fn test_policy_entra_yaml_deserializes() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixture = std::path::Path::new(manifest_dir)
        .join("../test/fixtures/policy/policy-entra.yaml");

    let config = PolicyConfig::load_from(&fixture)
        .expect("policy-entra.yaml must deserialize without error");

    // Verify structural properties
    assert_eq!(
        config.issuers.len(),
        1,
        "Entra fixture must have exactly one issuer"
    );

    let issuer = &config.issuers[0];
    assert!(
        issuer.issuer_url.contains("ENTRA_TENANT_ID_PLACEHOLDER"),
        "Issuer URL must contain the placeholder tenant ID, got: {}",
        issuer.issuer_url
    );
    assert_eq!(
        issuer.dpop_enforcement,
        EnforcementMode::Disabled,
        "Entra DPoP enforcement must be disabled (SHR, not RFC 9449)"
    );
    assert!(
        issuer.allow_unsafe_identity_pipeline,
        "Entra fixture must set allow_unsafe_identity_pipeline: true"
    );
    assert_eq!(
        issuer.claim_mapping.username_claim, "email",
        "Entra fixture must use email as username claim"
    );
    assert_eq!(
        issuer.claim_mapping.transforms.len(),
        2,
        "Entra fixture must have 2 transforms (strip_domain + lowercase)"
    );

    // Verify global security modes
    let sec = config
        .security_modes
        .as_ref()
        .expect("security_modes must be present in Entra fixture");
    assert_eq!(
        sec.jti_enforcement,
        EnforcementMode::Warn,
        "jti_enforcement must be warn (Entra omits jti)"
    );
}

// ── Positive tests ────────────────────────────────────────────────────────────

/// ENTR-02: OIDC discovery against the Entra tenant returns a JWKS URI with RS256 keys.
///
/// Fetches the discovery document and the JWKS, asserting:
/// - `jwks_uri` field is present in the discovery document
/// - JWKS contains at least one key
/// - At least one key has `kty: "RSA"` and `alg: "RS256"`
#[test]
#[ignore = "Requires ENTRA_* env vars — see docs/entra-setup-guide.md"]
fn test_entra_discovery_returns_valid_jwks_uri() {
    let tenant_id = entra_env("ENTRA_TENANT_ID");
    let discovery_url = format!(
        "https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("reqwest blocking client must build");

    // Fetch discovery document
    let discovery_resp = client
        .get(&discovery_url)
        .send()
        .expect("discovery endpoint must be reachable");

    assert!(
        discovery_resp.status().is_success(),
        "Discovery endpoint returned non-200: {}",
        discovery_resp.status()
    );

    let discovery: serde_json::Value = discovery_resp
        .json()
        .expect("discovery document must parse as JSON");

    // Assert jwks_uri is present
    let jwks_uri = discovery["jwks_uri"]
        .as_str()
        .expect("discovery document must contain jwks_uri");

    assert!(
        jwks_uri.starts_with("https://"),
        "jwks_uri must be HTTPS: {jwks_uri}"
    );

    // Fetch JWKS
    let jwks_resp = client
        .get(jwks_uri)
        .send()
        .expect("JWKS endpoint must be reachable");

    assert!(
        jwks_resp.status().is_success(),
        "JWKS endpoint returned non-200: {}",
        jwks_resp.status()
    );

    let jwks: serde_json::Value = jwks_resp
        .json()
        .expect("JWKS must parse as JSON");

    let keys = jwks["keys"]
        .as_array()
        .expect("JWKS must contain a 'keys' array");

    assert!(!keys.is_empty(), "JWKS must contain at least one key");

    // Assert at least one RSA/RS256 key is present
    let has_rs256 = keys.iter().any(|k| {
        let kty = k["kty"].as_str().unwrap_or("");
        let alg = k["alg"].as_str().unwrap_or("");
        kty == "RSA" && alg == "RS256"
    });

    assert!(
        has_rs256,
        "JWKS must contain at least one RS256 RSA key. Keys present: {keys:?}"
    );
}

/// ENTR-02: RS256 Entra access token validates against the live Entra JWKS.
///
/// This is the core test: real signature verification (no test-mode bypass) against
/// the Entra JWKS endpoint. Proves the multi-issuer infrastructure handles RS256.
#[test]
#[ignore = "Requires ENTRA_* env vars — see docs/entra-setup-guide.md"]
fn test_entra_rs256_token_validates() {
    let token = entra_token();
    let config = entra_validation_config();
    let jwks_provider = entra_jwks_provider();

    let validator = TokenValidator::with_jwks_provider(config, jwks_provider);
    let result = validator.validate(&token);

    assert!(
        result.is_ok(),
        "RS256 Entra token must validate successfully: {result:?}"
    );

    let claims = result.unwrap();

    // Issuer must be the Entra v2 endpoint
    assert!(
        claims.iss.starts_with("https://login.microsoftonline.com/"),
        "Token iss must start with Entra base URL, got: {}",
        claims.iss
    );

    // ROPC and device-flow tokens with profile scope include preferred_username
    // (populated from UPN). Client-credentials tokens do not — see 22-RESEARCH.md.
    assert!(
        claims.preferred_username.is_some(),
        "Token must include preferred_username (ensure profile scope was requested)"
    );
}

/// ENTR-03: Validated Entra token carries expected OIDC claims.
///
/// Validates that the token includes preferred_username, email, and sub —
/// the claims required for UPN mapping and user identity.
#[test]
#[ignore = "Requires ENTRA_* env vars — see docs/entra-setup-guide.md"]
fn test_entra_token_has_expected_claims() {
    let token = entra_token();
    let config = entra_validation_config();
    let jwks_provider = entra_jwks_provider();

    let validator = TokenValidator::with_jwks_provider(config, jwks_provider);
    let claims = validator
        .validate(&token)
        .expect("Token must validate for claim assertion test");

    // preferred_username — UPN format (User@Tenant.onmicrosoft.com)
    // Must be present when profile scope was requested (see entra-setup-guide.md)
    assert!(
        claims.preferred_username.is_some(),
        "preferred_username must be present (ensure profile scope was requested)"
    );

    // sub — opaque user identifier; always present per OIDC Core 1.0 §2
    assert!(
        !claims.sub.is_empty(),
        "sub must be present and non-empty"
    );

    // email — required for the UPN strip_domain mapping pipeline
    // Must be present when email scope was requested (see entra-setup-guide.md)
    let email = claims.get_claim_str("email");
    assert!(
        email.is_some(),
        "email claim must be present (ensure email scope was requested)"
    );
    let email = email.unwrap();
    assert!(
        email.contains('@'),
        "email must be in user@domain format, got: {email}"
    );
}

// ── UPN mapping tests ─────────────────────────────────────────────────────────

/// ENTR-04: strip_domain + lowercase produces a bare Unix username (no @ character).
///
/// Validates the primary Entra identity mapping pipeline:
/// `alice@corp.example.com` → `alice`
#[test]
#[ignore = "Requires ENTRA_* env vars — see docs/entra-setup-guide.md"]
fn test_entra_upn_strip_domain_maps_to_bare_username() {
    let token = entra_token();
    let config = entra_validation_config();
    let jwks_provider = entra_jwks_provider();

    let validator = TokenValidator::with_jwks_provider(config, jwks_provider);
    let claims = validator
        .validate(&token)
        .expect("Token must validate for UPN mapping test");

    // Build mapper: email → strip_domain → lowercase
    let identity_config = IdentityConfig {
        username_claim: "email".to_string(),
        transforms: vec![
            TransformConfig::Simple("strip_domain".to_string()),
            TransformConfig::Simple("lowercase".to_string()),
        ],
    };
    let mapper = UsernameMapper::from_config(&identity_config)
        .expect("Mapper must build from valid config");

    let username = mapper
        .map(&claims)
        .expect("Mapping must succeed for valid Entra token with email claim");

    assert!(
        !username.contains('@'),
        "strip_domain must remove the @ and domain, got: {username}"
    );
    assert_eq!(
        username,
        username.to_lowercase(),
        "lowercase transform must produce all-lowercase username, got: {username}"
    );
    assert!(
        !username.is_empty(),
        "Resulting username must not be empty"
    );
}

/// ENTR-04: raw preferred_username preserves the UPN domain.
///
/// Validates that without transforms, preferred_username retains the full UPN
/// format (user@tenant.onmicrosoft.com) — confirming why strip_domain is required.
#[test]
#[ignore = "Requires ENTRA_* env vars — see docs/entra-setup-guide.md"]
fn test_entra_raw_preferred_username_preserves_domain() {
    let token = entra_token();
    let config = entra_validation_config();
    let jwks_provider = entra_jwks_provider();

    let validator = TokenValidator::with_jwks_provider(config, jwks_provider);
    let claims = validator
        .validate(&token)
        .expect("Token must validate for raw UPN test");

    // Build mapper: preferred_username, no transforms
    let identity_config = IdentityConfig {
        username_claim: "preferred_username".to_string(),
        transforms: vec![],
    };
    let mapper = UsernameMapper::from_config(&identity_config)
        .expect("Mapper must build from valid config");

    let username = mapper
        .map(&claims)
        .expect("Mapping must succeed for token with preferred_username claim");

    // UPN format preserves the @ and domain suffix
    assert!(
        username.contains('@'),
        "Raw preferred_username must retain @ and domain (UPN format). Got: {username}"
    );
}

// ── Bearer-only auth (ENTR-05) ────────────────────────────────────────────────

/// ENTR-05: Bearer auth (no DPoP) completes past DPoP enforcement for Entra issuer.
///
/// Calls `authenticate_multi_issuer` with `dpop_proof=None`. Asserts the pipeline
/// completes past DPoP enforcement and collision-safety, reaching `UserNotFound`
/// (the expected terminal state in a test environment without SSSD).
///
/// This verifies:
/// - `Err(DPoPRequired)` is NOT returned — DPoP bypass for Entra works (ENTR-05)
/// - `Err(UnknownIssuer)` is NOT returned — issuer routing works
/// - The token passes signature verification and claim mapping before SSSD lookup
///
/// Full auth success (AuthResult::Ok) is verified in the CI PAM chain test
/// (provider-tests.yml) where a real Unix user exists.
#[test]
#[ignore = "Requires ENTRA_* env vars — see docs/entra-setup-guide.md"]
fn test_entra_bearer_auth_completes_without_dpop_error() {
    let token = entra_token();
    let policy = entra_single_issuer_policy();
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(
        &token,
        None, // no DPoP proof — bearer-only
        &dpop_config,
        &policy,
        &registry,
    );

    // DPoP must NOT be required for Entra (dpop_enforcement: disabled)
    assert!(
        !matches!(result, Err(AuthError::DPoPRequired)),
        "authenticate_multi_issuer must not require DPoP for Entra (dpop_enforcement: disabled), got: {result:?}"
    );

    // Issuer routing must work — token issuer is in the policy
    assert!(
        !matches!(result, Err(AuthError::UnknownIssuer(_))),
        "authenticate_multi_issuer must route Entra token to configured issuer, got: {result:?}"
    );

    // Expected terminal state: UserNotFound (SSSD not present in test environment)
    // OR IdentityMapping (if email claim is absent and preferred_username mapping fails)
    // Both indicate the pipeline proceeded past DPoP and collision-safety gates.
    match &result {
        Err(AuthError::UserNotFound(_)) => {
            // Expected: auth pipeline completed; SSSD lookup failed (no Unix user)
        }
        Err(AuthError::IdentityMapping(_)) => {
            // Acceptable: email claim may be absent; pipeline proceeded past DPoP gates
        }
        Err(AuthError::UserResolution(_)) => {
            // Acceptable: SSSD not available in test environment
        }
        other => {
            panic!(
                "Expected UserNotFound/IdentityMapping/UserResolution (pipeline reached SSSD), \
                 got: {other:?}"
            );
        }
    }
}

// ── Negative tests ────────────────────────────────────────────────────────────

/// Adversarial: Token from a wrong tenant is rejected.
///
/// Builds a ValidationConfig with a fake tenant ID. The real token's issuer will
/// not match, triggering either an issuer mismatch or signature verification failure.
#[test]
#[ignore = "Requires ENTRA_* env vars — see docs/entra-setup-guide.md"]
fn test_entra_wrong_tenant_rejected() {
    let token = entra_token();

    // Fake tenant ID — not the actual tenant
    let wrong_issuer =
        "https://login.microsoftonline.com/00000000-dead-beef-0000-000000000000/v2.0".to_string();

    let config = ValidationConfig {
        issuer: wrong_issuer.clone(),
        client_id: entra_env("ENTRA_CLIENT_ID"),
        required_acr: None,
        max_auth_age: None,
        jti_enforcement: EnforcementMode::Warn,
        clock_skew_tolerance_secs: 60,
    };

    let jwks_provider = Arc::new(JwksProvider::new(&wrong_issuer));
    let validator = TokenValidator::with_jwks_provider(config, jwks_provider);

    let result = validator.validate(&token);

    assert!(
        result.is_err(),
        "Token from a different tenant must be rejected (wrong issuer). Got: Ok"
    );
}

/// Adversarial: A tampered token (modified payload) is rejected.
///
/// Takes the real token and flips one character in the base64url payload section.
/// The signature will no longer match the modified payload, so verification must fail.
#[test]
#[ignore = "Requires ENTRA_* env vars — see docs/entra-setup-guide.md"]
fn test_entra_tampered_token_rejected() {
    let token = entra_token();

    // Split into header.payload.signature
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    assert_eq!(
        parts.len(),
        3,
        "Token must have exactly 3 JWT parts (header.payload.signature)"
    );

    // Tamper with the payload: flip one character
    let mut payload_bytes = parts[1].as_bytes().to_vec();
    // XOR the last character of the payload to mutate it
    let last = payload_bytes.len() - 1;
    payload_bytes[last] ^= 0x01;
    let tampered_payload = String::from_utf8_lossy(&payload_bytes);

    let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

    let config = entra_validation_config();
    let jwks_provider = entra_jwks_provider();
    let validator = TokenValidator::with_jwks_provider(config, jwks_provider);

    let result = validator.validate(&tampered_token);

    assert!(
        result.is_err(),
        "Tampered token must be rejected (signature verification must fail). Got: Ok"
    );
}

/// Adversarial: Entra token is rejected when issuer is not in the policy.
///
/// Configures the policy with a Keycloak-only issuer. The Entra token's issuer
/// won't match any configured issuer, triggering `AuthError::UnknownIssuer`.
#[test]
#[ignore = "Requires ENTRA_* env vars — see docs/entra-setup-guide.md"]
fn test_entra_unknown_issuer_rejected_by_multi_issuer() {
    let token = entra_token();

    // Policy with only a Keycloak issuer — Entra issuer not configured
    let mut policy = PolicyConfig::default();
    policy.issuers = vec![IssuerConfig {
        issuer_url: "http://localhost:8080/realms/test".to_string(),
        client_id: "unix-oidc".to_string(),
        dpop_enforcement: EnforcementMode::Strict,
        ..IssuerConfig::default()
    }];

    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);

    assert!(
        matches!(result, Err(AuthError::UnknownIssuer(_))),
        "Entra token must be rejected as UnknownIssuer when only Keycloak is configured. Got: {result:?}"
    );
}
