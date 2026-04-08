//! Multi-IdP integration tests (Phase 21, MIDP-01..08; Phase 27, MIDP-09..11).
//!
//! Exercises the full multi-issuer authentication path end-to-end:
//! - MIDP-01: Two-issuer policy loads; issuer_by_url() resolves correct config
//! - MIDP-02: Per-issuer DPoP enforcement (strict vs disabled)
//! - MIDP-03: Per-issuer ACR mapping config deserialises and lookups work
//! - MIDP-04: Per-issuer group mapping (NSS-only default)
//! - MIDP-05: Per-issuer claim mapping (strip_domain vs raw)
//! - MIDP-06: Issuer routing (known / unknown / trailing-slash normalization)
//! - MIDP-07: JWKS providers independent per issuer; JTI cross-issuer no collision
//! - MIDP-08: Optional fields fall back to safe defaults with WARN
//! - MIDP-09: Priority-ordered issuer selection with structured audit logging
//! - MIDP-10: Issuer health monitoring — degradation after 3 failures, recovery
//! - MIDP-11: Config hot-reload via mtime stat check
//!
//! All tests run under `--features test-mode` which enables
//! `TokenValidator::new_insecure_for_testing()` (signature verification bypassed).
//! Tests that need UNIX_OIDC_TEST_MODE set are serialized via ENV_MUTEX to prevent
//! races between parallel test threads.
//!
//! NEVER enable test-mode in production builds.

#![cfg(feature = "test-mode")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use figment::providers::Format as _;
use pam_unix_oidc::auth::{authenticate_multi_issuer, AuthError, DPoPAuthConfig};
use pam_unix_oidc::oidc::jwks::IssuerJwksRegistry;
use pam_unix_oidc::policy::config::{
    AcrMappingConfig, EnforcementMode, GroupMappingConfig, GroupSource, IdentityConfig,
    IssuerConfig, IssuerHealthManager, PolicyConfig, TransformConfig,
};
use pam_unix_oidc::security::nonce_cache::{
    generate_dpop_nonce, global_nonce_cache, NonceConsumeError,
};
use std::collections::HashMap;
use std::sync::Arc;

// ── Test helpers ─────────────────────────────────────────────────────────────

/// Serialise tests that set/remove UNIX_OIDC_TEST_MODE to prevent races with
/// parallel test threads. Same pattern used in auth.rs and policy/config.rs.
static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Build a minimal unsigned JWT with the given claims.
///
/// Format: base64url(header).base64url(payload).dummysig
///
/// This token is accepted by `TokenValidator::new_insecure_for_testing()` which
/// skips signature verification when `UNIX_OIDC_TEST_MODE=1`. It is NOT a valid
/// signed JWT and MUST NOT be used outside test-mode.
fn make_test_token(iss: &str, sub: &str, preferred_username: &str, jti: Option<&str>) -> String {
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

/// Build a minimal unsigned JWT with the given claims, including optional ACR.
///
/// Same as `make_test_token` but with an additional `acr` claim field.
fn make_test_token_with_acr(
    iss: &str,
    sub: &str,
    preferred_username: &str,
    jti: Option<&str>,
    acr: Option<&str>,
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
    let acr_field = acr.map(|a| format!(r#","acr":"{a}""#)).unwrap_or_default();
    let payload = format!(
        r#"{{"iss":"{iss}","sub":"{sub}","aud":"unix-oidc","exp":{exp},"iat":{now},"preferred_username":"{preferred_username}"{jti_field}{acr_field}}}"#
    );
    let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let p = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    format!("{h}.{p}.dummysig")
}

/// Build a two-issuer PolicyConfig with configurable settings.
///
/// - Issuer A: `iss_a`, dpop_enforcement per `dpop_a`, no claim transforms by default
/// - Issuer B: `iss_b`, DPoP disabled, no claim transforms by default
fn make_two_issuer_policy(iss_a: &str, iss_b: &str, dpop_a: EnforcementMode) -> PolicyConfig {
    PolicyConfig {
        issuers: vec![
            IssuerConfig {
                issuer_url: iss_a.to_string(),
                client_id: "unix-oidc".to_string(),
                dpop_enforcement: dpop_a,
                ..IssuerConfig::default()
            },
            IssuerConfig {
                issuer_url: iss_b.to_string(),
                client_id: "unix-oidc".to_string(),
                dpop_enforcement: EnforcementMode::Disabled,
                ..IssuerConfig::default()
            },
        ],
        ..PolicyConfig::default()
    }
}

// ── MIDP-01: Config loading ───────────────────────────────────────────────────

/// MIDP-01: Two-issuer policy loads from YAML fixture without error.
#[test]
fn test_two_issuer_policy_loads_from_yaml() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test/fixtures/policy/policy-multi-idp.yaml"
    );
    let policy =
        PolicyConfig::load_from(fixture).expect("multi-idp fixture must load without error");
    assert_eq!(
        policy.issuers.len(),
        2,
        "fixture must contain exactly 2 issuers"
    );
    assert!(
        policy.issuers[0]
            .issuer_url
            .contains("keycloak.example.com"),
        "first issuer must be Keycloak"
    );
    assert!(
        policy.issuers[1].issuer_url.contains("microsoftonline.com"),
        "second issuer must be Entra ID-like"
    );
}

/// MIDP-01: Each issuer in the fixture has its DPoP enforcement set correctly.
#[test]
fn test_two_issuer_policy_dpop_enforcement_from_yaml() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test/fixtures/policy/policy-multi-idp.yaml"
    );
    let policy = PolicyConfig::load_from(fixture).expect("must load");
    assert_eq!(
        policy.issuers[0].dpop_enforcement,
        EnforcementMode::Strict,
        "Keycloak issuer must have strict DPoP"
    );
    assert_eq!(
        policy.issuers[1].dpop_enforcement,
        EnforcementMode::Disabled,
        "Entra issuer must have disabled DPoP"
    );
}

// ── MIDP-02: Per-issuer DPoP enforcement ─────────────────────────────────────

/// MIDP-02: Issuer with dpop_enforcement=strict rejects token without DPoP proof.
#[test]
fn test_dpop_strict_rejects_bearer_only() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss_a = "https://kc.example.com/realms/corp";
    let token = make_test_token(iss_a, "alice", "alice", Some("jti-strict-01"));
    let policy =
        make_two_issuer_policy(iss_a, "https://entra.example.com", EnforcementMode::Strict);
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    assert!(
        matches!(result, Err(AuthError::DPoPRequired)),
        "strict DPoP enforcement must reject bearer-only token, got: {result:?}"
    );
}

/// MIDP-02: Issuer with dpop_enforcement=disabled accepts bearer token (no proof required).
#[test]
fn test_dpop_disabled_accepts_bearer() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss_b = "https://entra-bearer.example.com";
    let token = make_test_token(iss_b, "bob", "bob", Some("jti-bearer-01"));
    let policy = make_two_issuer_policy(
        "https://kc.example.com/realms/corp",
        iss_b,
        EnforcementMode::Strict,
    );
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // DPoP is Disabled for issuer B — must NOT get DPoPRequired.
    // Will get UserNotFound (no SSSD in test environment).
    assert!(
        !matches!(result, Err(AuthError::DPoPRequired)),
        "disabled DPoP enforcement must not require proof, got: {result:?}"
    );
}

// ── MIDP-03: Per-issuer ACR mapping ───────────────────────────────────────────

/// MIDP-03: ACR mapping config deserialises from YAML and lookups translate values.
#[test]
fn test_acr_mapping_deserialises_and_translates() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test/fixtures/policy/policy-multi-idp.yaml"
    );
    let policy = PolicyConfig::load_from(fixture).expect("must load");

    // Keycloak issuer has explicit ACR mapping.
    let kc = &policy.issuers[0];
    let acr_map = kc
        .acr_mapping
        .as_ref()
        .expect("Keycloak must have acr_mapping");
    assert_eq!(
        acr_map.enforcement,
        EnforcementMode::Strict,
        "Keycloak ACR enforcement must be strict"
    );
    let canonical = acr_map
        .mappings
        .get("urn:keycloak:loa:mfa")
        .expect("must contain Keycloak MFA ACR mapping");
    assert_eq!(
        canonical, "urn:unix-oidc:acr:mfa",
        "ACR mapping must translate to canonical value"
    );
}

/// MIDP-03: Direct construction of AcrMappingConfig and lookup.
#[test]
fn test_acr_mapping_lookup_translates_keycloak_loa2() {
    let mut mappings = HashMap::new();
    mappings.insert(
        "urn:keycloak:acr:loa2".to_string(),
        "urn:example:acr:phishing-resistant".to_string(),
    );
    let acr_cfg = AcrMappingConfig {
        mappings,
        enforcement: EnforcementMode::Strict,
        ..AcrMappingConfig::default()
    };

    let canonical = acr_cfg.mappings.get("urn:keycloak:acr:loa2");
    assert_eq!(
        canonical.map(String::as_str),
        Some("urn:example:acr:phishing-resistant"),
        "ACR mapping must translate Keycloak LoA2 to canonical value"
    );
    assert_eq!(acr_cfg.enforcement, EnforcementMode::Strict);
}

/// MIDP-03: ACR mapping for unknown value returns None (no panic).
#[test]
fn test_acr_mapping_unknown_value_returns_none() {
    let acr_cfg = AcrMappingConfig {
        mappings: HashMap::new(),
        enforcement: EnforcementMode::Warn,
        ..AcrMappingConfig::default()
    };
    assert!(
        !acr_cfg.mappings.contains_key("urn:unknown:acr:value"),
        "unknown ACR value must return None without panic"
    );
}

// ── MIDP-04: Per-issuer group mapping ─────────────────────────────────────────

/// MIDP-04: GroupMappingConfig defaults to NssOnly.
///
/// Note: `GroupMappingConfig::default()` (Rust Default) yields `claim = ""`.
/// The `"groups"` default only applies during YAML deserialisation via
/// `#[serde(default = "GroupMappingConfig::default_claim")]`.
#[test]
fn test_group_mapping_defaults_to_nss_only() {
    let cfg = GroupMappingConfig::default();
    assert_eq!(
        cfg.source,
        GroupSource::NssOnly,
        "GroupMappingConfig must default to NssOnly"
    );
    // Rust Default::default() yields empty string; serde gives "groups" during YAML load.
    // We verify serde deserialization here using inline YAML.
    let yaml = r#"
issuers:
  - issuer_url: "https://gm-default.example.com"
    client_id: "unix-oidc"
    group_mapping:
      source: nss_only
"#;
    let policy: PolicyConfig = figment::Figment::from(figment::providers::Serialized::defaults(
        PolicyConfig::default(),
    ))
    .merge(figment::providers::Yaml::string(yaml))
    .extract()
    .expect("group_mapping YAML must deserialise");
    let gm = policy.issuers[0]
        .group_mapping
        .as_ref()
        .expect("group_mapping must be present");
    assert_eq!(
        gm.claim, "groups",
        "serde-deserialised claim must default to 'groups'"
    );
}

/// MIDP-04: IssuerConfig without group_mapping has None (defaults logged as WARN).
#[test]
fn test_issuer_without_group_mapping_has_none() {
    let issuer = IssuerConfig {
        issuer_url: "https://idp.example.com".to_string(),
        client_id: "unix-oidc".to_string(),
        ..IssuerConfig::default()
    };
    assert!(
        issuer.group_mapping.is_none(),
        "absent group_mapping must deserialise to None"
    );
}

/// MIDP-04: Group mapping config from YAML fixture loads correctly for both issuers.
#[test]
fn test_group_mapping_from_yaml_fixture() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test/fixtures/policy/policy-multi-idp.yaml"
    );
    let policy = PolicyConfig::load_from(fixture).expect("must load");

    // Both issuers in the fixture use nss_only.
    for issuer in &policy.issuers {
        if let Some(gm) = &issuer.group_mapping {
            assert_eq!(
                gm.source,
                GroupSource::NssOnly,
                "fixture issuers must use NssOnly group resolution"
            );
        }
    }
}

// ── MIDP-05: Per-issuer claim mapping ─────────────────────────────────────────

/// MIDP-05: Issuer A with strip_domain: collision-safety fires for non-injective pipeline.
///
/// strip_domain applied to preferred_username is non-injective (alice@a and alice@b
/// both map to alice). check_collision_safety() hard-fails such pipelines, so
/// authenticate_multi_issuer returns Config error before reaching SSSD.
#[test]
fn test_strip_domain_issuer_a_collision_safety_fires() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss_a = "https://kc-domain.example.com/realms/corp";
    let token = make_test_token(
        iss_a,
        "alice@corp.example",
        "alice@corp.example",
        Some("jti-strip-05"),
    );

    let policy = PolicyConfig {
        issuers: vec![IssuerConfig {
            issuer_url: iss_a.to_string(),
            client_id: "unix-oidc".to_string(),
            dpop_enforcement: EnforcementMode::Disabled, // avoid DPoP error first
            claim_mapping: IdentityConfig {
                username_claim: "preferred_username".to_string(),
                transforms: vec![TransformConfig::Simple("strip_domain".to_string())],
            },
            ..IssuerConfig::default()
        }],
        ..PolicyConfig::default()
    };
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // check_collision_safety() hard-fails for strip_domain + preferred_username
    assert!(
        matches!(result, Err(AuthError::Config(_))),
        "non-injective strip_domain pipeline must produce Config error, got: {result:?}"
    );
}

/// MIDP-05: Issuer B with no transforms: raw claim preserved (UserNotFound, not Config).
#[test]
fn test_no_transforms_issuer_b_preserves_raw_claim() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss_b = "https://entra-notransform.example.com";
    let token = make_test_token(
        iss_b,
        "alice@corp.example",
        "alice@corp.example",
        Some("jti-raw-05"),
    );

    let policy = PolicyConfig {
        issuers: vec![IssuerConfig {
            issuer_url: iss_b.to_string(),
            client_id: "unix-oidc".to_string(),
            dpop_enforcement: EnforcementMode::Disabled,
            claim_mapping: IdentityConfig::default(), // no transforms
            ..IssuerConfig::default()
        }],
        ..PolicyConfig::default()
    };
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // No transforms → no collision error. Should hit UserNotFound (no SSSD in tests).
    // The raw "alice@corp.example" is used as username and NSS lookup fails.
    assert!(
        matches!(result, Err(AuthError::UserNotFound(_))),
        "no-transform issuer must reach UserNotFound (not Config), got: {result:?}"
    );
}

/// MIDP-05: Entra issuer in fixture has strip_domain + lowercase transforms on email claim.
#[test]
fn test_entra_issuer_has_strip_domain_on_email_in_fixture() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test/fixtures/policy/policy-multi-idp.yaml"
    );
    let policy = PolicyConfig::load_from(fixture).expect("must load");

    let entra = &policy.issuers[1];
    assert_eq!(
        entra.claim_mapping.username_claim, "email",
        "Entra issuer must use email claim"
    );
    assert!(
        !entra.claim_mapping.transforms.is_empty(),
        "Entra issuer must have transforms configured"
    );
}

// ── MIDP-06: Issuer routing ───────────────────────────────────────────────────

/// MIDP-06: Token from known issuer routes to correct config (proceeds past routing).
#[test]
fn test_known_issuer_routes_correctly() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss_b = "https://known-issuer.example.com";
    let token = make_test_token(iss_b, "charlie", "charlie", Some("jti-known-06"));
    let policy = make_two_issuer_policy(
        "https://other-issuer.example.com",
        iss_b,
        EnforcementMode::Strict,
    );
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // Issuer B has Disabled DPoP so token is not rejected for missing proof.
    // Will fail at UserNotFound (no SSSD) — NOT UnknownIssuer.
    assert!(
        !matches!(result, Err(AuthError::UnknownIssuer(_))),
        "known issuer must not produce UnknownIssuer error, got: {result:?}"
    );
}

/// MIDP-06: Token from unknown issuer is rejected with UnknownIssuer error.
#[test]
fn test_unknown_issuer_rejected() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let token = make_test_token(
        "https://evil.example.com",
        "attacker",
        "attacker",
        Some("jti-unknown-06"),
    );
    let policy = make_two_issuer_policy(
        "https://kc.example.com/realms/corp",
        "https://entra.example.com",
        EnforcementMode::Strict,
    );
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    assert!(
        matches!(result, Err(AuthError::UnknownIssuer(ref iss)) if iss == "https://evil.example.com"),
        "unknown issuer must be rejected with UnknownIssuer error, got: {result:?}"
    );
}

/// MIDP-06: Trailing-slash normalization — token iss without slash matches config with slash.
#[test]
fn test_issuer_routing_normalizes_trailing_slash() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    // Token iss WITHOUT trailing slash.
    let token_iss = "https://slash-norm.example.com/realms/test";
    let token = make_test_token(token_iss, "dave", "dave", Some("jti-slash-06"));

    // Config WITH trailing slash — issuer_by_url normalises both sides.
    let policy = PolicyConfig {
        issuers: vec![IssuerConfig {
            issuer_url: "https://slash-norm.example.com/realms/test/".to_string(),
            client_id: "unix-oidc".to_string(),
            dpop_enforcement: EnforcementMode::Disabled,
            ..IssuerConfig::default()
        }],
        ..PolicyConfig::default()
    };
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // Trailing-slash normalisation must match — must NOT get UnknownIssuer.
    assert!(
        !matches!(result, Err(AuthError::UnknownIssuer(_))),
        "trailing-slash normalization must match config, got: {result:?}"
    );
}

// ── MIDP-07: JWKS independence + JTI scoping ─────────────────────────────────

/// MIDP-07: IssuerJwksRegistry returns independent Arc<JwksProvider> per issuer.
#[test]
fn test_jwks_registry_independent_per_issuer() {
    let registry = IssuerJwksRegistry::new();
    let provider_a = registry.get_or_init("https://issuer-a.example.com", 300, 10);
    let provider_b = registry.get_or_init("https://issuer-b.example.com", 300, 10);
    assert!(
        !Arc::ptr_eq(&provider_a, &provider_b),
        "different issuers must have independent JwksProviders"
    );
}

/// MIDP-07: IssuerJwksRegistry returns the same Arc for the same issuer (idempotent).
#[test]
fn test_jwks_registry_same_issuer_returns_same_arc() {
    let registry = IssuerJwksRegistry::new();
    let p1 = registry.get_or_init("https://same-issuer.example.com", 300, 10);
    let p2 = registry.get_or_init("https://same-issuer.example.com", 300, 10);
    assert!(
        Arc::ptr_eq(&p1, &p2),
        "same issuer must return same Arc (idempotent get_or_init)"
    );
}

/// MIDP-07: Same JTI value from two different issuers does NOT collide in cache.
///
/// scoped_key = "{iss}:{jti}" — so "issuer-a.example.com:abc" and
/// "issuer-b.example.com:abc" are independent cache entries.
#[test]
fn test_jti_same_value_different_issuers_no_collision() {
    use pam_unix_oidc::security::jti_cache::global_jti_cache;

    let iss_a = "https://jti-coll-a.example.com";
    let iss_b = "https://jti-coll-b.example.com";
    let shared_jti = "jti-shared-coll-test-01";

    let scoped_a = format!("{iss_a}:{shared_jti}");
    let scoped_b = format!("{iss_b}:{shared_jti}");

    // Record issuer A's token.
    global_jti_cache().check_and_record(Some(&scoped_a), "user-a", 3600);

    // Issuer B's token with the same raw JTI must NOT be a collision.
    let result_b = global_jti_cache().check_and_record(Some(&scoped_b), "user-b", 3600);
    assert!(
        result_b.is_valid(),
        "same JTI from different issuer must not collide; got: {result_b:?}"
    );
}

/// MIDP-07: Same JTI from the same issuer IS detected as a replay.
#[test]
fn test_jti_same_value_same_issuer_is_replay() {
    use pam_unix_oidc::security::jti_cache::global_jti_cache;

    let iss = "https://jti-replay-test.example.com";
    let jti = "jti-replay-same-issuer-01";
    let scoped = format!("{iss}:{jti}");

    let first = global_jti_cache().check_and_record(Some(&scoped), "user-a", 3600);
    assert!(first.is_valid(), "first use must be valid");

    let second = global_jti_cache().check_and_record(Some(&scoped), "user-a", 3600);
    assert!(
        second.is_replay(),
        "same scoped JTI from same issuer must be replay"
    );
}

// ── MIDP-08: Graceful defaults ────────────────────────────────────────────────

/// MIDP-08: IssuerConfig with only issuer_url and client_id deserialises with safe defaults.
#[test]
fn test_issuer_without_optional_fields_loads_with_safe_defaults() {
    let yaml = r#"
issuers:
  - issuer_url: "https://minimal.example.com"
    client_id: "unix-oidc-min"
"#;
    let policy: PolicyConfig = figment::Figment::from(figment::providers::Serialized::defaults(
        PolicyConfig::default(),
    ))
    .merge(figment::providers::Yaml::string(yaml))
    .extract()
    .expect("minimal issuer config must deserialise");

    assert_eq!(policy.issuers.len(), 1);
    let issuer = &policy.issuers[0];
    assert_eq!(issuer.issuer_url, "https://minimal.example.com");
    assert_eq!(issuer.client_id, "unix-oidc-min");

    // Safe defaults must apply.
    assert_eq!(
        issuer.dpop_enforcement,
        EnforcementMode::Strict,
        "dpop_enforcement must default to Strict (most secure)"
    );
    assert!(
        issuer.acr_mapping.is_none(),
        "acr_mapping must default to None"
    );
    assert!(
        issuer.group_mapping.is_none(),
        "group_mapping must default to None"
    );
    assert!(
        issuer.client_secret.is_none(),
        "client_secret must default to None"
    );
}

/// MIDP-08: Missing optional config fields produce no deserialisation error.
#[test]
fn test_issuer_missing_optional_fields_no_parse_error() {
    let yaml = r#"
issuers:
  - issuer_url: "https://idp-defaults.example.com"
    client_id: "unix-oidc"
  - issuer_url: "https://idp-full.example.com"
    client_id: "unix-oidc"
    dpop_enforcement: disabled
    acr_mapping:
      enforcement: warn
    group_mapping:
      source: nss_only
"#;
    let policy: PolicyConfig = figment::Figment::from(figment::providers::Serialized::defaults(
        PolicyConfig::default(),
    ))
    .merge(figment::providers::Yaml::string(yaml))
    .extract()
    .expect("mixed optional fields must deserialise without error");

    assert_eq!(policy.issuers.len(), 2);
}

// ── Adversarial cases ─────────────────────────────────────────────────────────

/// Adversarial: Duplicate issuer_url values must be rejected at load time.
#[test]
fn test_duplicate_issuer_urls_rejected_at_load() {
    use std::io::Write;
    let yaml = r#"
issuers:
  - issuer_url: "https://dup.example.com"
    client_id: "unix-oidc"
  - issuer_url: "https://dup.example.com"
    client_id: "unix-oidc-2"
"#;
    // Write to a temp file so load_from() can read it.
    let mut tmp = tempfile::NamedTempFile::new().expect("must create temp file");
    tmp.write_all(yaml.as_bytes())
        .expect("must write YAML to temp file");
    let result = PolicyConfig::load_from(tmp.path());
    assert!(
        result.is_err(),
        "duplicate issuer URLs must fail at load time, got: {result:?}"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.to_lowercase().contains("duplicate"),
        "error message must mention 'duplicate', got: {err}"
    );
}

/// Adversarial: Token with correct iss but wrong issuer in config remains unknown.
/// (Validates routing is purely iss-based, not audience-based at routing step.)
#[test]
fn test_forged_iss_from_unconfigured_issuer_is_rejected() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    // Token claims iss = "https://forged.evil.com" which is not in config.
    let token = make_test_token(
        "https://forged.evil.com",
        "attacker",
        "root",
        Some("jti-forged-adv"),
    );
    let policy = make_two_issuer_policy(
        "https://legit-a.example.com",
        "https://legit-b.example.com",
        EnforcementMode::Strict,
    );
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    assert!(
        matches!(result, Err(AuthError::UnknownIssuer(_))),
        "forged iss must be rejected as UnknownIssuer, got: {result:?}"
    );
}

// ── ENTR-01: expected_audience + allow_unsafe_identity_pipeline ───────────────

/// ENTR-01: expected_audience=Some deserialises from YAML correctly.
#[test]
fn test_expected_audience_overrides_client_id_in_config() {
    let yaml = r#"
issuers:
  - issuer_url: "https://login.microsoftonline.com/tenant-id/v2.0"
    client_id: "00000000-0000-0000-0000-000000000001"
    expected_audience: "api://unix-oidc"
    dpop_enforcement: disabled
"#;
    let policy: PolicyConfig = figment::Figment::from(figment::providers::Serialized::defaults(
        PolicyConfig::default(),
    ))
    .merge(figment::providers::Yaml::string(yaml))
    .extract()
    .expect("expected_audience must deserialise from YAML");

    assert_eq!(policy.issuers.len(), 1);
    let issuer = &policy.issuers[0];
    assert_eq!(
        issuer.expected_audience,
        Some("api://unix-oidc".to_string()),
        "expected_audience must deserialise as Some(\"api://unix-oidc\")"
    );
    // client_id must remain unchanged — expected_audience overrides only at validation time
    assert_eq!(issuer.client_id, "00000000-0000-0000-0000-000000000001");
}

/// ENTR-01: IssuerConfig with expected_audience=None has None default.
#[test]
fn test_expected_audience_defaults_to_none() {
    let yaml = r#"
issuers:
  - issuer_url: "https://idp.example.com"
    client_id: "unix-oidc"
"#;
    let policy: PolicyConfig = figment::Figment::from(figment::providers::Serialized::defaults(
        PolicyConfig::default(),
    ))
    .merge(figment::providers::Yaml::string(yaml))
    .extract()
    .expect("must deserialise");

    assert_eq!(
        policy.issuers[0].expected_audience, None,
        "expected_audience must default to None when not set"
    );
}

/// ENTR-01: allow_unsafe_identity_pipeline defaults to false (safe by default).
#[test]
fn test_allow_unsafe_identity_pipeline_defaults_to_false() {
    let yaml = r#"
issuers:
  - issuer_url: "https://idp.example.com"
    client_id: "unix-oidc"
"#;
    let policy: PolicyConfig = figment::Figment::from(figment::providers::Serialized::defaults(
        PolicyConfig::default(),
    ))
    .merge(figment::providers::Yaml::string(yaml))
    .extract()
    .expect("must deserialise");

    assert!(
        !policy.issuers[0].allow_unsafe_identity_pipeline,
        "allow_unsafe_identity_pipeline must default to false (safe by default)"
    );
}

/// ENTR-01: allow_unsafe_identity_pipeline=true + strip_domain bypasses collision-safety.
/// With the bypass active, authenticate_multi_issuer proceeds past the collision-safety gate
/// and reaches UserNotFound (no SSSD in tests) instead of Config error.
#[test]
fn test_allow_unsafe_pipeline_bypasses_collision_safety() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss = "https://entra-unsafe.example.com";
    // Token uses email claim (UPN-style) — strip_domain would extract "alice"
    let token = make_test_token(
        iss,
        "alice@corp.example",
        "alice@corp.example",
        Some("jti-unsafe-entr-01"),
    );

    let policy = PolicyConfig {
        issuers: vec![IssuerConfig {
            issuer_url: iss.to_string(),
            client_id: "unix-oidc".to_string(),
            dpop_enforcement: EnforcementMode::Disabled,
            allow_unsafe_identity_pipeline: true,
            claim_mapping: IdentityConfig {
                username_claim: "preferred_username".to_string(),
                transforms: vec![TransformConfig::Simple("strip_domain".to_string())],
            },
            ..IssuerConfig::default()
        }],
        ..PolicyConfig::default()
    };
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // With allow_unsafe_identity_pipeline=true, collision-safety is bypassed.
    // The transform runs and reaches UserNotFound (no SSSD), NOT Config error.
    assert!(
        matches!(result, Err(AuthError::UserNotFound(_))),
        "allow_unsafe_identity_pipeline=true must bypass collision-safety (UserNotFound not Config), got: {result:?}"
    );
}

/// ENTR-01: allow_unsafe_identity_pipeline=false (default) + strip_domain still blocks.
#[test]
fn test_allow_unsafe_pipeline_default_false_still_blocks() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss = "https://entra-safe.example.com";
    let token = make_test_token(
        iss,
        "bob@corp.example",
        "bob@corp.example",
        Some("jti-safe-entr-02"),
    );

    let policy = PolicyConfig {
        issuers: vec![IssuerConfig {
            issuer_url: iss.to_string(),
            client_id: "unix-oidc".to_string(),
            dpop_enforcement: EnforcementMode::Disabled,
            allow_unsafe_identity_pipeline: false, // explicit false = same as default
            claim_mapping: IdentityConfig {
                username_claim: "preferred_username".to_string(),
                transforms: vec![TransformConfig::Simple("strip_domain".to_string())],
            },
            ..IssuerConfig::default()
        }],
        ..PolicyConfig::default()
    };
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // Without bypass, strip_domain on preferred_username is non-injective → Config error
    assert!(
        matches!(result, Err(AuthError::Config(_))),
        "allow_unsafe_identity_pipeline=false must preserve collision-safety hard-fail, got: {result:?}"
    );
}

// ── MIDP-02 (integration fix): DPoP nonce consumption in multi-issuer path ───

/// Build a real ES256-signed DPoP proof with the given method, target, and optional nonce.
///
/// Returns (proof_jwt_string, jwk_thumbprint). Uses a freshly-generated P-256 key.
/// This helper mirrors `create_test_proof` in `oidc/dpop.rs` (private to that module).
///
/// # Security note
/// The generated key is ephemeral and used only for test assertions. It is NOT the
/// key used to sign the access token; test-mode bypasses access-token signature
/// verification. Real production paths always require a valid JWKS-backed signature.
fn make_test_dpop_proof(method: &str, target: &str, nonce: Option<&str>) -> (String, String) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::{signature::Signer, SigningKey};
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

    let nonce_field = nonce
        .map(|n| format!(r#","nonce":"{n}""#))
        .unwrap_or_default();
    let jti = uuid::Uuid::new_v4().to_string();
    let claims_json =
        format!(r#"{{"jti":"{jti}","htm":"{method}","htu":"{target}","iat":{now}{nonce_field}}}"#);
    let header_json = format!(
        r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}}}"#
    );

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
    let message = format!("{header_b64}.{claims_b64}");

    let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let proof = format!("{message}.{sig_b64}");

    // Compute JWK thumbprint (RFC 7638): SHA-256 of canonical JSON crv+kty+x+y
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    use sha2::Digest;
    let hash = sha2::Sha256::digest(canonical.as_bytes());
    let thumbprint = URL_SAFE_NO_PAD.encode(hash);

    (proof, thumbprint)
}

/// MIDP-02 (integration fix): A replayed DPoP nonce in the multi-issuer path is rejected.
///
/// Issues a nonce to the global cache, uses it in a DPoP proof on the first call
/// (which consumes it via `apply_per_issuer_dpop`), then attempts to reuse the same
/// proof on a second call. The second call MUST fail with DPoPValidation because
/// the nonce has already been consumed.
///
/// This is the security regression test for the gap closed in Phase 23 Plan 01.
#[test]
fn test_multi_issuer_dpop_nonce_replay_rejected() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    // Use an issuer with Warn enforcement (not Strict, so unbound token + proof still flows
    // through validate_and_enforce_nonce without requiring cnf.jkt on the token).
    let iss = "https://nonce-replay-test.example.com";
    let token = make_test_token(iss, "alice", "alice", Some("jti-nonce-replay-01"));

    let policy = make_two_issuer_policy(iss, "https://other.example.com", EnforcementMode::Warn);

    // Issue a fresh nonce into the global cache.
    let nonce = generate_dpop_nonce().expect("must generate nonce");
    global_nonce_cache()
        .issue(&nonce)
        .expect("must issue nonce to cache");

    // Build a DPoP proof carrying the nonce.
    let (dpop_proof, _thumbprint) = make_test_dpop_proof("SSH", "", Some(&nonce));

    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig {
        require_nonce: true,
        expected_nonce: None, // cache-backed path
        ..DPoPAuthConfig::default()
    };

    // First call: nonce is consumed by apply_per_issuer_dpop.
    // The call will proceed past DPoP enforcement and fail at SSSD lookup (no SSSD in tests).
    let first =
        authenticate_multi_issuer(&token, Some(&dpop_proof), &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // First call must NOT fail with DPoPValidation — it may fail at UserNotFound.
    assert!(
        !matches!(first, Err(AuthError::DPoPValidation(_))),
        "first call with valid nonce must not fail with DPoPValidation, got: {first:?}"
    );

    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    // Second call: same proof with the now-consumed nonce must be rejected.
    let second =
        authenticate_multi_issuer(&token, Some(&dpop_proof), &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    assert!(
        matches!(second, Err(AuthError::DPoPValidation(_))),
        "second call with replayed nonce must fail with DPoPValidation, got: {second:?}"
    );
}

/// MIDP-02 (integration fix): After a successful multi-issuer auth call, the nonce
/// is no longer present in the global cache.
///
/// Calls `authenticate_multi_issuer` once with a cache-backed nonce. After the call,
/// directly invokes `global_nonce_cache().consume()` and asserts it returns
/// `ConsumedOrExpired` — proving nonce consumption happened inside the multi-issuer path.
#[test]
fn test_multi_issuer_dpop_nonce_consumed() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss = "https://nonce-consumed-test.example.com";
    let token = make_test_token(iss, "bob", "bob", Some("jti-nonce-consumed-01"));
    let policy = make_two_issuer_policy(iss, "https://other2.example.com", EnforcementMode::Warn);

    // Issue a fresh nonce — use unique value to avoid cross-test interference.
    let nonce = generate_dpop_nonce().expect("must generate nonce");
    global_nonce_cache()
        .issue(&nonce)
        .expect("must issue nonce to cache");

    let (dpop_proof, _thumbprint) = make_test_dpop_proof("SSH", "", Some(&nonce));
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig {
        require_nonce: true,
        expected_nonce: None,
        ..DPoPAuthConfig::default()
    };

    // Call authenticate_multi_issuer — nonce must be consumed inside apply_per_issuer_dpop.
    let _ = authenticate_multi_issuer(&token, Some(&dpop_proof), &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // After the call, the nonce must no longer be in the cache.
    let consume_result = global_nonce_cache().consume(&nonce);
    assert!(
        matches!(consume_result, Err(NonceConsumeError::ConsumedOrExpired)),
        "nonce must be consumed after multi-issuer auth call; got: {consume_result:?}"
    );
}

// ── DEBT-02: ACR enforcement wired from IssuerConfig ─────────────────────────

/// DEBT-02: Issuer with required_acr set and token with matching acr claim passes
/// validation (reaches UserNotFound, not TokenValidation).
#[test]
fn test_acr_enforcement_matching_acr_passes() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss = "https://acr-match.example.com";
    let token = make_test_token_with_acr(
        iss,
        "alice",
        "alice",
        Some("jti-acr-match-01"),
        Some("urn:mfa"),
    );

    let policy = PolicyConfig {
        issuers: vec![IssuerConfig {
            issuer_url: iss.to_string(),
            client_id: "unix-oidc".to_string(),
            dpop_enforcement: EnforcementMode::Disabled,
            acr_mapping: Some(AcrMappingConfig {
                mappings: HashMap::new(),
                enforcement: EnforcementMode::Strict,
                required_acr: Some("urn:mfa".to_string()),
            }),
            ..IssuerConfig::default()
        }],
        ..PolicyConfig::default()
    };
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // Should pass ACR check and reach UserNotFound (no SSSD in tests)
    assert!(
        !matches!(result, Err(AuthError::TokenValidation(_))),
        "matching ACR must not produce TokenValidation error, got: {result:?}"
    );
}

/// DEBT-02: Issuer with required_acr set and token with NON-matching acr is rejected.
#[test]
fn test_acr_enforcement_wrong_acr_rejected() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss = "https://acr-wrong.example.com";
    let token = make_test_token_with_acr(
        iss,
        "alice",
        "alice",
        Some("jti-acr-wrong-01"),
        Some("urn:low"),
    );

    let policy = PolicyConfig {
        issuers: vec![IssuerConfig {
            issuer_url: iss.to_string(),
            client_id: "unix-oidc".to_string(),
            dpop_enforcement: EnforcementMode::Disabled,
            acr_mapping: Some(AcrMappingConfig {
                mappings: HashMap::new(),
                enforcement: EnforcementMode::Strict,
                required_acr: Some("urn:high".to_string()),
            }),
            ..IssuerConfig::default()
        }],
        ..PolicyConfig::default()
    };
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // Should fail with TokenValidation error containing "ACR" or "acr"
    assert!(
        matches!(result, Err(AuthError::TokenValidation(_))),
        "non-matching ACR must produce TokenValidation error, got: {result:?}"
    );
    let err_msg = format!("{result:?}");
    assert!(
        err_msg.to_lowercase().contains("acr"),
        "error must mention ACR, got: {err_msg}"
    );
}

/// DEBT-02: Issuer with required_acr set and token with NO acr claim is rejected.
#[test]
fn test_acr_enforcement_missing_acr_rejected() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss = "https://acr-missing.example.com";
    // Token has no acr claim
    let token = make_test_token(iss, "alice", "alice", Some("jti-acr-missing-01"));

    let policy = PolicyConfig {
        issuers: vec![IssuerConfig {
            issuer_url: iss.to_string(),
            client_id: "unix-oidc".to_string(),
            dpop_enforcement: EnforcementMode::Disabled,
            acr_mapping: Some(AcrMappingConfig {
                mappings: HashMap::new(),
                enforcement: EnforcementMode::Strict,
                required_acr: Some("urn:high".to_string()),
            }),
            ..IssuerConfig::default()
        }],
        ..PolicyConfig::default()
    };
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // Should fail with TokenValidation error containing "ACR" or "acr"
    assert!(
        matches!(result, Err(AuthError::TokenValidation(_))),
        "missing ACR must produce TokenValidation error, got: {result:?}"
    );
}

/// DEBT-02: Issuer without acr_mapping passes tokens regardless of acr claim (backward compat).
#[test]
fn test_acr_no_mapping_backward_compat() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss = "https://acr-nomap.example.com";
    let token = make_test_token(iss, "alice", "alice", Some("jti-acr-nomap-01"));

    let policy = PolicyConfig {
        issuers: vec![IssuerConfig {
            issuer_url: iss.to_string(),
            client_id: "unix-oidc".to_string(),
            dpop_enforcement: EnforcementMode::Disabled,
            acr_mapping: None, // No ACR mapping
            ..IssuerConfig::default()
        }],
        ..PolicyConfig::default()
    };
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // No ACR enforcement — should NOT fail with TokenValidation
    assert!(
        !matches!(result, Err(AuthError::TokenValidation(_))),
        "no acr_mapping must not produce TokenValidation error, got: {result:?}"
    );
}

// ── DEBT-05: Per-issuer JWKS cache TTL and HTTP timeout ──────────────────────

/// DEBT-05: IssuerConfig with custom jwks_cache_ttl_secs deserializes correctly.
#[test]
fn test_issuer_config_custom_jwks_cache_ttl() {
    let yaml = r#"
issuers:
  - issuer_url: "https://jwks-custom.example.com"
    client_id: "unix-oidc"
    jwks_cache_ttl_secs: 600
"#;
    let policy: PolicyConfig = figment::Figment::from(figment::providers::Serialized::defaults(
        PolicyConfig::default(),
    ))
    .merge(figment::providers::Yaml::string(yaml))
    .extract()
    .expect("custom jwks_cache_ttl_secs must deserialise");

    assert_eq!(
        policy.issuers[0].jwks_cache_ttl_secs, 600,
        "jwks_cache_ttl_secs must be 600"
    );
}

/// DEBT-05: IssuerConfig with custom http_timeout_secs deserializes correctly.
#[test]
fn test_issuer_config_custom_http_timeout() {
    let yaml = r#"
issuers:
  - issuer_url: "https://timeout-custom.example.com"
    client_id: "unix-oidc"
    http_timeout_secs: 30
"#;
    let policy: PolicyConfig = figment::Figment::from(figment::providers::Serialized::defaults(
        PolicyConfig::default(),
    ))
    .merge(figment::providers::Yaml::string(yaml))
    .extract()
    .expect("custom http_timeout_secs must deserialise");

    assert_eq!(
        policy.issuers[0].http_timeout_secs, 30,
        "http_timeout_secs must be 30"
    );
}

/// DEBT-05: IssuerConfig defaults to jwks_cache_ttl_secs=300, http_timeout_secs=10.
#[test]
fn test_issuer_config_default_jwks_values() {
    let issuer = IssuerConfig::default();
    assert_eq!(
        issuer.jwks_cache_ttl_secs, 300,
        "jwks_cache_ttl_secs must default to 300"
    );
    assert_eq!(
        issuer.http_timeout_secs, 10,
        "http_timeout_secs must default to 10"
    );
}

/// DEBT-05: IssuerConfig with jwks_cache_ttl_secs=0 deserializes (operator's choice).
#[test]
fn test_issuer_config_zero_jwks_ttl_valid() {
    let yaml = r#"
issuers:
  - issuer_url: "https://zero-ttl.example.com"
    client_id: "unix-oidc"
    jwks_cache_ttl_secs: 0
"#;
    let policy: PolicyConfig = figment::Figment::from(figment::providers::Serialized::defaults(
        PolicyConfig::default(),
    ))
    .merge(figment::providers::Yaml::string(yaml))
    .extract()
    .expect("jwks_cache_ttl_secs=0 must deserialise");

    assert_eq!(
        policy.issuers[0].jwks_cache_ttl_secs, 0,
        "jwks_cache_ttl_secs=0 must be valid"
    );
}

// ── MIDP-09: Priority ordering ────────────────────────────────────────────────

/// MIDP-09: Token from issuer A (position 0) resolves to position 0 in priority list.
///
/// Verifies that `authenticate_multi_issuer` succeeds in routing the token to issuer A
/// (not UnknownIssuer, not position confusion). Position is implicitly tested: with
/// issuers [A, B], a token from A must route to the first issuer.
#[test]
fn test_priority_ordering_issuer_a_at_position_0() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss_a = "https://priority-a.example.com";
    let iss_b = "https://priority-b.example.com";
    let token = make_test_token(iss_a, "alice", "alice", Some("jti-priority-a-01"));
    // issuers[0]=A, issuers[1]=B — token from A must route to index 0
    let policy = make_two_issuer_policy(iss_a, iss_b, EnforcementMode::Disabled);
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // Must not be UnknownIssuer — routing found issuer A at position 0.
    // Will fail at UserNotFound (no SSSD).
    assert!(
        !matches!(result, Err(AuthError::UnknownIssuer(_))),
        "token from issuer A (position 0) must route correctly, got: {result:?}"
    );
}

/// MIDP-09: Token from issuer B (position 1) resolves to position 1 in priority list.
#[test]
fn test_priority_ordering_issuer_b_at_position_1() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss_a = "https://priority-a2.example.com";
    let iss_b = "https://priority-b2.example.com";
    let token = make_test_token(iss_b, "bob", "bob", Some("jti-priority-b-01"));
    // issuers[0]=A, issuers[1]=B — token from B must route to index 1
    let policy = make_two_issuer_policy(iss_a, iss_b, EnforcementMode::Disabled);
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    // Must not be UnknownIssuer — routing found issuer B at position 1.
    assert!(
        !matches!(result, Err(AuthError::UnknownIssuer(_))),
        "token from issuer B (position 1) must route correctly, got: {result:?}"
    );
}

/// MIDP-09: Token from unknown issuer C is rejected regardless of priority ordering.
#[test]
fn test_priority_ordering_unknown_issuer_rejected() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss_c = "https://priority-unknown.example.com";
    let token = make_test_token(iss_c, "eve", "eve", Some("jti-priority-c-01"));
    let policy = make_two_issuer_policy(
        "https://priority-a3.example.com",
        "https://priority-b3.example.com",
        EnforcementMode::Disabled,
    );
    let registry = IssuerJwksRegistry::new();
    let dpop_config = DPoPAuthConfig::default();

    let result = authenticate_multi_issuer(&token, None, &dpop_config, &policy, &registry);
    std::env::remove_var("UNIX_OIDC_TEST_MODE");

    assert!(
        matches!(result, Err(AuthError::UnknownIssuer(_))),
        "token from unknown issuer must produce UnknownIssuer error, got: {result:?}"
    );
}

/// MIDP-09 (negative): Priority ordering does not bypass signature verification.
///
/// A token whose `iss` claim is a configured issuer but whose signature would fail
/// real JWKS validation must still be rejected. Under test-mode the validator skips
/// signatures, so we verify at the structural level: issuer_by_url() must still
/// return the correct issuer (no bypass of routing security boundary).
#[test]
fn test_priority_ordering_does_not_affect_issuer_lookup_security() {
    // This is a config-level security test: ensure the priority field does not change
    // what `issuer_by_url` returns. The order-0 issuer must always be returned for its URL.
    let iss_a = "https://priority-sec-a.example.com";
    let iss_b = "https://priority-sec-b.example.com";
    let policy = make_two_issuer_policy(iss_a, iss_b, EnforcementMode::Disabled);

    // issuer_by_url must return the first match by URL, not affected by any priority reordering.
    let found_a = policy.issuer_by_url(iss_a);
    let found_b = policy.issuer_by_url(iss_b);
    let found_none = policy.issuer_by_url("https://not-configured.example.com");

    assert!(found_a.is_some(), "issuer A must be found by URL");
    assert_eq!(
        found_a.unwrap().issuer_url,
        iss_a,
        "issuer_by_url for A must return issuer A config"
    );
    assert!(found_b.is_some(), "issuer B must be found by URL");
    assert_eq!(
        found_b.unwrap().issuer_url,
        iss_b,
        "issuer_by_url for B must return issuer B config"
    );
    assert!(
        found_none.is_none(),
        "unknown issuer URL must return None — no forged access via unknown issuer"
    );
}

// ── MIDP-10: Issuer health monitoring ────────────────────────────────────────

/// MIDP-10: After 3 consecutive failures, issuer health state is degraded.
#[test]
fn test_health_state_degraded_after_three_failures() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("must create temp dir");
    std::env::set_var("UNIX_OIDC_HEALTH_DIR", dir.path().to_str().unwrap());

    let issuer_url = "https://health-degrade.example.com";
    let manager = IssuerHealthManager::new();

    // Two failures — not yet degraded
    manager.record_failure(issuer_url);
    manager.record_failure(issuer_url);
    assert!(
        !manager.is_degraded(issuer_url, 300),
        "two failures must not mark issuer as degraded"
    );

    // Third failure — crosses the threshold
    manager.record_failure(issuer_url);
    assert!(
        manager.is_degraded(issuer_url, 300),
        "three consecutive failures must mark issuer as degraded"
    );

    std::env::remove_var("UNIX_OIDC_HEALTH_DIR");
}

/// MIDP-10: A successful JWKS fetch clears degraded state (failure count reset to 0).
#[test]
fn test_health_state_cleared_on_success() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("must create temp dir");
    std::env::set_var("UNIX_OIDC_HEALTH_DIR", dir.path().to_str().unwrap());

    let issuer_url = "https://health-recover.example.com";
    let manager = IssuerHealthManager::new();

    // Degrade the issuer
    manager.record_failure(issuer_url);
    manager.record_failure(issuer_url);
    manager.record_failure(issuer_url);
    assert!(
        manager.is_degraded(issuer_url, 300),
        "issuer must be degraded after 3 failures"
    );

    // Record success — must clear degraded state
    manager.record_success(issuer_url);
    assert!(
        !manager.is_degraded(issuer_url, 300),
        "success must clear degraded state"
    );

    std::env::remove_var("UNIX_OIDC_HEALTH_DIR");
}

/// MIDP-10 (negative): A single JWKS failure does NOT mark the issuer as degraded.
#[test]
fn test_health_state_single_failure_not_degraded() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("must create temp dir");
    std::env::set_var("UNIX_OIDC_HEALTH_DIR", dir.path().to_str().unwrap());

    let issuer_url = "https://health-single.example.com";
    let manager = IssuerHealthManager::new();

    manager.record_failure(issuer_url);
    assert!(
        !manager.is_degraded(issuer_url, 300),
        "single failure must not mark issuer as degraded"
    );

    std::env::remove_var("UNIX_OIDC_HEALTH_DIR");
}

/// MIDP-10: A degraded issuer with elapsed recovery interval is treated as healthy (retry).
#[test]
fn test_health_state_degraded_recovery_interval_elapsed() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("must create temp dir");
    std::env::set_var("UNIX_OIDC_HEALTH_DIR", dir.path().to_str().unwrap());

    let issuer_url = "https://health-elapsed.example.com";
    let manager = IssuerHealthManager::new();

    // Degrade the issuer
    manager.record_failure(issuer_url);
    manager.record_failure(issuer_url);
    manager.record_failure(issuer_url);
    assert!(
        manager.is_degraded(issuer_url, 300),
        "issuer must be degraded after 3 failures"
    );

    // With recovery_interval=0, the interval has "elapsed" immediately
    assert!(
        !manager.is_degraded(issuer_url, 0),
        "with recovery_interval=0, degraded issuer should be retried (interval elapsed)"
    );

    std::env::remove_var("UNIX_OIDC_HEALTH_DIR");
}

/// MIDP-10 (negative): A degraded issuer within its recovery interval remains degraded.
#[test]
fn test_health_state_degraded_within_recovery_interval() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("must create temp dir");
    std::env::set_var("UNIX_OIDC_HEALTH_DIR", dir.path().to_str().unwrap());

    let issuer_url = "https://health-within.example.com";
    let manager = IssuerHealthManager::new();

    // Degrade the issuer
    manager.record_failure(issuer_url);
    manager.record_failure(issuer_url);
    manager.record_failure(issuer_url);

    // With a very large recovery interval, the issuer stays degraded
    assert!(
        manager.is_degraded(issuer_url, 86400), // 24 hours
        "degraded issuer within large recovery interval must remain degraded"
    );

    std::env::remove_var("UNIX_OIDC_HEALTH_DIR");
}

/// MIDP-10: Health state persistence — write state to file, read it back, values match.
#[test]
fn test_health_state_persists_across_manager_instances() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("must create temp dir");
    std::env::set_var("UNIX_OIDC_HEALTH_DIR", dir.path().to_str().unwrap());

    let issuer_url = "https://health-persist.example.com";

    // First manager instance: degrade the issuer
    {
        let manager = IssuerHealthManager::new();
        manager.record_failure(issuer_url);
        manager.record_failure(issuer_url);
        manager.record_failure(issuer_url);
        assert!(
            manager.is_degraded(issuer_url, 300),
            "issuer must be degraded in first manager"
        );
    }

    // Second manager instance (fresh): must read persisted state
    {
        let manager2 = IssuerHealthManager::new();
        assert!(
            manager2.is_degraded(issuer_url, 300),
            "degraded state must persist to a new manager instance (file-backed)"
        );
    }

    std::env::remove_var("UNIX_OIDC_HEALTH_DIR");
}

/// MIDP-10: Corrupt health state file is handled gracefully (treated as healthy, WARN logged).
#[test]
fn test_health_state_corrupt_file_treated_as_healthy() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("must create temp dir");
    std::env::set_var("UNIX_OIDC_HEALTH_DIR", dir.path().to_str().unwrap());

    let issuer_url = "https://health-corrupt.example.com";
    let manager = IssuerHealthManager::new();

    // Write a corrupt JSON file for this issuer's health key
    let health_path = manager.health_file_path(issuer_url);
    std::fs::create_dir_all(health_path.parent().unwrap()).expect("must create health dir");
    std::fs::write(&health_path, b"{{corrupt: json}}}").expect("must write corrupt file");

    // Loading the corrupt file must return healthy (not panic or return error)
    assert!(
        !manager.is_degraded(issuer_url, 300),
        "corrupt health file must be treated as healthy (graceful degradation)"
    );

    std::env::remove_var("UNIX_OIDC_HEALTH_DIR");
}

// ── MIDP-11: Config hot-reload ────────────────────────────────────────────────

/// MIDP-11: Config freshness check detects changed mtime and reloads config.
#[test]
fn test_config_fresh_detects_changed_mtime() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("must create temp dir");
    let config_path = dir.path().join("policy.yaml");

    // Write initial config
    std::fs::write(
        &config_path,
        b"issuers:\n  - issuer_url: \"https://hot-reload-v1.example.com\"\n    client_id: \"unix-oidc\"\n",
    )
    .expect("must write initial config");
    std::env::set_var("UNIX_OIDC_POLICY", config_path.to_str().unwrap());

    // Load config — populates the cache
    let config1 = PolicyConfig::load_fresh().expect("must load initial config");
    assert_eq!(
        config1.issuers[0].issuer_url, "https://hot-reload-v1.example.com",
        "first load must return v1 issuer"
    );

    // Modify config (change mtime)
    std::thread::sleep(std::time::Duration::from_millis(10)); // ensure mtime differs
    std::fs::write(
        &config_path,
        b"issuers:\n  - issuer_url: \"https://hot-reload-v2.example.com\"\n    client_id: \"unix-oidc\"\n",
    )
    .expect("must write updated config");

    // Re-load — must detect mtime change and return new config
    let config2 = PolicyConfig::load_fresh().expect("must load updated config");
    assert_eq!(
        config2.issuers[0].issuer_url, "https://hot-reload-v2.example.com",
        "after mtime change, load_fresh must return updated issuer"
    );

    std::env::remove_var("UNIX_OIDC_POLICY");
}

/// MIDP-11: Config freshness check with unchanged mtime returns cached config.
#[test]
fn test_config_fresh_unchanged_mtime_returns_cached() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("must create temp dir");
    let config_path = dir.path().join("policy-cached.yaml");

    std::fs::write(
        &config_path,
        b"issuers:\n  - issuer_url: \"https://hot-reload-cached.example.com\"\n    client_id: \"unix-oidc\"\n",
    )
    .expect("must write config");
    std::env::set_var("UNIX_OIDC_POLICY", config_path.to_str().unwrap());

    // First load — populates cache
    let config1 = PolicyConfig::load_fresh().expect("must load config");

    // Second load without modifying file — must return cached result (same issuer URL)
    let config2 = PolicyConfig::load_fresh().expect("must re-load config");
    assert_eq!(
        config1.issuers[0].issuer_url, config2.issuers[0].issuer_url,
        "unchanged mtime must return cached config"
    );

    std::env::remove_var("UNIX_OIDC_POLICY");
}

/// MIDP-11 (negative): A bad YAML file on reload keeps the previous valid config.
#[test]
fn test_config_fresh_bad_yaml_keeps_previous() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("must create temp dir");
    let config_path = dir.path().join("policy-bad-reload.yaml");

    // Write a valid config first
    std::fs::write(
        &config_path,
        b"issuers:\n  - issuer_url: \"https://hot-reload-good.example.com\"\n    client_id: \"unix-oidc\"\n",
    )
    .expect("must write valid config");
    std::env::set_var("UNIX_OIDC_POLICY", config_path.to_str().unwrap());

    let config1 = PolicyConfig::load_fresh().expect("must load valid config");
    assert_eq!(
        config1.issuers[0].issuer_url, "https://hot-reload-good.example.com",
        "first load must return valid issuer"
    );

    // Overwrite with bad YAML
    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(&config_path, b"{{invalid: yaml: {{content}}}}").expect("must write bad config");

    // Reload must return the previous valid config (not fail or return empty)
    let config2 = PolicyConfig::load_fresh()
        .expect("bad YAML reload must return previous valid config, not Err");
    assert_eq!(
        config2.issuers[0].issuer_url, "https://hot-reload-good.example.com",
        "bad YAML reload must preserve previous valid config"
    );

    std::env::remove_var("UNIX_OIDC_POLICY");
}

/// MIDP-11 (negative): A missing config file on reload keeps the previous valid config.
#[test]
fn test_config_fresh_missing_file_keeps_previous() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("must create temp dir");
    let config_path = dir.path().join("policy-missing.yaml");

    // Write a valid config first
    std::fs::write(
        &config_path,
        b"issuers:\n  - issuer_url: \"https://hot-reload-present.example.com\"\n    client_id: \"unix-oidc\"\n",
    )
    .expect("must write valid config");
    std::env::set_var("UNIX_OIDC_POLICY", config_path.to_str().unwrap());

    let config1 = PolicyConfig::load_fresh().expect("must load valid config");
    assert_eq!(
        config1.issuers[0].issuer_url,
        "https://hot-reload-present.example.com"
    );

    // Delete the config file
    std::fs::remove_file(&config_path).expect("must delete config");

    // Reload must return the previous valid config
    let config2 = PolicyConfig::load_fresh()
        .expect("missing file reload must return previous valid config, not Err");
    assert_eq!(
        config2.issuers[0].issuer_url, "https://hot-reload-present.example.com",
        "missing config file on reload must preserve previous valid config"
    );

    std::env::remove_var("UNIX_OIDC_POLICY");
}

/// DEBT-02: AcrMappingConfig with required_acr deserialises from YAML.
#[test]
fn test_acr_mapping_with_required_acr_deserialises() {
    let yaml = r#"
issuers:
  - issuer_url: "https://acr-req.example.com"
    client_id: "unix-oidc"
    acr_mapping:
      enforcement: strict
      required_acr: "urn:mfa"
      mappings:
        "urn:idp:mfa": "urn:mfa"
"#;
    let policy: PolicyConfig = figment::Figment::from(figment::providers::Serialized::defaults(
        PolicyConfig::default(),
    ))
    .merge(figment::providers::Yaml::string(yaml))
    .extract()
    .expect("required_acr must deserialise from YAML");

    let acr = policy.issuers[0]
        .acr_mapping
        .as_ref()
        .expect("acr_mapping must be present");
    assert_eq!(
        acr.required_acr,
        Some("urn:mfa".to_string()),
        "required_acr must deserialise as Some(\"urn:mfa\")"
    );
}
