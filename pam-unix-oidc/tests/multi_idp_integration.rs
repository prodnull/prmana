//! Multi-IdP integration tests (Phase 21, MIDP-01..08).
//!
//! Exercises the full multi-issuer authentication path end-to-end:
//! - MIDP-01: Two-issuer policy loads; backward-compat via effective_issuers()
//! - MIDP-02: Per-issuer DPoP enforcement (strict vs disabled)
//! - MIDP-03: Per-issuer ACR mapping config deserialises and lookups work
//! - MIDP-04: Per-issuer group mapping (NSS-only default vs TokenClaim)
//! - MIDP-05: Per-issuer claim mapping (strip_domain vs raw)
//! - MIDP-06: Issuer routing (known / unknown / trailing-slash normalization)
//! - MIDP-07: JWKS providers independent per issuer; JTI cross-issuer no collision
//! - MIDP-08: Optional fields fall back to safe defaults with WARN
//!
//! All tests run under `--features test-mode` which enables
//! `TokenValidator::new_insecure_for_testing()` (signature verification bypassed).
//! Tests that need UNIX_OIDC_TEST_MODE set are serialized via ENV_MUTEX to prevent
//! races between parallel test threads.
//!
//! NEVER enable test-mode in production builds.

#![cfg(feature = "test-mode")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pam_unix_oidc::auth::{authenticate_multi_issuer, AuthError, DPoPAuthConfig};
use pam_unix_oidc::oidc::jwks::IssuerJwksRegistry;
use pam_unix_oidc::policy::config::{
    AcrMappingConfig, EnforcementMode, GroupMappingConfig, GroupSource, IdentityConfig,
    IssuerConfig, PolicyConfig, TransformConfig,
};
use figment::providers::Format as _;
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
    let jti_field = jti
        .map(|j| format!(r#","jti":"{j}""#))
        .unwrap_or_default();
    let payload = format!(
        r#"{{"iss":"{iss}","sub":"{sub}","aud":"unix-oidc","exp":{exp},"iat":{now},"preferred_username":"{preferred_username}"{jti_field}}}"#
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
    let mut policy = PolicyConfig::default();
    policy.issuers = vec![
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
    ];
    policy
}

// ── MIDP-01: Config loading ───────────────────────────────────────────────────

/// MIDP-01: Two-issuer policy loads from YAML fixture without error.
#[test]
fn test_two_issuer_policy_loads_from_yaml() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test/fixtures/policy/policy-multi-idp.yaml"
    );
    let policy = PolicyConfig::load_from(fixture)
        .expect("multi-idp fixture must load without error");
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
        policy.issuers[1]
            .issuer_url
            .contains("microsoftonline.com"),
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

/// MIDP-01: effective_issuers() returns issuers[] when non-empty.
#[test]
fn test_effective_issuers_returns_configured() {
    let policy = make_two_issuer_policy(
        "https://kc.example.com/realms/a",
        "https://entra.example.com",
        EnforcementMode::Strict,
    );
    let effective = policy
        .effective_issuers()
        .expect("effective_issuers must succeed");
    assert_eq!(effective.len(), 2, "must return both configured issuers");
}

// ── MIDP-02: Per-issuer DPoP enforcement ─────────────────────────────────────

/// MIDP-02: Issuer with dpop_enforcement=strict rejects token without DPoP proof.
#[test]
fn test_dpop_strict_rejects_bearer_only() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("UNIX_OIDC_TEST_MODE", "1");

    let iss_a = "https://kc.example.com/realms/corp";
    let token = make_test_token(iss_a, "alice", "alice", Some("jti-strict-01"));
    let policy = make_two_issuer_policy(
        iss_a,
        "https://entra.example.com",
        EnforcementMode::Strict,
    );
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
    let acr_map = kc.acr_mapping.as_ref().expect("Keycloak must have acr_mapping");
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
    };
    assert!(
        acr_cfg.mappings.get("urn:unknown:acr:value").is_none(),
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

/// MIDP-04: GroupMappingConfig with source=TokenClaim carries claim name.
#[test]
fn test_group_mapping_token_claim_mode() {
    let cfg = GroupMappingConfig {
        source: GroupSource::TokenClaim,
        claim: "roles".to_string(),
        name_map: HashMap::new(),
    };
    assert_eq!(cfg.source, GroupSource::TokenClaim);
    assert_eq!(cfg.claim, "roles");
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
    let token = make_test_token(iss_a, "alice@corp.example", "alice@corp.example", Some("jti-strip-05"));

    let mut policy = PolicyConfig::default();
    policy.issuers = vec![
        IssuerConfig {
            issuer_url: iss_a.to_string(),
            client_id: "unix-oidc".to_string(),
            dpop_enforcement: EnforcementMode::Disabled, // avoid DPoP error first
            claim_mapping: IdentityConfig {
                username_claim: "preferred_username".to_string(),
                transforms: vec![TransformConfig::Simple("strip_domain".to_string())],
            },
            ..IssuerConfig::default()
        },
    ];
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
    let token = make_test_token(iss_b, "alice@corp.example", "alice@corp.example", Some("jti-raw-05"));

    let mut policy = PolicyConfig::default();
    policy.issuers = vec![
        IssuerConfig {
            issuer_url: iss_b.to_string(),
            client_id: "unix-oidc".to_string(),
            dpop_enforcement: EnforcementMode::Disabled,
            claim_mapping: IdentityConfig::default(), // no transforms
            ..IssuerConfig::default()
        },
    ];
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
    let mut policy = PolicyConfig::default();
    policy.issuers = vec![IssuerConfig {
        issuer_url: "https://slash-norm.example.com/realms/test/".to_string(),
        client_id: "unix-oidc".to_string(),
        dpop_enforcement: EnforcementMode::Disabled,
        ..IssuerConfig::default()
    }];
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
