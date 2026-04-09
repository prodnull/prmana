//! Integration tests for RFC 8693 token exchange delegation validation.
//!
//! These tests exercise the delegation validation functions with realistic
//! token claim structures, covering both happy paths and adversarial scenarios.
//!
//! References:
//! - RFC 8693 §4.1 (`act` claim)
//! - ADR-005-alignment (DPoP token exchange design)

use std::collections::HashMap;

use pam_unix_oidc::oidc::token::{ActClaim, ConfirmationClaim, StringOrVec, TokenClaims};
use pam_unix_oidc::oidc::validation::{
    validate_delegation, validate_delegation_optional, validate_exchanged_token_lifetime,
    ValidationError,
};
use pam_unix_oidc::policy::config::DelegationConfig;

/// Helper: build a `TokenClaims` with given sub, iat, exp, and optional act claim.
fn make_claims(sub: &str, iat: i64, exp: i64, act: Option<ActClaim>) -> TokenClaims {
    TokenClaims {
        sub: sub.into(),
        preferred_username: Some(sub.into()),
        iss: "https://idp.example.com".into(),
        aud: StringOrVec::String("unix-oidc".into()),
        exp,
        iat,
        auth_time: None,
        acr: None,
        amr: None,
        jti: Some("test-jti".into()),
        cnf: Some(ConfirmationClaim {
            jkt: Some("test-jkt".into()),
        }),
        act,
        extra: HashMap::new(),
    }
}

/// Helper: build a standard `DelegationConfig` allowing two jump hosts.
fn standard_config() -> DelegationConfig {
    DelegationConfig {
        allowed_exchangers: vec!["jump-host-a".into(), "jump-host-b".into()],
        max_depth: 2,
        exchanged_token_max_lifetime_secs: 300,
    }
}

// ── Happy paths ────────────────────────────────────────────────────────────

/// 1. Token with act claim + matching delegation config -> accepted.
///
/// The exchanger's client_id matches an entry in allowed_exchangers and the
/// delegation depth (1) is within max_depth (2).
#[test]
fn test_exchange_accepted_with_valid_config() {
    let config = standard_config();
    let act = ActClaim {
        sub: "service-jump-host-a".into(),
        client_id: Some("jump-host-a".into()),
        act: None,
    };
    assert!(validate_delegation(&act, &config).is_ok());
}

/// 2. Token without act -> normal validation path (no delegation check needed).
///
/// delegation_depth() returns 0, confirming the absence of an act chain.
/// Callers only invoke validate_delegation() when act is Some.
#[test]
fn test_no_act_claim_passes_through() {
    let claims = make_claims("alice", 1000, 9_999_999_999, None);
    assert_eq!(claims.delegation_depth(), 0);
    // No act claim = nothing to validate, delegation functions not called
}

// ── Rejection paths ────────────────────────────────────────────────────────

/// 3. Token with act claim + no delegation config -> rejected.
///
/// When the issuer has no delegation section in policy.yaml, any exchanged
/// token must be hard-rejected. This is the security-by-default invariant.
#[test]
fn test_exchange_rejected_no_delegation_config() {
    let act = ActClaim {
        sub: "jump-host-a".into(),
        client_id: Some("jump-host-a".into()),
        act: None,
    };
    let err = validate_delegation_optional(&act, None).unwrap_err();
    assert!(
        matches!(err, ValidationError::DelegationNotAllowed),
        "Expected DelegationNotAllowed, got: {err:?}"
    );
}

/// 4. Token with act claim + unauthorized exchanger -> rejected.
///
/// The exchanger's client_id does not appear in allowed_exchangers.
/// The error must identify the offending exchanger for audit logging.
#[test]
fn test_exchange_rejected_unauthorized_exchanger() {
    let config = standard_config();
    let act = ActClaim {
        sub: "evil-host".into(),
        client_id: Some("evil-host".into()),
        act: None,
    };
    let err = validate_delegation(&act, &config).unwrap_err();
    match err {
        ValidationError::UnauthorizedExchanger { exchanger } => {
            assert_eq!(exchanger, "evil-host");
        }
        other => panic!("Expected UnauthorizedExchanger, got: {other:?}"),
    }
}

/// 5. Token with nested act exceeding max_depth -> rejected.
///
/// Config allows max_depth=1 (single hop), but the act chain has depth=2
/// (jump-host-b -> jump-host-a). Must be rejected with accurate depth report.
#[test]
fn test_exchange_rejected_depth_exceeded() {
    let mut config = standard_config();
    config.max_depth = 1; // Only single-hop allowed
    let act = ActClaim {
        sub: "jump-host-b".into(),
        client_id: Some("jump-host-b".into()),
        act: Some(Box::new(ActClaim {
            sub: "jump-host-a".into(),
            client_id: None,
            act: None,
        })),
    };
    let err = validate_delegation(&act, &config).unwrap_err();
    match err {
        ValidationError::DelegationDepthExceeded { actual, max } => {
            assert_eq!(actual, 2);
            assert_eq!(max, 1);
        }
        other => panic!("Expected DelegationDepthExceeded, got: {other:?}"),
    }
}

/// 6. Exchanged token lifetime exceeding max -> rejected.
///
/// Config allows 300s max lifetime. Token has iat=0, exp=600 (600s lifetime).
/// Must be rejected with accurate lifetime report.
#[test]
fn test_exchange_rejected_lifetime_exceeded() {
    let config = standard_config(); // max 300s
    // Token with 600s lifetime (iat=0, exp=600)
    let claims = make_claims(
        "alice",
        0,
        600,
        Some(ActClaim {
            sub: "jump-host-a".into(),
            client_id: Some("jump-host-a".into()),
            act: None,
        }),
    );
    let err = validate_exchanged_token_lifetime(&claims, &config).unwrap_err();
    match err {
        ValidationError::ExchangedTokenLifetimeExceeded {
            actual_secs,
            max_secs,
        } => {
            assert_eq!(actual_secs, 600);
            assert_eq!(max_secs, 300);
        }
        other => panic!("Expected ExchangedTokenLifetimeExceeded, got: {other:?}"),
    }
}

// ── Adversarial edge cases ─────────────────────────────────────────────────

/// 7. act.sub contains path traversal chars -> exchanger match fails safely.
///
/// Ensures that malicious act.sub / client_id values containing directory
/// traversal sequences are treated as plain strings and simply fail the
/// allowlist check. No path interpretation occurs.
#[test]
fn test_adversarial_path_traversal_in_act_sub() {
    let config = standard_config();
    let act = ActClaim {
        sub: "../../../etc/passwd".into(),
        client_id: Some("../../../etc/passwd".into()),
        act: None,
    };
    let err = validate_delegation(&act, &config).unwrap_err();
    assert!(
        matches!(err, ValidationError::UnauthorizedExchanger { .. }),
        "Path traversal in act.sub must fail as unauthorized exchanger"
    );
}

/// 8. Deeply nested act chain (100 levels) -> rejected, no stack overflow.
///
/// Builds a 100-deep delegation chain. With max_depth=5, the depth check
/// must reject it early. The iterative depth counter must handle deep
/// chains without stack overflow (no recursion in the hot path).
#[test]
fn test_adversarial_deep_nesting_no_stack_overflow() {
    let mut config = standard_config();
    config.max_depth = 5; // Low limit
    config.allowed_exchangers.push("hop-99".into());

    // Build a 100-level chain: hop-99 -> hop-98 -> ... -> hop-0
    let mut innermost = ActClaim {
        sub: "hop-0".into(),
        client_id: None,
        act: None,
    };
    for i in 1..100 {
        innermost = ActClaim {
            sub: format!("hop-{i}"),
            client_id: if i == 99 {
                Some("hop-99".into())
            } else {
                None
            },
            act: Some(Box::new(innermost)),
        };
    }

    let err = validate_delegation(&innermost, &config).unwrap_err();
    assert!(
        matches!(err, ValidationError::DelegationDepthExceeded { .. }),
        "100-deep chain must be rejected: {err:?}"
    );
}
