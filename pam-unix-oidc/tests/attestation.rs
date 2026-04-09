//! Integration tests for hardware attestation verification (ADR-018).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pam_unix_oidc::oidc::attestation::{
    verify_attestation, verify_attestation_optional, AttestationError, AttestationEvidence,
};
use pam_unix_oidc::policy::config::{AttestationConfig, EnforcementMode};

fn valid_evidence() -> AttestationEvidence {
    AttestationEvidence {
        certify_info: URL_SAFE_NO_PAD.encode(vec![0xABu8; 48]),
        signature: URL_SAFE_NO_PAD.encode(vec![0xCDu8; 64]),
        ak_public: URL_SAFE_NO_PAD.encode(vec![0xEFu8; 96]),
    }
}

/// 1. Valid attestation + structural check -> pass
#[test]
fn test_valid_attestation_passes() {
    assert!(verify_attestation(&valid_evidence()).is_ok());
}

/// 2. Tampered certify_info (not valid base64) -> graceful error
#[test]
fn test_malformed_base64_certify_info() {
    let mut ev = valid_evidence();
    ev.certify_info = "!!!invalid!!!".into();
    let err = verify_attestation(&ev).unwrap_err();
    assert!(matches!(err, AttestationError::InvalidEncoding { .. }));
}

/// 3. Attestation missing + strict mode -> reject
#[test]
fn test_strict_mode_rejects_missing() {
    let config = AttestationConfig {
        enforcement: EnforcementMode::Strict,
    };
    let err = verify_attestation_optional(None, Some(&config)).unwrap_err();
    assert!(matches!(err, AttestationError::MissingStrict));
}

/// 4. Attestation missing + warn mode -> pass with warning
#[test]
fn test_warn_mode_allows_missing() {
    let config = AttestationConfig {
        enforcement: EnforcementMode::Warn,
    };
    assert!(verify_attestation_optional(None, Some(&config)).is_ok());
}

/// 5. Attestation missing + disabled mode -> pass silently
#[test]
fn test_disabled_mode_skips() {
    let config = AttestationConfig {
        enforcement: EnforcementMode::Disabled,
    };
    assert!(verify_attestation_optional(None, Some(&config)).is_ok());
}

/// 6. Invalid signature length -> reject
#[test]
fn test_wrong_signature_length_rejected() {
    let mut ev = valid_evidence();
    ev.signature = URL_SAFE_NO_PAD.encode([0u8; 48]); // 48 instead of 64
    let err = verify_attestation(&ev).unwrap_err();
    assert!(matches!(err, AttestationError::InvalidSignatureLength(48)));
}

/// 7. certify_info too short (below TPMS_ATTEST minimum) -> reject
#[test]
fn test_certify_info_below_minimum_size() {
    let mut ev = valid_evidence();
    ev.certify_info = URL_SAFE_NO_PAD.encode([0u8; 5]);
    let err = verify_attestation(&ev).unwrap_err();
    assert!(matches!(err, AttestationError::StructurallyInvalid(_)));
}
