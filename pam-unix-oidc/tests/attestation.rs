//! Integration tests for hardware attestation verification (ADR-018).

use std::path::PathBuf;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pam_unix_oidc::oidc::attestation::{
    verify_attestation, verify_attestation_optional, AttestationError, AttestationEvidence,
};
use pam_unix_oidc::policy::config::{AttestationConfig, EnforcementMode};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    attestation_evidence: AttestationEvidence,
    #[serde(default)]
    dpop_key: Option<serde_json::Value>,
}

fn load_fixture(name: &str) -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test/fixtures/attestation")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn valid_evidence() -> (AttestationEvidence, serde_json::Value) {
    let fixture = load_fixture("valid_attestation.json");
    (
        fixture.attestation_evidence,
        fixture.dpop_key.expect("valid fixture must have dpop_key"),
    )
}

/// 1. Valid attestation + cryptographic checks -> pass
#[test]
fn test_valid_attestation_passes() {
    let (evidence, jwk) = valid_evidence();
    assert!(verify_attestation(&evidence, &jwk).is_ok());
}

/// 2. Tampered certify_info -> AK signature failure
#[test]
fn test_tampered_certify_info_fails_signature() {
    let valid = load_fixture("valid_attestation.json");
    let fixture = load_fixture("tampered_certify_info.json");
    let err = verify_attestation(
        &fixture.attestation_evidence,
        valid.dpop_key.as_ref().unwrap(),
    )
    .unwrap_err();
    assert!(matches!(err, AttestationError::InvalidAkSignature));
}

/// 3. Attestation missing + strict mode -> reject
#[test]
fn test_strict_mode_rejects_missing() {
    let config = AttestationConfig {
        enforcement: EnforcementMode::Strict,
    };
    let err = verify_attestation_optional(None, None, Some(&config)).unwrap_err();
    assert!(matches!(err, AttestationError::MissingStrict));
}

/// 4. Attestation missing + warn mode -> pass with warning
#[test]
fn test_warn_mode_allows_missing() {
    let config = AttestationConfig {
        enforcement: EnforcementMode::Warn,
    };
    assert!(verify_attestation_optional(None, None, Some(&config)).is_ok());
}

/// 5. Attestation missing + disabled mode -> pass silently
#[test]
fn test_disabled_mode_skips() {
    let config = AttestationConfig {
        enforcement: EnforcementMode::Disabled,
    };
    assert!(verify_attestation_optional(None, None, Some(&config)).is_ok());
}

/// 6. Invalid signature length -> reject before crypto verification
#[test]
fn test_wrong_signature_length_rejected() {
    let (mut ev, jwk) = valid_evidence();
    ev.signature = URL_SAFE_NO_PAD.encode([0u8; 48]); // 48 instead of 64
    let err = verify_attestation(&ev, &jwk).unwrap_err();
    assert!(matches!(err, AttestationError::InvalidSignatureLength(48)));
}

/// 7. certify_info too short -> reject
#[test]
fn test_certify_info_below_minimum_size() {
    let (mut ev, jwk) = valid_evidence();
    ev.certify_info = URL_SAFE_NO_PAD.encode([0u8; 5]);
    let err = verify_attestation(&ev, &jwk).unwrap_err();
    assert!(matches!(err, AttestationError::StructurallyInvalid(_)));
}

/// 8. Name mismatch fixture -> reject
#[test]
fn test_name_mismatch_fixture_rejected() {
    let fixture = load_fixture("name_mismatch.json");
    let err = verify_attestation(
        &fixture.attestation_evidence,
        fixture.dpop_key.as_ref().unwrap(),
    )
    .unwrap_err();
    assert!(matches!(err, AttestationError::NameMismatch));
}
