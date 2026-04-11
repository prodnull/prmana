//! Hardware attestation verification for DPoP proofs (ADR-018).
//!
//! Verifies TPM key attestation evidence embedded in the DPoP proof JWT header.
//! Phase 38 adds cryptographic verification:
//! - AK ECDSA signature verification over `certify_info`
//! - TPMS_ATTEST parsing to extract the certified key Name
//! - Name matching against the DPoP JWK's reconstructed TPMT_PUBLIC
//!
//! Still deferred:
//! - EK certificate chain verification

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::policy::config::{AttestationConfig, EnforcementMode};

/// Attestation evidence extracted from the DPoP proof `attest` header field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// TPMS_ATTEST structure (base64url-encoded).
    pub certify_info: String,
    /// ECDSA signature over certify_info by the Attestation Key (base64url-encoded).
    pub signature: String,
    /// Public area of the Attestation Key (base64url-encoded).
    pub ak_public: String,
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("Attestation evidence missing but enforcement is strict")]
    MissingStrict,

    #[error("Invalid base64url in attestation field '{field}': {reason}")]
    InvalidEncoding { field: String, reason: String },

    #[error("Attestation signature length invalid: expected 64 bytes, got {0}")]
    InvalidSignatureLength(usize),

    #[error("Attestation evidence structurally invalid: {0}")]
    StructurallyInvalid(String),

    #[error("AK signature verification failed")]
    InvalidAkSignature,

    #[error("AK public area invalid: {0}")]
    InvalidAkPublic(String),

    #[error("Certified TPM Name does not match DPoP key")]
    NameMismatch,

    #[error("DPoP JWK invalid for attestation matching: {0}")]
    InvalidDpopJwk(String),
}

const TPM_GENERATED_VALUE: [u8; 4] = [0xFF, 0x54, 0x43, 0x47];
const TPM_ST_ATTEST_CERTIFY: [u8; 2] = [0x80, 0x17];
const TPM_ALG_SHA256: [u8; 2] = [0x00, 0x0B];
const TPMT_PUBLIC_P256_LEN: usize = 88;

/// Verify attestation evidence from a DPoP proof header.
///
/// Verification checks:
/// 1. All three fields are present and valid base64url
/// 2. Signature is 64 bytes (P-256 ECDSA r||s)
/// 3. certify_info is non-empty (TPMS_ATTEST minimum size)
/// 4. AK ECDSA signature verifies over certify_info
/// 5. attested.name in TPMS_ATTEST matches the DPoP public key
pub fn verify_attestation(
    evidence: &AttestationEvidence,
    dpop_jwk: &serde_json::Value,
) -> Result<(), AttestationError> {
    // Decode and validate certify_info
    let certify_bytes = URL_SAFE_NO_PAD
        .decode(&evidence.certify_info)
        .map_err(|e| AttestationError::InvalidEncoding {
            field: "certify_info".into(),
            reason: e.to_string(),
        })?;
    if certify_bytes.is_empty() {
        return Err(AttestationError::StructurallyInvalid(
            "certify_info is empty".into(),
        ));
    }
    // TPMS_ATTEST minimum: magic (4) + type (2) + qualifiedSigner (2+) + extraData (2+)
    // + clock (8) + resetCount (4) + restartCount (4) + safe (1) + firmwareVersion (8)
    // + attested (varies) = at least ~40 bytes
    if certify_bytes.len() < 40 {
        return Err(AttestationError::StructurallyInvalid(format!(
            "certify_info too short ({} bytes, minimum ~40 for TPMS_ATTEST)",
            certify_bytes.len()
        )));
    }

    // Decode and validate signature (P-256 ECDSA = 64 bytes: 32r + 32s)
    let sig_bytes = URL_SAFE_NO_PAD.decode(&evidence.signature).map_err(|e| {
        AttestationError::InvalidEncoding {
            field: "signature".into(),
            reason: e.to_string(),
        }
    })?;
    if sig_bytes.len() != 64 {
        return Err(AttestationError::InvalidSignatureLength(sig_bytes.len()));
    }

    // Decode and validate ak_public
    let ak_bytes = URL_SAFE_NO_PAD.decode(&evidence.ak_public).map_err(|e| {
        AttestationError::InvalidEncoding {
            field: "ak_public".into(),
            reason: e.to_string(),
        }
    })?;
    if ak_bytes.is_empty() {
        return Err(AttestationError::StructurallyInvalid(
            "ak_public is empty".into(),
        ));
    }

    verify_ak_signature(&certify_bytes, &sig_bytes, &ak_bytes)?;
    let certified_name = parse_certified_name(&certify_bytes)?;
    match_name_to_jwk(&certified_name, dpop_jwk)?;

    Ok(())
}

fn verify_ak_signature(
    certify_info: &[u8],
    signature: &[u8],
    ak_public: &[u8],
) -> Result<(), AttestationError> {
    if ak_public.len() < TPMT_PUBLIC_P256_LEN {
        return Err(AttestationError::InvalidAkPublic(format!(
            "TPMT_PUBLIC too short: {} bytes",
            ak_public.len()
        )));
    }
    if signature.len() != 64 {
        return Err(AttestationError::InvalidSignatureLength(signature.len()));
    }

    let x_len = read_u16_be(ak_public, 20)? as usize;
    let x_start = 22;
    let x_end = x_start + x_len;
    if x_len != 32 || x_end > ak_public.len() {
        return Err(AttestationError::InvalidAkPublic(format!(
            "unexpected AK x coordinate length: {x_len}"
        )));
    }

    let y_len = read_u16_be(ak_public, x_end)? as usize;
    let y_start = x_end + 2;
    let y_end = y_start + y_len;
    if y_len != 32 || y_end > ak_public.len() {
        return Err(AttestationError::InvalidAkPublic(format!(
            "unexpected AK y coordinate length: {y_len}"
        )));
    }

    let point = EncodedPoint::from_affine_coordinates(
        (&ak_public[x_start..x_end]).into(),
        (&ak_public[y_start..y_end]).into(),
        false,
    );
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| AttestationError::InvalidAkPublic(e.to_string()))?;
    let signature =
        Signature::from_slice(signature).map_err(|_| AttestationError::InvalidAkSignature)?;
    verifying_key
        .verify(certify_info, &signature)
        .map_err(|_| AttestationError::InvalidAkSignature)
}

fn parse_certified_name(certify_info: &[u8]) -> Result<Vec<u8>, AttestationError> {
    if certify_info.len() < 71 {
        return Err(AttestationError::StructurallyInvalid(
            "certify_info too short for TPMS_ATTEST certify structure".into(),
        ));
    }
    if certify_info[0..4] != TPM_GENERATED_VALUE {
        return Err(AttestationError::StructurallyInvalid(
            "TPMS_ATTEST magic mismatch".into(),
        ));
    }
    if certify_info[4..6] != TPM_ST_ATTEST_CERTIFY {
        return Err(AttestationError::StructurallyInvalid(
            "TPMS_ATTEST type is not ATTEST_CERTIFY".into(),
        ));
    }

    let mut offset = 6;
    offset = skip_tpm2b(certify_info, offset)?;
    offset = skip_tpm2b(certify_info, offset)?;

    if certify_info.len() < offset + 17 + 8 {
        return Err(AttestationError::StructurallyInvalid(
            "TPMS_ATTEST truncated before attested section".into(),
        ));
    }
    offset += 17; // TPMS_CLOCK_INFO
    offset += 8; // firmwareVersion

    let name_len = read_u16_be(certify_info, offset)? as usize;
    let name_start = offset + 2;
    let name_end = name_start + name_len;
    if name_len != 34 || name_end > certify_info.len() {
        return Err(AttestationError::StructurallyInvalid(format!(
            "unexpected attested.name length: {name_len}"
        )));
    }

    Ok(certify_info[name_start..name_end].to_vec())
}

fn match_name_to_jwk(
    certified_name: &[u8],
    dpop_jwk: &serde_json::Value,
) -> Result<(), AttestationError> {
    let x_b64 = dpop_jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AttestationError::InvalidDpopJwk("missing x".into()))?;
    let y_b64 = dpop_jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AttestationError::InvalidDpopJwk("missing y".into()))?;
    let x = URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|e| AttestationError::InvalidDpopJwk(format!("x decode failed: {e}")))?;
    let y = URL_SAFE_NO_PAD
        .decode(y_b64)
        .map_err(|e| AttestationError::InvalidDpopJwk(format!("y decode failed: {e}")))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(AttestationError::InvalidDpopJwk(
            "P-256 coordinates must be 32 bytes".into(),
        ));
    }

    let mut public_area = Vec::with_capacity(TPMT_PUBLIC_P256_LEN);
    public_area.extend_from_slice(&[
        0x00, 0x23, // TPM_ALG_ECC
        0x00, 0x0B, // TPM_ALG_SHA256
        0x00, 0x06, 0x00, 0xF2, // objectAttributes
        0x00, 0x00, // authPolicy length
        0x00, 0x10, // symmetric = TPM_ALG_NULL
        0x00, 0x18, // scheme = TPM_ALG_ECDSA
        0x00, 0x0B, // scheme hash = TPM_ALG_SHA256
        0x00, 0x03, // curve = TPM_ECC_NIST_P256
        0x00, 0x10, // kdf = TPM_ALG_NULL
        0x00, 0x20, // unique.x length
    ]);
    public_area.extend_from_slice(&x);
    public_area.extend_from_slice(&[0x00, 0x20]); // unique.y length
    public_area.extend_from_slice(&y);

    if public_area.len() != TPMT_PUBLIC_P256_LEN {
        return Err(AttestationError::InvalidDpopJwk(format!(
            "unexpected reconstructed TPMT_PUBLIC length: {}",
            public_area.len()
        )));
    }

    let mut expected_name = Vec::with_capacity(34);
    expected_name.extend_from_slice(&TPM_ALG_SHA256);
    expected_name.extend_from_slice(&Sha256::digest(&public_area));

    if certified_name != expected_name {
        return Err(AttestationError::NameMismatch);
    }
    Ok(())
}

fn skip_tpm2b(buf: &[u8], offset: usize) -> Result<usize, AttestationError> {
    let len = read_u16_be(buf, offset)? as usize;
    let next = offset + 2 + len;
    if next > buf.len() {
        return Err(AttestationError::StructurallyInvalid(
            "TPM2B field overruns buffer".into(),
        ));
    }
    Ok(next)
}

fn read_u16_be(buf: &[u8], offset: usize) -> Result<u16, AttestationError> {
    if offset + 2 > buf.len() {
        return Err(AttestationError::StructurallyInvalid(
            "unexpected end of buffer".into(),
        ));
    }
    Ok(u16::from_be_bytes([buf[offset], buf[offset + 1]]))
}

/// Verify attestation evidence with enforcement mode awareness.
///
/// - `strict`: Evidence must be present and valid, or authentication fails.
/// - `warn`: Log warning if evidence is missing/invalid, but allow.
/// - `disabled`: Skip entirely.
///
/// When `config` is `None`, attestation is not checked (backward compat).
pub fn verify_attestation_optional(
    evidence: Option<&AttestationEvidence>,
    dpop_jwk: Option<&serde_json::Value>,
    config: Option<&AttestationConfig>,
) -> Result<(), AttestationError> {
    let config = match config {
        Some(c) => c,
        None => return Ok(()), // No attestation config = not checked
    };

    match config.enforcement {
        EnforcementMode::Disabled => Ok(()),
        EnforcementMode::Warn => match evidence {
            Some(ev) => {
                if let Some(jwk) = dpop_jwk {
                    if let Err(e) = verify_attestation(ev, jwk) {
                        tracing::warn!(
                            error = %e,
                            "Hardware attestation verification failed (warn mode — allowing)"
                        );
                    }
                } else {
                    tracing::warn!(
                        "No DPoP JWK available for attestation verification (warn mode — allowing)"
                    );
                }
                Ok(())
            }
            None => {
                tracing::warn!("No attestation evidence in DPoP proof (warn mode — allowing)");
                Ok(())
            }
        },
        EnforcementMode::Strict => match evidence {
            Some(ev) => {
                let jwk = dpop_jwk.ok_or_else(|| {
                    AttestationError::InvalidDpopJwk(
                        "missing DPoP JWK for attestation verification".into(),
                    )
                })?;
                verify_attestation(ev, jwk)
            }
            None => Err(AttestationError::MissingStrict),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::path::PathBuf;

    fn valid_evidence() -> AttestationEvidence {
        // 48 bytes of fake TPMS_ATTEST (meets minimum size)
        let certify_bytes = vec![0u8; 48];
        // 64 bytes of fake ECDSA signature
        let sig_bytes = vec![0u8; 64];
        // Some fake AK public bytes
        let ak_bytes = vec![0u8; 32];

        AttestationEvidence {
            certify_info: URL_SAFE_NO_PAD.encode(&certify_bytes),
            signature: URL_SAFE_NO_PAD.encode(&sig_bytes),
            ak_public: URL_SAFE_NO_PAD.encode(&ak_bytes),
        }
    }

    #[test]
    fn test_verify_valid_attestation() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "rB0rEX8zlqF1JhkC7XzKOPFkJO2aflrEs-L-ikqur9M",
            "y": "go8feGMnMZUKmn28KhXy5se55CclGr3geaFl_i9EfS8"
        });
        // fake bytes still fail cryptographic validation; keep this as structural smoke
        let err = verify_attestation(&valid_evidence(), &jwk).unwrap_err();
        assert!(matches!(
            err,
            AttestationError::InvalidAkPublic(_) | AttestationError::InvalidAkSignature
        ));
    }

    #[test]
    fn test_verify_invalid_base64() {
        let mut ev = valid_evidence();
        ev.certify_info = "not-valid-base64!!!".into();
        let err = verify_attestation(&ev, &serde_json::json!({})).unwrap_err();
        assert!(
            matches!(err, AttestationError::InvalidEncoding { field, .. } if field == "certify_info")
        );
    }

    #[test]
    fn test_verify_wrong_signature_length() {
        let mut ev = valid_evidence();
        ev.signature = URL_SAFE_NO_PAD.encode([0u8; 32]); // 32 instead of 64
        let err = verify_attestation(&ev, &serde_json::json!({})).unwrap_err();
        assert!(matches!(err, AttestationError::InvalidSignatureLength(32)));
    }

    #[test]
    fn test_verify_certify_info_too_short() {
        let mut ev = valid_evidence();
        ev.certify_info = URL_SAFE_NO_PAD.encode([0u8; 10]); // too short
        let err = verify_attestation(&ev, &serde_json::json!({})).unwrap_err();
        assert!(matches!(err, AttestationError::StructurallyInvalid(_)));
    }

    #[test]
    fn test_verify_empty_ak_public() {
        let mut ev = valid_evidence();
        ev.ak_public = URL_SAFE_NO_PAD.encode([]); // empty
        let err = verify_attestation(&ev, &serde_json::json!({})).unwrap_err();
        assert!(matches!(err, AttestationError::StructurallyInvalid(_)));
    }

    #[test]
    fn test_optional_strict_missing_rejects() {
        let config = AttestationConfig {
            enforcement: EnforcementMode::Strict,
        };
        let err = verify_attestation_optional(None, None, Some(&config)).unwrap_err();
        assert!(matches!(err, AttestationError::MissingStrict));
    }

    #[test]
    fn test_optional_warn_missing_allows() {
        let config = AttestationConfig {
            enforcement: EnforcementMode::Warn,
        };
        assert!(verify_attestation_optional(None, None, Some(&config)).is_ok());
    }

    #[test]
    fn test_optional_disabled_skips() {
        let config = AttestationConfig {
            enforcement: EnforcementMode::Disabled,
        };
        assert!(verify_attestation_optional(None, None, Some(&config)).is_ok());
    }

    #[test]
    fn test_optional_no_config_allows() {
        let ev = valid_evidence();
        assert!(verify_attestation_optional(Some(&ev), None, None).is_ok());
        assert!(verify_attestation_optional(None, None, None).is_ok());
    }

    #[test]
    fn test_optional_strict_valid_allows() {
        let config = AttestationConfig {
            enforcement: EnforcementMode::Strict,
        };
        let ev = valid_evidence();
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "rB0rEX8zlqF1JhkC7XzKOPFkJO2aflrEs-L-ikqur9M",
            "y": "go8feGMnMZUKmn28KhXy5se55CclGr3geaFl_i9EfS8"
        });
        assert!(verify_attestation_optional(Some(&ev), Some(&jwk), Some(&config)).is_err());
    }

    #[test]
    fn test_optional_strict_invalid_rejects() {
        let config = AttestationConfig {
            enforcement: EnforcementMode::Strict,
        };
        let mut ev = valid_evidence();
        ev.signature = URL_SAFE_NO_PAD.encode([0u8; 32]); // wrong length
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "rB0rEX8zlqF1JhkC7XzKOPFkJO2aflrEs-L-ikqur9M",
            "y": "go8feGMnMZUKmn28KhXy5se55CclGr3geaFl_i9EfS8"
        });
        let err = verify_attestation_optional(Some(&ev), Some(&jwk), Some(&config)).unwrap_err();
        assert!(matches!(err, AttestationError::InvalidSignatureLength(_)));
    }

    #[test]
    fn test_optional_warn_invalid_allows() {
        let config = AttestationConfig {
            enforcement: EnforcementMode::Warn,
        };
        let mut ev = valid_evidence();
        ev.signature = URL_SAFE_NO_PAD.encode([0u8; 32]); // wrong length
                                                          // Warn mode: logs but allows
        assert!(verify_attestation_optional(Some(&ev), None, Some(&config)).is_ok());
    }

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

    #[test]
    fn test_fixture_valid_attestation_passes() {
        let fixture = load_fixture("valid_attestation.json");
        let jwk = fixture.dpop_key.as_ref().unwrap();
        assert!(verify_attestation(&fixture.attestation_evidence, jwk).is_ok());
    }

    #[test]
    fn test_fixture_tampered_certify_info_fails_signature() {
        let valid = load_fixture("valid_attestation.json");
        let fixture = load_fixture("tampered_certify_info.json");
        let err = verify_attestation(
            &fixture.attestation_evidence,
            valid.dpop_key.as_ref().unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, AttestationError::InvalidAkSignature));
    }

    #[test]
    fn test_fixture_wrong_ak_signature_fails_signature() {
        let valid = load_fixture("valid_attestation.json");
        let fixture = load_fixture("wrong_ak_signature.json");
        let err = verify_attestation(
            &fixture.attestation_evidence,
            valid.dpop_key.as_ref().unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, AttestationError::InvalidAkSignature));
    }

    #[test]
    fn test_fixture_name_mismatch_fails() {
        let fixture = load_fixture("name_mismatch.json");
        let err = verify_attestation(
            &fixture.attestation_evidence,
            fixture.dpop_key.as_ref().unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, AttestationError::NameMismatch));
    }

    #[test]
    fn test_parse_certified_name_from_fixture() {
        let fixture = load_fixture("valid_attestation.json");
        let certify = URL_SAFE_NO_PAD
            .decode(&fixture.attestation_evidence.certify_info)
            .unwrap();
        let name = parse_certified_name(&certify).unwrap();
        assert_eq!(name.len(), 34);
        assert_eq!(&name[0..2], &TPM_ALG_SHA256);
    }

    #[test]
    fn test_parse_certified_name_rejects_bad_magic() {
        let fixture = load_fixture("valid_attestation.json");
        let mut certify = URL_SAFE_NO_PAD
            .decode(&fixture.attestation_evidence.certify_info)
            .unwrap();
        certify[0] ^= 0x01;
        let err = parse_certified_name(&certify).unwrap_err();
        assert!(matches!(err, AttestationError::StructurallyInvalid(_)));
    }

    #[test]
    fn test_match_name_to_jwk_accepts_fixture() {
        let fixture = load_fixture("valid_attestation.json");
        let certify = URL_SAFE_NO_PAD
            .decode(&fixture.attestation_evidence.certify_info)
            .unwrap();
        let name = parse_certified_name(&certify).unwrap();
        assert!(match_name_to_jwk(&name, fixture.dpop_key.as_ref().unwrap()).is_ok());
    }
}
