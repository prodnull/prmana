//! Hardware attestation verification for DPoP proofs (ADR-018).
//!
//! Verifies TPM key attestation evidence embedded in the DPoP proof JWT header.
//! Phase 37 implements structural validation only — base64url decoding,
//! field presence, ECDSA signature length (64 bytes for P-256 r||s), and
//! TPMS_ATTEST minimum size (~40 bytes). No cryptographic verification is
//! performed at this phase.
//!
//! Deferred to Phase 38+:
//! - AK ECDSA signature verification over certify_info
//! - TPMS_ATTEST parsing to extract certified key Name
//! - Name matching against DPoP JWK thumbprint
//! - EK certificate chain verification

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
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
}

/// Verify attestation evidence from a DPoP proof header.
///
/// Phase 37 verification checks:
/// 1. All three fields are present and valid base64url
/// 2. Signature is 64 bytes (P-256 ECDSA r||s)
/// 3. certify_info is non-empty (TPMS_ATTEST minimum size)
///
/// Phase 38+ will add:
/// - AK ECDSA signature verification over certify_info
/// - TPMS_ATTEST parsing to extract certified key Name
/// - Name matching against DPoP JWK thumbprint
/// - EK certificate chain verification
pub fn verify_attestation(
    evidence: &AttestationEvidence,
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
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&evidence.signature)
        .map_err(|e| AttestationError::InvalidEncoding {
            field: "signature".into(),
            reason: e.to_string(),
        })?;
    if sig_bytes.len() != 64 {
        return Err(AttestationError::InvalidSignatureLength(sig_bytes.len()));
    }

    // Decode and validate ak_public
    let ak_bytes = URL_SAFE_NO_PAD
        .decode(&evidence.ak_public)
        .map_err(|e| AttestationError::InvalidEncoding {
            field: "ak_public".into(),
            reason: e.to_string(),
        })?;
    if ak_bytes.is_empty() {
        return Err(AttestationError::StructurallyInvalid(
            "ak_public is empty".into(),
        ));
    }

    Ok(())
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
    config: Option<&AttestationConfig>,
) -> Result<(), AttestationError> {
    let config = match config {
        Some(c) => c,
        None => return Ok(()), // No attestation config = not checked
    };

    match config.enforcement {
        EnforcementMode::Disabled => Ok(()),
        EnforcementMode::Warn => {
            match evidence {
                Some(ev) => {
                    if let Err(e) = verify_attestation(ev) {
                        tracing::warn!(
                            error = %e,
                            "Hardware attestation verification failed (warn mode — allowing)"
                        );
                    }
                    Ok(())
                }
                None => {
                    tracing::warn!(
                        "No attestation evidence in DPoP proof (warn mode — allowing)"
                    );
                    Ok(())
                }
            }
        }
        EnforcementMode::Strict => match evidence {
            Some(ev) => verify_attestation(ev),
            None => Err(AttestationError::MissingStrict),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(verify_attestation(&valid_evidence()).is_ok());
    }

    #[test]
    fn test_verify_invalid_base64() {
        let mut ev = valid_evidence();
        ev.certify_info = "not-valid-base64!!!".into();
        let err = verify_attestation(&ev).unwrap_err();
        assert!(
            matches!(err, AttestationError::InvalidEncoding { field, .. } if field == "certify_info")
        );
    }

    #[test]
    fn test_verify_wrong_signature_length() {
        let mut ev = valid_evidence();
        ev.signature = URL_SAFE_NO_PAD.encode([0u8; 32]); // 32 instead of 64
        let err = verify_attestation(&ev).unwrap_err();
        assert!(matches!(err, AttestationError::InvalidSignatureLength(32)));
    }

    #[test]
    fn test_verify_certify_info_too_short() {
        let mut ev = valid_evidence();
        ev.certify_info = URL_SAFE_NO_PAD.encode([0u8; 10]); // too short
        let err = verify_attestation(&ev).unwrap_err();
        assert!(matches!(err, AttestationError::StructurallyInvalid(_)));
    }

    #[test]
    fn test_verify_empty_ak_public() {
        let mut ev = valid_evidence();
        ev.ak_public = URL_SAFE_NO_PAD.encode([]); // empty
        let err = verify_attestation(&ev).unwrap_err();
        assert!(matches!(err, AttestationError::StructurallyInvalid(_)));
    }

    #[test]
    fn test_optional_strict_missing_rejects() {
        let config = AttestationConfig {
            enforcement: EnforcementMode::Strict,
        };
        let err = verify_attestation_optional(None, Some(&config)).unwrap_err();
        assert!(matches!(err, AttestationError::MissingStrict));
    }

    #[test]
    fn test_optional_warn_missing_allows() {
        let config = AttestationConfig {
            enforcement: EnforcementMode::Warn,
        };
        assert!(verify_attestation_optional(None, Some(&config)).is_ok());
    }

    #[test]
    fn test_optional_disabled_skips() {
        let config = AttestationConfig {
            enforcement: EnforcementMode::Disabled,
        };
        assert!(verify_attestation_optional(None, Some(&config)).is_ok());
    }

    #[test]
    fn test_optional_no_config_allows() {
        let ev = valid_evidence();
        assert!(verify_attestation_optional(Some(&ev), None).is_ok());
        assert!(verify_attestation_optional(None, None).is_ok());
    }

    #[test]
    fn test_optional_strict_valid_allows() {
        let config = AttestationConfig {
            enforcement: EnforcementMode::Strict,
        };
        let ev = valid_evidence();
        assert!(verify_attestation_optional(Some(&ev), Some(&config)).is_ok());
    }

    #[test]
    fn test_optional_strict_invalid_rejects() {
        let config = AttestationConfig {
            enforcement: EnforcementMode::Strict,
        };
        let mut ev = valid_evidence();
        ev.signature = URL_SAFE_NO_PAD.encode([0u8; 32]); // wrong length
        let err = verify_attestation_optional(Some(&ev), Some(&config)).unwrap_err();
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
        assert!(verify_attestation_optional(Some(&ev), Some(&config)).is_ok());
    }
}
