//! DPoP proof generation (RFC 9449)
//!
//! This module exposes three layers of API:
//!
//! 1. `build_dpop_message()` — constructs the unsigned `header_b64.claims_b64` string.
//!    Takes a public key JWK value so hardware signers can call it without exposing
//!    private key material.
//!
//! 2. `assemble_dpop_proof()` — appends a raw r‖s signature (64 bytes for P-256) to
//!    the unsigned message, producing the final `header.claims.sig` JWT string.
//!
//! 3. `generate_dpop_proof()` — convenience wrapper: calls `build_dpop_message` +
//!    p256 sign + `assemble_dpop_proof`. Used by `SoftwareSigner` unchanged.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::instrument;
use uuid::Uuid;

/// DPoP proof claims per RFC 9449
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPoPClaims {
    /// Unique identifier for the proof (prevents replay)
    pub jti: String,
    /// HTTP method (GET, POST, etc.) or "SSH" for our use case
    pub htm: String,
    /// Target URI (server hostname for SSH)
    pub htu: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Server-provided nonce (optional but recommended)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// EC public key in JWK format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcPublicKeyJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// Build the unsigned DPoP message (`header_b64.claims_b64`).
///
/// This function takes the public key JWK as a `serde_json::Value` so that
/// hardware signers (YubiKey, TPM) can call it without exposing private key
/// material. The returned string is the signing input for the DPoP proof.
///
/// # Errors
///
/// Returns `DPoPError::ClockError` if the system clock is before the Unix epoch.
/// Returns `DPoPError::Json` if serialisation fails.
///
/// # Tracing
///
/// The span captures `method` and `target` for correlation.  `access_token`
/// and `nonce` are skipped — they contain bearer credentials and server nonces
/// that must never appear in logs.
#[instrument(skip(public_key_jwk, nonce), fields(method, target))]
pub fn build_dpop_message(
    public_key_jwk: &serde_json::Value,
    method: &str,
    target: &str,
    nonce: Option<&str>,
) -> Result<String, DPoPError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DPoPError::ClockError)?
        .as_secs() as i64;

    let claims = DPoPClaims {
        jti: Uuid::new_v4().to_string(),
        htm: method.to_string(),
        htu: target.to_string(),
        iat: now,
        nonce: nonce.map(String::from),
    };

    // Build header with embedded JWK (RFC 9449 §4.2)
    let header_json = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": public_key_jwk
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims)?.as_bytes());

    Ok(format!("{header_b64}.{claims_b64}"))
}

/// Assemble a DPoP JWT from a signed message and raw r‖s signature bytes.
///
/// `message` is the `header_b64.claims_b64` string returned by `build_dpop_message`.
/// `sig_rs_bytes` must be exactly 64 bytes (32-byte r followed by 32-byte s for P-256).
///
/// # Errors
///
/// Returns `DPoPError::InvalidSignatureLength` if `sig_rs_bytes.len() != 64`.
///
/// # Tracing
///
/// All parameters are skipped — `message` contains JWT claims (including the
/// embedded JWK and `htu`/`htm` claims) and `sig_rs_bytes` is raw key material.
/// The span records only entry/exit timing for latency observability.
#[instrument(skip_all)]
pub fn assemble_dpop_proof(message: &str, sig_rs_bytes: &[u8]) -> Result<String, DPoPError> {
    if sig_rs_bytes.len() != 64 {
        return Err(DPoPError::InvalidSignatureLength(sig_rs_bytes.len()));
    }
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_rs_bytes);
    Ok(format!("{message}.{sig_b64}"))
}

/// Generate a DPoP proof JWT using a software signing key.
///
/// This is a convenience wrapper used by `SoftwareSigner`. Hardware signers
/// call `build_dpop_message` + `assemble_dpop_proof` directly.
///
/// The proof contains:
/// - Header with typ=dpop+jwt, alg=ES256, and embedded JWK
/// - Claims with jti, htm, htu, iat, and optional nonce
/// - ES256 signature
///
/// # Tracing
///
/// `signing_key` is skipped — it contains the DPoP private key material and
/// must never appear in logs or spans.  `nonce` is skipped as a server-issued
/// bearer secret.  `method` and `target` are captured for correlation with the
/// IPC request span.
#[instrument(skip(signing_key, nonce), fields(method, target))]
pub fn generate_dpop_proof(
    signing_key: &SigningKey,
    method: &str,
    target: &str,
    nonce: Option<&str>,
) -> Result<String, DPoPError> {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);

    let x = URL_SAFE_NO_PAD.encode(point.x().ok_or(DPoPError::InvalidKey)?);
    let y = URL_SAFE_NO_PAD.encode(point.y().ok_or(DPoPError::InvalidKey)?);

    let public_key_jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y
    });

    let message = build_dpop_message(&public_key_jwk, method, target, nonce)?;
    let signature: Signature = signing_key.sign(message.as_bytes());
    // p256 Signature::to_bytes() returns 64-byte raw r‖s (RFC 9449 §4.2)
    assemble_dpop_proof(&message, &signature.to_bytes())
}

/// Build the unsigned DPoP message with a specified algorithm.
///
/// Like `build_dpop_message` but allows overriding the `alg` header field
/// for composite algorithms (e.g., `ML-DSA-65-ES256`).
///
/// # Security
///
/// The `alg` parameter is validated against an allowlist to prevent algorithm
/// confusion attacks (e.g., `"none"`, `"HS256"`). Only algorithms that this
/// agent can produce valid DPoP proofs for are accepted.
#[instrument(skip(public_key_jwk, nonce), fields(method, target, alg))]
pub fn build_dpop_message_with_alg(
    public_key_jwk: &serde_json::Value,
    method: &str,
    target: &str,
    nonce: Option<&str>,
    alg: &str,
) -> Result<String, DPoPError> {
    // Security: allowlist prevents algorithm confusion attacks (RFC 9449 §4.2).
    // Only algorithms this agent can produce valid proofs for are permitted.
    const ALLOWED_ALGORITHMS: &[&str] = &["ES256", "ML-DSA-65-ES256"];
    if !ALLOWED_ALGORITHMS.contains(&alg) {
        return Err(DPoPError::UnsupportedAlgorithm(alg.to_string()));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DPoPError::ClockError)?
        .as_secs() as i64;

    let claims = DPoPClaims {
        jti: Uuid::new_v4().to_string(),
        htm: method.to_string(),
        htu: target.to_string(),
        iat: now,
        nonce: nonce.map(String::from),
    };

    let header_json = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": public_key_jwk
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims)?.as_bytes());

    Ok(format!("{header_b64}.{claims_b64}"))
}

/// Assemble a DPoP JWT from a signed message and variable-length signature bytes.
///
/// Unlike `assemble_dpop_proof` (which enforces 64-byte ES256 signatures), this
/// accepts arbitrary-length signatures for composite algorithms.
#[instrument(skip_all)]
pub fn assemble_dpop_proof_composite(message: &str, sig_bytes: &[u8]) -> Result<String, DPoPError> {
    if sig_bytes.is_empty() {
        return Err(DPoPError::InvalidSignatureLength(0));
    }
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);
    Ok(format!("{message}.{sig_b64}"))
}

/// Extract the JWK from a DPoP proof header
pub fn extract_jwk_from_proof(proof: &str) -> Result<EcPublicKeyJwk, DPoPError> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(DPoPError::InvalidProofFormat);
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| DPoPError::InvalidBase64)?;

    #[derive(Deserialize)]
    struct Header {
        typ: String,
        jwk: EcPublicKeyJwk,
    }

    let header: Header = serde_json::from_slice(&header_bytes)?;

    if header.typ != "dpop+jwt" {
        return Err(DPoPError::InvalidProofType);
    }

    Ok(header.jwk)
}

#[derive(Debug, thiserror::Error)]
pub enum DPoPError {
    #[error("Invalid key")]
    InvalidKey,
    #[error("Clock error")]
    ClockError,
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid proof format")]
    InvalidProofFormat,
    #[error("Invalid base64")]
    InvalidBase64,
    #[error("Invalid proof type (expected dpop+jwt)")]
    InvalidProofType,
    /// Returned when `assemble_dpop_proof` receives a signature that is not 64 bytes.
    /// P-256 ECDSA raw r‖s signatures are always exactly 64 bytes.
    #[error("Invalid signature length: expected 64 bytes, got {0}")]
    InvalidSignatureLength(usize),
    /// Propagated from hardware signer backends (YubiKey, TPM).
    #[error("Hardware signer error: {0}")]
    HardwareSigner(String),
    /// Returned when `build_dpop_message_with_alg` receives an algorithm not in the allowlist.
    /// Prevents algorithm confusion attacks (RFC 9449 §4.2).
    #[error("Unsupported DPoP algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::thumbprint::compute_ec_thumbprint;
    use p256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn test_generate_proof_format() {
        let signing_key = SigningKey::random(&mut OsRng);

        let proof = generate_dpop_proof(&signing_key, "SSH", "server.example.com", None).unwrap();

        // JWT format: header.payload.signature
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        // All parts should be valid base64url
        for part in &parts {
            assert!(URL_SAFE_NO_PAD.decode(part).is_ok());
        }
    }

    #[test]
    fn test_proof_contains_correct_header() {
        let signing_key = SigningKey::random(&mut OsRng);

        let proof = generate_dpop_proof(&signing_key, "SSH", "server.example.com", None).unwrap();

        let jwk = extract_jwk_from_proof(&proof).unwrap();

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert!(!jwk.x.is_empty());
        assert!(!jwk.y.is_empty());
    }

    #[test]
    fn test_proof_contains_correct_claims() {
        let signing_key = SigningKey::random(&mut OsRng);

        let proof = generate_dpop_proof(
            &signing_key,
            "POST",
            "https://api.example.com/token",
            Some("server-nonce-123"),
        )
        .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: DPoPClaims = serde_json::from_slice(&claims_bytes).unwrap();

        assert_eq!(claims.htm, "POST");
        assert_eq!(claims.htu, "https://api.example.com/token");
        assert_eq!(claims.nonce, Some("server-nonce-123".to_string()));
        assert!(!claims.jti.is_empty());
        assert!(claims.iat > 0);
    }

    #[test]
    fn test_proof_thumbprint_matches_key() {
        let signing_key = SigningKey::random(&mut OsRng);
        let expected_thumbprint = compute_ec_thumbprint(signing_key.verifying_key());

        let proof = generate_dpop_proof(&signing_key, "SSH", "server.example.com", None).unwrap();

        let jwk = extract_jwk_from_proof(&proof).unwrap();

        // Reconstruct verifying key from JWK and compute thumbprint
        let x_bytes = URL_SAFE_NO_PAD.decode(&jwk.x).unwrap();
        let y_bytes = URL_SAFE_NO_PAD.decode(&jwk.y).unwrap();

        // Build uncompressed point: 0x04 || x || y
        let mut point_bytes = vec![0x04];
        point_bytes.extend_from_slice(&x_bytes);
        point_bytes.extend_from_slice(&y_bytes);

        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point_bytes).unwrap();
        let actual_thumbprint = compute_ec_thumbprint(&verifying_key);

        assert_eq!(expected_thumbprint, actual_thumbprint);
    }

    #[test]
    fn test_unique_jti_per_proof() {
        let signing_key = SigningKey::random(&mut OsRng);

        let proof1 = generate_dpop_proof(&signing_key, "SSH", "server.example.com", None).unwrap();
        let proof2 = generate_dpop_proof(&signing_key, "SSH", "server.example.com", None).unwrap();

        let parts1: Vec<&str> = proof1.split('.').collect();
        let parts2: Vec<&str> = proof2.split('.').collect();

        let claims1: DPoPClaims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts1[1]).unwrap()).unwrap();
        let claims2: DPoPClaims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts2[1]).unwrap()).unwrap();

        assert_ne!(claims1.jti, claims2.jti);
    }

    // --- Tests for the refactored build/assemble API ---

    #[test]
    fn test_build_dpop_message_produces_two_part_string() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "test_x_value_base64url",
            "y": "test_y_value_base64url"
        });
        let msg = build_dpop_message(&jwk, "SSH", "server.example.com", None).unwrap();
        let parts: Vec<&str> = msg.split('.').collect();
        assert_eq!(
            parts.len(),
            2,
            "build_dpop_message must return header.claims"
        );
        // Both parts must be valid base64url
        for part in &parts {
            assert!(URL_SAFE_NO_PAD.decode(part).is_ok());
        }
    }

    #[test]
    fn test_build_dpop_message_header_contains_jwk() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "some_x",
            "y": "some_y"
        });
        let msg = build_dpop_message(&jwk, "SSH", "host", None).unwrap();
        let header_b64 = msg.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"]["kty"], "EC");
        assert_eq!(header["jwk"]["crv"], "P-256");
    }

    #[test]
    fn test_assemble_dpop_proof_valid_64_byte_sig() {
        let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
        let msg = build_dpop_message(&jwk, "SSH", "host", None).unwrap();
        let sig = vec![0u8; 64];
        let proof = assemble_dpop_proof(&msg, &sig).unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "assemble_dpop_proof must produce a 3-part JWT"
        );
        // Third part must decode to 64 bytes
        let decoded = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(decoded.len(), 64);
    }

    #[test]
    fn test_assemble_dpop_proof_rejects_63_bytes() {
        let msg = "header.claims".to_string();
        let sig = vec![0u8; 63];
        let result = assemble_dpop_proof(&msg, &sig);
        assert!(matches!(result, Err(DPoPError::InvalidSignatureLength(63))));
    }

    #[test]
    fn test_assemble_dpop_proof_rejects_65_bytes() {
        let msg = "header.claims".to_string();
        let sig = vec![0u8; 65];
        let result = assemble_dpop_proof(&msg, &sig);
        assert!(matches!(result, Err(DPoPError::InvalidSignatureLength(65))));
    }

    // ── F-15: algorithm allowlist for build_dpop_message_with_alg ──────────

    /// F-15 positive: ES256 is accepted.
    #[test]
    fn test_build_dpop_message_with_alg_accepts_es256() {
        let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
        let result = build_dpop_message_with_alg(&jwk, "SSH", "host", None, "ES256");
        assert!(result.is_ok(), "ES256 must be accepted: {result:?}");
    }

    /// F-15 positive: ML-DSA-65-ES256 (PQC composite) is accepted.
    #[test]
    fn test_build_dpop_message_with_alg_accepts_ml_dsa_65_es256() {
        let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
        let result = build_dpop_message_with_alg(&jwk, "SSH", "host", None, "ML-DSA-65-ES256");
        assert!(
            result.is_ok(),
            "ML-DSA-65-ES256 must be accepted: {result:?}"
        );
    }

    /// F-15 negative: "none" algorithm is rejected (algorithm confusion attack).
    #[test]
    fn test_build_dpop_message_with_alg_rejects_none() {
        let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
        let result = build_dpop_message_with_alg(&jwk, "SSH", "host", None, "none");
        assert!(
            matches!(result, Err(DPoPError::UnsupportedAlgorithm(ref a)) if a == "none"),
            "\"none\" must be rejected: {result:?}"
        );
    }

    /// F-15 negative: HS256 (symmetric) is rejected.
    #[test]
    fn test_build_dpop_message_with_alg_rejects_hs256() {
        let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
        let result = build_dpop_message_with_alg(&jwk, "SSH", "host", None, "HS256");
        assert!(
            matches!(result, Err(DPoPError::UnsupportedAlgorithm(ref a)) if a == "HS256"),
            "HS256 must be rejected: {result:?}"
        );
    }

    /// F-15 negative: RS256 is rejected (not in agent's supported algorithms).
    #[test]
    fn test_build_dpop_message_with_alg_rejects_rs256() {
        let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
        let result = build_dpop_message_with_alg(&jwk, "SSH", "host", None, "RS256");
        assert!(
            matches!(result, Err(DPoPError::UnsupportedAlgorithm(ref a)) if a == "RS256"),
            "RS256 must be rejected: {result:?}"
        );
    }

    /// F-15 negative: empty string is rejected.
    #[test]
    fn test_build_dpop_message_with_alg_rejects_empty() {
        let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
        let result = build_dpop_message_with_alg(&jwk, "SSH", "host", None, "");
        assert!(
            matches!(result, Err(DPoPError::UnsupportedAlgorithm(ref a)) if a.is_empty()),
            "Empty algorithm must be rejected: {result:?}"
        );
    }

    #[test]
    fn test_generate_dpop_proof_uses_build_assemble_internally() {
        // Verify that generate_dpop_proof produces the same format as manual build+assemble.
        // We can't easily verify the signature matches (different random key), but we
        // verify the structural invariant: 3 parts, header/claims decode correctly.
        let signing_key = SigningKey::random(&mut OsRng);
        let proof = generate_dpop_proof(&signing_key, "GET", "https://example.com", None).unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }
}
