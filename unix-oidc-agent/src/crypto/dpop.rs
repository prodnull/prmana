//! DPoP proof generation (RFC 9449)

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
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

/// Generate a DPoP proof JWT
///
/// The proof contains:
/// - Header with typ=dpop+jwt, alg=ES256, and embedded JWK
/// - Claims with jti, htm, htu, iat, and optional nonce
/// - ES256 signature
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

    // Build header with embedded JWK
    let header_json = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims)?.as_bytes());

    let message = format!("{}.{}", header_b64, claims_b64);
    let signature: Signature = signing_key.sign(message.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}", message, sig_b64))
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
}
