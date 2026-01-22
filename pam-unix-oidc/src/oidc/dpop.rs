//! DPoP proof validation for server-side (RFC 9449)
//!
//! Security hardening:
//! - JTI replay protection (RFC 9449 Section 11.1)
//! - Constant-time comparison for cryptographic values
//! - JWK coordinate length validation

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use once_cell::sync::Lazy;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Expected coordinate length for P-256 (32 bytes)
const P256_COORDINATE_LEN: usize = 32;

/// Maximum entries in the DPoP JTI cache before forced cleanup/rejection
/// This prevents memory exhaustion attacks where an attacker submits many unique JTIs
const MAX_JTI_CACHE_ENTRIES: usize = 100_000;

/// Global DPoP JTI cache for replay protection (RFC 9449 Section 11.1)
static DPOP_JTI_CACHE: Lazy<DPoPJtiCache> = Lazy::new(DPoPJtiCache::new);

/// DPoP JTI cache for replay protection
struct DPoPJtiCache {
    entries: RwLock<HashMap<String, Instant>>,
    last_cleanup: RwLock<Instant>,
}

impl DPoPJtiCache {
    fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Check if JTI is a replay and record it if not
    /// Returns true if this is a new JTI (valid), false if replay or cache full
    fn check_and_record(&self, jti: &str, ttl_seconds: u64) -> bool {
        self.maybe_cleanup();

        let now = Instant::now();
        let expires_at = now + Duration::from_secs(ttl_seconds);

        // Check if JTI already exists
        {
            let entries = self.entries.read().unwrap();
            if let Some(&exp) = entries.get(jti) {
                if exp > now {
                    return false; // Replay detected
                }
            }
        }

        // Record the JTI
        {
            let mut entries = self.entries.write().unwrap();
            // Double-check after acquiring write lock
            if let Some(&exp) = entries.get(jti) {
                if exp > now {
                    return false; // Replay detected
                }
            }

            // Security: Enforce size limit to prevent memory exhaustion
            // If cache is full after cleanup, reject new entries
            if entries.len() >= MAX_JTI_CACHE_ENTRIES {
                // Force cleanup to try to make room
                let before_cleanup = entries.len();
                entries.retain(|_, exp| *exp > now);

                // If still at capacity after cleanup, reject
                if entries.len() >= MAX_JTI_CACHE_ENTRIES {
                    tracing::warn!(
                        cache_size = entries.len(),
                        before_cleanup = before_cleanup,
                        "DPoP JTI cache at capacity, rejecting new proof"
                    );
                    return false;
                }
            }

            entries.insert(jti.to_string(), expires_at);
        }

        true // New JTI
    }

    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let last = self.last_cleanup.read().unwrap();
            now.duration_since(*last) > Duration::from_secs(300)
        };

        if should_cleanup {
            let mut entries = self.entries.write().unwrap();
            entries.retain(|_, exp| *exp > now);
            *self.last_cleanup.write().unwrap() = now;
        }
    }
}

/// Constant-time string comparison for cryptographic values
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// DPoP proof claims
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct DPoPProofClaims {
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    #[serde(default)]
    pub nonce: Option<String>,
}

/// JWK embedded in DPoP proof header
#[derive(Debug, Deserialize)]
pub struct EcJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// DPoP validation configuration
#[derive(Debug, Clone)]
pub struct DPoPConfig {
    /// Maximum age of proof in seconds (default: 60)
    pub max_proof_age: u64,
    /// Whether nonce is required
    pub require_nonce: bool,
    /// Expected nonce value (if require_nonce is true)
    pub expected_nonce: Option<String>,
    /// Expected method (e.g., "SSH", "POST")
    pub expected_method: String,
    /// Expected target (hostname or URL)
    pub expected_target: String,
}

impl Default for DPoPConfig {
    fn default() -> Self {
        Self {
            max_proof_age: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "SSH".to_string(),
            expected_target: String::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum DPoPValidationError {
    #[error("Invalid proof format")]
    InvalidFormat,
    #[error("Invalid header")]
    InvalidHeader(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Missing JWK in header")]
    MissingJwk,
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm(String),
    #[error("Proof expired")]
    ProofExpired { iat: i64, now: i64 },
    #[error("Method mismatch")]
    MethodMismatch { expected: String, actual: String },
    #[error("Target mismatch")]
    TargetMismatch { expected: String, actual: String },
    #[error("Nonce mismatch")]
    NonceMismatch,
    #[error("Missing nonce")]
    MissingNonce,
    #[error("Thumbprint mismatch")]
    ThumbprintMismatch {
        token_jkt: String,
        proof_jkt: String,
    },
    #[error("Token missing cnf.jkt claim")]
    MissingTokenBinding,
    #[error("Base64 decode error")]
    Base64Error,
    #[error("JSON parse error")]
    JsonError(String),
    #[error("DPoP proof replay detected")]
    ReplayDetected,
    #[error("Invalid JWK key parameters")]
    InvalidKeyParameters,
}

/// Validate a DPoP proof and return the JWK thumbprint
///
/// Returns the thumbprint of the public key that signed the proof.
/// This should be compared against the token's `cnf.jkt` claim.
pub fn validate_dpop_proof(
    proof: &str,
    config: &DPoPConfig,
) -> Result<String, DPoPValidationError> {
    // Split proof into parts
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(DPoPValidationError::InvalidFormat);
    }

    // Decode header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| DPoPValidationError::Base64Error)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| DPoPValidationError::JsonError(e.to_string()))?;

    // Verify typ
    if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
        return Err(DPoPValidationError::InvalidHeader(
            "typ must be dpop+jwt".to_string(),
        ));
    }

    // Verify alg
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DPoPValidationError::InvalidHeader("missing alg".to_string()))?;

    if alg != "ES256" {
        return Err(DPoPValidationError::UnsupportedAlgorithm(alg.to_string()));
    }

    // Extract JWK
    let jwk: EcJwk = header
        .get("jwk")
        .ok_or(DPoPValidationError::MissingJwk)
        .and_then(|v| {
            serde_json::from_value(v.clone())
                .map_err(|e| DPoPValidationError::JsonError(e.to_string()))
        })?;

    // Verify signature
    let message = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| DPoPValidationError::Base64Error)?;

    let verifying_key = jwk_to_verifying_key(&jwk)?;

    // ES256 signatures are 64 bytes (r || s)
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| DPoPValidationError::InvalidSignature)?;

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| DPoPValidationError::InvalidSignature)?;

    // Decode claims
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| DPoPValidationError::Base64Error)?;
    let claims: DPoPProofClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|e| DPoPValidationError::JsonError(e.to_string()))?;

    // Validate iat (proof age)
    // Note: This can only fail if system time is before 1970-01-01, which indicates
    // a severely misconfigured system. We use expect() to document this assumption
    // rather than silently failing, as authentication on such a system would be
    // unreliable anyway.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX epoch - clock is misconfigured")
        .as_secs() as i64;

    if now - claims.iat > config.max_proof_age as i64 {
        return Err(DPoPValidationError::ProofExpired {
            iat: claims.iat,
            now,
        });
    }

    // Don't accept proofs from the future (with small clock skew allowance)
    if claims.iat > now + 5 {
        return Err(DPoPValidationError::ProofExpired {
            iat: claims.iat,
            now,
        });
    }

    // Validate method
    if claims.htm != config.expected_method {
        return Err(DPoPValidationError::MethodMismatch {
            expected: config.expected_method.clone(),
            actual: claims.htm,
        });
    }

    // Validate target
    if claims.htu != config.expected_target {
        return Err(DPoPValidationError::TargetMismatch {
            expected: config.expected_target.clone(),
            actual: claims.htu,
        });
    }

    // Validate nonce (constant-time comparison to prevent timing attacks)
    if config.require_nonce {
        match (&claims.nonce, &config.expected_nonce) {
            (Some(proof_nonce), Some(expected_nonce)) => {
                if !constant_time_eq(proof_nonce, expected_nonce) {
                    return Err(DPoPValidationError::NonceMismatch);
                }
            }
            (None, _) => return Err(DPoPValidationError::MissingNonce),
            _ => {}
        }
    }

    // JTI replay protection (RFC 9449 Section 11.1)
    // TTL = max_proof_age + 5 seconds (for clock skew)
    let jti_ttl = config.max_proof_age + 5;
    if !DPOP_JTI_CACHE.check_and_record(&claims.jti, jti_ttl) {
        return Err(DPoPValidationError::ReplayDetected);
    }

    // Compute and return thumbprint
    Ok(compute_jwk_thumbprint(&jwk))
}

/// Verify that the proof's key matches the token's cnf.jkt claim
/// Uses constant-time comparison to prevent timing attacks
pub fn verify_dpop_binding(
    proof_thumbprint: &str,
    token_jkt: &str,
) -> Result<(), DPoPValidationError> {
    // Use constant-time comparison to prevent timing attacks
    if !constant_time_eq(proof_thumbprint, token_jkt) {
        return Err(DPoPValidationError::ThumbprintMismatch {
            token_jkt: token_jkt.to_string(),
            proof_jkt: proof_thumbprint.to_string(),
        });
    }
    Ok(())
}

fn jwk_to_verifying_key(jwk: &EcJwk) -> Result<VerifyingKey, DPoPValidationError> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(DPoPValidationError::UnsupportedAlgorithm(format!(
            "kty={}, crv={}",
            jwk.kty, jwk.crv
        )));
    }

    let x_bytes = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|_| DPoPValidationError::Base64Error)?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(&jwk.y)
        .map_err(|_| DPoPValidationError::Base64Error)?;

    // Validate coordinate lengths for P-256 (32 bytes each)
    if x_bytes.len() != P256_COORDINATE_LEN || y_bytes.len() != P256_COORDINATE_LEN {
        return Err(DPoPValidationError::InvalidKeyParameters);
    }

    // Build uncompressed point: 0x04 || x || y
    let mut point_bytes = vec![0x04];
    point_bytes.extend_from_slice(&x_bytes);
    point_bytes.extend_from_slice(&y_bytes);

    VerifyingKey::from_sec1_bytes(&point_bytes).map_err(|_| DPoPValidationError::InvalidSignature)
}

fn compute_jwk_thumbprint(jwk: &EcJwk) -> String {
    // RFC 7638: canonical JSON with lexicographic member ordering
    // For EC P-256: crv < kty < x < y
    //
    // Security: Use hardcoded canonical values for kty and crv instead of
    // user-supplied values. We only support ES256 (P-256), so these are fixed.
    // This prevents potential thumbprint manipulation via non-canonical values.
    // The actual kty/crv values are validated in jwk_to_verifying_key() before
    // this function is called.
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk.x, jwk.y
    );

    let hash = Sha256::digest(canonical.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use p256::elliptic_curve::rand_core::OsRng;

    // Helper to create a test proof
    fn create_test_proof(method: &str, target: &str, nonce: Option<&str>) -> (String, String) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let jwk = EcJwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: x.clone(),
            y: y.clone(),
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = DPoPProofClaims {
            jti: uuid::Uuid::new_v4().to_string(),
            htm: method.to_string(),
            htu: target.to_string(),
            iat: now,
            nonce: nonce.map(String::from),
        };

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
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap().as_bytes());

        let message = format!("{}.{}", header_b64, claims_b64);

        let signature: Signature = signing_key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let proof = format!("{}.{}", message, sig_b64);
        let thumbprint = compute_jwk_thumbprint(&jwk);

        (proof, thumbprint)
    }

    #[test]
    fn test_validate_valid_proof() {
        let (proof, _thumbprint) = create_test_proof("SSH", "server.example.com", None);

        let config = DPoPConfig {
            max_proof_age: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "SSH".to_string(),
            expected_target: "server.example.com".to_string(),
        };

        let result = validate_dpop_proof(&proof, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_proof_with_nonce() {
        let (proof, _) = create_test_proof("SSH", "server.example.com", Some("abc123"));

        let config = DPoPConfig {
            max_proof_age: 60,
            require_nonce: true,
            expected_nonce: Some("abc123".to_string()),
            expected_method: "SSH".to_string(),
            expected_target: "server.example.com".to_string(),
        };

        let result = validate_dpop_proof(&proof, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_wrong_method() {
        let (proof, _) = create_test_proof("POST", "server.example.com", None);

        let config = DPoPConfig {
            max_proof_age: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "SSH".to_string(),
            expected_target: "server.example.com".to_string(),
        };

        let result = validate_dpop_proof(&proof, &config);
        assert!(matches!(
            result,
            Err(DPoPValidationError::MethodMismatch { .. })
        ));
    }

    #[test]
    fn test_reject_wrong_target() {
        let (proof, _) = create_test_proof("SSH", "other.example.com", None);

        let config = DPoPConfig {
            max_proof_age: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "SSH".to_string(),
            expected_target: "server.example.com".to_string(),
        };

        let result = validate_dpop_proof(&proof, &config);
        assert!(matches!(
            result,
            Err(DPoPValidationError::TargetMismatch { .. })
        ));
    }

    #[test]
    fn test_reject_wrong_nonce() {
        let (proof, _) = create_test_proof("SSH", "server.example.com", Some("wrong"));

        let config = DPoPConfig {
            max_proof_age: 60,
            require_nonce: true,
            expected_nonce: Some("correct".to_string()),
            expected_method: "SSH".to_string(),
            expected_target: "server.example.com".to_string(),
        };

        let result = validate_dpop_proof(&proof, &config);
        assert!(matches!(result, Err(DPoPValidationError::NonceMismatch)));
    }

    #[test]
    fn test_verify_dpop_binding() {
        let (proof, thumbprint) = create_test_proof("SSH", "server.example.com", None);

        let config = DPoPConfig {
            max_proof_age: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "SSH".to_string(),
            expected_target: "server.example.com".to_string(),
        };

        let proof_thumbprint = validate_dpop_proof(&proof, &config).unwrap();

        // Should match
        assert!(verify_dpop_binding(&proof_thumbprint, &thumbprint).is_ok());

        // Should not match different thumbprint
        assert!(verify_dpop_binding(&proof_thumbprint, "wrong-thumbprint").is_err());
    }

    #[test]
    fn test_replay_detection() {
        // Create a proof with a specific JTI
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Use a fixed JTI for this test
        let fixed_jti = format!("replay-test-{}", now);

        let claims = DPoPProofClaims {
            jti: fixed_jti.clone(),
            htm: "SSH".to_string(),
            htu: "replay-test.example.com".to_string(),
            iat: now,
            nonce: None,
        };

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
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap().as_bytes());

        let message = format!("{}.{}", header_b64, claims_b64);
        let signature: Signature = signing_key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let proof = format!("{}.{}", message, sig_b64);

        let config = DPoPConfig {
            max_proof_age: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "SSH".to_string(),
            expected_target: "replay-test.example.com".to_string(),
        };

        // First use should succeed
        let result1 = validate_dpop_proof(&proof, &config);
        assert!(result1.is_ok(), "First use should succeed");

        // Second use with same JTI should be detected as replay
        let result2 = validate_dpop_proof(&proof, &config);
        assert!(
            matches!(result2, Err(DPoPValidationError::ReplayDetected)),
            "Second use should be detected as replay"
        );
    }

    #[test]
    fn test_constant_time_eq() {
        // Test the constant-time comparison function
        assert!(constant_time_eq("hello", "hello"));
        assert!(!constant_time_eq("hello", "world"));
        assert!(!constant_time_eq("hello", "hell")); // Different lengths
        assert!(!constant_time_eq("", "x"));
        assert!(constant_time_eq("", ""));
    }
}
