//! Server-side DPoP proof validation (RFC 9449)
//!
//! Security hardening:
//! - JTI replay protection (RFC 9449 Section 11.1)
//! - Constant-time comparison for cryptographic values
//! - JWK coordinate length validation

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub use crate::error::DPoPValidationError;
use crate::jwk::EcPublicJwk;

/// Expected coordinate length for P-256 (32 bytes)
const P256_COORDINATE_LEN: usize = 32;

/// Global DPoP JTI cache for replay protection (RFC 9449 Section 11.1)
static DPOP_JTI_CACHE: std::sync::LazyLock<DPoPJtiCache> =
    std::sync::LazyLock::new(DPoPJtiCache::new);

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
    /// Returns true if this is a new JTI (valid), false if replay
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
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
struct DPoPProofClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(default)]
    nonce: Option<String>,
}

/// DPoP validation configuration
#[derive(Debug, Clone)]
pub struct DPoPConfig {
    /// Maximum age of proof in seconds (default: 60)
    pub max_proof_age_secs: u64,
    /// Whether nonce is required
    pub require_nonce: bool,
    /// Expected nonce value (if require_nonce is true)
    pub expected_nonce: Option<String>,
    /// Expected HTTP method (e.g., "GET", "POST")
    pub expected_method: String,
    /// Expected target URI (e.g., "https://api.example.com/token")
    pub expected_target: String,
}

impl Default for DPoPConfig {
    fn default() -> Self {
        Self {
            max_proof_age_secs: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "POST".to_string(),
            expected_target: String::new(),
        }
    }
}

/// Validate a DPoP proof and return the JWK thumbprint
///
/// Returns the thumbprint of the public key that signed the proof.
/// This should be compared against the token's `cnf.jkt` claim.
///
/// # Arguments
///
/// * `proof` - The DPoP proof JWT
/// * `config` - Validation configuration
///
/// # Returns
///
/// The JWK thumbprint on success, or a validation error.
///
/// # Example
///
/// ```rust,ignore
/// use oauth_dpop::{validate_proof, DPoPConfig};
///
/// let config = DPoPConfig {
///     max_proof_age_secs: 60,
///     require_nonce: false,
///     expected_nonce: None,
///     expected_method: "POST".to_string(),
///     expected_target: "https://api.example.com/token".to_string(),
/// };
///
/// match validate_proof(&proof, &config) {
///     Ok(thumbprint) => {
///         // Compare thumbprint with token's cnf.jkt claim
///         println!("Valid proof from key: {}", thumbprint);
///     }
///     Err(e) => eprintln!("Validation failed: {}", e),
/// }
/// ```
pub fn validate_proof(proof: &str, config: &DPoPConfig) -> Result<String, DPoPValidationError> {
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
    let jwk: EcPublicJwk = header
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    if now - claims.iat > config.max_proof_age_secs as i64 {
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
    let jti_ttl = config.max_proof_age_secs + 5;
    if !DPOP_JTI_CACHE.check_and_record(&claims.jti, jti_ttl) {
        return Err(DPoPValidationError::ReplayDetected);
    }

    // Compute and return thumbprint
    Ok(compute_jwk_thumbprint(&jwk))
}

/// Verify that the proof's key matches the token's cnf.jkt claim
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `proof_thumbprint` - Thumbprint returned from `validate_proof`
/// * `token_jkt` - The `cnf.jkt` claim from the access token
///
/// # Returns
///
/// `Ok(())` if thumbprints match, `Err(ThumbprintMismatch)` otherwise.
pub fn verify_binding(
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

fn jwk_to_verifying_key(jwk: &EcPublicJwk) -> Result<VerifyingKey, DPoPValidationError> {
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

fn compute_jwk_thumbprint(jwk: &EcPublicJwk) -> String {
    // RFC 7638: canonical JSON with lexicographic member ordering
    // For EC P-256: crv < kty < x < y
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
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

        let jwk = EcPublicJwk::new(x.clone(), y.clone());

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
        let (proof, _thumbprint) = create_test_proof("POST", "https://example.com/token", None);

        let config = DPoPConfig {
            max_proof_age_secs: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "POST".to_string(),
            expected_target: "https://example.com/token".to_string(),
        };

        let result = validate_proof(&proof, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_proof_with_nonce() {
        let (proof, _) = create_test_proof("POST", "https://example.com/token", Some("abc123"));

        let config = DPoPConfig {
            max_proof_age_secs: 60,
            require_nonce: true,
            expected_nonce: Some("abc123".to_string()),
            expected_method: "POST".to_string(),
            expected_target: "https://example.com/token".to_string(),
        };

        let result = validate_proof(&proof, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_wrong_method() {
        let (proof, _) = create_test_proof("GET", "https://example.com/token", None);

        let config = DPoPConfig {
            max_proof_age_secs: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "POST".to_string(),
            expected_target: "https://example.com/token".to_string(),
        };

        let result = validate_proof(&proof, &config);
        assert!(matches!(
            result,
            Err(DPoPValidationError::MethodMismatch { .. })
        ));
    }

    #[test]
    fn test_reject_wrong_target() {
        let (proof, _) = create_test_proof("POST", "https://other.com/token", None);

        let config = DPoPConfig {
            max_proof_age_secs: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "POST".to_string(),
            expected_target: "https://example.com/token".to_string(),
        };

        let result = validate_proof(&proof, &config);
        assert!(matches!(
            result,
            Err(DPoPValidationError::TargetMismatch { .. })
        ));
    }

    #[test]
    fn test_reject_wrong_nonce() {
        let (proof, _) = create_test_proof("POST", "https://example.com/token", Some("wrong"));

        let config = DPoPConfig {
            max_proof_age_secs: 60,
            require_nonce: true,
            expected_nonce: Some("correct".to_string()),
            expected_method: "POST".to_string(),
            expected_target: "https://example.com/token".to_string(),
        };

        let result = validate_proof(&proof, &config);
        assert!(matches!(result, Err(DPoPValidationError::NonceMismatch)));
    }

    #[test]
    fn test_verify_binding() {
        let (proof, thumbprint) = create_test_proof("POST", "https://example.com/token", None);

        let config = DPoPConfig {
            max_proof_age_secs: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "POST".to_string(),
            expected_target: "https://example.com/token".to_string(),
        };

        let proof_thumbprint = validate_proof(&proof, &config).unwrap();

        // Should match
        assert!(verify_binding(&proof_thumbprint, &thumbprint).is_ok());

        // Should not match different thumbprint
        assert!(verify_binding(&proof_thumbprint, "wrong-thumbprint").is_err());
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
            htm: "POST".to_string(),
            htu: "https://replay-test.example.com/token".to_string(),
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
            max_proof_age_secs: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "POST".to_string(),
            expected_target: "https://replay-test.example.com/token".to_string(),
        };

        // First use should succeed
        let result1 = validate_proof(&proof, &config);
        assert!(result1.is_ok(), "First use should succeed");

        // Second use with same JTI should be detected as replay
        let result2 = validate_proof(&proof, &config);
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
