//! DPoP client for proof generation

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::error::DPoPError;
use crate::jwk::EcPublicJwk;
use crate::thumbprint::compute_thumbprint;
use crate::DPoPClaims;

/// DPoP client for generating proofs
///
/// The client holds a P-256 signing key and can generate DPoP proofs
/// for HTTP requests. The key thumbprint can be used for the `cnf.jkt`
/// claim in tokens.
///
/// # Example
///
/// ```rust
/// use dpop::DPoPClient;
///
/// // Generate a new client with a random keypair
/// let client = DPoPClient::generate();
///
/// // Get the thumbprint for token binding
/// println!("Thumbprint: {}", client.thumbprint());
///
/// // Create a proof for an HTTP request
/// let proof = client.create_proof("POST", "https://api.example.com/token", None)?;
/// # Ok::<(), dpop::DPoPError>(())
/// ```
pub struct DPoPClient {
    signing_key: SigningKey,
    thumbprint: String,
}

impl DPoPClient {
    /// Generate a new DPoP client with a random P-256 keypair
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let thumbprint = compute_thumbprint(signing_key.verifying_key());
        Self {
            signing_key,
            thumbprint,
        }
    }

    /// Create a DPoP client from an existing signing key
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let thumbprint = compute_thumbprint(signing_key.verifying_key());
        Self {
            signing_key,
            thumbprint,
        }
    }

    /// Get the JWK thumbprint of this client's public key
    ///
    /// This thumbprint should be used for the `cnf.jkt` claim in tokens
    /// to bind them to this client.
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// Get the public key as a JWK
    pub fn public_key_jwk(&self) -> EcPublicJwk {
        let verifying_key = self.signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let x = URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y"));

        EcPublicJwk::new(x, y)
    }

    /// Create a DPoP proof for an HTTP request
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method (e.g., "GET", "POST")
    /// * `target` - Target URI (e.g., "https://api.example.com/token")
    /// * `nonce` - Optional server-provided nonce
    ///
    /// # Returns
    ///
    /// A signed JWT proof in the format `header.claims.signature`
    pub fn create_proof(
        &self,
        method: &str,
        target: &str,
        nonce: Option<&str>,
    ) -> Result<String, DPoPError> {
        self.create_proof_internal(method, target, nonce, None)
    }

    /// Create a DPoP proof with an access token hash (for resource requests)
    ///
    /// When accessing protected resources with a DPoP-bound access token,
    /// the proof should include an `ath` claim containing the SHA-256 hash
    /// of the access token.
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method
    /// * `target` - Target URI
    /// * `nonce` - Optional server-provided nonce
    /// * `access_token` - The access token to bind to this proof
    pub fn create_proof_with_ath(
        &self,
        method: &str,
        target: &str,
        nonce: Option<&str>,
        access_token: &str,
    ) -> Result<String, DPoPError> {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(access_token.as_bytes());
        let ath = URL_SAFE_NO_PAD.encode(hash);
        self.create_proof_internal(method, target, nonce, Some(ath))
    }

    fn create_proof_internal(
        &self,
        method: &str,
        target: &str,
        nonce: Option<&str>,
        ath: Option<String>,
    ) -> Result<String, DPoPError> {
        let verifying_key = self.signing_key.verifying_key();
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
            ath,
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
        let signature: Signature = self.signing_key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{}.{}", message, sig_b64))
    }

    /// Extract the JWK from a DPoP proof header
    ///
    /// This can be used to verify that a proof was created with a specific key.
    pub fn extract_jwk_from_proof(proof: &str) -> Result<EcPublicJwk, DPoPError> {
        let parts: Vec<&str> = proof.split('.').collect();
        if parts.len() != 3 {
            return Err(DPoPError::InvalidProofFormat);
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| DPoPError::InvalidBase64)?;

        #[derive(serde::Deserialize)]
        struct Header {
            typ: String,
            jwk: EcPublicJwk,
        }

        let header: Header = serde_json::from_slice(&header_bytes)?;

        if header.typ != "dpop+jwt" {
            return Err(DPoPError::InvalidProofType);
        }

        Ok(header.jwk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_client() {
        let client = DPoPClient::generate();
        assert!(!client.thumbprint().is_empty());
        // SHA-256 = 32 bytes = 43 base64url chars
        assert_eq!(client.thumbprint().len(), 43);
    }

    #[test]
    fn test_proof_format() {
        let client = DPoPClient::generate();
        let proof = client
            .create_proof("POST", "https://example.com/token", None)
            .unwrap();

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
        let client = DPoPClient::generate();
        let proof = client
            .create_proof("GET", "https://api.example.com/resource", None)
            .unwrap();

        let jwk = DPoPClient::extract_jwk_from_proof(&proof).unwrap();

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert!(!jwk.x.is_empty());
        assert!(!jwk.y.is_empty());
    }

    #[test]
    fn test_proof_contains_correct_claims() {
        let client = DPoPClient::generate();
        let proof = client
            .create_proof(
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
    fn test_unique_jti_per_proof() {
        let client = DPoPClient::generate();

        let proof1 = client
            .create_proof("GET", "https://example.com", None)
            .unwrap();
        let proof2 = client
            .create_proof("GET", "https://example.com", None)
            .unwrap();

        let parts1: Vec<&str> = proof1.split('.').collect();
        let parts2: Vec<&str> = proof2.split('.').collect();

        let claims1: DPoPClaims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts1[1]).unwrap()).unwrap();
        let claims2: DPoPClaims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts2[1]).unwrap()).unwrap();

        assert_ne!(claims1.jti, claims2.jti);
    }

    #[test]
    fn test_proof_with_ath() {
        let client = DPoPClient::generate();
        let access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";

        let proof = client
            .create_proof_with_ath("GET", "https://api.example.com/resource", None, access_token)
            .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: DPoPClaims = serde_json::from_slice(&claims_bytes).unwrap();

        assert!(claims.ath.is_some());
        // ath should be SHA-256 hash = 43 base64url chars
        assert_eq!(claims.ath.unwrap().len(), 43);
    }

    #[test]
    fn test_public_key_jwk() {
        let client = DPoPClient::generate();
        let jwk = client.public_key_jwk();

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert!(!jwk.x.is_empty());
        assert!(!jwk.y.is_empty());
    }

    #[test]
    fn test_thumbprint_matches_proof_jwk() {
        let client = DPoPClient::generate();
        let proof = client
            .create_proof("GET", "https://example.com", None)
            .unwrap();

        let jwk = DPoPClient::extract_jwk_from_proof(&proof).unwrap();
        let proof_thumbprint = crate::thumbprint::compute_thumbprint_from_jwk(&jwk);

        assert_eq!(client.thumbprint(), proof_thumbprint);
    }
}
