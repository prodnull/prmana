//! Signer trait and implementations for DPoP proof signing

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;

use crate::crypto::dpop::{generate_dpop_proof, DPoPError};
use crate::crypto::thumbprint::compute_ec_thumbprint;

/// Trait for DPoP signing operations
///
/// This abstraction allows for different key storage backends:
/// - SoftwareSigner: Keys in memory/keychain
/// - YubiKeySigner: Keys on hardware token (future)
/// - TpmSigner: Keys in TPM (future)
pub trait DPoPSigner: Send + Sync {
    /// Get the JWK thumbprint of this signer's public key
    fn thumbprint(&self) -> String;

    /// Generate a DPoP proof for the given target
    fn sign_proof(
        &self,
        method: &str,
        target: &str,
        nonce: Option<&str>,
    ) -> Result<String, DPoPError>;

    /// Get the public key in JWK format
    fn public_key_jwk(&self) -> serde_json::Value;
}

/// Software-based signer using in-memory or keychain-stored keys
pub struct SoftwareSigner {
    signing_key: SigningKey,
    thumbprint: String,
}

impl SoftwareSigner {
    /// Create a new signer with a randomly generated key
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let thumbprint = compute_ec_thumbprint(signing_key.verifying_key());
        Self {
            signing_key,
            thumbprint,
        }
    }

    /// Create a signer from an existing key
    pub fn from_key(signing_key: SigningKey) -> Self {
        let thumbprint = compute_ec_thumbprint(signing_key.verifying_key());
        Self {
            signing_key,
            thumbprint,
        }
    }

    /// Export the signing key bytes (for secure storage)
    pub fn export_key(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Import a signing key from bytes
    pub fn import_key(bytes: &[u8]) -> Result<Self, SignerError> {
        let signing_key =
            SigningKey::from_slice(bytes).map_err(|_| SignerError::InvalidKeyBytes)?;
        Ok(Self::from_key(signing_key))
    }

    /// Get the verifying (public) key
    pub fn verifying_key(&self) -> &p256::ecdsa::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl DPoPSigner for SoftwareSigner {
    fn thumbprint(&self) -> String {
        self.thumbprint.clone()
    }

    fn sign_proof(
        &self,
        method: &str,
        target: &str,
        nonce: Option<&str>,
    ) -> Result<String, DPoPError> {
        generate_dpop_proof(&self.signing_key, method, target, nonce)
    }

    fn public_key_jwk(&self) -> serde_json::Value {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        // SAFETY: Uncompressed points always have x,y coordinates
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y"));

        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("Invalid key bytes")]
    InvalidKeyBytes,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Storage error: {0}")]
    Storage(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_generate_signer() {
        let signer = SoftwareSigner::generate();

        // Thumbprint should be valid (43 chars for SHA-256 base64url)
        assert_eq!(signer.thumbprint().len(), 43);
    }

    #[test]
    fn test_signer_export_import_roundtrip() {
        let signer1 = SoftwareSigner::generate();
        let exported = signer1.export_key();

        let signer2 = SoftwareSigner::import_key(&exported).unwrap();

        assert_eq!(signer1.thumbprint(), signer2.thumbprint());
    }

    #[test]
    fn test_signer_generates_valid_proofs() {
        let signer = SoftwareSigner::generate();

        let proof = signer
            .sign_proof("SSH", "server.example.com", None)
            .unwrap();

        // Should be valid JWT format
        assert_eq!(proof.split('.').count(), 3);
    }

    #[test]
    fn test_public_key_jwk_format() {
        let signer = SoftwareSigner::generate();
        let jwk = signer.public_key_jwk();

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["x"].is_string());
        assert!(jwk["y"].is_string());
    }

    #[test]
    fn test_signer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SoftwareSigner>();
    }

    #[test]
    fn test_signer_in_arc() {
        let signer: Arc<dyn DPoPSigner> = Arc::new(SoftwareSigner::generate());

        // Should be able to use through Arc
        let thumb = signer.thumbprint();
        assert_eq!(thumb.len(), 43);
    }
}
