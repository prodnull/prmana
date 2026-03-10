//! Signer trait and implementations for DPoP proof signing
//!
//! `SoftwareSigner` is the primary implementation. It wraps a `ProtectedSigningKey`
//! (heap-allocated, mlock'd, ZeroizeOnDrop) so that key material is protected in
//! memory throughout the lifetime of the signer.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::SigningKey;
use zeroize::Zeroizing;

use crate::crypto::dpop::{generate_dpop_proof, DPoPError};
use crate::crypto::protected_key::ProtectedSigningKey;

/// Trait for DPoP signing operations
///
/// This abstraction allows for different key storage backends:
/// - SoftwareSigner: Keys in memory (heap-locked via mlock, zeroed on drop)
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

/// Software-based DPoP signer.
///
/// Internally holds a `Box<ProtectedSigningKey>` which provides:
/// - Heap-stable allocation (no accidental stack copies of key material)
/// - `mlock(2)` on the allocation where supported (prevents swap exposure)
/// - `ZeroizeOnDrop` on the inner `SigningKey` (memory wiped on drop)
/// - `Zeroizing<Vec<u8>>` export (wiped after storage write)
pub struct SoftwareSigner {
    key: Box<ProtectedSigningKey>,
}

impl SoftwareSigner {
    /// Create a new signer with a randomly generated key.
    pub fn generate() -> Self {
        Self {
            key: ProtectedSigningKey::generate(),
        }
    }

    /// Create a signer from an existing `SigningKey`.
    ///
    /// The key is immediately wrapped in a `ProtectedSigningKey` (heap-allocated,
    /// mlock attempted). This replaces the old stack-resident field.
    pub fn from_key(signing_key: SigningKey) -> Self {
        // ProtectedSigningKey doesn't expose a constructor from SigningKey directly.
        // Round-trip through bytes: export to Zeroizing<Vec<u8>>, then import.
        // This is safe: to_bytes() returns a FieldBytes (stack copy), which we
        // immediately move into Zeroizing to ensure it's wiped after use.
        let bytes = Zeroizing::new(signing_key.to_bytes().to_vec());
        Self {
            // from_bytes on a valid SigningKey cannot fail
            key: ProtectedSigningKey::from_bytes(&bytes)
                .expect("SigningKey round-trip through bytes must succeed"),
        }
    }

    /// Export the signing key bytes as a `Zeroizing<Vec<u8>>` (MEM-01).
    ///
    /// The returned value automatically zeroes its contents on drop. Callers
    /// should not copy the inner bytes into a plain `Vec<u8>` or `&[u8]` that
    /// will outlive the current scope.
    ///
    /// The `Zeroizing<Vec<u8>>` derefs to `&[u8]`, so passing `&exported` to
    /// storage APIs that accept `&[u8]` works without any conversions.
    pub fn export_key(&self) -> Zeroizing<Vec<u8>> {
        self.key.export_key()
    }

    /// Import a signing key from bytes.
    ///
    /// The bytes are parsed and immediately wrapped in a `ProtectedSigningKey`.
    /// The caller is responsible for zeroing `bytes` after the call if they
    /// came from unprotected storage (e.g., use `Zeroizing<Vec<u8>>` for retrieval).
    pub fn import_key(bytes: &[u8]) -> Result<Self, SignerError> {
        let key = ProtectedSigningKey::from_bytes(bytes)?;
        Ok(Self { key })
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> &p256::ecdsa::VerifyingKey {
        self.key.verifying_key()
    }
}

impl DPoPSigner for SoftwareSigner {
    fn thumbprint(&self) -> String {
        self.key.thumbprint().to_owned()
    }

    fn sign_proof(
        &self,
        method: &str,
        target: &str,
        nonce: Option<&str>,
    ) -> Result<String, DPoPError> {
        generate_dpop_proof(self.key.signing_key(), method, target, nonce)
    }

    fn public_key_jwk(&self) -> serde_json::Value {
        let point = self.key.verifying_key().to_encoded_point(false);
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
        let exported: Zeroizing<Vec<u8>> = signer1.export_key();

        // Zeroizing<Vec<u8>> derefs to &[u8] via AsRef/Deref
        let signer2 = SoftwareSigner::import_key(&exported).unwrap();

        assert_eq!(signer1.thumbprint(), signer2.thumbprint());
    }

    #[test]
    fn test_export_key_returns_zeroizing() {
        let signer = SoftwareSigner::generate();
        // Type annotation verifies the return type is Zeroizing<Vec<u8>>
        let exported: Zeroizing<Vec<u8>> = signer.export_key();
        // P-256 private key = 32 bytes
        assert_eq!(exported.len(), 32, "P-256 private key must be 32 bytes");
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

    #[test]
    fn test_from_key_roundtrip() {
        use p256::elliptic_curve::rand_core::OsRng;
        let signing_key = SigningKey::random(&mut OsRng);
        let expected_thumb = {
            use crate::crypto::thumbprint::compute_ec_thumbprint;
            compute_ec_thumbprint(signing_key.verifying_key())
        };

        let signer = SoftwareSigner::from_key(signing_key);
        assert_eq!(signer.thumbprint(), expected_thumb);
    }

    #[test]
    fn test_export_deref_to_slice() {
        // Verify exported bytes can be passed directly to import_key as &[u8]
        // (Zeroizing<Vec<u8>> impls Deref<Target=[u8]>)
        let signer = SoftwareSigner::generate();
        let exported = signer.export_key();
        // This must compile and succeed — &*exported coerces to &[u8]
        let _ = SoftwareSigner::import_key(&exported).unwrap();
    }
}
