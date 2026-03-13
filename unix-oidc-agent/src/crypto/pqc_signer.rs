//! Hybrid PQC DPoP signer: ML-DSA-65 + ES256 composite signatures
//!
//! Implements draft-ietf-jose-pq-composite-sigs-01 for DPoP proof signing.
//! The composite signature is: `2-byte ML-DSA length prefix || ML-DSA-65 sig || ES256 sig`.
//! Both components sign the same message (the DPoP JWT header.claims).
//!
//! # Feature gate
//!
//! This module is only compiled when `--features pqc` is active.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ml_dsa::{MlDsa65, Seed};
use p256::ecdsa::{signature::Signer as _, Signature as Es256Signature};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::dpop::{build_dpop_message_with_alg, assemble_dpop_proof_composite, DPoPError};
use crate::crypto::protected_key::ProtectedSigningKey;
use crate::crypto::signer::{DPoPSigner, SignerError};

/// JWS algorithm identifier for composite ML-DSA-65 + ES256.
/// Per draft-ietf-jose-pq-composite-sigs-01.
pub const ALG_ML_DSA_65_ES256: &str = "ML-DSA-65-ES256";

/// ML-DSA-65 signature size (FIPS 204).
const ML_DSA_65_SIG_SIZE: usize = 3309;

/// ES256 signature size (raw r||s).
const ES256_SIG_SIZE: usize = 64;

/// Hybrid PQC signer combining ML-DSA-65 and ES256 (P-256 ECDSA).
///
/// Both keys sign the same DPoP message. The resulting proof contains a composite
/// signature per draft-ietf-jose-pq-composite-sigs-01:
///
/// - 2-byte big-endian length prefix for the ML-DSA-65 component
/// - ML-DSA-65 signature (3309 bytes)
/// - ES256 signature (64 bytes, fixed)
///
/// The JWK is a composite key with `kty: "COMPOSITE"` containing both the PQ and
/// traditional EC public key components.
pub struct HybridPqcSigner {
    /// Traditional ES256 key with memory protection (mlock, ZeroizeOnDrop).
    ec_key: Box<ProtectedSigningKey>,
    /// ML-DSA-65 signing key. ZeroizeOnDrop when `zeroize` feature is enabled on ml-dsa.
    pq_key: ml_dsa::SigningKey<MlDsa65>,
    /// ML-DSA-65 verifying key (cached for JWK construction).
    pq_vk: ml_dsa::VerifyingKey<MlDsa65>,
    /// Pre-computed composite JWK thumbprint (RFC 7638 extended for composite keys).
    thumbprint: String,
    /// ML-DSA seed for key export/import (32 bytes). Wrapped in Zeroizing.
    pq_seed: Zeroizing<[u8; 32]>,
}

impl HybridPqcSigner {
    /// Generate a new hybrid key pair with random keys.
    ///
    /// Uses `OsRng` (via p256's rand_core 0.6) for the 32-byte ML-DSA seed,
    /// and `ProtectedSigningKey::generate()` for the EC key.
    pub fn generate() -> Self {
        let ec_key = ProtectedSigningKey::generate();

        // Generate ML-DSA-65 seed using OsRng (rand_core 0.6 from p256).
        // SigningKey::from_seed is deterministic — the seed IS the private key.
        let mut seed_bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed_bytes.as_mut());
        let seed = Seed::from(*seed_bytes);
        let pq_key = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed);
        let pq_vk = pq_key.verifying_key();

        let thumbprint = Self::compute_composite_thumbprint(&ec_key, &pq_vk);

        Self {
            ec_key,
            pq_key,
            pq_vk,
            thumbprint,
            pq_seed: seed_bytes,
        }
    }

    /// Reconstruct from stored key material.
    ///
    /// `ec_bytes` is the 32-byte P-256 private scalar.
    /// `pq_seed_bytes` is the 32-byte ML-DSA seed.
    pub fn from_key_bytes(ec_bytes: &[u8], pq_seed_bytes: &[u8]) -> Result<Self, SignerError> {
        if pq_seed_bytes.len() != 32 {
            return Err(SignerError::InvalidKeyBytes);
        }
        let ec_key = ProtectedSigningKey::from_bytes(ec_bytes)?;

        let mut seed_bytes = Zeroizing::new([0u8; 32]);
        seed_bytes.copy_from_slice(pq_seed_bytes);
        let seed = Seed::from(*seed_bytes);
        let pq_key = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed);
        let pq_vk = pq_key.verifying_key();

        let thumbprint = Self::compute_composite_thumbprint(&ec_key, &pq_vk);

        Ok(Self {
            ec_key,
            pq_key,
            pq_vk,
            thumbprint,
            pq_seed: seed_bytes,
        })
    }

    /// Export the EC key bytes (32 bytes, Zeroizing).
    pub fn export_ec_key(&self) -> Zeroizing<Vec<u8>> {
        self.ec_key.export_key()
    }

    /// Export the ML-DSA seed (32 bytes, Zeroizing).
    pub fn export_pq_seed(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.pq_seed.to_vec())
    }

    /// Build the composite JWK (for embedding in DPoP proof headers).
    fn composite_jwk(&self) -> serde_json::Value {
        let ec_point = self.ec_key.verifying_key().to_encoded_point(false);
        let ec_x = URL_SAFE_NO_PAD.encode(ec_point.x().expect("uncompressed point has x"));
        let ec_y = URL_SAFE_NO_PAD.encode(ec_point.y().expect("uncompressed point has y"));

        let pq_pub = URL_SAFE_NO_PAD.encode(self.pq_vk.encode().as_slice());

        serde_json::json!({
            "kty": "COMPOSITE",
            "alg": ALG_ML_DSA_65_ES256,
            "pq": {
                "kty": "AKP",
                "alg": "ML-DSA-65",
                "pub": pq_pub
            },
            "trad": {
                "kty": "EC",
                "crv": "P-256",
                "x": ec_x,
                "y": ec_y
            }
        })
    }

    /// Compute the composite JWK thumbprint per RFC 7638 (extended).
    ///
    /// Canonical JSON with members in lexicographic order:
    /// `{"alg":"ML-DSA-65-ES256","kty":"COMPOSITE","pq":{...},"trad":{...}}`
    ///
    /// Inner JWK members are also in lexicographic order.
    fn compute_composite_thumbprint(
        ec_key: &ProtectedSigningKey,
        pq_vk: &ml_dsa::VerifyingKey<MlDsa65>,
    ) -> String {
        let ec_point = ec_key.verifying_key().to_encoded_point(false);
        let ec_x = URL_SAFE_NO_PAD.encode(ec_point.x().expect("uncompressed point has x"));
        let ec_y = URL_SAFE_NO_PAD.encode(ec_point.y().expect("uncompressed point has y"));
        let pq_pub = URL_SAFE_NO_PAD.encode(pq_vk.encode().as_slice());

        // RFC 7638: Members in lexicographic order.
        // Outer: alg < kty < pq < trad
        // Inner pq: alg < kty < pub
        // Inner trad: crv < kty < x < y
        let canonical = format!(
            r#"{{"alg":"{ALG_ML_DSA_65_ES256}","kty":"COMPOSITE","pq":{{"alg":"ML-DSA-65","kty":"AKP","pub":"{pq_pub}"}},"trad":{{"crv":"P-256","kty":"EC","x":"{ec_x}","y":"{ec_y}"}}}}"#,
        );

        let hash = Sha256::digest(canonical.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    }

    /// Produce the composite signature bytes.
    ///
    /// Format per draft-ietf-jose-pq-composite-sigs-01:
    /// `2-byte BE length of ML-DSA sig || ML-DSA-65 sig || ES256 sig`
    fn composite_sign(&self, message: &[u8]) -> Result<Vec<u8>, DPoPError> {
        // Sign with ML-DSA-65 (deterministic, empty context via Signer trait)
        use ml_dsa::signature::Signer as MlDsaSigner;
        let pq_sig = self.pq_key.sign(message);
        let pq_sig_bytes = pq_sig.encode();

        // Sign with ES256 (P-256 ECDSA)
        let ec_sig: Es256Signature = self.ec_key.signing_key().sign(message);
        let ec_sig_bytes = ec_sig.to_bytes();

        debug_assert_eq!(pq_sig_bytes.len(), ML_DSA_65_SIG_SIZE);
        debug_assert_eq!(ec_sig_bytes.len(), ES256_SIG_SIZE);

        // Assemble: 2-byte BE length prefix for ML-DSA, then ML-DSA sig, then ES256 sig
        let pq_len = pq_sig_bytes.len() as u16;
        let mut composite = Vec::with_capacity(2 + ML_DSA_65_SIG_SIZE + ES256_SIG_SIZE);
        composite.extend_from_slice(&pq_len.to_be_bytes());
        composite.extend_from_slice(pq_sig_bytes.as_slice());
        composite.extend_from_slice(&ec_sig_bytes);

        Ok(composite)
    }
}

impl DPoPSigner for HybridPqcSigner {
    fn thumbprint(&self) -> String {
        self.thumbprint.clone()
    }

    fn sign_proof(
        &self,
        method: &str,
        target: &str,
        nonce: Option<&str>,
    ) -> Result<String, DPoPError> {
        let jwk = self.composite_jwk();
        let message = build_dpop_message_with_alg(&jwk, method, target, nonce, ALG_ML_DSA_65_ES256)?;

        let composite_sig = self.composite_sign(message.as_bytes())?;
        assemble_dpop_proof_composite(&message, &composite_sig)
    }

    fn public_key_jwk(&self) -> serde_json::Value {
        self.composite_jwk()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hybrid_signer() {
        let signer = HybridPqcSigner::generate();
        // Composite thumbprint: SHA-256 base64url = 43 chars
        assert_eq!(signer.thumbprint().len(), 43);
    }

    #[test]
    fn test_composite_jwk_structure() {
        let signer = HybridPqcSigner::generate();
        let jwk = signer.public_key_jwk();

        assert_eq!(jwk["kty"], "COMPOSITE");
        assert_eq!(jwk["alg"], ALG_ML_DSA_65_ES256);
        assert_eq!(jwk["pq"]["kty"], "AKP");
        assert_eq!(jwk["pq"]["alg"], "ML-DSA-65");
        assert!(jwk["pq"]["pub"].is_string());
        assert_eq!(jwk["trad"]["kty"], "EC");
        assert_eq!(jwk["trad"]["crv"], "P-256");
        assert!(jwk["trad"]["x"].is_string());
        assert!(jwk["trad"]["y"].is_string());
    }

    #[test]
    fn test_composite_thumbprint_deterministic() {
        let signer = HybridPqcSigner::generate();
        let t1 = signer.thumbprint();
        let t2 = signer.thumbprint();
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_different_keys_different_thumbprints() {
        let s1 = HybridPqcSigner::generate();
        let s2 = HybridPqcSigner::generate();
        assert_ne!(s1.thumbprint(), s2.thumbprint());
    }

    #[test]
    fn test_export_import_roundtrip() {
        let signer1 = HybridPqcSigner::generate();
        let ec_bytes = signer1.export_ec_key();
        let pq_seed = signer1.export_pq_seed();

        let signer2 = HybridPqcSigner::from_key_bytes(&ec_bytes, &pq_seed).unwrap();

        assert_eq!(signer1.thumbprint(), signer2.thumbprint());
    }

    #[test]
    fn test_sign_proof_produces_valid_jwt() {
        let signer = HybridPqcSigner::generate();
        let proof = signer
            .sign_proof("SSH", "server.example.com", None)
            .unwrap();

        // JWT format: header.payload.signature
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode header and verify algorithm
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], ALG_ML_DSA_65_ES256);
        assert_eq!(header["jwk"]["kty"], "COMPOSITE");
    }

    #[test]
    fn test_composite_signature_format() {
        let signer = HybridPqcSigner::generate();
        let sig_bytes = signer.composite_sign(b"test message").unwrap();

        // 2-byte length prefix + ML-DSA-65 sig + ES256 sig
        assert_eq!(sig_bytes.len(), 2 + ML_DSA_65_SIG_SIZE + ES256_SIG_SIZE);

        // Verify length prefix
        let pq_len = u16::from_be_bytes([sig_bytes[0], sig_bytes[1]]);
        assert_eq!(pq_len as usize, ML_DSA_65_SIG_SIZE);
    }

    #[test]
    fn test_from_key_bytes_invalid_pq_seed() {
        let ec_key = ProtectedSigningKey::generate();
        let ec_bytes = ec_key.export_key();
        let bad_seed = vec![0u8; 16]; // wrong length
        assert!(HybridPqcSigner::from_key_bytes(&ec_bytes, &bad_seed).is_err());
    }

    #[test]
    fn test_signer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HybridPqcSigner>();
    }
}
