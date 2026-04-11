//! Cryptographic operations for DPoP
//!
//! This module provides:
//! - JWK thumbprint computation (RFC 7638)
//! - DPoP proof generation (RFC 9449)
//! - Signer trait for pluggable key backends
//! - Memory-protected signing key wrapper (MEM-01/02/04/05)

pub mod attestation_pop;
pub mod dpop;
pub mod protected_key;
pub mod signer;
pub mod thumbprint;

#[cfg(feature = "yubikey")]
pub mod yubikey_signer;

// tpm_signer is compiled on all platforms when --features tpm is active.
// The `pad_to_32` helper and its unit tests are platform-independent.
// `TpmSigner` itself uses tss-esapi (Linux only) and is gated accordingly
// inside the module.
#[cfg(feature = "tpm")]
pub mod tpm_signer;

#[cfg(feature = "pqc")]
pub mod pqc_signer;

#[cfg(feature = "spire")]
pub mod spire_signer;

pub use attestation_pop::{
    attach_client_attestation, build_client_attestation, build_client_attestation_headers,
    build_client_attestation_pop, ClientAttestationHeaders,
};
pub use dpop::{
    assemble_dpop_proof, assemble_dpop_proof_composite, build_dpop_message,
    build_dpop_message_with_alg, generate_dpop_proof, DPoPClaims, DPoPError,
};
pub use protected_key::{mlock_probe, MlockStatus, ProtectedSigningKey};
pub use signer::{DPoPSigner, SignerError, SoftwareSigner};
pub use thumbprint::compute_ec_thumbprint;

#[cfg(feature = "yubikey")]
pub use yubikey_signer::YubiKeySigner;

#[cfg(all(feature = "tpm", target_os = "linux"))]
pub use tpm_signer::TpmSigner;

#[cfg(feature = "pqc")]
pub use pqc_signer::HybridPqcSigner;

#[cfg(feature = "spire")]
pub use spire_signer::{SpireConfig, SpireSigner};
