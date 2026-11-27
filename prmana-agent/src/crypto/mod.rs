//! Cryptographic operations for DPoP
//!
//! This module provides:
//! - JWK thumbprint computation (RFC 7638)
//! - DPoP proof generation (RFC 9449)
//! - Signer trait for pluggable key backends
//! - Memory-protected signing key wrapper (MEM-01/02/04/05)

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

pub use dpop::{
    assemble_dpop_proof, assemble_dpop_proof_composite, build_dpop_message,
    build_dpop_message_with_alg, generate_dpop_proof, DPoPClaims, DPoPError,
};
pub use protected_key::{mlock_probe, MlockStatus, ProtectedSigningKey};
pub use signer::{DPoPSigner, SignerError, SoftwareSigner};
pub use thumbprint::compute_ec_thumbprint;

/// Fill `buf` with bytes from the OS CSPRNG.
///
/// Security: fails closed. If the OS RNG is unavailable we panic rather than
/// return, because every caller uses the output as secret material (PKCE
/// verifier, ML-DSA seed) or as overwrite data, and continuing with a
/// zeroed or partially filled buffer would silently produce predictable
/// secrets. This matches the behaviour of the `rand_core::OsRng` it replaces.
/// The agent is a CLI/daemon, not a PAM path, so panicking here cannot lock
/// a user out of a host.
pub(crate) fn fill_random(buf: &mut [u8]) {
    if let Err(e) = getrandom::fill(buf) {
        panic!("OS CSPRNG unavailable, refusing to continue: {e}");
    }
}

#[cfg(feature = "yubikey")]
pub use yubikey_signer::YubiKeySigner;

#[cfg(all(feature = "tpm", target_os = "linux"))]
pub use tpm_signer::TpmSigner;

#[cfg(feature = "pqc")]
pub use pqc_signer::HybridPqcSigner;
