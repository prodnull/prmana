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

pub use dpop::{assemble_dpop_proof, build_dpop_message, generate_dpop_proof, DPoPClaims, DPoPError};
pub use protected_key::{mlock_probe, MlockStatus, ProtectedSigningKey};
pub use signer::{DPoPSigner, SignerError, SoftwareSigner};
pub use thumbprint::compute_ec_thumbprint;
