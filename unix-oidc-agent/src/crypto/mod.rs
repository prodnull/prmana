//! Cryptographic operations for DPoP
//!
//! This module provides:
//! - JWK thumbprint computation (RFC 7638)
//! - DPoP proof generation (RFC 9449)
//! - Signer trait for pluggable key backends

pub mod dpop;
pub mod signer;
pub mod thumbprint;

pub use dpop::{generate_dpop_proof, DPoPClaims, DPoPError};
pub use signer::{DPoPSigner, SignerError, SoftwareSigner};
pub use thumbprint::compute_ec_thumbprint;
