//! Error types for DPoP operations

use thiserror::Error;

/// Errors that can occur during DPoP proof generation (client-side)
#[derive(Debug, Error)]
pub enum DPoPError {
    /// Invalid cryptographic key
    #[error("Invalid key")]
    InvalidKey,

    /// System clock error
    #[error("Clock error")]
    ClockError,

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid proof format (not a valid JWT)
    #[error("Invalid proof format")]
    InvalidProofFormat,

    /// Invalid base64 encoding
    #[error("Invalid base64")]
    InvalidBase64,

    /// Invalid proof type (expected dpop+jwt)
    #[error("Invalid proof type (expected dpop+jwt)")]
    InvalidProofType,
}

/// Errors that can occur during DPoP proof validation (server-side)
#[cfg(feature = "server")]
#[derive(Debug, Error)]
pub enum DPoPValidationError {
    /// Invalid proof format (not a valid JWT)
    #[error("Invalid proof format")]
    InvalidFormat,

    /// Invalid JWT header
    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    /// Invalid cryptographic signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Missing JWK in proof header
    #[error("Missing JWK in header")]
    MissingJwk,

    /// Unsupported algorithm (only ES256 is supported)
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Proof has expired or is from the future
    #[error("Proof expired (iat={iat}, now={now})")]
    ProofExpired {
        /// Issued-at timestamp from proof
        iat: i64,
        /// Current server time
        now: i64,
    },

    /// HTTP method doesn't match expected value
    #[error("Method mismatch (expected={expected}, actual={actual})")]
    MethodMismatch {
        /// Expected HTTP method
        expected: String,
        /// Actual HTTP method in proof
        actual: String,
    },

    /// Target URI doesn't match expected value
    #[error("Target mismatch (expected={expected}, actual={actual})")]
    TargetMismatch {
        /// Expected target URI
        expected: String,
        /// Actual target URI in proof
        actual: String,
    },

    /// Nonce doesn't match expected value
    #[error("Nonce mismatch")]
    NonceMismatch,

    /// Nonce required but not provided
    #[error("Missing nonce")]
    MissingNonce,

    /// Thumbprint doesn't match token binding
    #[error("Thumbprint mismatch (token_jkt={token_jkt}, proof_jkt={proof_jkt})")]
    ThumbprintMismatch {
        /// Thumbprint from token's cnf.jkt claim
        token_jkt: String,
        /// Thumbprint from proof's JWK
        proof_jkt: String,
    },

    /// Token missing cnf.jkt claim for DPoP binding
    #[error("Token missing cnf.jkt claim")]
    MissingTokenBinding,

    /// Base64 decoding error
    #[error("Base64 decode error")]
    Base64Error,

    /// JSON parsing error
    #[error("JSON parse error: {0}")]
    JsonError(String),

    /// DPoP proof replay detected (same JTI used twice)
    #[error("DPoP proof replay detected")]
    ReplayDetected,

    /// Invalid JWK key parameters (wrong coordinate length, etc.)
    #[error("Invalid JWK key parameters")]
    InvalidKeyParameters,
}
