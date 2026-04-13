//! # DPoP - Demonstrating Proof of Possession (RFC 9449)
//!
//! This crate provides a complete implementation of OAuth 2.0 DPoP (Demonstrating
//! Proof of Possession) as defined in [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).
//!
//! DPoP is a mechanism for sender-constraining OAuth 2.0 tokens by binding them to
//! a cryptographic key held by the client. This prevents stolen tokens from being
//! used by attackers who don't possess the private key.
//!
//! ## Features
//!
//! - **`client`** (default): Client-side DPoP proof generation
//! - **`server`** (default): Server-side proof validation with replay protection
//!
//! ## Quick Start
//!
//! ### Client-side: Generate a DPoP proof
//!
//! ```rust
//! use oauth_dpop::{DPoPClient, DPoPError};
//!
//! // Create a new DPoP client (generates a P-256 keypair)
//! let client = DPoPClient::generate();
//!
//! // Get the key thumbprint (for the cnf.jkt claim in tokens)
//! println!("Thumbprint: {}", client.thumbprint());
//!
//! // Generate a proof for an HTTP request
//! let proof = client.create_proof("POST", "https://api.example.com/token", None)?;
//!
//! // Generate a proof with a server-provided nonce
//! let proof_with_nonce = client.create_proof(
//!     "GET",
//!     "https://api.example.com/resource",
//!     Some("server-nonce-123")
//! )?;
//! # Ok::<(), DPoPError>(())
//! ```
//!
//! ### Server-side: Validate a DPoP proof
//!
//! ```rust,ignore
//! use oauth_dpop::{validate_proof, DPoPConfig};
//!
//! // Create a validator with configuration
//! let config = DPoPConfig {
//!     max_proof_age_secs: 60,
//!     require_nonce: false,
//!     expected_nonce: None,
//!     expected_method: "POST".to_string(),
//!     expected_target: "https://api.example.com/token".to_string(),
//! };
//!
//! // Validate the proof and get the thumbprint
//! let result = validate_proof(&proof, &config);
//! match result {
//!     Ok(thumbprint) => {
//!         // Compare thumbprint with token's cnf.jkt claim
//!         println!("Proof valid, thumbprint: {}", thumbprint);
//!     }
//!     Err(e) => {
//!         eprintln!("Proof validation failed: {}", e);
//!     }
//! }
//! ```
//!
//! ## Security Considerations
//!
//! This implementation includes several security hardening measures:
//!
//! - **JTI Replay Protection**: Each proof's unique identifier (jti) is cached to
//!   prevent replay attacks. The cache automatically cleans up expired entries.
//! - **Constant-Time Comparison**: Cryptographic values (nonces, thumbprints) are
//!   compared using constant-time operations to prevent timing attacks.
//! - **Key Parameter Validation**: P-256 coordinate lengths are validated to be
//!   exactly 32 bytes to prevent malformed key attacks.
//! - **Proof Age Validation**: Proofs are rejected if they're too old or from the future.
//!
//! ## Algorithm Support
//!
//! Currently supports:
//! - **ES256** (ECDSA with P-256 and SHA-256) - recommended by RFC 9449
//!
//! Future versions may add support for:
//! - RS256, PS256 (RSA-based algorithms)
//! - EdDSA (Ed25519)

mod client;
mod error;
mod jwk;
#[cfg(feature = "server")]
mod server;
mod thumbprint;

pub use client::DPoPClient;
pub use error::DPoPError;
pub use jwk::{EcPublicJwk, JwkThumbprint};
#[cfg(feature = "server")]
pub use error::DPoPValidationError;
#[cfg(feature = "server")]
pub use server::{validate_proof, verify_binding, DPoPConfig};
pub use thumbprint::{compute_thumbprint, compute_thumbprint_from_coordinates, compute_thumbprint_from_jwk};

/// DPoP proof claims per RFC 9449 Section 4.2
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DPoPClaims {
    /// Unique identifier for the proof (prevents replay)
    pub jti: String,
    /// HTTP method (GET, POST, etc.)
    pub htm: String,
    /// HTTP target URI
    pub htu: String,
    /// Issued at timestamp (seconds since Unix epoch)
    pub iat: i64,
    /// Server-provided nonce (optional but recommended)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Access token hash for token binding (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_generation() {
        let client = DPoPClient::generate();
        assert!(!client.thumbprint().is_empty());
    }

    #[test]
    fn test_proof_generation() {
        let client = DPoPClient::generate();
        let proof = client
            .create_proof("POST", "https://example.com/token", None)
            .unwrap();

        // JWT has 3 parts
        assert_eq!(proof.split('.').count(), 3);
    }

    #[test]
    fn test_proof_with_nonce() {
        let client = DPoPClient::generate();
        let proof = client
            .create_proof("GET", "https://example.com/api", Some("nonce123"))
            .unwrap();

        assert!(!proof.is_empty());
    }

    #[cfg(feature = "server")]
    #[test]
    fn test_client_server_roundtrip() {
        let client = DPoPClient::generate();
        let proof = client
            .create_proof("POST", "https://example.com/token", None)
            .unwrap();

        let config = DPoPConfig {
            max_proof_age_secs: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "POST".to_string(),
            expected_target: "https://example.com/token".to_string(),
        };

        let thumbprint = validate_proof(&proof, &config).unwrap();
        assert_eq!(thumbprint, client.thumbprint());
    }

    #[cfg(feature = "server")]
    #[test]
    fn test_binding_verification() {
        let client = DPoPClient::generate();
        let proof = client
            .create_proof("POST", "https://example.com/token", None)
            .unwrap();

        let config = DPoPConfig {
            max_proof_age_secs: 60,
            require_nonce: false,
            expected_nonce: None,
            expected_method: "POST".to_string(),
            expected_target: "https://example.com/token".to_string(),
        };

        let proof_thumbprint = validate_proof(&proof, &config).unwrap();

        // Should succeed with matching thumbprint
        assert!(verify_binding(&proof_thumbprint, &client.thumbprint()).is_ok());

        // Should fail with different thumbprint
        assert!(verify_binding(&proof_thumbprint, "wrong-thumbprint").is_err());
    }
}
