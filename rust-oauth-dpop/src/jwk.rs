//! JSON Web Key (JWK) types for DPoP

use serde::{Deserialize, Serialize};

/// EC public key in JWK format (P-256/ES256)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcPublicJwk {
    /// Key type (always "EC")
    pub kty: String,
    /// Curve name (always "P-256" for ES256)
    pub crv: String,
    /// X coordinate (base64url-encoded)
    pub x: String,
    /// Y coordinate (base64url-encoded)
    pub y: String,
}

impl EcPublicJwk {
    /// Create a new EC public JWK for P-256
    pub fn new(x: String, y: String) -> Self {
        Self {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x,
            y,
        }
    }
}

/// JWK Thumbprint (RFC 7638)
///
/// A thumbprint is a SHA-256 hash of the canonical JSON representation
/// of a JWK, providing a unique identifier for the key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JwkThumbprint(String);

impl JwkThumbprint {
    /// Create a new thumbprint from a base64url-encoded string
    pub fn new(thumbprint: String) -> Self {
        Self(thumbprint)
    }

    /// Get the thumbprint as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the inner string
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for JwkThumbprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for JwkThumbprint {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for JwkThumbprint {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<JwkThumbprint> for String {
    fn from(t: JwkThumbprint) -> Self {
        t.0
    }
}
