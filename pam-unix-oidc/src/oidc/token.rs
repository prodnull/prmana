//! JWT token parsing and claims extraction.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Failed to decode token: {0}")]
    DecodeError(String),
    #[error("Missing required claim: {0}")]
    MissingClaim(String),
    #[error("Invalid token format")]
    InvalidFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (user identifier)
    pub sub: String,

    /// Preferred username (maps to SSSD uid)
    pub preferred_username: String,

    /// Issuer
    pub iss: String,

    /// Audience
    pub aud: StringOrVec,

    /// Expiration time
    pub exp: i64,

    /// Issued at
    pub iat: i64,

    /// Authentication time
    #[serde(default)]
    pub auth_time: Option<i64>,

    /// Authentication Context Class Reference
    #[serde(default)]
    pub acr: Option<String>,

    /// Authentication Methods References
    #[serde(default)]
    pub amr: Option<Vec<String>>,

    /// JWT ID
    #[serde(default)]
    pub jti: Option<String>,

    /// Confirmation claim (DPoP binding)
    /// RFC 9449: Contains jkt (JWK thumbprint) for DPoP-bound tokens
    #[serde(default)]
    pub cnf: Option<ConfirmationClaim>,
}

/// Confirmation claim for proof-of-possession (RFC 9449)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationClaim {
    /// JWK SHA-256 thumbprint for DPoP binding
    #[serde(default)]
    pub jkt: Option<String>,
}

/// Handle audience as string or array
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrVec {
    String(String),
    Vec(Vec<String>),
}

impl StringOrVec {
    /// Check if the audience contains a specific value
    pub fn contains(&self, value: &str) -> bool {
        match self {
            StringOrVec::String(s) => s == value,
            StringOrVec::Vec(v) => v.iter().any(|s| s == value),
        }
    }
}

impl TokenClaims {
    /// Parse claims from a JWT token (without validation)
    /// For testing and claim extraction only
    pub fn from_token(token: &str) -> Result<Self, TokenError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(TokenError::InvalidFormat);
        }

        let payload = parts[1];
        let decoded =
            base64_decode_url_safe(payload).map_err(|e| TokenError::DecodeError(e.to_string()))?;

        serde_json::from_slice(&decoded).map_err(|e| TokenError::DecodeError(e.to_string()))
    }
}

fn base64_decode_url_safe(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    // Strip any padding characters to handle both padded and unpadded base64url
    let trimmed = input.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_token_claims() {
        let token = create_test_token();
        let claims = TokenClaims::from_token(&token).unwrap();

        assert_eq!(claims.preferred_username, "testuser");
        assert_eq!(claims.sub, "testuser");
        assert_eq!(claims.iss, "http://localhost:8080/realms/test");
    }

    #[test]
    fn test_parse_invalid_format() {
        let result = TokenClaims::from_token("not.a.valid.token");
        assert!(matches!(result, Err(TokenError::InvalidFormat)));
    }

    #[test]
    fn test_string_or_vec_contains() {
        let single = StringOrVec::String("unix-oidc".to_string());
        assert!(single.contains("unix-oidc"));
        assert!(!single.contains("other"));

        let multiple = StringOrVec::Vec(vec!["unix-oidc".to_string(), "other-client".to_string()]);
        assert!(multiple.contains("unix-oidc"));
        assert!(multiple.contains("other-client"));
        assert!(!multiple.contains("unknown"));
    }

    #[test]
    fn test_parse_missing_parts() {
        let result = TokenClaims::from_token("only.two");
        assert!(matches!(result, Err(TokenError::InvalidFormat)));
    }

    fn create_test_token() -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let payload = r#"{"sub":"testuser","preferred_username":"testuser","iss":"http://localhost:8080/realms/test","aud":"unix-oidc","exp":1705500000,"iat":1705400000,"acr":"urn:example:acr:mfa","auth_time":1705400000,"jti":"test-token-id"}"#;

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        format!("{}.{}.fake-signature", header_b64, payload_b64)
    }
}
