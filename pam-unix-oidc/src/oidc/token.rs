//! JWT token parsing and claims extraction.

use std::collections::HashMap;

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

    /// All remaining claims not matched by the fields above.
    ///
    /// Used by [`UsernameMapper`] to access custom claims (e.g. `email`,
    /// `groups`, or IdP-specific attributes) without enumerating every possible
    /// field in the struct.  Serde flatten is transparent — the extra map only
    /// captures keys that are NOT already matched by the named fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
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
    /// Extract a claim as a `String` regardless of where it lives in the struct.
    ///
    /// Checks the known typed fields first (sub, preferred_username, iss, acr, jti),
    /// then falls back to the `extra` map for arbitrary/custom claims (e.g. `email`,
    /// `groups`, or IdP-specific attributes).
    ///
    /// Returns `None` if the claim is absent or not representable as a string.
    pub fn get_claim_str(&self, claim: &str) -> Option<String> {
        match claim {
            "sub" => Some(self.sub.clone()),
            "preferred_username" => Some(self.preferred_username.clone()),
            "iss" => Some(self.iss.clone()),
            "acr" => self.acr.clone(),
            "jti" => self.jti.clone(),
            other => {
                // Fall through to the extra HashMap for any other claim name.
                self.extra.get(other).and_then(|v| match v {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    serde_json::Value::Bool(b) => Some(b.to_string()),
                    _ => None,
                })
            }
        }
    }

    /// Extract the `groups` claim as a `Vec<String>` for audit enrichment.
    ///
    /// Returns `None` if the `groups` claim is absent or is not an array of strings.
    /// Non-string array elements are silently skipped.
    ///
    /// This is intentionally lenient — the groups claim is used for audit logging
    /// only, never for access control decisions (which use NSS group resolution).
    pub fn groups_for_audit(&self) -> Option<Vec<String>> {
        self.extra.get("groups").and_then(|v| match v {
            serde_json::Value::Array(arr) => {
                let groups: Vec<String> = arr
                    .iter()
                    .filter_map(|item| item.as_str().map(String::from))
                    .collect();
                if groups.is_empty() {
                    None
                } else {
                    Some(groups)
                }
            }
            _ => None,
        })
    }

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

    fn create_test_token_with_extra() -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        // Includes custom claims: email and groups
        let payload = r#"{"sub":"testuser","preferred_username":"testuser","iss":"http://localhost:8080/realms/test","aud":"unix-oidc","exp":1705500000,"iat":1705400000,"email":"testuser@corp.com","groups":["unix-users","developers"]}"#;

        let header_b64 = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        format!("{}.{}.fake-signature", header_b64, payload_b64)
    }

    // ── Phase 8: get_claim_str and groups_for_audit tests ───────────────────

    #[test]
    fn test_get_claim_str_typed_fields() {
        let token = create_test_token();
        let claims = TokenClaims::from_token(&token).unwrap();

        assert_eq!(claims.get_claim_str("sub"), Some("testuser".to_string()));
        assert_eq!(
            claims.get_claim_str("preferred_username"),
            Some("testuser".to_string())
        );
        assert_eq!(
            claims.get_claim_str("iss"),
            Some("http://localhost:8080/realms/test".to_string())
        );
        assert_eq!(
            claims.get_claim_str("acr"),
            Some("urn:example:acr:mfa".to_string())
        );
        assert_eq!(
            claims.get_claim_str("jti"),
            Some("test-token-id".to_string())
        );
    }

    #[test]
    fn test_get_claim_str_from_extra_map() {
        let token = create_test_token_with_extra();
        let claims = TokenClaims::from_token(&token).unwrap();

        assert_eq!(
            claims.get_claim_str("email"),
            Some("testuser@corp.com".to_string())
        );
    }

    #[test]
    fn test_get_claim_str_missing_returns_none() {
        let token = create_test_token();
        let claims = TokenClaims::from_token(&token).unwrap();

        assert_eq!(claims.get_claim_str("nonexistent_claim"), None);
    }

    #[test]
    fn test_groups_for_audit_returns_groups_array() {
        let token = create_test_token_with_extra();
        let claims = TokenClaims::from_token(&token).unwrap();

        let groups = claims.groups_for_audit();
        assert!(groups.is_some());
        let groups = groups.unwrap();
        assert_eq!(groups, vec!["unix-users", "developers"]);
    }

    #[test]
    fn test_groups_for_audit_absent_returns_none() {
        let token = create_test_token(); // no groups claim
        let claims = TokenClaims::from_token(&token).unwrap();

        assert!(claims.groups_for_audit().is_none());
    }

    #[test]
    fn test_extra_flatten_is_transparent_for_existing_tests() {
        // Verify that adding #[serde(flatten)] extra didn't break existing claim parsing.
        let token = create_test_token();
        let claims = TokenClaims::from_token(&token).unwrap();

        assert_eq!(claims.preferred_username, "testuser");
        assert_eq!(claims.sub, "testuser");
        assert_eq!(claims.iss, "http://localhost:8080/realms/test");
    }
}
