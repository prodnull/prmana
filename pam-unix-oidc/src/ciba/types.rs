// CIBA (Client-Initiated Backchannel Authentication) types.
//
// RFC reference: OpenID Connect CIBA Core 1.0 Final
// ACR constants: OpenID EAP ACR Values 1.0 Final

use serde::Deserialize;
use thiserror::Error;

/// ACR value for phishing-resistant authentication (e.g. FIDO2 security key without hardware binding).
/// Source: OpenID EAP ACR Values 1.0 Final, §2.1
pub const ACR_PHR: &str = "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant";

/// ACR value for phishing-resistant hardware-bound authentication (e.g. FIDO2 with resident key/TPM).
/// Source: OpenID EAP ACR Values 1.0 Final, §2.2
pub const ACR_PHRH: &str = "http://schemas.openid.net/acr/2016/07/phishing-resistant-hardware";

/// CIBA grant type URN per CIBA Core 1.0 §10.1.
///
/// Note: The URN uses `openid:params` not `ietf:params` — this is intentional.
pub const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";

/// Errors that can occur during CIBA backchannel authentication.
///
/// Variants map to CIBA Core 1.0 §11 error codes where applicable.
#[derive(Debug, Error)]
pub enum CibaError {
    /// IdP is processing the request; poll again after `interval` seconds (CIBA §11).
    #[error("Authorization pending")]
    AuthorizationPending,

    /// Poll interval exceeded; slow down (CIBA §11).
    #[error("Too many poll requests — slow down")]
    SlowDown,

    /// User denied or authentication failed at the authenticator (CIBA §11).
    #[error("Access denied by user or authenticator")]
    AccessDenied,

    /// The `auth_req_id` has expired before the user completed authentication (CIBA §11).
    #[error("Backchannel authentication request expired")]
    ExpiredToken,

    /// Local timeout waiting for the user to authenticate (not a protocol error).
    #[error("Timed out waiting for backchannel authentication")]
    Timeout,

    /// Required ACR claim is absent from the returned token.
    #[error("ACR claim absent; required: {required}")]
    AcrMissing { required: String },

    /// ACR claim present but insufficient for the required level.
    #[error("ACR insufficient; required: {required}, got: {got}")]
    AcrInsufficient { required: String, got: String },

    /// IdP does not advertise "poll" in `backchannel_token_delivery_modes_supported`.
    #[error("CIBA poll delivery mode not supported by IdP")]
    DeliveryModeNotSupported,

    /// OIDC discovery has no `backchannel_authentication_endpoint`.
    #[error("IdP does not support CIBA (no backchannel_authentication_endpoint in discovery)")]
    NoCibaEndpoint,

    /// Unexpected protocol-level error (e.g. unknown error code from IdP).
    #[error("CIBA protocol error: {0}")]
    Protocol(String),

    /// Network / HTTP transport error.
    #[error("CIBA network error: {0}")]
    Network(String),
}

/// Response from the backchannel authentication endpoint (CIBA Core 1.0 §7.3).
#[derive(Debug, Deserialize)]
pub struct BackchannelAuthResponse {
    /// Opaque token used to poll for the final grant.
    pub auth_req_id: String,
    /// Seconds until the `auth_req_id` expires.
    pub expires_in: u64,
    /// Minimum seconds between token poll attempts. Defaults to 5 if absent.
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    5
}

/// Successful token response from the token endpoint when using the CIBA grant.
///
/// Fields per RFC 6749 §5.1 and CIBA Core 1.0 §10.2.
#[derive(Debug, Deserialize)]
pub struct CibaTokenResponse {
    pub access_token: String,
    /// May be absent if the server did not issue an ID token.
    pub id_token: Option<String>,
    pub token_type: String,
    pub expires_in: Option<u64>,
}

/// Error body returned by the token endpoint during CIBA polling (CIBA Core 1.0 §11).
#[derive(Debug, Deserialize)]
pub struct CibaTokenErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

// ─── ACR helpers ─────────────────────────────────────────────────────────────

/// Return `true` when `got` satisfies the `required` ACR level.
///
/// Satisfaction rules:
/// - Exact match always satisfies.
/// - `ACR_PHRH` (hardware-bound) satisfies `ACR_PHR` (phishing-resistant) because
///   hardware attestation is a strict superset of phishing resistance.
/// - `ACR_PHR` does NOT satisfy `ACR_PHRH` — the hardware property cannot be inferred.
/// - Unknown URIs: only exact match satisfies (no implied hierarchy).
///
/// Source: OpenID EAP ACR Values 1.0 Final, Appendix A.
pub fn satisfies_acr(required: &str, got: &str) -> bool {
    if required == got {
        return true;
    }
    // Hardware-bound (phrh) is a strict superset of phishing-resistant (phr).
    if required == ACR_PHR && got == ACR_PHRH {
        return true;
    }
    false
}

/// Validate that `actual` satisfies `required`, returning a hard-fail [`CibaError`] otherwise.
///
/// This is a security invariant: ACR validation is never configurable or warn-only.
/// An absent or insufficient ACR when FIDO2 is required is a gate that must not be bypassed.
pub fn validate_acr(required: &str, actual: Option<&str>) -> Result<(), CibaError> {
    match actual {
        None => Err(CibaError::AcrMissing {
            required: required.to_string(),
        }),
        Some(got) if satisfies_acr(required, got) => Ok(()),
        Some(got) => Err(CibaError::AcrInsufficient {
            required: required.to_string(),
            got: got.to_string(),
        }),
    }
}

/// Map a CIBA error string (from the token endpoint `error` field) to a typed [`CibaError`].
///
/// Error codes per CIBA Core 1.0 §11.
pub fn parse_ciba_error(error: &str) -> CibaError {
    match error {
        "authorization_pending" => CibaError::AuthorizationPending,
        "slow_down" => CibaError::SlowDown,
        "access_denied" => CibaError::AccessDenied,
        "expired_token" => CibaError::ExpiredToken,
        other => CibaError::Protocol(other.to_string()),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ACR constants ──────────────────────────────────────────────────────

    #[test]
    fn acr_constants_have_correct_uris() {
        assert_eq!(
            ACR_PHR,
            "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant"
        );
        assert_eq!(
            ACR_PHRH,
            "http://schemas.openid.net/acr/2016/07/phishing-resistant-hardware"
        );
    }

    #[test]
    fn ciba_grant_type_uses_openid_not_ietf_urn() {
        assert_eq!(CIBA_GRANT_TYPE, "urn:openid:params:grant-type:ciba");
        assert!(!CIBA_GRANT_TYPE.contains("ietf:params"));
    }

    // ── satisfies_acr ─────────────────────────────────────────────────────

    #[test]
    fn satisfies_acr_exact_match_returns_true() {
        assert!(satisfies_acr(ACR_PHR, ACR_PHR));
        assert!(satisfies_acr(ACR_PHRH, ACR_PHRH));
    }

    #[test]
    fn satisfies_acr_hardware_satisfies_phishing_resistant() {
        // phrh is a strict superset of phr
        assert!(satisfies_acr(ACR_PHR, ACR_PHRH));
    }

    #[test]
    fn satisfies_acr_phishing_resistant_does_not_satisfy_hardware() {
        // phr does NOT satisfy phrh — the hardware property cannot be inferred
        assert!(!satisfies_acr(ACR_PHRH, ACR_PHR));
    }

    #[test]
    fn satisfies_acr_unknown_uri_requires_exact_match() {
        assert!(satisfies_acr(
            "urn:example:acr:high",
            "urn:example:acr:high"
        ));
        assert!(!satisfies_acr(
            "urn:example:acr:high",
            "urn:example:acr:medium"
        ));
    }

    // ── validate_acr ──────────────────────────────────────────────────────

    #[test]
    fn validate_acr_none_returns_acr_missing() {
        let err = validate_acr(ACR_PHR, None).unwrap_err();
        assert!(matches!(err, CibaError::AcrMissing { required } if required == ACR_PHR));
    }

    #[test]
    fn validate_acr_exact_match_returns_ok() {
        assert!(validate_acr(ACR_PHR, Some(ACR_PHR)).is_ok());
    }

    #[test]
    fn validate_acr_hardware_satisfies_phr_required() {
        assert!(validate_acr(ACR_PHR, Some(ACR_PHRH)).is_ok());
    }

    #[test]
    fn validate_acr_phr_does_not_satisfy_phrh_required() {
        let err = validate_acr(ACR_PHRH, Some(ACR_PHR)).unwrap_err();
        assert!(matches!(err, CibaError::AcrInsufficient { .. }));
    }

    // ── parse_ciba_error ──────────────────────────────────────────────────

    #[test]
    fn parse_ciba_error_authorization_pending() {
        assert!(matches!(
            parse_ciba_error("authorization_pending"),
            CibaError::AuthorizationPending
        ));
    }

    #[test]
    fn parse_ciba_error_slow_down() {
        assert!(matches!(parse_ciba_error("slow_down"), CibaError::SlowDown));
    }

    #[test]
    fn parse_ciba_error_access_denied() {
        assert!(matches!(
            parse_ciba_error("access_denied"),
            CibaError::AccessDenied
        ));
    }

    #[test]
    fn parse_ciba_error_expired_token() {
        assert!(matches!(
            parse_ciba_error("expired_token"),
            CibaError::ExpiredToken
        ));
    }

    #[test]
    fn parse_ciba_error_unknown_maps_to_protocol() {
        let err = parse_ciba_error("invalid_grant");
        assert!(matches!(err, CibaError::Protocol(s) if s == "invalid_grant"));
    }

    // ── BackchannelAuthResponse deserialization ────────────────────────────

    #[test]
    fn backchannel_auth_response_deserializes() {
        let json = r#"{"auth_req_id":"abc123","expires_in":120,"interval":3}"#;
        let r: BackchannelAuthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.auth_req_id, "abc123");
        assert_eq!(r.expires_in, 120);
        assert_eq!(r.interval, 3);
    }

    #[test]
    fn backchannel_auth_response_interval_defaults_to_5() {
        let json = r#"{"auth_req_id":"abc123","expires_in":120}"#;
        let r: BackchannelAuthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.interval, 5);
    }

    // ── CibaTokenResponse deserialization ─────────────────────────────────

    #[test]
    fn ciba_token_response_with_id_token() {
        let json =
            r#"{"access_token":"at","id_token":"it","token_type":"Bearer","expires_in":3600}"#;
        let r: CibaTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.access_token, "at");
        assert_eq!(r.id_token, Some("it".to_string()));
        assert_eq!(r.expires_in, Some(3600));
    }

    #[test]
    fn ciba_token_response_without_id_token() {
        let json = r#"{"access_token":"at","token_type":"Bearer"}"#;
        let r: CibaTokenResponse = serde_json::from_str(json).unwrap();
        assert!(r.id_token.is_none());
        assert!(r.expires_in.is_none());
    }
}
