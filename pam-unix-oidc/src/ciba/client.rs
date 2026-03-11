// CibaClient — builds CIBA backchannel authentication request parameters.
//
// This is a parameter-builder only; HTTP execution is the agent daemon's responsibility.
// This keeps the PAM crate free of async I/O for CIBA.

use crate::oidc::jwks::OidcDiscovery;

use super::types::{CibaError, CIBA_GRANT_TYPE};

/// Client that constructs CIBA backchannel authentication and token poll parameters
/// from a discovered OIDC metadata document.
#[derive(Debug)]
pub struct CibaClient {
    backchannel_endpoint: String,
    token_endpoint: String,
    client_id: String,
    client_secret: Option<String>,
}

impl CibaClient {
    /// Create a new `CibaClient` from OIDC discovery metadata.
    ///
    /// Returns `CibaError::NoCibaEndpoint` if the discovery document does not
    /// advertise `backchannel_authentication_endpoint`.
    ///
    /// Returns `CibaError::DeliveryModeNotSupported` if the IdP explicitly lists
    /// `backchannel_token_delivery_modes_supported` but does not include `"poll"`.
    /// If the field is absent, poll mode is assumed supported (some IdPs omit it
    /// when poll is the only mode available).
    pub fn new(
        discovery: &OidcDiscovery,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<Self, CibaError> {
        let backchannel_endpoint = discovery
            .backchannel_authentication_endpoint
            .clone()
            .ok_or(CibaError::NoCibaEndpoint)?;

        // If the IdP declares delivery modes, verify poll is in the list.
        // If the field is absent, we optimistically assume poll is available.
        if let Some(modes) = &discovery.backchannel_token_delivery_modes_supported {
            if !modes.iter().any(|m| m == "poll") {
                return Err(CibaError::DeliveryModeNotSupported);
            }
        }

        Ok(Self {
            backchannel_endpoint,
            token_endpoint: discovery.token_endpoint.clone(),
            client_id: client_id.to_string(),
            client_secret: client_secret.map(str::to_string),
        })
    }

    /// Build URL-encoded form parameters for the backchannel authentication request.
    ///
    /// Per CIBA Core 1.0 §7.1. Parameters are returned as `(&'static str, &str)` tuples
    /// suitable for use with `reqwest::RequestBuilder::form()`.
    pub fn build_backchannel_auth_params<'a>(
        &'a self,
        login_hint: &'a str,
        binding_message: &'a str,
        acr_values: Option<&'a str>,
    ) -> Vec<(&'static str, &'a str)> {
        let mut params: Vec<(&'static str, &'a str)> = vec![
            ("client_id", &self.client_id),
            ("scope", "openid"),
            ("login_hint", login_hint),
            ("binding_message", binding_message),
        ];
        if let Some(secret) = &self.client_secret {
            params.push(("client_secret", secret.as_str()));
        }
        if let Some(acr) = acr_values {
            params.push(("acr_values", acr));
        }
        params
    }

    /// Build URL-encoded form parameters for the token poll request.
    ///
    /// Per CIBA Core 1.0 §10.1. Uses the `urn:openid:params:grant-type:ciba` grant type.
    pub fn build_ciba_token_params<'a>(
        &'a self,
        auth_req_id: &'a str,
    ) -> Vec<(&'static str, &'a str)> {
        let mut params: Vec<(&'static str, &'a str)> = vec![
            ("grant_type", CIBA_GRANT_TYPE),
            ("client_id", &self.client_id),
            ("auth_req_id", auth_req_id),
        ];
        if let Some(secret) = &self.client_secret {
            params.push(("client_secret", secret.as_str()));
        }
        params
    }

    /// Return the backchannel authentication endpoint URL.
    pub fn backchannel_endpoint(&self) -> &str {
        &self.backchannel_endpoint
    }

    /// Return the token endpoint URL.
    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }
}

/// Build a user-friendly binding message from a command and hostname.
///
/// Security: command arguments are stripped — they may contain sensitive paths or data.
/// The message is capped at 64 characters per CIBA spec guidance for authenticator UIs.
///
/// Examples:
/// - `("cat /etc/shadow", "server-01")` → `"sudo cat on server-01"`
/// - `("/usr/bin/systemctl restart nginx", "prod-web-01")` → `"sudo systemctl on prod-web-01"`
pub fn build_binding_message(command: &str, hostname: &str) -> String {
    // Extract the first whitespace-delimited token (the executable path or name).
    let exe_path = command.split_whitespace().next().unwrap_or("");
    // Take only the last path component (basename).
    let exe_name = exe_path.split('/').next_back().unwrap_or("unknown");
    let exe_name = if exe_name.is_empty() { "unknown" } else { exe_name };

    let msg = format!("sudo {} on {}", exe_name, hostname);

    // Truncate to 64 characters (CIBA spec recommends short binding_message for
    // authenticator UI display; see CIBA Core 1.0 §7.1 binding_message guidance).
    if msg.len() <= 64 {
        msg
    } else {
        msg[..64].to_string()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::jwks::OidcDiscovery;

    fn make_discovery(
        backchannel: Option<&str>,
        modes: Option<Vec<&str>>,
    ) -> OidcDiscovery {
        OidcDiscovery {
            jwks_uri: "https://idp.example.com/jwks".to_string(),
            issuer: "https://idp.example.com".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            device_authorization_endpoint: None,
            backchannel_authentication_endpoint: backchannel.map(str::to_string),
            backchannel_token_delivery_modes_supported: modes
                .map(|v| v.into_iter().map(str::to_string).collect()),
            revocation_endpoint: None,
        }
    }

    // ── CibaClient::new ───────────────────────────────────────────────────

    #[test]
    fn new_returns_error_when_no_backchannel_endpoint() {
        let d = make_discovery(None, None);
        let err = CibaClient::new(&d, "my-client", None).unwrap_err();
        assert!(matches!(err, CibaError::NoCibaEndpoint));
    }

    #[test]
    fn new_returns_error_when_poll_not_in_modes() {
        let d = make_discovery(
            Some("https://idp.example.com/bc-authn"),
            Some(vec!["push", "ping"]),
        );
        let err = CibaClient::new(&d, "my-client", None).unwrap_err();
        assert!(matches!(err, CibaError::DeliveryModeNotSupported));
    }

    #[test]
    fn new_succeeds_when_poll_in_modes() {
        let d = make_discovery(
            Some("https://idp.example.com/bc-authn"),
            Some(vec!["poll"]),
        );
        assert!(CibaClient::new(&d, "my-client", None).is_ok());
    }

    #[test]
    fn new_succeeds_when_modes_absent() {
        // Some IdPs omit the field when poll is the only mode; we assume poll is available.
        let d = make_discovery(Some("https://idp.example.com/bc-authn"), None);
        assert!(CibaClient::new(&d, "my-client", None).is_ok());
    }

    // ── build_backchannel_auth_params ──────────────────────────────────────

    #[test]
    fn backchannel_auth_params_includes_required_fields() {
        let d = make_discovery(Some("https://idp.example.com/bc-authn"), None);
        let client = CibaClient::new(&d, "my-client", None).unwrap();
        let params = client.build_backchannel_auth_params("alice", "sudo cat on srv", None);

        let keys: Vec<&str> = params.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"client_id"));
        assert!(keys.contains(&"scope"));
        assert!(keys.contains(&"login_hint"));
        assert!(keys.contains(&"binding_message"));
    }

    #[test]
    fn backchannel_auth_params_includes_acr_values_when_some() {
        let d = make_discovery(Some("https://idp.example.com/bc-authn"), None);
        let client = CibaClient::new(&d, "my-client", None).unwrap();
        let params =
            client.build_backchannel_auth_params("alice", "sudo cat on srv", Some("phr"));

        let acr = params.iter().find(|(k, _)| *k == "acr_values").map(|(_, v)| *v);
        assert_eq!(acr, Some("phr"));
    }

    #[test]
    fn backchannel_auth_params_omits_acr_values_when_none() {
        let d = make_discovery(Some("https://idp.example.com/bc-authn"), None);
        let client = CibaClient::new(&d, "my-client", None).unwrap();
        let params = client.build_backchannel_auth_params("alice", "sudo cat on srv", None);

        assert!(!params.iter().any(|(k, _)| *k == "acr_values"));
    }

    #[test]
    fn backchannel_auth_params_includes_client_secret_when_set() {
        let d = make_discovery(Some("https://idp.example.com/bc-authn"), None);
        let client = CibaClient::new(&d, "my-client", Some("s3cr3t")).unwrap();
        let params = client.build_backchannel_auth_params("alice", "sudo cat on srv", None);

        let secret = params
            .iter()
            .find(|(k, _)| *k == "client_secret")
            .map(|(_, v)| *v);
        assert_eq!(secret, Some("s3cr3t"));
    }

    // ── build_ciba_token_params ────────────────────────────────────────────

    #[test]
    fn ciba_token_params_uses_correct_grant_type() {
        let d = make_discovery(Some("https://idp.example.com/bc-authn"), None);
        let client = CibaClient::new(&d, "my-client", None).unwrap();
        let params = client.build_ciba_token_params("req-id-abc");

        let gt = params
            .iter()
            .find(|(k, _)| *k == "grant_type")
            .map(|(_, v)| *v);
        assert_eq!(gt, Some(CIBA_GRANT_TYPE));
        assert_eq!(gt, Some("urn:openid:params:grant-type:ciba"));
    }

    #[test]
    fn ciba_token_params_includes_auth_req_id() {
        let d = make_discovery(Some("https://idp.example.com/bc-authn"), None);
        let client = CibaClient::new(&d, "my-client", None).unwrap();
        let params = client.build_ciba_token_params("req-id-xyz");

        let req_id = params
            .iter()
            .find(|(k, _)| *k == "auth_req_id")
            .map(|(_, v)| *v);
        assert_eq!(req_id, Some("req-id-xyz"));
    }

    // ── build_binding_message ─────────────────────────────────────────────

    #[test]
    fn binding_message_strips_args_keeps_basename() {
        assert_eq!(
            build_binding_message("cat /etc/shadow", "server-01"),
            "sudo cat on server-01"
        );
    }

    #[test]
    fn binding_message_strips_full_path_and_args() {
        assert_eq!(
            build_binding_message("/usr/bin/systemctl restart nginx", "prod-web-01"),
            "sudo systemctl on prod-web-01"
        );
    }

    #[test]
    fn binding_message_truncates_to_64_chars() {
        let long_host = "a".repeat(100);
        let msg = build_binding_message("ls", &long_host);
        assert_eq!(msg.len(), 64);
    }

    #[test]
    fn binding_message_does_not_truncate_short_message() {
        let msg = build_binding_message("cat", "srv");
        assert_eq!(msg, "sudo cat on srv");
        assert!(msg.len() <= 64);
    }
}
