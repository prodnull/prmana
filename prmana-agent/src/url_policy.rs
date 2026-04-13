//! Endpoint URL validation for agent network calls.
//!
//! Production endpoints must use HTTPS. Plain HTTP is accepted only for
//! loopback development/testing endpoints such as local wiremock servers.

use std::net::IpAddr;

use prmana_core::oidc::jwks::OidcDiscovery;
use reqwest::Url;

/// Validate that an endpoint URL uses HTTPS, or loopback HTTP for local testing.
pub fn validate_endpoint_url(url: &str, field_name: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|e| format!("{field_name} is not a valid URL: {e}"))?;

    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(&parsed) => Ok(()),
        "http" => Err(format!(
            "{field_name} must use https:// or loopback http://, got {url}"
        )),
        other => Err(format!(
            "{field_name} must use https:// or loopback http://, got scheme {other}"
        )),
    }
}

/// Validate the endpoints contained in an OIDC discovery document.
pub fn validate_oidc_discovery(discovery: &OidcDiscovery) -> Result<(), String> {
    validate_endpoint_url(&discovery.issuer, "issuer")?;
    validate_endpoint_url(&discovery.jwks_uri, "jwks_uri")?;
    validate_endpoint_url(&discovery.token_endpoint, "token_endpoint")?;

    if let Some(endpoint) = discovery.authorization_endpoint.as_deref() {
        validate_endpoint_url(endpoint, "authorization_endpoint")?;
    }
    if let Some(endpoint) = discovery.device_authorization_endpoint.as_deref() {
        validate_endpoint_url(endpoint, "device_authorization_endpoint")?;
    }
    if let Some(endpoint) = discovery.backchannel_authentication_endpoint.as_deref() {
        validate_endpoint_url(endpoint, "backchannel_authentication_endpoint")?;
    }
    if let Some(endpoint) = discovery.revocation_endpoint.as_deref() {
        validate_endpoint_url(endpoint, "revocation_endpoint")?;
    }

    Ok(())
}

/// Validate the endpoint fields in a raw OIDC discovery JSON document.
pub fn validate_discovery_document(document: &serde_json::Value) -> Result<(), String> {
    for field in [
        "issuer",
        "jwks_uri",
        "token_endpoint",
        "authorization_endpoint",
        "device_authorization_endpoint",
        "backchannel_authentication_endpoint",
        "revocation_endpoint",
    ] {
        if let Some(url) = document.get(field).and_then(|value| value.as_str()) {
            validate_endpoint_url(url, field)?;
        }
    }

    Ok(())
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_endpoint_url_accepts_https() {
        assert!(validate_endpoint_url("https://idp.example.com/token", "token_endpoint").is_ok());
    }

    #[test]
    fn test_validate_endpoint_url_accepts_loopback_http() {
        assert!(validate_endpoint_url("http://127.0.0.1:8080/token", "token_endpoint").is_ok());
        assert!(validate_endpoint_url("http://localhost:8080/token", "token_endpoint").is_ok());
    }

    #[test]
    fn test_validate_endpoint_url_rejects_non_loopback_http() {
        let err =
            validate_endpoint_url("http://idp.example.com/token", "token_endpoint").unwrap_err();
        assert!(err.contains("https://"));
    }

    #[test]
    fn test_validate_discovery_document_rejects_insecure_endpoint() {
        let document = serde_json::json!({
            "issuer": "https://idp.example.com",
            "jwks_uri": "https://idp.example.com/jwks",
            "token_endpoint": "http://idp.example.com/token"
        });

        let err = validate_discovery_document(&document).unwrap_err();
        assert!(err.contains("token_endpoint"));
    }
}
