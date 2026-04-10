//! OAuth 2.0 Authorization Code + PKCE flow helpers.
//!
//! This module implements RFC 7636 PKCE, a localhost callback receiver for the
//! redirect, and the code exchange request with DPoP binding.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use reqwest::Url;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::crypto::DPoPSigner;

/// Default timeout for the localhost callback receiver.
pub const CALLBACK_TIMEOUT_SECS: u64 = 120;

const SUCCESS_HTML: &str = concat!(
    "<!doctype html><html><head><meta charset=\"utf-8\">",
    "<title>unix-oidc-agent</title></head><body>",
    "<h1>Authentication complete</h1>",
    "<p>You can return to the terminal.</p>",
    "</body></html>"
);

const ERROR_HTML: &str = concat!(
    "<!doctype html><html><head><meta charset=\"utf-8\">",
    "<title>unix-oidc-agent</title></head><body>",
    "<h1>Authentication failed</h1>",
    "<p>The callback was rejected. Return to the terminal for details.</p>",
    "</body></html>"
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackResult {
    pub code: String,
    pub state: String,
}

pub struct CallbackListener {
    redirect_uri: String,
    receiver: oneshot::Receiver<anyhow::Result<CallbackResult>>,
}

impl CallbackListener {
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub async fn wait(self, timeout: Duration) -> anyhow::Result<CallbackResult> {
        tokio::time::timeout(timeout, self.receiver)
            .await
            .map_err(|_| anyhow!("Timed out waiting for authorization callback"))?
            .map_err(|_| anyhow!("Callback listener stopped unexpectedly"))?
    }
}

#[derive(Debug, Clone)]
pub struct TokenExchangeRequest<'a> {
    pub token_endpoint: &'a str,
    pub code: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: &'a str,
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
}

/// Generate an RFC 7636 PKCE verifier/challenge pair using the S256 method.
pub fn generate_pkce() -> (String, String) {
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let verifier = URL_SAFE_NO_PAD.encode(random);
    let challenge = compute_pkce_challenge(&verifier);
    (verifier, challenge)
}

fn compute_pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Build the authorization URL for the auth-code flow with PKCE.
pub fn build_authorization_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: &str,
    code_challenge: &str,
) -> anyhow::Result<Url> {
    let mut url = Url::parse(authorization_endpoint)
        .with_context(|| format!("Invalid authorization endpoint: {authorization_endpoint}"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", scope)
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url)
}

/// Start a localhost callback listener on a random port.
pub async fn start_callback_listener(expected_state: &str) -> anyhow::Result<CallbackListener> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("Failed to bind localhost callback listener")?;
    let redirect_uri = format!("http://{}/callback", listener.local_addr()?);
    let expected_state = expected_state.to_string();
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let result = async {
            let (mut stream, _) = listener.accept().await?;
            let request = read_http_request(&mut stream).await?;
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .ok_or_else(|| anyhow!("Malformed callback request"))?;

            let url = Url::parse(&format!("http://localhost{path}"))
                .context("Failed to parse callback URL")?;
            let query: HashMap<String, String> = url.query_pairs().into_owned().collect();

            let response = match (query.get("code"), query.get("state")) {
                (Some(code), Some(state)) if state == &expected_state => {
                    write_http_response(&mut stream, "200 OK", SUCCESS_HTML).await?;
                    Ok(CallbackResult {
                        code: code.clone(),
                        state: state.clone(),
                    })
                }
                (_, Some(_)) => {
                    write_http_response(&mut stream, "400 Bad Request", ERROR_HTML).await?;
                    Err(anyhow!("Callback state mismatch"))
                }
                _ => {
                    write_http_response(&mut stream, "400 Bad Request", ERROR_HTML).await?;
                    Err(anyhow!("Missing code or state in callback"))
                }
            }?;

            Ok::<CallbackResult, anyhow::Error>(response)
        }
        .await;

        let _ = tx.send(result);
    });

    Ok(CallbackListener {
        redirect_uri,
        receiver: rx,
    })
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> anyhow::Result<String> {
    use tokio::io::AsyncReadExt;

    let mut buffer = [0u8; 4096];
    let bytes_read = stream
        .read(&mut buffer)
        .await
        .context("Failed to read callback request")?;
    if bytes_read == 0 {
        return Err(anyhow!("Empty callback request"));
    }
    Ok(String::from_utf8_lossy(&buffer[..bytes_read]).into_owned())
}

async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    body: &str,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("Failed to write callback response")
}

/// Exchange the authorization code for tokens with DPoP binding.
pub async fn exchange_code(
    client: &reqwest::Client,
    signer: &dyn DPoPSigner,
    request: TokenExchangeRequest<'_>,
) -> anyhow::Result<Value> {
    let dpop_proof = signer
        .sign_proof("POST", request.token_endpoint, None)
        .map_err(|e| anyhow!("Failed to generate DPoP proof for code exchange: {e}"))?;

    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", request.code),
        ("redirect_uri", request.redirect_uri),
        ("code_verifier", request.code_verifier),
        ("client_id", request.client_id),
    ];

    if let Some(secret) = request.client_secret {
        params.push(("client_secret", secret));
    }

    let response = client
        .post(request.token_endpoint)
        .header("DPoP", dpop_proof)
        .form(&params)
        .send()
        .await
        .context("Authorization code exchange request failed")?;

    if response.status().is_success() {
        response
            .json()
            .await
            .context("Failed to parse code exchange response")
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(anyhow!(
            "Authorization code exchange failed: {status} {body}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SoftwareSigner;
    use std::io::Write;
    use std::net::TcpStream;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_generate_pkce_verifier_length_and_charset() {
        let (verifier, _) = generate_pkce();
        assert!((43..=128).contains(&verifier.len()));
        assert!(verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_code_challenge_matches_sha256_of_verifier() {
        let (verifier, challenge) = generate_pkce();
        assert_eq!(challenge, compute_pkce_challenge(&verifier));
    }

    #[test]
    fn test_build_authorization_url_includes_required_params() {
        let url = build_authorization_url(
            "https://idp.example.com/authorize",
            "unix-oidc",
            "http://127.0.0.1:8080/callback",
            "openid profile",
            "state123",
            "challenge123",
        )
        .unwrap();

        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("unix-oidc")
        );
        assert_eq!(
            params.get("redirect_uri").map(String::as_str),
            Some("http://127.0.0.1:8080/callback")
        );
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid profile")
        );
        assert_eq!(params.get("state").map(String::as_str), Some("state123"));
        assert_eq!(
            params.get("code_challenge").map(String::as_str),
            Some("challenge123")
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
    }

    #[tokio::test]
    async fn test_state_mismatch_on_callback_is_rejected() {
        let listener = start_callback_listener("expected-state").await.unwrap();
        let port = Url::parse(listener.redirect_uri()).unwrap().port().unwrap();

        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            stream,
            "GET /callback?code=abc&state=wrong-state HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();

        let err = listener.wait(Duration::from_secs(2)).await.unwrap_err();
        assert!(err.to_string().contains("state mismatch"));
    }

    #[tokio::test]
    async fn test_callback_listener_times_out_without_request() {
        let listener = start_callback_listener("state").await.unwrap();
        let err = listener.wait(Duration::from_millis(50)).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("Timed out waiting for authorization callback"));
    }

    #[tokio::test]
    async fn test_code_exchange_posts_required_form_and_dpop_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header_exists("DPoP"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "abc",
                "expires_in": 3600,
                "refresh_token": "refresh",
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let signer = SoftwareSigner::generate();
        let response = exchange_code(
            &client,
            &signer,
            TokenExchangeRequest {
                token_endpoint: &format!("{}/token", server.uri()),
                code: "code123",
                redirect_uri: "http://127.0.0.1:1234/callback",
                code_verifier: "verifier123",
                client_id: "unix-oidc",
                client_secret: Some("secret123"),
            },
        )
        .await
        .unwrap();

        assert_eq!(response["access_token"], "abc");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let body = std::str::from_utf8(&requests[0].body).unwrap();
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=code123"));
        assert!(body.contains("code_verifier=verifier123"));
        assert!(body.contains("client_id=unix-oidc"));
        assert!(requests[0].headers.contains_key("DPoP"));
    }

    #[tokio::test]
    async fn test_dpop_header_present_in_exchange_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "abc",
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let signer = SoftwareSigner::generate();
        exchange_code(
            &client,
            &signer,
            TokenExchangeRequest {
                token_endpoint: &format!("{}/token", server.uri()),
                code: "code123",
                redirect_uri: "http://127.0.0.1:1234/callback",
                code_verifier: "verifier123",
                client_id: "unix-oidc",
                client_secret: None,
            },
        )
        .await
        .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert!(requests[0].headers.contains_key("DPoP"));
    }
}
