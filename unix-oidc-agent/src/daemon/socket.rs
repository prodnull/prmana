//! Unix socket server and client

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::crypto::DPoPSigner;
use crate::daemon::protocol::{AgentRequest, AgentResponse, MetricsFormat};
use crate::metrics::MetricsCollector;
use crate::storage::{FileStorage, SecureStorage, KEY_ACCESS_TOKEN, KEY_TOKEN_METADATA};

#[cfg(test)]
use crate::daemon::protocol::AgentResponseData;

/// Agent state shared across connections
pub struct AgentState {
    pub signer: Option<Arc<dyn DPoPSigner>>,
    pub access_token: Option<String>,
    pub token_expires: Option<i64>,
    pub username: Option<String>,
    /// Metrics collector for observability
    pub metrics: Arc<MetricsCollector>,
}

impl AgentState {
    pub fn new() -> Self {
        Self {
            signer: None,
            access_token: None,
            token_expires: None,
            username: None,
            metrics: Arc::new(MetricsCollector::new()),
        }
    }

    pub fn is_logged_in(&self) -> bool {
        self.signer.is_some() && self.access_token.is_some()
    }
}

impl Default for AgentState {
    fn default() -> Self {
        Self::new()
    }
}

/// Unix socket server for the agent daemon
pub struct AgentServer {
    socket_path: PathBuf,
    state: Arc<RwLock<AgentState>>,
}

impl AgentServer {
    pub fn new(socket_path: PathBuf, state: Arc<RwLock<AgentState>>) -> Self {
        Self { socket_path, state }
    }

    /// Get the default socket path
    pub fn default_socket_path() -> PathBuf {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"));

        runtime_dir.join("unix-oidc-agent.sock")
    }

    /// Start the server and listen for connections
    pub async fn serve(&self) -> Result<(), std::io::Error> {
        // Remove existing socket if present
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        // Set socket permissions (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.socket_path, perms)?;
        }

        info!("Agent listening on {:?}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, state).await {
                            error!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }
}

async fn handle_connection(
    stream: UnixStream,
    state: Arc<RwLock<AgentState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Record connection metric
    {
        let state_read = state.read().await;
        state_read.metrics.record_connection();
    }

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let request: AgentRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                // Record error metric
                {
                    let state_read = state.read().await;
                    state_read.metrics.record_request(true);
                }
                let response =
                    AgentResponse::error(format!("Invalid request: {}", e), "INVALID_REQUEST");
                let response_json = serde_json::to_string(&response)? + "\n";
                writer.write_all(response_json.as_bytes()).await?;
                line.clear();
                continue;
            }
        };

        debug!("Received request: {:?}", request);

        let (response, is_error) = handle_request(request, &state).await;

        // Record request metric
        {
            let state_read = state.read().await;
            state_read.metrics.record_request(is_error);
        }

        let response_json = serde_json::to_string(&response)? + "\n";
        writer.write_all(response_json.as_bytes()).await?;

        line.clear();
    }

    Ok(())
}

/// Handle a request and return (response, is_error)
async fn handle_request(
    request: AgentRequest,
    state: &Arc<RwLock<AgentState>>,
) -> (AgentResponse, bool) {
    match request {
        AgentRequest::GetProof {
            target,
            method,
            nonce,
        } => {
            let start = Instant::now();
            let state_read = state.read().await;

            let signer = match &state_read.signer {
                Some(s) => s,
                None => {
                    state_read
                        .metrics
                        .record_proof_request(false, start.elapsed());
                    return (AgentResponse::error("Not logged in", "NOT_LOGGED_IN"), true);
                }
            };

            let token = match &state_read.access_token {
                Some(t) => t.clone(),
                None => {
                    state_read
                        .metrics
                        .record_proof_request(false, start.elapsed());
                    return (AgentResponse::error("No access token", "NO_TOKEN"), true);
                }
            };

            match signer.sign_proof(&method, &target, nonce.as_deref()) {
                Ok(proof) => {
                    let expires_in = state_read
                        .token_expires
                        .map(|exp| {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as i64;
                            (exp - now).max(0) as u64
                        })
                        .unwrap_or(0);

                    state_read
                        .metrics
                        .record_proof_request(true, start.elapsed());
                    (AgentResponse::proof(token, proof, expires_in), false)
                }
                Err(e) => {
                    state_read
                        .metrics
                        .record_proof_request(false, start.elapsed());
                    (AgentResponse::error(e.to_string(), "PROOF_ERROR"), true)
                }
            }
        }

        AgentRequest::Status => {
            let state_read = state.read().await;

            (
                AgentResponse::status(
                    state_read.is_logged_in(),
                    state_read.username.clone(),
                    state_read.signer.as_ref().map(|s| s.thumbprint()),
                    state_read.token_expires,
                ),
                false,
            )
        }

        AgentRequest::Metrics { format } => {
            let state_read = state.read().await;
            let snapshot = state_read.metrics.snapshot();

            let response = match format {
                MetricsFormat::Json => AgentResponse::metrics(snapshot),
                MetricsFormat::Prometheus => AgentResponse::metrics_text(snapshot.to_prometheus()),
            };

            (response, false)
        }

        AgentRequest::Refresh => {
            let start = Instant::now();

            // Perform token refresh using stored refresh token
            match perform_token_refresh(state).await {
                Ok((new_token, expires_at, username)) => {
                    // Update state with new token
                    let mut state_write = state.write().await;
                    state_write.access_token = Some(new_token);
                    state_write.token_expires = Some(expires_at);
                    if let Some(u) = username {
                        state_write.username = Some(u);
                    }

                    let expires_in = {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64;
                        (expires_at - now).max(0) as u64
                    };

                    state_write
                        .metrics
                        .record_token_refresh(true, start.elapsed());
                    (AgentResponse::refreshed(expires_in), false)
                }
                Err(e) => {
                    let state_read = state.read().await;
                    state_read
                        .metrics
                        .record_token_refresh(false, start.elapsed());
                    (AgentResponse::error(e.to_string(), "REFRESH_ERROR"), true)
                }
            }
        }

        AgentRequest::Shutdown => {
            info!("Shutdown requested");
            std::process::exit(0);
        }
    }
}

/// Client for connecting to the agent
pub struct AgentClient {
    socket_path: PathBuf,
}

impl Default for AgentClient {
    fn default() -> Self {
        Self::new(AgentServer::default_socket_path())
    }
}

impl AgentClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    pub async fn send(&self, request: AgentRequest) -> Result<AgentResponse, ClientError> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| ClientError::Connection(e.to_string()))?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        let request_json = serde_json::to_string(&request)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        writer
            .write_all(request_json.as_bytes())
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        writer
            .write_all(b"\n")
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;

        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;

        serde_json::from_str(&response_line).map_err(|e| ClientError::Serialization(e.to_string()))
    }

    pub async fn get_proof(
        &self,
        target: &str,
        method: &str,
        nonce: Option<&str>,
    ) -> Result<AgentResponse, ClientError> {
        self.send(AgentRequest::GetProof {
            target: target.to_string(),
            method: method.to_string(),
            nonce: nonce.map(String::from),
        })
        .await
    }

    pub async fn status(&self) -> Result<AgentResponse, ClientError> {
        self.send(AgentRequest::Status).await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("IO error: {0}")]
    Io(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Perform token refresh using stored refresh token
async fn perform_token_refresh(
    _state: &Arc<RwLock<AgentState>>,
) -> Result<(String, i64, Option<String>), Box<dyn std::error::Error + Send + Sync>> {
    // Load storage
    let storage = FileStorage::new().map_err(|e| format!("Storage error: {}", e))?;

    // Load token metadata
    let metadata_bytes = storage
        .retrieve(KEY_TOKEN_METADATA)
        .map_err(|_| "No token metadata found. Please login first.")?;

    let metadata: serde_json::Value = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| format!("Failed to parse token metadata: {}", e))?;

    // Get refresh token
    let refresh_token = metadata["refresh_token"]
        .as_str()
        .ok_or("No refresh token found. Please login again.")?
        .to_string();

    // Get OIDC config
    let token_endpoint = metadata["token_endpoint"]
        .as_str()
        .ok_or("No token endpoint found. Please login again.")?
        .to_string();

    let client_id = metadata["client_id"]
        .as_str()
        .ok_or("No client_id found. Please login again.")?
        .to_string();

    let client_secret = metadata["client_secret"].as_str().map(String::from);

    info!("Performing token refresh...");

    // Perform refresh in blocking task (reqwest::blocking)
    let result = tokio::task::spawn_blocking(move || {
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let mut params = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", client_id.as_str()),
        ];

        if let Some(ref secret) = client_secret {
            params.push(("client_secret", secret.as_str()));
        }

        let response = http_client
            .post(&token_endpoint)
            .form(&params)
            .send()
            .map_err(|e| format!("Token refresh request failed: {}", e))?;

        if response.status().is_success() {
            let token_response: serde_json::Value = response
                .json()
                .map_err(|e| format!("Failed to parse token response: {}", e))?;
            Ok(token_response)
        } else {
            let error: serde_json::Value = response
                .json()
                .unwrap_or_else(|_| serde_json::json!({"error": "unknown"}));
            let error_msg = error["error_description"]
                .as_str()
                .or(error["error"].as_str())
                .unwrap_or("Unknown error");
            Err(format!("Token refresh failed: {}", error_msg))
        }
    })
    .await
    .map_err(|e| format!("Task error: {}", e))??;

    // Extract new token information
    let access_token = result["access_token"]
        .as_str()
        .ok_or("No access_token in refresh response")?
        .to_string();

    let expires_in = result["expires_in"].as_u64().unwrap_or(3600);
    let token_expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + expires_in as i64;

    // Get new refresh token if provided (some IdPs rotate refresh tokens)
    let new_refresh_token = result["refresh_token"]
        .as_str()
        .unwrap_or(metadata["refresh_token"].as_str().unwrap_or(""));

    // Store the new token
    storage
        .store(KEY_ACCESS_TOKEN, access_token.as_bytes())
        .map_err(|e| format!("Failed to store access token: {}", e))?;

    // Update token metadata
    let updated_metadata = serde_json::json!({
        "expires_at": token_expires,
        "refresh_token": new_refresh_token,
        "issuer": metadata["issuer"],
        "token_endpoint": metadata["token_endpoint"],
        "client_id": metadata["client_id"],
        "client_secret": metadata["client_secret"],
    });
    storage
        .store(KEY_TOKEN_METADATA, updated_metadata.to_string().as_bytes())
        .map_err(|e| format!("Failed to store metadata: {}", e))?;

    // Extract username from token (simple base64 decode of payload)
    let username = extract_username_from_token(&access_token);

    info!("Token refreshed successfully, expires in {}s", expires_in);

    Ok((access_token, token_expires, username))
}

/// Extract username from a JWT access token without full validation
fn extract_username_from_token(token: &str) -> Option<String> {
    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode payload (base64url)
    let payload = base64_decode_url(parts[1])?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;

    // Priority order for username extraction
    if let Some(unix_user) = claims["unix_username"].as_str() {
        return Some(unix_user.to_string());
    }
    if let Some(preferred) = claims["preferred_username"].as_str() {
        return Some(preferred.to_string());
    }
    if let Some(upn) = claims["upn"].as_str() {
        return Some(upn.split('@').next().unwrap_or(upn).to_string());
    }
    if let Some(email) = claims["email"].as_str() {
        return Some(email.split('@').next().unwrap_or(email).to_string());
    }
    if let Some(sub) = claims["sub"].as_str() {
        warn!("Using sub claim as username: {}", sub);
        return Some(sub.to_string());
    }

    None
}

/// Decode base64url (JWT uses URL-safe base64 without padding)
fn base64_decode_url(input: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(input).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SoftwareSigner;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_server_client_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        // Create state with a signer and token
        let signer = Arc::new(SoftwareSigner::generate());
        let state = Arc::new(RwLock::new(AgentState {
            signer: Some(signer.clone()),
            access_token: Some("test-token".to_string()),
            token_expires: Some(9999999999),
            username: Some("testuser".to_string()),
            metrics: Arc::new(MetricsCollector::new()),
        }));

        // Start server in background
        let server = AgentServer::new(socket_path.clone(), state);
        let _server_handle = tokio::spawn(async move {
            let _ = server.serve().await;
        });

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Create client and send request
        let client = AgentClient::new(socket_path);

        let response = client.status().await.unwrap();

        if let AgentResponse::Success(AgentResponseData::Status {
            logged_in,
            username,
            ..
        }) = response
        {
            assert!(logged_in);
            assert_eq!(username, Some("testuser".to_string()));
        } else {
            panic!("Unexpected response: {:?}", response);
        }
    }

    #[tokio::test]
    async fn test_get_proof() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test2.sock");

        let signer = Arc::new(SoftwareSigner::generate());
        let state = Arc::new(RwLock::new(AgentState {
            signer: Some(signer.clone()),
            access_token: Some("test-token".to_string()),
            token_expires: Some(9999999999),
            username: Some("testuser".to_string()),
            metrics: Arc::new(MetricsCollector::new()),
        }));

        let server = AgentServer::new(socket_path.clone(), state);
        let _server_handle = tokio::spawn(async move {
            let _ = server.serve().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = AgentClient::new(socket_path);
        let response = client
            .get_proof("server.example.com", "SSH", None)
            .await
            .unwrap();

        if let AgentResponse::Success(AgentResponseData::Proof {
            token, dpop_proof, ..
        }) = response
        {
            assert_eq!(token, "test-token");
            // Proof should be a JWT (3 parts)
            assert_eq!(dpop_proof.split('.').count(), 3);
        } else {
            panic!("Unexpected response: {:?}", response);
        }
    }

    #[tokio::test]
    async fn test_not_logged_in() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test3.sock");

        // Empty state - not logged in
        let state = Arc::new(RwLock::new(AgentState::new()));

        let server = AgentServer::new(socket_path.clone(), state);
        let _server_handle = tokio::spawn(async move {
            let _ = server.serve().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = AgentClient::new(socket_path);
        let response = client
            .get_proof("server.example.com", "SSH", None)
            .await
            .unwrap();

        if let AgentResponse::Error { code, .. } = response {
            assert_eq!(code, "NOT_LOGGED_IN");
        } else {
            panic!("Expected error response: {:?}", response);
        }
    }

    #[test]
    fn test_base64_decode_url() {
        // Valid base64url
        let result = base64_decode_url("SGVsbG8");
        assert_eq!(result, Some(b"Hello".to_vec()));

        // Invalid base64
        let result = base64_decode_url("!!!invalid!!!");
        assert!(result.is_none());

        // Empty string
        let result = base64_decode_url("");
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn test_extract_username_from_token() {
        use base64::Engine;
        // Create a synthetic JWT with preferred_username claim
        // Header: {"alg":"none","typ":"JWT"}
        // Payload: {"preferred_username":"testuser","sub":"123"}
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"preferred_username":"testuser","sub":"123"}"#);
        let token = format!("{}.{}.", header, payload);

        let result = extract_username_from_token(&token);
        assert_eq!(result, Some("testuser".to_string()));
    }

    #[test]
    fn test_extract_username_from_token_invalid() {
        // Invalid token format (not 3 parts)
        let result = extract_username_from_token("not-a-jwt");
        assert!(result.is_none());

        // Invalid base64 in payload
        let result = extract_username_from_token("header.!!!invalid!!!.sig");
        assert!(result.is_none());

        // Two part token (missing signature)
        let result = extract_username_from_token("header.payload");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_username_from_token_fallbacks() {
        use base64::Engine;

        // Test: falls back to sub when no username claims present
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":"user123","iat":1234567890}"#);
        let token = format!("{}.{}.", header, payload);

        let result = extract_username_from_token(&token);
        assert_eq!(result, Some("user123".to_string()));

        // Test: unix_username takes priority
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"unix_username":"unixuser","preferred_username":"preferred","sub":"sub"}"#);
        let token = format!("{}.{}.", header, payload);

        let result = extract_username_from_token(&token);
        assert_eq!(result, Some("unixuser".to_string()));

        // Test: email extraction (strip domain)
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"email":"user@example.com"}"#);
        let token = format!("{}.{}.", header, payload);

        let result = extract_username_from_token(&token);
        assert_eq!(result, Some("user".to_string()));
    }

    #[test]
    fn test_agent_state_new() {
        let state = AgentState::new();
        assert!(state.signer.is_none());
        assert!(state.access_token.is_none());
        assert!(state.token_expires.is_none());
        assert!(state.username.is_none());
    }
}
