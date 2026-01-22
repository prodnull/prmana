//! unix-oidc-agent: OIDC authentication agent with DPoP support
//!
//! This agent manages OIDC tokens and DPoP proofs for passwordless SSH authentication.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use unix_oidc_agent::crypto::{DPoPSigner, SoftwareSigner};
use unix_oidc_agent::daemon::{
    AgentClient, AgentResponse, AgentResponseData, AgentServer, AgentState,
};
use unix_oidc_agent::storage::{
    FileStorage, SecureStorage, KEY_ACCESS_TOKEN, KEY_DPOP_PRIVATE, KEY_TOKEN_METADATA,
};

/// Claims from an OIDC access token for username extraction
#[derive(Debug, Serialize, Deserialize)]
struct TokenClaims {
    /// Subject identifier (often the user ID)
    sub: Option<String>,
    /// Preferred username (common in Keycloak, Azure AD)
    preferred_username: Option<String>,
    /// Email address (fallback)
    email: Option<String>,
    /// Unix username (custom claim)
    unix_username: Option<String>,
    /// UPN - User Principal Name (Azure AD)
    upn: Option<String>,
}

#[derive(Parser)]
#[command(name = "unix-oidc-agent")]
#[command(about = "OIDC authentication agent with DPoP support")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with the IdP using device flow
    Login {
        /// IdP issuer URL (defaults to OIDC_ISSUER env var)
        #[arg(long)]
        issuer: Option<String>,

        /// OAuth client ID (defaults to OIDC_CLIENT_ID or "unix-oidc")
        #[arg(long)]
        client_id: Option<String>,

        /// OAuth client secret (optional)
        #[arg(long)]
        client_secret: Option<String>,
    },

    /// Show current authentication status
    Status,

    /// Refresh the access token using the refresh token
    Refresh,

    /// Revoke tokens but keep the DPoP keypair
    Logout,

    /// Delete all credentials including the DPoP keypair
    Reset {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },

    /// Run the agent daemon
    Serve {
        /// Socket path (defaults to $XDG_RUNTIME_DIR/unix-oidc-agent.sock)
        #[arg(long)]
        socket: Option<String>,

        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
    },

    /// Get a token and proof for a target (used by SSH)
    GetProof {
        /// Target server hostname
        #[arg(long)]
        target: String,

        /// HTTP method (defaults to SSH)
        #[arg(long, default_value = "SSH")]
        method: String,

        /// Server-provided nonce
        #[arg(long)]
        nonce: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("unix_oidc_agent=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Login {
            issuer,
            client_id,
            client_secret,
        } => run_login(issuer, client_id, client_secret).await,

        Commands::Status => run_status().await,

        Commands::Refresh => run_refresh().await,

        Commands::Logout => run_logout().await,

        Commands::Reset { force } => run_reset(force).await,

        Commands::Serve {
            socket,
            foreground: _,
        } => run_serve(socket).await,

        Commands::GetProof {
            target,
            method,
            nonce,
        } => run_get_proof(target, method, nonce).await,
    }
}

/// Run the agent daemon
async fn run_serve(socket: Option<String>) -> anyhow::Result<()> {
    let socket_path = socket
        .map(PathBuf::from)
        .unwrap_or_else(AgentServer::default_socket_path);

    info!("Starting agent daemon on {:?}", socket_path);

    // Try to load existing credentials from storage
    let state = load_agent_state().await?;
    let state = Arc::new(RwLock::new(state));

    let server = AgentServer::new(socket_path.clone(), state);

    println!("unix-oidc-agent listening on {:?}", socket_path);
    println!("Press Ctrl+C to stop");

    server
        .serve()
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}

/// Get status from the running daemon
async fn run_status() -> anyhow::Result<()> {
    let client = AgentClient::default();

    match client.status().await {
        Ok(AgentResponse::Success(AgentResponseData::Status {
            logged_in,
            username,
            thumbprint,
            token_expires,
        })) => {
            if logged_in {
                println!("Status: Logged in");
                if let Some(u) = username {
                    println!("  User: {}", u);
                }
                if let Some(t) = thumbprint {
                    println!("  DPoP thumbprint: {}", t);
                }
                if let Some(exp) = token_expires {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    let remaining = exp - now;
                    if remaining > 0 {
                        println!("  Token expires in: {}s", remaining);
                    } else {
                        println!("  Token: EXPIRED");
                    }
                }
            } else {
                println!("Status: Not logged in");
                if let Some(t) = thumbprint {
                    println!("  DPoP thumbprint: {} (keypair exists)", t);
                }
            }
            Ok(())
        }
        Ok(AgentResponse::Error { message, code }) => {
            error!("Agent error: {} ({})", message, code);
            Err(anyhow::anyhow!("Agent error: {}", message))
        }
        Ok(_) => Err(anyhow::anyhow!("Unexpected response from agent")),
        Err(e) => {
            // Agent might not be running
            println!("Status: Agent not running");
            println!("  Error: {}", e);
            println!("  Start the agent with: unix-oidc-agent serve");

            // Check if we have stored credentials
            if let Ok(storage) = FileStorage::new() {
                if storage.exists(KEY_DPOP_PRIVATE) {
                    println!("  DPoP keypair: stored");
                }
                if storage.exists(KEY_ACCESS_TOKEN) {
                    println!("  Access token: stored");
                }
            }
            Ok(())
        }
    }
}

/// Get a DPoP proof from the running daemon
async fn run_get_proof(
    target: String,
    method: String,
    nonce: Option<String>,
) -> anyhow::Result<()> {
    let client = AgentClient::default();

    match client.get_proof(&target, &method, nonce.as_deref()).await {
        Ok(AgentResponse::Success(AgentResponseData::Proof {
            token,
            dpop_proof,
            expires_in,
        })) => {
            // Output in a format that SSH can consume
            println!("{}", token);
            println!("{}", dpop_proof);
            info!("Token expires in {}s", expires_in);
            Ok(())
        }
        Ok(AgentResponse::Error { message, code }) => {
            error!("Agent error: {} ({})", message, code);
            if code == "NOT_LOGGED_IN" {
                eprintln!("Error: Not logged in. Run: unix-oidc-agent login");
            }
            Err(anyhow::anyhow!("Agent error: {}", message))
        }
        Ok(_) => Err(anyhow::anyhow!("Unexpected response from agent")),
        Err(e) => {
            eprintln!("Error: Could not connect to agent: {}", e);
            eprintln!("Start the agent with: unix-oidc-agent serve");
            Err(anyhow::anyhow!("Agent connection error: {}", e))
        }
    }
}

/// Authenticate with the IdP using device flow
async fn run_login(
    issuer: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
) -> anyhow::Result<()> {
    let issuer = issuer
        .or_else(|| std::env::var("OIDC_ISSUER").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("OIDC_ISSUER not set. Use --issuer or set OIDC_ISSUER env var")
        })?;

    let client_id = client_id
        .or_else(|| std::env::var("OIDC_CLIENT_ID").ok())
        .unwrap_or_else(|| "unix-oidc".to_string());

    let client_secret = client_secret.or_else(|| std::env::var("OIDC_CLIENT_SECRET").ok());

    info!("Starting device flow authentication with {}", issuer);

    // Initialize or load DPoP signer
    let storage = FileStorage::new()?;
    let signer = load_or_create_signer(&storage)?;

    println!("DPoP thumbprint: {}", signer.thumbprint());
    println!();
    println!("Starting device authorization flow with: {}", issuer);
    println!("Client ID: {}", client_id);
    println!();

    // Use spawn_blocking for the sync device flow client
    let issuer_clone = issuer.clone();
    let client_id_clone = client_id.clone();
    let secret_clone = client_secret.clone();

    // Store issuer for refresh operations
    let issuer_for_storage = issuer.clone();
    let client_id_for_storage = client_id.clone();
    let client_secret_for_storage = client_secret.clone();

    let token_result = tokio::task::spawn_blocking(move || {
        use std::time::Duration;

        // Discover OIDC endpoints
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_clone.trim_end_matches('/')
        );

        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        // Fetch OIDC discovery document
        let discovery: serde_json::Value = http_client
            .get(&discovery_url)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to fetch OIDC discovery: {}", e))?
            .json()
            .map_err(|e| anyhow::anyhow!("Failed to parse OIDC discovery: {}", e))?;

        let device_endpoint = discovery["device_authorization_endpoint"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("IdP does not support device authorization"))?;

        let token_endpoint = discovery["token_endpoint"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Token endpoint not found in discovery"))?
            .to_string();

        // Start device authorization
        let mut params = vec![("client_id", client_id_clone.as_str()), ("scope", "openid")];

        if let Some(ref secret) = secret_clone {
            params.push(("client_secret", secret.as_str()));
        }

        let device_response: serde_json::Value = http_client
            .post(device_endpoint)
            .form(&params)
            .send()
            .map_err(|e| anyhow::anyhow!("Device authorization request failed: {}", e))?
            .json()
            .map_err(|e| anyhow::anyhow!("Failed to parse device response: {}", e))?;

        let device_code = device_response["device_code"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No device_code in response"))?;

        let user_code = device_response["user_code"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No user_code in response"))?;

        let verification_uri = device_response["verification_uri"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No verification_uri in response"))?;

        let verification_uri_complete = device_response["verification_uri_complete"].as_str();

        let expires_in = device_response["expires_in"].as_u64().unwrap_or(600);
        let interval = device_response["interval"].as_u64().unwrap_or(5);

        // Display instructions to user
        println!("┌──────────────────────────────────────────────────────────┐");
        println!("│                    Device Authorization                   │");
        println!("├──────────────────────────────────────────────────────────┤");
        println!("│                                                          │");
        println!("│  1. Open your browser to:                                │");
        println!(
            "│     {}{}│",
            verification_uri,
            " ".repeat(53 - verification_uri.len().min(53))
        );
        println!("│                                                          │");
        println!(
            "│  2. Enter the code:  {}{}│",
            user_code,
            " ".repeat(35 - user_code.len().min(35))
        );
        println!("│                                                          │");
        if let Some(complete_uri) = verification_uri_complete {
            println!("│  Or visit directly:                                      │");
            let uri_display = if complete_uri.len() > 50 {
                format!("{}...", &complete_uri[..47])
            } else {
                complete_uri.to_string()
            };
            println!(
                "│     {}{}│",
                uri_display,
                " ".repeat(53 - uri_display.len().min(53))
            );
            println!("│                                                          │");
        }
        println!(
            "│  Code expires in {} seconds                            │",
            expires_in
        );
        println!("└──────────────────────────────────────────────────────────┘");
        println!();
        println!("Waiting for authentication...");

        // Poll for token
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(expires_in);
        let mut poll_interval = Duration::from_secs(interval);

        loop {
            if start.elapsed() >= timeout {
                return Err(anyhow::anyhow!("Device code expired"));
            }

            std::thread::sleep(poll_interval);

            let mut token_params = vec![
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", client_id_clone.as_str()),
            ];

            if let Some(ref secret) = secret_clone {
                token_params.push(("client_secret", secret.as_str()));
            }

            let response = http_client
                .post(&token_endpoint)
                .form(&token_params)
                .send()
                .map_err(|e| anyhow::anyhow!("Token request failed: {}", e))?;

            if response.status().is_success() {
                let token_response: serde_json::Value = response
                    .json()
                    .map_err(|e| anyhow::anyhow!("Failed to parse token response: {}", e))?;

                // Return both the token response and the token endpoint
                return Ok((token_response, token_endpoint));
            }

            let error_response: serde_json::Value = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse error response: {}", e))?;

            match error_response["error"].as_str() {
                Some("authorization_pending") => {
                    print!(".");
                    use std::io::Write;
                    std::io::stdout().flush().ok();
                    continue;
                }
                Some("slow_down") => {
                    poll_interval += Duration::from_secs(5);
                    continue;
                }
                Some("access_denied") => {
                    return Err(anyhow::anyhow!("Access denied by user"));
                }
                Some("expired_token") => {
                    return Err(anyhow::anyhow!("Device code expired"));
                }
                Some(err) => {
                    let desc = error_response["error_description"]
                        .as_str()
                        .unwrap_or("Unknown error");
                    return Err(anyhow::anyhow!("Authentication failed: {} - {}", err, desc));
                }
                None => {
                    return Err(anyhow::anyhow!("Unknown error response"));
                }
            }
        }
    })
    .await??;

    let (token_result, token_endpoint) = token_result;

    println!();
    println!("Authentication successful!");

    // Extract token information
    let access_token = token_result["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token in response"))?;

    let expires_in = token_result["expires_in"].as_u64().unwrap_or(3600);
    let token_expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + expires_in as i64;

    // Store the token
    storage.store(KEY_ACCESS_TOKEN, access_token.as_bytes())?;

    // Store token metadata (expiry, refresh token, and OIDC config for refresh)
    let metadata = serde_json::json!({
        "expires_at": token_expires,
        "refresh_token": token_result["refresh_token"].as_str(),
        "issuer": issuer_for_storage,
        "token_endpoint": token_endpoint,
        "client_id": client_id_for_storage,
        "client_secret": client_secret_for_storage,
    });
    storage.store(KEY_TOKEN_METADATA, metadata.to_string().as_bytes())?;

    println!("Token stored successfully");
    println!("Token expires in: {}s", expires_in);
    println!();
    println!("Start the agent daemon with: unix-oidc-agent serve");

    Ok(())
}

/// Logout - clear tokens but keep keypair
async fn run_logout() -> anyhow::Result<()> {
    let storage = FileStorage::new()?;

    let mut cleared = false;

    if storage.exists(KEY_ACCESS_TOKEN) {
        storage.delete(KEY_ACCESS_TOKEN)?;
        cleared = true;
        println!("Access token cleared");
    }

    if storage.exists(KEY_TOKEN_METADATA) {
        storage.delete(KEY_TOKEN_METADATA)?;
        cleared = true;
        println!("Token metadata cleared");
    }

    if storage.exists("unix-oidc-refresh-token") {
        storage.delete("unix-oidc-refresh-token")?;
        cleared = true;
        println!("Refresh token cleared");
    }

    if cleared {
        println!();
        println!("Logged out successfully. DPoP keypair retained.");
        println!("Run 'unix-oidc-agent reset --force' to delete everything.");
    } else {
        println!("No tokens found to clear.");
    }

    Ok(())
}

/// Refresh the access token using the stored refresh token
async fn run_refresh() -> anyhow::Result<()> {
    let storage = FileStorage::new()?;

    // Load token metadata
    let metadata_bytes = storage
        .retrieve(KEY_TOKEN_METADATA)
        .map_err(|_| anyhow::anyhow!("No token metadata found. Please login first."))?;

    let metadata: serde_json::Value = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse token metadata: {}", e))?;

    // Get refresh token
    let refresh_token = metadata["refresh_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No refresh token found. Please login again."))?;

    // Get OIDC config
    let token_endpoint = metadata["token_endpoint"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No token endpoint found. Please login again."))?
        .to_string();

    let client_id = metadata["client_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No client_id found. Please login again."))?
        .to_string();

    let client_secret = metadata["client_secret"].as_str().map(String::from);

    println!("Refreshing access token...");

    // Perform refresh in blocking task
    let refresh_token_clone = refresh_token.to_string();
    let token_result = tokio::task::spawn_blocking(move || {
        use std::time::Duration;

        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        let mut params = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token_clone.as_str()),
            ("client_id", client_id.as_str()),
        ];

        if let Some(ref secret) = client_secret {
            params.push(("client_secret", secret.as_str()));
        }

        let response = http_client
            .post(&token_endpoint)
            .form(&params)
            .send()
            .map_err(|e| anyhow::anyhow!("Token refresh request failed: {}", e))?;

        if response.status().is_success() {
            let token_response: serde_json::Value = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse token response: {}", e))?;
            Ok(token_response)
        } else {
            let error: serde_json::Value = response
                .json()
                .unwrap_or_else(|_| serde_json::json!({"error": "unknown"}));
            let error_msg = error["error_description"]
                .as_str()
                .or(error["error"].as_str())
                .unwrap_or("Unknown error");
            Err(anyhow::anyhow!("Token refresh failed: {}", error_msg))
        }
    })
    .await??;

    // Extract new token information
    let access_token = token_result["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token in refresh response"))?;

    let expires_in = token_result["expires_in"].as_u64().unwrap_or(3600);
    let token_expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + expires_in as i64;

    // Get new refresh token if provided (some IdPs rotate refresh tokens)
    let new_refresh_token = token_result["refresh_token"]
        .as_str()
        .unwrap_or(metadata["refresh_token"].as_str().unwrap_or(""));

    // Store the new token
    storage.store(KEY_ACCESS_TOKEN, access_token.as_bytes())?;

    // Update token metadata
    let updated_metadata = serde_json::json!({
        "expires_at": token_expires,
        "refresh_token": new_refresh_token,
        "issuer": metadata["issuer"],
        "token_endpoint": metadata["token_endpoint"],
        "client_id": metadata["client_id"],
        "client_secret": metadata["client_secret"],
    });
    storage.store(KEY_TOKEN_METADATA, updated_metadata.to_string().as_bytes())?;

    println!("Token refreshed successfully!");
    println!("Token expires in: {}s", expires_in);

    Ok(())
}

/// Reset - delete all credentials including keypair
async fn run_reset(force: bool) -> anyhow::Result<()> {
    if !force {
        println!("This will delete your DPoP keypair and all tokens.");
        println!("You will need to re-authenticate on all servers.");
        println!();
        println!("Use --force to confirm.");
        return Ok(());
    }

    let storage = FileStorage::new()?;
    let mut cleared = Vec::new();

    // Delete all stored credentials
    for key in &[
        KEY_DPOP_PRIVATE,
        KEY_ACCESS_TOKEN,
        KEY_TOKEN_METADATA,
        "unix-oidc-refresh-token",
    ] {
        if storage.exists(key) {
            storage.delete(key)?;
            cleared.push(*key);
        }
    }

    if cleared.is_empty() {
        println!("No credentials found to clear.");
    } else {
        println!("Cleared credentials:");
        for key in &cleared {
            println!("  - {}", key);
        }
        println!();
        println!("All credentials deleted.");
    }

    Ok(())
}

/// Load agent state from storage
async fn load_agent_state() -> anyhow::Result<AgentState> {
    let storage = match FileStorage::new() {
        Ok(s) => s,
        Err(_) => {
            info!("No storage available, starting with empty state");
            return Ok(AgentState::new());
        }
    };

    let signer = match load_or_create_signer(&storage) {
        Ok(s) => Some(Arc::new(s) as Arc<dyn unix_oidc_agent::crypto::DPoPSigner>),
        Err(e) => {
            info!("Could not load signer: {}", e);
            None
        }
    };

    let access_token = storage
        .retrieve(KEY_ACCESS_TOKEN)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());

    let token_expires = storage
        .retrieve(KEY_TOKEN_METADATA)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["expires_at"].as_i64());

    // Extract username from token claims
    let username = access_token
        .as_ref()
        .and_then(|token| extract_username_from_token(token));

    Ok(AgentState {
        signer,
        access_token,
        token_expires,
        username,
        metrics: std::sync::Arc::new(unix_oidc_agent::metrics::MetricsCollector::new()),
    })
}

/// Load existing signer or create a new one
fn load_or_create_signer(storage: &FileStorage) -> anyhow::Result<SoftwareSigner> {
    if let Ok(key_bytes) = storage.retrieve(KEY_DPOP_PRIVATE) {
        info!("Loading existing DPoP keypair");
        SoftwareSigner::import_key(&key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to import key: {}", e))
    } else {
        info!("Generating new DPoP keypair");
        let signer = SoftwareSigner::generate();
        storage.store(KEY_DPOP_PRIVATE, &signer.export_key())?;
        Ok(signer)
    }
}

/// Extract username from a JWT access token without validating signature
///
/// This is safe because we're just extracting claims from a token we already trust
/// (we received it from the IdP during login). The PAM module validates the signature.
fn extract_username_from_token(token: &str) -> Option<String> {
    // Create a validation that skips signature verification
    // We're just extracting claims, not validating the token
    let mut validation = Validation::new(Algorithm::ES256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_aud = false;

    // Use an empty key since we're not validating
    let key = DecodingKey::from_secret(&[]);

    match decode::<TokenClaims>(token, &key, &validation) {
        Ok(token_data) => {
            let claims = token_data.claims;

            // Priority order for username extraction:
            // 1. unix_username - custom claim for Unix systems
            // 2. preferred_username - standard OIDC claim
            // 3. upn - Azure AD User Principal Name (strip domain)
            // 4. email - use local part before @
            // 5. sub - subject identifier as last resort

            if let Some(unix_user) = claims.unix_username {
                info!("Extracted username from unix_username claim: {}", unix_user);
                return Some(unix_user);
            }

            if let Some(preferred) = claims.preferred_username {
                info!(
                    "Extracted username from preferred_username claim: {}",
                    preferred
                );
                return Some(preferred);
            }

            if let Some(upn) = claims.upn {
                // UPN is usually user@domain, take the local part
                let username = upn.split('@').next().unwrap_or(&upn).to_string();
                info!("Extracted username from upn claim: {}", username);
                return Some(username);
            }

            if let Some(email) = claims.email {
                // Take local part of email
                let username = email.split('@').next().unwrap_or(&email).to_string();
                info!("Extracted username from email claim: {}", username);
                return Some(username);
            }

            if let Some(sub) = claims.sub {
                warn!(
                    "Using sub claim as username (no better claim available): {}",
                    sub
                );
                return Some(sub);
            }

            None
        }
        Err(e) => {
            warn!("Failed to decode token for username extraction: {}", e);
            None
        }
    }
}
