//! unix-oidc-agent: OIDC authentication agent with DPoP support
//!
//! This agent manages OIDC tokens and DPoP proofs for passwordless SSH authentication.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use unix_oidc_agent::config::AgentConfig;
use unix_oidc_agent::crypto::protected_key::mlock_probe;
use unix_oidc_agent::crypto::{DPoPSigner, MlockStatus, SoftwareSigner};
use unix_oidc_agent::daemon::{
    acquire_listener, spawn_refresh_task, AgentClient, AgentResponse, AgentResponseData,
    AgentServer, AgentState,
};
use unix_oidc_agent::hardware::{build_signer, provision_signer, SignerConfig};
use unix_oidc_agent::security::disable_core_dumps;
use unix_oidc_agent::storage::{
    SecureStorage, StorageRouter, KEY_ACCESS_TOKEN, KEY_DPOP_PRIVATE, KEY_TOKEN_METADATA,
};
#[cfg(feature = "pqc")]
use unix_oidc_agent::storage::KEY_PQ_SEED;

mod askpass;

/// Initialise the tracing subscriber with JSON auto-detection.
///
/// # JSON auto-detection
///
/// JSON output is selected when **either** of the following conditions is true:
///
/// - `UNIX_OIDC_LOG_FORMAT=json` — explicit operator opt-in (useful for
///   non-systemd log aggregation pipelines, e.g. Loki, Splunk HEC, CloudWatch).
/// - `JOURNAL_STREAM` is set — systemd sets this variable in the process
///   environment when the unit's `StandardOutput` / `StandardError` is wired
///   to the journal.  JSON output integrates cleanly with `journald`'s
///   structured field storage and downstream log shippers.
///
/// When neither variable is set, a human-readable, colour-capable format is
/// used for interactive terminal sessions.
///
/// # journald layer (Linux only)
///
/// On Linux, when `JOURNAL_STREAM` is set, an additional `tracing-journald`
/// layer is composed alongside the JSON formatter.  This layer writes
/// structured log records directly to the sd-journal socket (`/run/systemd/journal/socket`),
/// mapping tracing levels to `syslog(3)` PRIORITY codes (RFC 5424) so that
/// journal filters (`journalctl -p err`) work correctly.
///
/// The journald layer is added **best-effort** — if the socket is unavailable
/// (container without a mounted journal, or macOS build artefact running on
/// Linux) the layer is silently omitted and the JSON formatter alone is used.
///
/// # RUST_LOG
///
/// The subscriber respects `RUST_LOG` for per-module level control.
/// The default directive is `unix_oidc_agent=info` so the daemon is quiet by
/// default and operators can opt into `debug` or `trace` without rebuilding.
///
/// # Panics / initialisation failure
///
/// Uses `try_init()` rather than `init()` so that test harnesses can call this
/// function multiple times without panicking on the second registration attempt.
/// Errors from `try_init()` are silently discarded — the worst case is that
/// logging is unavailable, which the caller can detect via other means.
fn init_tracing() {
    // Build the log-level filter. RUST_LOG takes priority; fall back to INFO
    // for the agent crate and WARN for everything else.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("unix_oidc_agent=info,warn"));

    // Determine whether JSON output is requested.
    let use_json = std::env::var("UNIX_OIDC_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
        || std::env::var("JOURNAL_STREAM").is_ok();

    if use_json {
        // JSON layer — suitable for log aggregators and journald.
        let json_layer = fmt::layer().json();

        // Conditionally compose tracing-journald (Linux only).
        // On non-Linux builds the cfg gate produces a registry with only the
        // JSON layer, which is the correct fallback.
        #[cfg(target_os = "linux")]
        {
            // tracing_journald::layer() returns Err when the journal socket is
            // absent (e.g., inside a container without /run/systemd/journal/socket).
            // We add it best-effort; if unavailable, fall through to JSON-only.
            let registry = tracing_subscriber::registry().with(filter).with(json_layer);

            if std::env::var("JOURNAL_STREAM").is_ok() {
                if let Ok(journald) = tracing_journald::layer() {
                    let _ = registry.with(journald).try_init();
                    return;
                }
            }
            let _ = registry.try_init();
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(json_layer)
                .try_init();
        }
    } else {
        // Human-readable format for interactive terminal sessions.
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
            .try_init();
    }
}

#[cfg(test)]
mod tracing_init_tests {
    use super::*;

    /// Verify that init_tracing() can be called without panicking.
    ///
    /// Uses try_init() internally so multiple calls (across test invocations
    /// in the same process) do not panic on "global subscriber already set".
    #[test]
    fn test_init_tracing_no_panic() {
        // Call twice to verify try_init() prevents double-registration panics.
        init_tracing();
        init_tracing();
        // If we reach here, no panic occurred.
    }
}

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

        /// Signer backend: software (default), yubikey:<slot> (e.g. yubikey:9a), tpm.
        /// Hardware signers must be provisioned first with `unix-oidc-agent provision --signer <spec>`.
        #[arg(long, default_value = "software")]
        signer: String,
    },

    /// Provision a hardware key for DPoP signing.
    ///
    /// Generates a P-256 key on the specified hardware device.
    /// After provisioning, use `login --signer <spec>` to authenticate.
    Provision {
        /// Hardware signer to provision: yubikey:<slot> (e.g. yubikey:9a) or tpm.
        /// Use "yubikey:9a" for the recommended PIV Authentication slot.
        #[arg(long)]
        signer: String,
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

    /// Install the agent as a launchd service (macOS) or print systemd instructions (Linux).
    ///
    /// On macOS, writes a plist to ~/Library/LaunchAgents/ and runs `launchctl load`.
    /// The agent will start automatically at login and be kept alive by launchd.
    Install {
        /// Path to the unix-oidc-agent binary.
        /// Defaults to the currently-running executable (std::env::current_exe()).
        #[arg(long)]
        binary_path: Option<String>,
    },

    /// Uninstall the launchd service (macOS) or print systemd instructions (Linux).
    ///
    /// On macOS, runs `launchctl unload` and removes the plist from ~/Library/LaunchAgents/.
    Uninstall,

    /// Handle SSH keyboard-interactive prompts (invoked as SSH_ASKPASS).
    ///
    /// SSH spawns this binary once per prompt with the prompt string as argv[1].
    /// Handles three PAM prompt types from the DPoP authentication flow:
    ///
    /// - `DPOP_NONCE:<value>` — stores the server nonce in a tmpfile for the next round.
    /// - `DPOP_PROOF: ` — reads the stored nonce, calls GetProof IPC, prints the DPoP proof.
    /// - `OIDC Token: ` — reads the cached token (from the DPOP_PROOF round) or calls GetProof IPC.
    ///
    /// # Usage
    ///
    /// ```shell
    /// export SSH_ASKPASS=unix-oidc-agent
    /// export SSH_ASKPASS_REQUIRE=force
    /// ssh user@host
    /// ```
    ///
    /// The agent binary must be in $PATH for SSH_ASKPASS to work.
    #[command(name = "ssh-askpass")]
    SshAskpass {
        /// The prompt string from SSH keyboard-interactive conversation (passed as argv[1] by SSH).
        prompt: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging with JSON auto-detection.
    // JSON mode is activated by UNIX_OIDC_LOG_FORMAT=json or when running
    // under systemd (JOURNAL_STREAM env var set by the systemd unit).
    // See init_tracing() for full documentation.
    init_tracing();

    let cli = Cli::parse();

    match cli.command {
        Commands::Login {
            issuer,
            client_id,
            client_secret,
            signer,
        } => run_login(issuer, client_id, client_secret, signer).await,

        Commands::Provision { signer } => run_provision(signer).await,

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

        Commands::Install { binary_path } => run_install(binary_path).await,

        Commands::Uninstall => run_uninstall().await,

        Commands::SshAskpass { prompt } => askpass::run_ssh_askpass(prompt).await,
    }
}

/// Run the agent daemon.
///
/// Startup sequence:
/// 1. Process hardening (core dumps disabled, mlock probe)
/// 2. Storage migration
/// 3. Load existing credentials
/// 4. **Gate 1:** Acquire socket via `acquire_listener()` (systemd activation or standalone bind)
/// 5. **Gate 2:** Config validation (`AgentConfig::load()` + `timeouts.validate()`)
/// 6. **Gate 3:** Best-effort JWKS prefetch (WARN on failure, never blocks readiness)
/// 7. Send `sd_notify READY=1` — systemd marks the service active
/// 8. Enter `serve_with_listener()` accept loop (SIGTERM/SIGINT handled inside)
///
/// Source: sd-notify 0.5 readiness pattern — https://docs.rs/sd-notify/0.5.0/sd_notify/
async fn run_serve(socket: Option<String>) -> anyhow::Result<()> {
    let socket_path = socket
        .map(PathBuf::from)
        .unwrap_or_else(AgentServer::default_socket_path);

    info!(socket_path = %socket_path.display(), "Starting unix-oidc-agent daemon");

    // Process hardening: disable core dumps before loading any key material.
    // Best-effort — failures are logged as WARN, daemon continues.
    disable_core_dumps();

    // Probe mlock availability before loading keys.
    // The result is stored in AgentState for status reporting.
    let mlock_result = mlock_probe();
    let mlock_status_str = match &mlock_result {
        MlockStatus::Active => "mlock active: key pages memory-locked".to_string(),
        MlockStatus::Unavailable(reason) => {
            format!("mlock unavailable: {reason}")
        }
    };
    info!("Memory protection: {}", mlock_status_str);

    // Run migration at daemon startup: the primary trigger for file→keyring migration.
    // Attempt migration before loading state so that load_agent_state reads from the
    // correct (post-migration) backend.
    // Retain the router to capture backend kind and migration status for status reporting.
    let (storage_backend_str, migration_status_str) = match StorageRouter::detect() {
        Ok(mut router) => {
            match router.maybe_migrate() {
                Ok(0) => {}
                Ok(n) => info!(
                    n,
                    "Migrated credentials to keyring backend at daemon startup"
                ),
                Err(e) => {
                    warn!(error = %e, "Credential migration failed at startup (continuing)");
                }
            }
            (
                router.kind.display_name().to_string(),
                router.migration_status.display_name().to_string(),
            )
        }
        Err(e) => {
            warn!(error = %e, "StorageRouter::detect() failed at startup");
            ("unknown".to_string(), "n/a".to_string())
        }
    };
    info!("Storage: {}", storage_backend_str);

    // Try to load existing credentials from storage.
    // load_agent_state() reads signer_type from metadata and populates state.signer_type.
    let mut state = load_agent_state().await?;
    state.mlock_status = Some(mlock_status_str);
    state.storage_backend = Some(storage_backend_str);
    state.migration_status = Some(migration_status_str);
    // signer_type is already set by load_agent_state(); log it for observability.
    if let Some(ref st) = state.signer_type {
        info!(signer_type = %st, "Active signer backend");
    }
    let state = Arc::new(RwLock::new(state));

    // If credentials were loaded at startup (daemon restart while logged in), spawn
    // the background auto-refresh task so long sessions don't hit natural expiry.
    // Threshold: 80% of token lifetime (configurable in policy.yaml SessionConfig —
    // the daemon reads a fixed default for now; full config integration is a follow-up).
    const REFRESH_THRESHOLD_PERCENT: u8 = 80;
    {
        let state_read = state.read().await;
        if state_read.is_logged_in() {
            if let Some(token_expires) = state_read.token_expires {
                drop(state_read); // release read lock before write in spawn_refresh_task
                let handle = spawn_refresh_task(
                    Arc::clone(&state),
                    token_expires,
                    REFRESH_THRESHOLD_PERCENT,
                );
                state.write().await.refresh_task = Some(handle);
                info!("Auto-refresh task spawned for existing session");
            }
        }
    }

    // --- sd-notify readiness gates ---

    // Gate 1: Acquire socket.
    // Uses systemd socket activation when LISTEN_FDS/LISTEN_PID are set;
    // falls back to standalone bind otherwise.
    let listener = acquire_listener(&socket_path)
        .map_err(|e| anyhow::anyhow!("Failed to acquire socket: {e}"))?;
    info!(socket_path = %socket_path.display(), "Socket acquired");

    // Gate 2: Config validated.
    // AgentConfig::load() runs figment layered loading + TimeoutsConfig::validate().
    // Non-fatal if config file is absent — defaults are safe for production use.
    let ipc_idle_timeout_secs = match AgentConfig::load() {
        Ok(config) => {
            info!("Configuration validated");
            config.timeouts.ipc_idle_timeout_secs
        }
        Err(e) => {
            warn!(error = %e, "Configuration load/validation warning (using defaults)");
            60 // default matches TimeoutsConfig::default().ipc_idle_timeout_secs
        }
    };

    // Gate 3: Best-effort JWKS prefetch.
    // Fetches discovery + JWKS for the configured issuer to warm the cache.
    // Failure downgrades to WARN — the daemon will retry on the first auth request.
    // This is run in a blocking task because JwksProvider uses reqwest::blocking.
    let issuer_for_prefetch = {
        AgentConfig::load()
            .ok()
            .and_then(|c| if c.issuer.is_empty() { None } else { Some(c) })
    };
    if let Some(config) = issuer_for_prefetch {
        let issuer = config.issuer.clone();
        let ttl = config.timeouts.jwks_cache_ttl_secs;
        let http_timeout = config.timeouts.jwks_http_timeout_secs;
        match tokio::task::spawn_blocking(move || {
            use pam_unix_oidc::oidc::JwksProvider;
            let provider = JwksProvider::with_timeouts(&issuer, ttl, http_timeout);
            provider.refresh_jwks()
        })
        .await
        {
            Ok(Ok(())) => info!("Initial JWKS prefetch succeeded"),
            Ok(Err(e)) => {
                warn!(error = %e, "Initial JWKS prefetch failed — will retry on first auth")
            }
            Err(e) => warn!(error = %e, "JWKS prefetch task panicked — will retry on first auth"),
        }
    } else {
        info!("No issuer configured; skipping JWKS prefetch");
    }

    // Send READY=1: all three gates passed (or best-effort failures logged as WARN).
    // sd_notify is a no-op when NOTIFY_SOCKET is not set (standalone mode).
    // Source: sd-notify 0.5 — https://docs.rs/sd-notify/0.5.0/sd_notify/
    let _ = sd_notify::notify(&[
        sd_notify::NotifyState::Ready,
        sd_notify::NotifyState::Status("unix-oidc-agent ready"),
    ]);
    info!("Agent ready (sd_notify READY=1 sent if systemd-managed)");

    let server = AgentServer::new(socket_path, state)
        .with_idle_timeout(Duration::from_secs(ipc_idle_timeout_secs));
    server
        .serve_with_listener(listener)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))
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
            mlock_status,
            storage_backend,
            migration_status,
            signer_type,
            refresh_failed,
        })) => {
            if logged_in {
                println!("Status: Logged in");
                if let Some(u) = username {
                    println!("  User: {u}");
                }
                if let Some(t) = thumbprint {
                    println!("  DPoP thumbprint: {t}");
                }
                if let Some(exp) = token_expires {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    let remaining = exp - now;
                    if remaining > 0 {
                        println!("  Token expires in: {remaining}s");
                    } else {
                        println!("  Token: EXPIRED");
                    }
                }
            } else {
                println!("Status: Not logged in");
                if let Some(t) = thumbprint {
                    println!("  DPoP thumbprint: {t} (keypair exists)");
                }
            }
            if let Some(signer) = signer_type {
                println!("  Signer: {}", format_signer_type(&signer));
            }
            if let Some(mem) = mlock_status {
                println!("  Memory protection: {mem}");
            }
            if let Some(backend) = storage_backend {
                println!("  Storage: {backend}");
            }
            if let Some(migration) = migration_status {
                println!("  Migration: {migration}");
            }
            if refresh_failed == Some(true) {
                println!("  Auto-refresh: FAILED (token will expire; re-login required)");
            }
            Ok(())
        }
        Ok(AgentResponse::Error { message, code }) => {
            error!("Agent error: {} ({})", message, code);
            Err(anyhow::anyhow!("Agent error: {message}"))
        }
        Ok(_) => Err(anyhow::anyhow!("Unexpected response from agent")),
        Err(e) => {
            // Agent might not be running
            println!("Status: Agent not running");
            println!("  Error: {e}");
            println!("  Start the agent with: unix-oidc-agent serve");

            // Check if we have stored credentials
            if let Ok(storage) = StorageRouter::detect() {
                println!("  Storage: {}", storage.kind.display_name());
                println!("  Migration: {}", storage.migration_status.display_name());
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
            println!("{token}");
            println!("{dpop_proof}");
            info!("Token expires in {}s", expires_in);
            Ok(())
        }
        Ok(AgentResponse::Error { message, code }) => {
            error!("Agent error: {} ({})", message, code);
            if code == "NOT_LOGGED_IN" {
                eprintln!("Error: Not logged in. Run: unix-oidc-agent login");
            }
            Err(anyhow::anyhow!("Agent error: {message}"))
        }
        Ok(_) => Err(anyhow::anyhow!("Unexpected response from agent")),
        Err(e) => {
            eprintln!("Error: Could not connect to agent: {e}");
            eprintln!("Start the agent with: unix-oidc-agent serve");
            Err(anyhow::anyhow!("Agent connection error: {e}"))
        }
    }
}

/// Authenticate with the IdP using device flow
async fn run_login(
    issuer: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    signer_spec: String,
) -> anyhow::Result<()> {
    let issuer = issuer
        .or_else(|| std::env::var("OIDC_ISSUER").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("OIDC_ISSUER not set. Use --issuer or set OIDC_ISSUER env var")
        })?;

    let client_id = client_id
        .or_else(|| std::env::var("OIDC_CLIENT_ID").ok())
        .unwrap_or_else(|| "unix-oidc".to_string());

    // Security (MEM-03): wrap client_secret in SecretString immediately — must not appear in logs.
    let client_secret: Option<SecretString> = client_secret.map(SecretString::from).or_else(|| {
        std::env::var("OIDC_CLIENT_SECRET")
            .ok()
            .map(SecretString::from)
    });

    info!("Starting device flow authentication with {}", issuer);

    // Load agent config for timeout and skew parameters.
    // Failure is non-fatal — use defaults so the login flow still works.
    let device_flow_timeout_secs = AgentConfig::load()
        .map(|c| c.timeouts.device_flow_http_timeout_secs)
        .unwrap_or(30);

    // Initialize or load DPoP signer via the best available backend.
    // Run migration here: login is the primary user-facing trigger after upgrade.
    let mut storage = StorageRouter::detect()?;
    match storage.maybe_migrate() {
        Ok(0) => {}
        Ok(n) => info!(n, "Migrated credentials to keyring backend"),
        Err(e) => {
            warn!(error = %e, "Credential migration failed (continuing with current backend)")
        }
    }

    // Select signer backend based on --signer flag and crypto config.
    // "software" (default) uses ES256 or PQC hybrid (if enable_pqc is set).
    // Hardware specs (yubikey:<slot>, tpm) use build_signer() to open the pre-provisioned device key.
    let (signer_type, signer_arc): (String, Arc<dyn DPoPSigner>) =
        if signer_spec == "software" || signer_spec.is_empty() {
            // Check if PQC hybrid mode is enabled in config.
            #[cfg(feature = "pqc")]
            {
                let pqc_enabled = AgentConfig::load()
                    .map(|c| c.crypto.enable_pqc)
                    .unwrap_or(false);
                if pqc_enabled {
                    let pqc = load_or_create_pqc_signer(&storage)?;
                    let arc: Arc<dyn DPoPSigner> = Arc::new(pqc);
                    ("pqc".to_string(), arc)
                } else {
                    let sw = load_or_create_signer(&storage)?;
                    let arc: Arc<dyn DPoPSigner> = Arc::new(sw);
                    ("software".to_string(), arc)
                }
            }
            #[cfg(not(feature = "pqc"))]
            {
                let sw = load_or_create_signer(&storage)?;
                let arc: Arc<dyn DPoPSigner> = Arc::new(sw);
                ("software".to_string(), arc)
            }
        } else {
            let hw_config = SignerConfig::load();
            let arc = build_signer(&signer_spec, &hw_config)?;
            (signer_spec.clone(), arc)
        };

    // Backward-compat alias for the rest of the function (DPoP proof generation not needed here,
    // but thumbprint display is).
    let signer = signer_arc.as_ref();

    println!("DPoP thumbprint: {}", signer.thumbprint());
    println!();
    println!("Starting device authorization flow with: {issuer}");
    println!("Client ID: {client_id}");
    println!();

    // Use spawn_blocking for the sync device flow client
    let issuer_clone = issuer.clone();
    let client_id_clone = client_id.clone();
    // SecretString is Clone (String: CloneableSecret in secrecy 0.10) — safe to clone for closure capture.
    let secret_clone = client_secret.clone();

    // Store issuer for refresh operations
    let issuer_for_storage = issuer.clone();
    let client_id_for_storage = client_id.clone();
    let client_secret_for_storage = client_secret.clone();
    // signer_type is a String — clone to use in metadata write after spawn_blocking.
    let signer_type_for_storage = signer_type.clone();

    let token_result = tokio::task::spawn_blocking(move || {
        use std::time::Duration;

        // Discover OIDC endpoints
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_clone.trim_end_matches('/')
        );

        // device_flow_timeout_secs is loaded from AgentConfig above (default 30s).
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(device_flow_timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        // Fetch OIDC discovery document
        let discovery: serde_json::Value = http_client
            .get(&discovery_url)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to fetch OIDC discovery: {e}"))?
            .json()
            .map_err(|e| anyhow::anyhow!("Failed to parse OIDC discovery: {e}"))?;

        let device_endpoint = discovery["device_authorization_endpoint"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("IdP does not support device authorization"))?;

        let token_endpoint = discovery["token_endpoint"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Token endpoint not found in discovery"))?
            .to_string();

        // RFC 7009: revocation endpoint is optional — some IdPs don't publish it.
        // Extract from discovery; if absent, revocation will be skipped gracefully.
        let revocation_endpoint: Option<String> = discovery["revocation_endpoint"]
            .as_str()
            .map(str::to_string);

        // Start device authorization
        let mut params = vec![("client_id", client_id_clone.as_str()), ("scope", "openid")];

        if let Some(ref secret) = secret_clone {
            // Security (MEM-03): expose_secret() at HTTP param boundary only.
            let secret_str: &str = secret.expose_secret();
            params.push(("client_secret", secret_str));
        }

        let device_response: serde_json::Value = http_client
            .post(device_endpoint)
            .form(&params)
            .send()
            .map_err(|e| anyhow::anyhow!("Device authorization request failed: {e}"))?
            .json()
            .map_err(|e| anyhow::anyhow!("Failed to parse device response: {e}"))?;

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
        println!("│  Code expires in {expires_in} seconds                            │");
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
                // Security (MEM-03): expose_secret() at HTTP param boundary only.
                let secret_str: &str = secret.expose_secret();
                token_params.push(("client_secret", secret_str));
            }

            let response = http_client
                .post(&token_endpoint)
                .form(&token_params)
                .send()
                .map_err(|e| anyhow::anyhow!("Token request failed: {e}"))?;

            if response.status().is_success() {
                let token_response: serde_json::Value = response
                    .json()
                    .map_err(|e| anyhow::anyhow!("Failed to parse token response: {e}"))?;

                // Return token response, token endpoint, and revocation endpoint (if any).
                return Ok((token_response, token_endpoint, revocation_endpoint.clone()));
            }

            let error_response: serde_json::Value = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse error response: {e}"))?;

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
                    return Err(anyhow::anyhow!("Authentication failed: {err} - {desc}"));
                }
                None => {
                    return Err(anyhow::anyhow!("Unknown error response"));
                }
            }
        }
    })
    .await??;

    let (token_result, token_endpoint, revocation_endpoint) = token_result;

    println!();
    println!("Authentication successful!");

    // Extract token information.
    // Wrap in SecretString immediately — must not appear in logs (MEM-03).
    let access_token = SecretString::from(
        token_result["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access_token in response"))?
            .to_string(),
    );

    let expires_in = token_result["expires_in"].as_u64().unwrap_or(3600);
    let token_expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + expires_in as i64;

    // Storage write: expose_secret() is the audit boundary for persistence.
    storage.store(KEY_ACCESS_TOKEN, access_token.expose_secret().as_bytes())?;

    // For software signers: persist the DPoP private key (it's held in process memory).
    // For hardware signers (YubiKey, TPM): the key never leaves the device — do NOT store it.
    if signer_type_for_storage == "software" {
        // load_or_create_signer already stored the key; nothing to do here.
        // This branch exists for clarity: hardware signers must NOT write KEY_DPOP_PRIVATE.
    }

    // Store token metadata (expiry, refresh token, OIDC config for refresh, and signer_type).
    // signer_type is read back at daemon startup to reconstruct the correct signer.
    // Storage write: expose_secret() is the audit boundary — raw value written to disk only here.
    let metadata = serde_json::json!({
        "expires_at": token_expires,
        "refresh_token": token_result["refresh_token"].as_str(),
        "issuer": issuer_for_storage,
        "token_endpoint": token_endpoint,
        "client_id": client_id_for_storage,
        "client_secret": client_secret_for_storage.as_ref().map(|s| { let v: &str = s.expose_secret(); v }),
        // Persisted signer type: restored by load_agent_state() on daemon restart.
        // "software" means key is in KEY_DPOP_PRIVATE; hardware specs mean key is on device.
        "signer_type": signer_type_for_storage,
        // RFC 7009: revocation endpoint from OIDC discovery (optional).
        // Populated only when the IdP advertises "revocation_endpoint" in discovery.
        // cleanup_session() uses this to send best-effort revocation on session close.
        "revocation_endpoint": revocation_endpoint,
    });
    storage.store(KEY_TOKEN_METADATA, metadata.to_string().as_bytes())?;

    println!("Token stored successfully");
    println!("Token expires in: {expires_in}s");
    if signer_type_for_storage != "software" {
        println!(
            "Signer: {} (hardware key on device)",
            format_signer_type(&signer_type_for_storage)
        );
    }
    println!();
    println!("Start the agent daemon with: unix-oidc-agent serve");

    Ok(())
}

/// Format a signer type spec for user-friendly display.
///
/// - `"software"` → `"software"`
/// - `"yubikey:9a"` → `"yubikey (slot 9a)"`
/// - `"tpm"` → `"tpm"`
fn format_signer_type(spec: &str) -> String {
    if let Some(slot) = spec.strip_prefix("yubikey:") {
        format!("yubikey (slot {slot})")
    } else {
        spec.to_string()
    }
}

/// Provision a hardware key for DPoP signing.
async fn run_provision(signer_spec: String) -> anyhow::Result<()> {
    if signer_spec == "software" || signer_spec.is_empty() {
        println!("Software signer auto-generates at login. No provisioning needed.");
        println!("Run `unix-oidc-agent login` to authenticate with a software key.");
        return Ok(());
    }

    // Validate yubikey slot spec up front.
    if signer_spec.starts_with("yubikey:") {
        let slot = signer_spec.strip_prefix("yubikey:").unwrap_or("");
        if slot.is_empty() {
            anyhow::bail!(
                "YubiKey slot must be specified: --signer yubikey:9a (PIV Authentication slot recommended)"
            );
        }
    }

    println!(
        "Provisioning key on {}...",
        format_signer_type(&signer_spec)
    );

    let config = SignerConfig::load();
    let (signer_type, signer) = provision_signer(&signer_spec, &config)?;

    println!(
        "Key provisioned successfully on {}.",
        format_signer_type(&signer_type)
    );
    println!("DPoP thumbprint: {}", signer.thumbprint());
    println!();
    println!("Run `unix-oidc-agent login --signer {signer_type}` to authenticate.");

    Ok(())
}

/// Logout - clear tokens but keep keypair
async fn run_logout() -> anyhow::Result<()> {
    let storage = StorageRouter::detect()?;

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
    let storage = StorageRouter::detect()?;

    // Load token metadata
    let metadata_bytes = storage
        .retrieve(KEY_TOKEN_METADATA)
        .map_err(|_| anyhow::anyhow!("No token metadata found. Please login first."))?;

    let metadata: serde_json::Value = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse token metadata: {e}"))?;

    // Security (MEM-03): wrap refresh_token in SecretString at extraction — must not appear in logs.
    let refresh_token = SecretString::from(
        metadata["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No refresh token found. Please login again."))?
            .to_string(),
    );

    // Get OIDC config
    let token_endpoint = metadata["token_endpoint"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No token endpoint found. Please login again."))?
        .to_string();

    let client_id = metadata["client_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No client_id found. Please login again."))?
        .to_string();

    // Security (MEM-03): wrap client_secret in SecretString at extraction — must not appear in logs.
    let client_secret: Option<SecretString> = metadata["client_secret"]
        .as_str()
        .map(|s| SecretString::from(s.to_string()));

    println!("Refreshing access token...");

    // Load agent config for timeout parameters.
    // Failure is non-fatal — use defaults so the refresh flow still works.
    let device_flow_timeout_secs = AgentConfig::load()
        .map(|c| c.timeouts.device_flow_http_timeout_secs)
        .unwrap_or(30);

    // Perform refresh in blocking task.
    // SecretString is Clone (String: CloneableSecret in secrecy 0.10) — safe to clone for closure capture.
    let refresh_token_clone = refresh_token.clone();
    let token_result = tokio::task::spawn_blocking(move || {
        use std::time::Duration;

        // device_flow_timeout_secs is loaded from AgentConfig above (default 30s).
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(device_flow_timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        let refresh_token_str: &str = refresh_token_clone.expose_secret();
        let mut params = vec![
            ("grant_type", "refresh_token"),
            // Security (MEM-03): expose_secret() at HTTP param boundary only.
            ("refresh_token", refresh_token_str),
            ("client_id", client_id.as_str()),
        ];

        if let Some(ref secret) = client_secret {
            // Security (MEM-03): expose_secret() at HTTP param boundary only.
            let secret_str: &str = secret.expose_secret();
            params.push(("client_secret", secret_str));
        }

        let response = http_client
            .post(&token_endpoint)
            .form(&params)
            .send()
            .map_err(|e| anyhow::anyhow!("Token refresh request failed: {e}"))?;

        if response.status().is_success() {
            let token_response: serde_json::Value = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse token response: {e}"))?;
            Ok(token_response)
        } else {
            let error: serde_json::Value = response
                .json()
                .unwrap_or_else(|_| serde_json::json!({"error": "unknown"}));
            let error_msg = error["error_description"]
                .as_str()
                .or(error["error"].as_str())
                .unwrap_or("Unknown error");
            Err(anyhow::anyhow!("Token refresh failed: {error_msg}"))
        }
    })
    .await??;

    // Extract new token information.
    // Wrap in SecretString immediately — must not appear in logs (MEM-03).
    let access_token = SecretString::from(
        token_result["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access_token in refresh response"))?
            .to_string(),
    );

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

    // Storage write: expose_secret() is the audit boundary for persistence.
    storage.store(KEY_ACCESS_TOKEN, access_token.expose_secret().as_bytes())?;

    // Update token metadata
    let updated_metadata = serde_json::json!({
        "expires_at": token_expires,
        "refresh_token": new_refresh_token,
        "issuer": metadata["issuer"],
        "token_endpoint": metadata["token_endpoint"],
        "client_id": metadata["client_id"],
        "client_secret": metadata["client_secret"],
        // Preserve signer_type across refresh — prevents hardware signer users from losing DPoP binding
        "signer_type": metadata["signer_type"],
    });
    storage.store(KEY_TOKEN_METADATA, updated_metadata.to_string().as_bytes())?;

    println!("Token refreshed successfully!");
    println!("Token expires in: {expires_in}s");

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

    let storage = StorageRouter::detect()?;
    let mut cleared = Vec::new();

    // Delete all stored credentials (includes PQ seed if PQC feature is compiled in)
    #[allow(unused_mut)]
    let mut keys_to_delete: Vec<&str> = vec![
        KEY_DPOP_PRIVATE,
        KEY_ACCESS_TOKEN,
        KEY_TOKEN_METADATA,
        "unix-oidc-refresh-token",
    ];
    #[cfg(feature = "pqc")]
    keys_to_delete.push(KEY_PQ_SEED);
    for key in &keys_to_delete {
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
            println!("  - {key}");
        }
        println!();
        println!("All credentials deleted.");
    }

    Ok(())
}

/// Load agent state from storage, restoring the correct signer backend from metadata.
///
/// For software signers: loads or creates the DPoP key from `KEY_DPOP_PRIVATE`.
/// For hardware signers (yubikey:*, tpm): calls `build_signer()` to re-open the device key.
///
/// Per CONTEXT.md design decision: if a hardware signer is specified in metadata but the
/// device is unavailable, signer is set to None (ERROR logged, no silent fallback to software).
async fn load_agent_state() -> anyhow::Result<AgentState> {
    let storage = match StorageRouter::detect() {
        Ok(s) => s,
        Err(_) => {
            info!("No storage available, starting with empty state");
            return Ok(AgentState::new());
        }
    };

    // Read token metadata to determine signer type (stored by run_login).
    let metadata: Option<serde_json::Value> = storage
        .retrieve(KEY_TOKEN_METADATA)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| serde_json::from_str(&s).ok());

    let signer_type_from_metadata = metadata
        .as_ref()
        .and_then(|v| v["signer_type"].as_str())
        .map(|s| s.to_string());

    let (signer, signer_type): (
        Option<Arc<dyn unix_oidc_agent::crypto::DPoPSigner>>,
        Option<String>,
    ) = match signer_type_from_metadata.as_deref() {
        None | Some("software") => {
            // No signer_type in metadata (pre-hardware-feature login) or explicit "software".
            let result = match load_or_create_signer(&storage) {
                Ok(s) => Some(Arc::new(s) as Arc<dyn unix_oidc_agent::crypto::DPoPSigner>),
                Err(e) => {
                    info!("Could not load software signer: {}", e);
                    None
                }
            };
            (result, Some("software".to_string()))
        }
        #[cfg(feature = "pqc")]
        Some("pqc") => {
            let result = match load_or_create_pqc_signer(&storage) {
                Ok(s) => Some(Arc::new(s) as Arc<dyn unix_oidc_agent::crypto::DPoPSigner>),
                Err(e) => {
                    error!("Could not load PQC hybrid signer: {}", e);
                    None
                }
            };
            (result, Some("pqc".to_string()))
        }
        Some(hw_spec) => {
            // Hardware signer: attempt to re-open from device.
            // No silent fallback — per CONTEXT.md: if hardware unavailable, daemon
            // starts without signing capability and user must re-login.
            let hw_config = SignerConfig::load();
            match build_signer(hw_spec, &hw_config) {
                Ok(arc) => {
                    info!(signer = %hw_spec, "Hardware signer loaded successfully");
                    (Some(arc), Some(hw_spec.to_string()))
                }
                Err(e) => {
                    error!(
                        signer = %hw_spec,
                        error = %e,
                        "Hardware signer unavailable — re-login required: \
                         `unix-oidc-agent login --signer {}`",
                        hw_spec
                    );
                    (None, Some(hw_spec.to_string()))
                }
            }
        }
    };

    let access_token_raw = storage
        .retrieve(KEY_ACCESS_TOKEN)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());

    let token_expires = metadata.as_ref().and_then(|v| v["expires_at"].as_i64());

    // Extract username from token claims (before wrapping in SecretString)
    let username = access_token_raw
        .as_ref()
        .and_then(|token| extract_username_from_token(token));

    // Security (MEM-03): wrap access token in SecretString so it is never
    // accidentally emitted via Debug/Display/tracing.
    let access_token = access_token_raw.map(SecretString::from);

    // Extract OIDC config from token metadata for CIBA step-up use.
    // Security (MEM-03): client_secret wrapped in SecretString at extraction point.
    let oidc_issuer = metadata
        .as_ref()
        .and_then(|v| v["issuer"].as_str())
        .map(|s| s.to_string());

    let oidc_client_id = metadata
        .as_ref()
        .and_then(|v| v["client_id"].as_str())
        .map(|s| s.to_string());

    let oidc_client_secret: Option<SecretString> = metadata
        .as_ref()
        .and_then(|v| v["client_secret"].as_str())
        .map(|s| SecretString::from(s.to_string()));

    Ok(AgentState {
        signer,
        access_token,
        token_expires,
        username,
        metrics: std::sync::Arc::new(unix_oidc_agent::metrics::MetricsCollector::new()),
        mlock_status: None,
        storage_backend: None,
        migration_status: None,
        signer_type,
        refresh_task: None,
        refresh_failed: false,
        oidc_issuer,
        oidc_client_id,
        oidc_client_secret,
        pending_step_ups: std::collections::HashMap::new(),
    })
}

/// Load existing signer or create a new one
fn load_or_create_signer(storage: &dyn SecureStorage) -> anyhow::Result<SoftwareSigner> {
    if let Ok(key_bytes) = storage.retrieve(KEY_DPOP_PRIVATE) {
        info!("Loading existing DPoP keypair");
        SoftwareSigner::import_key(&key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to import key: {e}"))
    } else {
        info!("Generating new DPoP keypair");
        let signer = SoftwareSigner::generate();
        storage.store(KEY_DPOP_PRIVATE, &signer.export_key())?;
        Ok(signer)
    }
}

/// Load existing PQC hybrid signer or create a new one.
///
/// Stores both the EC key (`KEY_DPOP_PRIVATE`) and the ML-DSA seed (`KEY_PQ_SEED`).
/// Both are 32 bytes. The EC key is shared with `SoftwareSigner` so downgrading
/// from PQC to classic ES256 is seamless (the same EC key is reused).
#[cfg(feature = "pqc")]
fn load_or_create_pqc_signer(
    storage: &dyn SecureStorage,
) -> anyhow::Result<unix_oidc_agent::crypto::HybridPqcSigner> {
    let ec_bytes_opt = storage.retrieve(KEY_DPOP_PRIVATE).ok();
    let pq_seed_opt = storage.retrieve(KEY_PQ_SEED).ok();

    match (ec_bytes_opt, pq_seed_opt) {
        (Some(ec_bytes), Some(pq_seed)) => {
            info!("Loading existing PQC hybrid DPoP keypair");
            unix_oidc_agent::crypto::HybridPqcSigner::from_key_bytes(&ec_bytes, &pq_seed)
                .map_err(|e| anyhow::anyhow!("Failed to import PQC hybrid key: {e}"))
        }
        _ => {
            info!("Generating new PQC hybrid DPoP keypair (ML-DSA-65 + ES256)");
            let signer = unix_oidc_agent::crypto::HybridPqcSigner::generate();
            storage.store(KEY_DPOP_PRIVATE, &signer.export_ec_key())?;
            storage.store(KEY_PQ_SEED, &signer.export_pq_seed())?;
            Ok(signer)
        }
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

// ── launchd plist template (compiled in at build time) ───────────────────────
//
// The template is embedded so that `unix-oidc-agent install` works without
// requiring the contrib/ directory to be present on the target machine.
#[cfg(target_os = "macos")]
const LAUNCHD_PLIST_TEMPLATE: &str =
    include_str!("../../contrib/launchd/com.unix-oidc.agent.plist.template");

/// Label used in the plist and in launchctl commands.
#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "com.unix-oidc.agent";

/// Install the agent as a launchd service (macOS) or print instructions (Linux).
///
/// On macOS:
///   1. Resolves the binary path (--binary-path or current_exe()).
///   2. Determines the per-user socket path via $TMPDIR.
///   3. Substitutes {{BINARY_PATH}}, {{SOCKET_PATH}}, {{HOME}} in the template.
///   4. Writes the plist to ~/Library/LaunchAgents/com.unix-oidc.agent.plist.
///   5. Runs `launchctl load <plist>` to activate the service.
///
/// On Linux: prints a message directing the user to the contrib/systemd/ units.
async fn run_install(binary_path: Option<String>) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        // Resolve binary path: explicit flag > current executable.
        let bin = match binary_path {
            Some(p) => p,
            None => std::env::current_exe()
                .map_err(|e| anyhow::anyhow!("Cannot determine current executable: {}", e))?
                .to_string_lossy()
                .into_owned(),
        };

        // macOS sets $TMPDIR to a per-user temp directory (e.g. /var/folders/…/T/).
        // Use it so that multiple users on the same host each get their own socket.
        let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        let socket_path = format!("{}/unix-oidc-agent.sock", tmpdir.trim_end_matches('/'));

        // Home directory for log paths and plist destination.
        let home = std::env::var("HOME").map_err(|_| {
            anyhow::anyhow!("$HOME is not set — cannot determine LaunchAgents path")
        })?;

        // Substitute all template placeholders.
        let plist_content = LAUNCHD_PLIST_TEMPLATE
            .replace("{{BINARY_PATH}}", &bin)
            .replace("{{SOCKET_PATH}}", &socket_path)
            .replace("{{HOME}}", &home);

        // Ensure ~/Library/LaunchAgents/ and ~/Library/Logs/ exist.
        let launch_agents_dir = format!("{}/Library/LaunchAgents", home);
        let logs_dir = format!("{}/Library/Logs", home);
        std::fs::create_dir_all(&launch_agents_dir)
            .map_err(|e| anyhow::anyhow!("Cannot create {}: {}", launch_agents_dir, e))?;
        std::fs::create_dir_all(&logs_dir)
            .map_err(|e| anyhow::anyhow!("Cannot create {}: {}", logs_dir, e))?;

        // Write the plist file.
        let plist_path = format!("{}/{}.plist", launch_agents_dir, LAUNCHD_LABEL);
        std::fs::write(&plist_path, &plist_content)
            .map_err(|e| anyhow::anyhow!("Cannot write plist to {}: {}", plist_path, e))?;
        info!(plist_path = %plist_path, "Plist written");

        // Load via launchctl — this activates the service immediately.
        //
        // `launchctl load` may emit a deprecation warning on macOS >= 13 recommending
        // `launchctl bootstrap domain-target plist`; both work for per-user LaunchAgents.
        // We use `load` for maximum backward compatibility (macOS 11+).
        let status = std::process::Command::new("launchctl")
            .args(["load", &plist_path])
            .status()
            .map_err(|e| anyhow::anyhow!("Failed to run launchctl load: {}", e))?;

        if !status.success() {
            // launchctl exits non-zero if the service is already loaded.  Check whether
            // the service is actually running before treating this as a fatal error.
            let running = std::process::Command::new("launchctl")
                .args(["list", LAUNCHD_LABEL])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            if running {
                println!("Agent already loaded (launchctl load returned non-zero, but service is running).");
            } else {
                anyhow::bail!(
                    "launchctl load failed with exit code {:?}; plist written to {}",
                    status.code(),
                    plist_path
                );
            }
        }

        println!("unix-oidc-agent installed and loaded.");
        println!();
        println!("  Plist:   {}", plist_path);
        println!("  Socket:  {}", socket_path);
        println!("  Binary:  {}", bin);
        println!("  Logs:    {}/Library/Logs/unix-oidc-agent.log", home);
        println!();
        println!("The agent will start automatically at login.");
        println!("Run `unix-oidc-agent login` to authenticate.");

        Ok(())
    }

    // Non-macOS platforms: print instructions for the systemd units.
    #[cfg(not(target_os = "macos"))]
    {
        // Accept the flag for forward compat but do not use it on Linux.
        let _ = binary_path;

        println!("Automatic installation is only supported on macOS (launchd).");
        println!();
        println!("On Linux, install the systemd user units from contrib/systemd/:");
        println!();
        println!("  cp contrib/systemd/unix-oidc-agent.service ~/.config/systemd/user/");
        println!("  cp contrib/systemd/unix-oidc-agent.socket   ~/.config/systemd/user/");
        println!("  systemctl --user daemon-reload");
        println!("  systemctl --user enable --now unix-oidc-agent.socket");

        Ok(())
    }
}

/// Uninstall the launchd service (macOS) or print instructions (Linux).
///
/// On macOS:
///   1. Runs `launchctl unload ~/Library/LaunchAgents/com.unix-oidc.agent.plist`.
///   2. Removes the plist file.
///
/// On Linux: prints the equivalent systemd disable command.
async fn run_uninstall() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("$HOME is not set"))?;
        let plist_path = format!("{}/Library/LaunchAgents/{}.plist", home, LAUNCHD_LABEL);

        if !std::path::Path::new(&plist_path).exists() {
            println!(
                "Plist not found at {} — agent may not be installed.",
                plist_path
            );
            return Ok(());
        }

        // Unload first; ignore errors (service might already be stopped).
        let status = std::process::Command::new("launchctl")
            .args(["unload", &plist_path])
            .status()
            .map_err(|e| anyhow::anyhow!("Failed to run launchctl unload: {}", e))?;

        if !status.success() {
            warn!(
                "launchctl unload returned non-zero exit code {:?}; proceeding with plist removal",
                status.code()
            );
        }

        // Remove plist file.
        std::fs::remove_file(&plist_path)
            .map_err(|e| anyhow::anyhow!("Cannot remove {}: {}", plist_path, e))?;
        info!(plist_path = %plist_path, "Plist removed");

        println!("unix-oidc-agent uninstalled.");
        println!();
        println!("  Removed: {}", plist_path);
        println!();
        println!("Run `unix-oidc-agent install` to reinstall.");

        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        println!("Automatic uninstallation is only supported on macOS (launchd).");
        println!();
        println!("On Linux, disable the systemd user units:");
        println!();
        println!("  systemctl --user disable --now unix-oidc-agent.socket");
        println!("  systemctl --user disable --now unix-oidc-agent.service");
        println!("  rm ~/.config/systemd/user/unix-oidc-agent.{{service,socket}}");
        println!("  systemctl --user daemon-reload");

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    /// Helper that mimics the updated_metadata construction pattern used in
    /// run_refresh() and perform_token_refresh(). This is the exact pattern
    /// from production code — if the production pattern changes, this helper
    /// must be updated to match.
    fn build_refresh_metadata(metadata: &serde_json::Value) -> serde_json::Value {
        let new_refresh_token = "new-rt";
        let token_expires = "2026-01-01T00:00:00Z";
        serde_json::json!({
            "expires_at": token_expires,
            "refresh_token": new_refresh_token,
            "issuer": metadata["issuer"],
            "token_endpoint": metadata["token_endpoint"],
            "client_id": metadata["client_id"],
            "client_secret": metadata["client_secret"],
            // Preserve signer_type across refresh — prevents hardware signer users from losing DPoP binding
            "signer_type": metadata["signer_type"],
        })
    }

    #[test]
    fn test_refresh_metadata_preserves_signer_type() {
        // YubiKey signer type
        let metadata = serde_json::json!({
            "expires_at": "2025-12-31T00:00:00Z",
            "refresh_token": "old-rt",
            "issuer": "https://idp.example.com",
            "token_endpoint": "https://idp.example.com/token",
            "client_id": "my-client",
            "client_secret": "my-secret",
            "signer_type": "yubikey:9a",
        });
        let updated = build_refresh_metadata(&metadata);
        assert_eq!(updated["signer_type"].as_str(), Some("yubikey:9a"));

        // TPM signer type
        let metadata_tpm = serde_json::json!({
            "expires_at": "2025-12-31T00:00:00Z",
            "refresh_token": "old-rt",
            "issuer": "https://idp.example.com",
            "token_endpoint": "https://idp.example.com/token",
            "client_id": "my-client",
            "client_secret": null,
            "signer_type": "tpm",
        });
        let updated_tpm = build_refresh_metadata(&metadata_tpm);
        assert_eq!(updated_tpm["signer_type"].as_str(), Some("tpm"));

        // Software signer type
        let metadata_sw = serde_json::json!({
            "expires_at": "2025-12-31T00:00:00Z",
            "refresh_token": "old-rt",
            "issuer": "https://idp.example.com",
            "token_endpoint": "https://idp.example.com/token",
            "client_id": "my-client",
            "client_secret": null,
            "signer_type": "software",
        });
        let updated_sw = build_refresh_metadata(&metadata_sw);
        assert_eq!(updated_sw["signer_type"].as_str(), Some("software"));

        // Legacy metadata with NO signer_type field (pre-hardware-feature login)
        let metadata_legacy = serde_json::json!({
            "expires_at": "2025-12-31T00:00:00Z",
            "refresh_token": "old-rt",
            "issuer": "https://idp.example.com",
            "token_endpoint": "https://idp.example.com/token",
            "client_id": "my-client",
            "client_secret": null,
        });
        let updated_legacy = build_refresh_metadata(&metadata_legacy);
        assert!(
            updated_legacy["signer_type"].is_null(),
            "Legacy metadata without signer_type should produce null, not crash"
        );
    }

    // ── launchd install ──────────────────────────────────────────────────────────
    /// Verify template substitution produces valid XML with no remaining placeholders.
    #[test]
    fn test_install_template_substitution_no_placeholders() {
        let template = include_str!("../../contrib/launchd/com.unix-oidc.agent.plist.template");
        let substituted = template
            .replace("{{BINARY_PATH}}", "/usr/local/bin/unix-oidc-agent")
            .replace("{{SOCKET_PATH}}", "/tmp/unix-oidc-agent.sock")
            .replace("{{HOME}}", "/Users/testuser");

        // No remaining placeholders after substitution.
        assert!(
            !substituted.contains("{{"),
            "Substituted plist still contains '{{' — unresolved placeholder"
        );
        assert!(
            !substituted.contains("}}"),
            "Substituted plist still contains '}}' — unresolved placeholder"
        );

        // Must look like XML.
        assert!(
            substituted.starts_with("<?xml"),
            "Substituted plist does not start with XML declaration"
        );

        // Key structural elements must be present.
        assert!(substituted.contains("com.unix-oidc.agent"), "Label missing");
        assert!(substituted.contains("KeepAlive"), "KeepAlive missing");
        assert!(substituted.contains("RunAtLoad"), "RunAtLoad missing");
        assert!(substituted.contains("Sockets"), "Sockets dict missing");
        assert!(
            substituted.contains("/usr/local/bin/unix-oidc-agent"),
            "Binary path not substituted"
        );
        assert!(
            substituted.contains("/tmp/unix-oidc-agent.sock"),
            "Socket path not substituted"
        );
        assert!(
            substituted.contains("/Users/testuser"),
            "HOME not substituted"
        );
    }
}
