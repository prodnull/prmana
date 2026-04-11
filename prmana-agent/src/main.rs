//! prmana-agent: OIDC authentication agent with DPoP support
//!
//! This agent manages OIDC tokens and DPoP proofs for passwordless SSH authentication.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use jsonwebtoken::dangerous::insecure_decode;
use pam_prmana::oidc::jwks::OidcDiscovery;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use prmana_agent::auth_code::{
    build_authorization_url, exchange_code, generate_pkce, start_callback_listener,
    CallbackListener, TokenExchangeRequest, CALLBACK_TIMEOUT_SECS,
};
use prmana_agent::config::{AgentConfig, ClientAttestationConfig};
use prmana_agent::crypto::protected_key::mlock_probe;
use prmana_agent::crypto::{
    build_client_attestation_headers, DPoPSigner, MlockStatus, SoftwareSigner,
};
use prmana_agent::daemon::{
    acquire_listener, spawn_refresh_task, AgentClient, AgentRequest, AgentResponse,
    AgentResponseData, AgentServer, AgentState,
};
use prmana_agent::hardware::{build_signer, provision_signer, SignerConfig};
use prmana_agent::sanitize::sanitize_terminal_output;
use prmana_agent::security::disable_core_dumps;
#[cfg(feature = "pqc")]
use prmana_agent::storage::KEY_PQ_SEED;
use prmana_agent::storage::{
    SecureStorage, StorageRouter, KEY_ACCESS_TOKEN, KEY_DPOP_PRIVATE, KEY_TOKEN_METADATA,
};
use uuid::Uuid;

mod askpass;

/// Initialise the tracing subscriber with JSON auto-detection.
///
/// # JSON auto-detection
///
/// JSON output is selected when **either** of the following conditions is true:
///
/// - `PRMANA_LOG_FORMAT=json` — explicit operator opt-in (useful for
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
/// The default directive is `prmana_agent=info` so the daemon is quiet by
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
        .unwrap_or_else(|_| EnvFilter::new("prmana_agent=info,warn"));

    // Determine whether JSON output is requested.
    let use_json = std::env::var("PRMANA_LOG_FORMAT")
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
#[command(name = "prmana-agent")]
#[command(about = "OIDC authentication agent with DPoP support")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with the IdP using device flow or auth code + PKCE
    Login {
        /// IdP issuer URL (defaults to OIDC_ISSUER env var)
        #[arg(long)]
        issuer: Option<String>,

        /// OAuth client ID (defaults to OIDC_CLIENT_ID or "prmana")
        #[arg(long)]
        client_id: Option<String>,

        /// OAuth client secret (optional, prefer OIDC_CLIENT_SECRET env var)
        #[arg(long, hide = true)]
        client_secret: Option<String>,

        /// Signer backend: software (default), yubikey:<slot> (e.g. yubikey:9a), tpm, spire.
        /// Hardware signers (yubikey, tpm) must be provisioned first with `provision --signer <spec>`.
        /// SPIRE signer fetches JWT-SVIDs from local SPIRE agent (requires --features spire).
        #[arg(long, default_value = "software")]
        signer: String,

        /// OAuth login flow: device (default) or authcode.
        #[arg(long, default_value = "device")]
        flow: String,
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
        /// Socket path (defaults to $XDG_RUNTIME_DIR/prmana-agent.sock)
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
        /// Path to the prmana-agent binary.
        /// Defaults to the currently-running executable (std::env::current_exe()).
        #[arg(long)]
        binary_path: Option<String>,
    },

    /// Uninstall the launchd service (macOS) or print systemd instructions (Linux).
    ///
    /// On macOS, runs `launchctl unload` and removes the plist from ~/Library/LaunchAgents/.
    Uninstall,

    /// Exchange a subject token for a new DPoP-bound token targeting a different audience.
    ///
    /// Used for multi-hop SSH: a jump host exchanges the user's token for a new
    /// token bound to the jump host's DPoP key, targeting the next hop.
    /// Implements RFC 8693 (Token Exchange) with DPoP rebinding per ADR-005.
    Exchange {
        /// The subject token to exchange (from the connecting user's SSH session).
        #[arg(long)]
        subject_token: String,

        /// Target audience (hostname of the next hop).
        #[arg(long)]
        audience: String,

        /// IdP token endpoint URL override. If not specified, discovered from stored issuer config.
        #[arg(long)]
        token_endpoint: Option<String>,
    },

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
    /// export SSH_ASKPASS=prmana-agent
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
    // JSON mode is activated by PRMANA_LOG_FORMAT=json or when running
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
            flow,
        } => run_login(issuer, client_id, client_secret, signer, flow).await,

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

        Commands::Exchange {
            subject_token,
            audience,
            token_endpoint,
        } => {
            let client = AgentClient::default();
            let response = client
                .send(AgentRequest::ExchangeToken {
                    subject_token,
                    audience,
                    method: "SSH".to_string(),
                    token_endpoint,
                })
                .await;
            match response {
                Ok(AgentResponse::Success(data)) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".to_string())
                    );
                    Ok(())
                }
                Ok(AgentResponse::Error { message, code }) => {
                    eprintln!("Exchange failed: {message} ({code})");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error: Could not connect to agent: {e}");
                    eprintln!("Start the agent with: prmana-agent serve");
                    Err(anyhow::anyhow!("Agent connection error: {e}"))
                }
            }
        }

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

    info!(socket_path = %socket_path.display(), "Starting prmana-agent daemon");

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
    use prmana_agent::config::TimeoutsConfig;
    let timeouts = match AgentConfig::load() {
        Ok(config) => {
            info!("Configuration validated");
            config.timeouts
        }
        Err(e) => {
            warn!(error = %e, "Configuration load/validation warning (using defaults)");
            TimeoutsConfig::default()
        }
    };
    let ipc_idle_timeout_secs = timeouts.ipc_idle_timeout_secs;
    let sweep_interval_secs = timeouts.sweep_interval_secs;

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
            use pam_prmana::oidc::JwksProvider;
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
        sd_notify::NotifyState::Status("prmana-agent ready"),
    ]);
    info!("Agent ready (sd_notify READY=1 sent if systemd-managed)");

    let server = AgentServer::new(socket_path, state)
        .with_idle_timeout(Duration::from_secs(ipc_idle_timeout_secs))
        .with_sweep_interval(Duration::from_secs(sweep_interval_secs))
        .with_session_dir(PathBuf::from("/run/prmana/sessions/"));
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
            presence_cache_ttl_secs,
            presence_cache_active,
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
            if let Some(ttl) = presence_cache_ttl_secs {
                let active = presence_cache_active.unwrap_or(0);
                if ttl > 0 {
                    println!("  Presence cache: {ttl}s TTL, {active} active");
                } else {
                    println!("  Presence cache: disabled");
                }
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
            println!("  Start the agent with: prmana-agent serve");

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

    match client
        .get_proof(&target, &method, nonce.as_deref(), None)
        .await
    {
        Ok(AgentResponse::Success(AgentResponseData::Proof {
            token,
            dpop_proof,
            expires_in,
            ..
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
                eprintln!("Error: Not logged in. Run: prmana-agent login");
            }
            Err(anyhow::anyhow!("Agent error: {message}"))
        }
        Ok(_) => Err(anyhow::anyhow!("Unexpected response from agent")),
        Err(e) => {
            eprintln!("Error: Could not connect to agent: {e}");
            eprintln!("Start the agent with: prmana-agent serve");
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
    flow: String,
) -> anyhow::Result<()> {
    let issuer = issuer
        .or_else(|| std::env::var("OIDC_ISSUER").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("OIDC_ISSUER not set. Use --issuer or set OIDC_ISSUER env var")
        })?;

    let client_id = client_id
        .or_else(|| std::env::var("OIDC_CLIENT_ID").ok())
        .unwrap_or_else(|| "prmana".to_string());

    // Security: warn if client_secret was passed via CLI arg — visible in `ps` output.
    // Prefer OIDC_CLIENT_SECRET env var instead.
    if client_secret.is_some() {
        eprintln!(
            "WARNING: --client-secret passes secrets via command line (visible in ps). \
             Use OIDC_CLIENT_SECRET env var instead."
        );
    }

    // Security (MEM-03): wrap client_secret in SecretString immediately — must not appear in logs.
    let client_secret: Option<SecretString> = client_secret.map(SecretString::from).or_else(|| {
        std::env::var("OIDC_CLIENT_SECRET")
            .ok()
            .map(SecretString::from)
    });

    if flow != "device" && flow != "authcode" {
        anyhow::bail!("Invalid --flow value '{flow}'. Supported values: device, authcode");
    }

    info!(issuer = %issuer, flow = %flow, "Starting authentication flow");

    // Load agent config for timeout and skew parameters.
    // Failure is non-fatal — use defaults so the login flow still works.
    let agent_config = AgentConfig::load().unwrap_or_default();
    let device_flow_timeout_secs = agent_config.timeouts.device_flow_http_timeout_secs;

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
                    let arc: Arc<dyn DPoPSigner> = Arc::new(*pqc);
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

    // ── SPIRE login path (Phase 35-02, Codex HIGH-1 fix) ────────────────────
    //
    // SPIRE sessions bypass device flow entirely: the JWT-SVID is the access
    // token, fetched directly from the local SPIRE agent. No refresh tokens,
    // no token endpoints, no client secrets.
    #[cfg(feature = "spire")]
    if signer_spec == "spire" {
        println!("Fetching JWT-SVID from SPIRE agent...");

        // Build a fresh SpireSigner to call fetch_svid().
        // We already have one in signer_arc, but we need the concrete type
        // for fetch_svid() which is not on the DPoPSigner trait.
        let hw_config = SignerConfig::load();
        let spire_cfg = hw_config
            .spire
            .as_ref()
            .map(|s| prmana_agent::crypto::SpireConfig {
                socket_path: s.socket_path.clone().unwrap_or_else(|| {
                    prmana_agent::crypto::spire_signer::DEFAULT_SPIRE_SOCKET.to_string()
                }),
                audience: s.audience.clone().unwrap_or_default(),
                spiffe_id: s.spiffe_id.clone(),
            })
            .unwrap_or_default();
        let spire_signer = prmana_agent::crypto::SpireSigner::new(spire_cfg)
            .map_err(|e| anyhow::anyhow!("Failed to create SpireSigner: {e}"))?;

        let (spiffe_id, svid_token) = spire_signer
            .fetch_svid_async()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch JWT-SVID from SPIRE agent: {e}"))?;

        println!("SPIFFE ID: {spiffe_id}");
        println!("JWT-SVID acquired from SPIRE agent");

        // Parse SVID expiry for metadata.
        let svid_exp = prmana_agent::crypto::spire_signer::parse_jwt_exp_secs(&svid_token);
        let token_expires = svid_exp.unwrap_or_else(|| {
            // Default: 5 minutes from now (typical SVID TTL).
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            (now + 300) as i64
        });

        // Store JWT-SVID as the access token.
        let access_token = SecretString::from(svid_token);
        storage.store(KEY_ACCESS_TOKEN, access_token.expose_secret().as_bytes())?;

        // SPIRE metadata: no refresh token, no token endpoint, no client secret.
        let metadata = serde_json::json!({
            "expires_at": token_expires,
            "refresh_token": null,
            "issuer": issuer,
            "token_endpoint": null,
            "client_id": client_id,
            "client_secret": null,
            "signer_type": "spire",
            "revocation_endpoint": null,
            "spiffe_id": spiffe_id,
        });
        storage.store(KEY_TOKEN_METADATA, metadata.to_string().as_bytes())?;

        println!("JWT-SVID stored successfully");
        println!("SVID expires at: {token_expires}");
        println!();
        println!("Start the agent daemon with: prmana-agent serve");
        return Ok(());
    }

    // ── Failover-aware login (Phase 41) ──────────────────────────────────
    //
    // Check if the requested issuer has a failover pair configured. If so,
    // attempt login against the primary; on availability failure, retry with
    // the secondary. In-flight requests are never switched mid-stream — if
    // a flow fails, the entire attempt against that issuer fails and the next
    // attempt uses the failover target.
    use prmana_agent::failover::{FailoverPairConfig, FailoverRuntime};

    let failover_pair: Option<FailoverPairConfig> = agent_config
        .failover_pairs
        .iter()
        .find(|p| {
            p.primary_issuer_url.trim_end_matches('/') == issuer.trim_end_matches('/')
                || p.secondary_issuer_url.trim_end_matches('/') == issuer.trim_end_matches('/')
        })
        .cloned();

    // Attempt login against a single issuer. Returns typed error to distinguish
    // availability failures from policy/protocol failures.
    let attempt_login = |target_issuer: String,
                         flow_type: String,
                         cid: String,
                         csecret: Option<SecretString>,
                         signer: Arc<dyn DPoPSigner>,
                         attestation: ClientAttestationConfig,
                         timeout: u64| async move {
        let discovery = match fetch_oidc_discovery(&target_issuer, timeout).await {
            Ok(d) => d,
            Err(e) => {
                // Classify discovery failure: if the error message contains typical
                // availability indicators, treat as availability failure.
                let is_availability = e.to_string().contains("Failed to fetch OIDC discovery")
                    || e.to_string().contains("HTTP 5");
                return Err((e, is_availability));
            }
        };

        let result = if flow_type == "authcode" {
            let authorization_endpoint = discovery
                .authorization_endpoint
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("IdP does not advertise authorization_endpoint"));
            let authorization_endpoint = match authorization_endpoint {
                Ok(ep) => ep,
                Err(e) => return Err((e, false)),
            };

            if let Some(methods) = &discovery.code_challenge_methods_supported {
                if !methods.iter().any(|m| m == "S256") {
                    return Err((
                        anyhow::anyhow!("IdP does not advertise PKCE S256 support"),
                        false,
                    ));
                }
            }

            run_auth_code_flow(
                authorization_endpoint,
                &discovery.token_endpoint,
                discovery.revocation_endpoint.clone(),
                &cid,
                csecret.as_ref(),
                signer.as_ref(),
                &attestation,
                timeout,
            )
            .await
        } else {
            let device_endpoint = match discovery.device_authorization_endpoint.clone() {
                Some(ep) => ep,
                None => {
                    return Err((
                        anyhow::anyhow!("IdP does not support device authorization"),
                        false,
                    ))
                }
            };

            run_device_flow(
                &device_endpoint,
                &discovery.token_endpoint,
                discovery.revocation_endpoint.clone(),
                &cid,
                csecret,
                signer,
                attestation,
                timeout,
            )
            .await
        };

        match result {
            Ok(token_result) => Ok((token_result, target_issuer, discovery.token_endpoint)),
            Err(e) => {
                // Classify the login flow error for failover purposes.
                let err_str = e.to_string();
                let is_availability = err_str.contains("request failed")
                    || err_str.contains("timed out")
                    || err_str.contains("connection")
                    || err_str.contains("connect")
                    || err_str.contains("DNS")
                    || err_str.contains("HTTP 5");
                Err((e, is_availability))
            }
        }
    };

    let (token_result, effective_issuer, token_endpoint) = if let Some(ref pair) = failover_pair {
        let mut runtime = FailoverRuntime::new(pair.clone());
        let resolved = runtime.resolve_issuer();
        let target = resolved.issuer_url.clone();

        println!("Starting {flow} flow with: {target} (failover pair configured)");
        println!("Client ID: {client_id}");
        println!();

        match attempt_login(
            target.clone(),
            flow.clone(),
            client_id.clone(),
            client_secret.clone(),
            Arc::clone(&signer_arc),
            agent_config.client_attestation.clone(),
            pair.request_timeout_secs,
        )
        .await
        {
            Ok(result) => {
                runtime.record_success(&target);
                result
            }
            Err((primary_err, is_availability)) => {
                if !is_availability {
                    // Policy/protocol failure — no failover.
                    return Err(primary_err);
                }

                // Availability failure — record and try secondary.
                if let Some(event) = runtime.record_failure(&target, &primary_err.to_string()) {
                    warn!("Failover event: {event:?}");
                }

                let fallback = runtime.resolve_issuer();
                if fallback.issuer_url.trim_end_matches('/') == target.trim_end_matches('/') {
                    // No different issuer to try (already exhausted or same).
                    return Err(primary_err
                        .context("Primary issuer unavailable and no failover target available"));
                }

                println!();
                warn!(
                    primary = %target,
                    secondary = %fallback.issuer_url,
                    "Primary issuer unavailable — failing over to secondary"
                );
                println!("Retrying with: {}", fallback.issuer_url);
                println!();

                match attempt_login(
                    fallback.issuer_url.clone(),
                    flow.clone(),
                    client_id.clone(),
                    client_secret.clone(),
                    Arc::clone(&signer_arc),
                    agent_config.client_attestation.clone(),
                    pair.request_timeout_secs,
                )
                .await
                {
                    Ok(result) => {
                        runtime.record_success(&fallback.issuer_url);
                        info!(
                            secondary = %fallback.issuer_url,
                            "Login succeeded via secondary issuer"
                        );
                        result
                    }
                    Err((secondary_err, _)) => {
                        runtime.record_failure(&fallback.issuer_url, &secondary_err.to_string());
                        Err(secondary_err.context("Both primary and secondary issuers unavailable"))?
                    }
                }
            }
        }
    } else {
        // No failover pair — standard single-issuer login.
        println!("Starting {flow} flow with: {issuer}");
        println!("Client ID: {client_id}");
        println!();

        let discovery = fetch_oidc_discovery(&issuer, device_flow_timeout_secs).await?;

        let result = if flow == "authcode" {
            let authorization_endpoint = discovery
                .authorization_endpoint
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("IdP does not advertise authorization_endpoint"))?;

            if let Some(methods) = &discovery.code_challenge_methods_supported {
                if !methods.iter().any(|m| m == "S256") {
                    anyhow::bail!("IdP does not advertise PKCE S256 support");
                }
            }

            run_auth_code_flow(
                authorization_endpoint,
                &discovery.token_endpoint,
                discovery.revocation_endpoint.clone(),
                &client_id,
                client_secret.as_ref(),
                signer_arc.as_ref(),
                &agent_config.client_attestation,
                device_flow_timeout_secs,
            )
            .await?
        } else {
            let device_endpoint = discovery
                .device_authorization_endpoint
                .clone()
                .ok_or_else(|| anyhow::anyhow!("IdP does not support device authorization"))?;

            run_device_flow(
                &device_endpoint,
                &discovery.token_endpoint,
                discovery.revocation_endpoint.clone(),
                &client_id,
                client_secret.clone(),
                Arc::clone(&signer_arc),
                agent_config.client_attestation.clone(),
                device_flow_timeout_secs,
            )
            .await?
        };

        (result, issuer.clone(), discovery.token_endpoint.clone())
    };

    println!();
    println!("Authentication successful!");

    // token_result is (json_response, token_endpoint_used, revocation_endpoint)
    // effective_issuer is the issuer URL that was actually used (may differ from CLI if failover)
    // token_endpoint is the token endpoint from discovery of the effective issuer
    persist_login_tokens(
        &mut storage,
        &token_result.0,
        &effective_issuer,
        &token_endpoint,
        &client_id,
        client_secret.as_ref(),
        &signer_type,
        token_result.2.as_deref(),
    )?;

    let expires_in = token_result.0["expires_in"].as_u64().unwrap_or(3600);
    println!("Token stored successfully");
    println!("Token expires in: {expires_in}s");
    if signer_type != "software" {
        println!(
            "Signer: {} (hardware key on device)",
            format_signer_type(&signer_type)
        );
    }
    println!();
    println!("Start the agent daemon with: prmana-agent serve");

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_device_flow(
    device_endpoint: &str,
    token_endpoint: &str,
    revocation_endpoint: Option<String>,
    client_id: &str,
    client_secret: Option<SecretString>,
    signer_for_poll: Arc<dyn DPoPSigner>,
    client_attestation: ClientAttestationConfig,
    device_flow_timeout_secs: u64,
) -> anyhow::Result<(serde_json::Value, String, Option<String>)> {
    let device_endpoint = device_endpoint.to_string();
    let token_endpoint = token_endpoint.to_string();
    let client_id = client_id.to_string();
    tokio::task::spawn_blocking(move || {
        use std::time::Duration;
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(device_flow_timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        // Start device authorization
        let mut params = vec![("client_id", client_id.as_str()), ("scope", "openid")];

        if let Some(ref secret) = client_secret {
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

        let verification_uri_raw = device_response["verification_uri"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No verification_uri in response"))?;

        // SHRD-05: Sanitize terminal escape sequences from IdP-supplied URIs.
        // A compromised IdP could inject ANSI escape sequences to attack the terminal.
        let (verification_uri, uri_was_sanitized) = sanitize_terminal_output(verification_uri_raw);
        if uri_was_sanitized {
            let removed = prmana_agent::sanitize::format_removed_bytes(
                verification_uri_raw,
                &verification_uri,
            );
            warn!(
                raw_uri_len = verification_uri_raw.len(),
                sanitized_uri_len = verification_uri.len(),
                removed_bytes = %removed,
                "Sanitized terminal escape sequences from verification_uri"
            );
        }

        let verification_uri_complete_raw = device_response["verification_uri_complete"].as_str();
        let verification_uri_complete = verification_uri_complete_raw.map(|raw| {
            let (sanitized, was_modified) = sanitize_terminal_output(raw);
            if was_modified {
                let removed = prmana_agent::sanitize::format_removed_bytes(raw, &sanitized);
                warn!(
                    raw_uri_len = raw.len(),
                    sanitized_uri_len = sanitized.len(),
                    removed_bytes = %removed,
                    "Sanitized terminal escape sequences from verification_uri_complete"
                );
            }
            sanitized
        });

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
        if let Some(ref complete_uri) = verification_uri_complete {
            println!("│  Or visit directly:                                      │");
            let uri_display = if complete_uri.len() > 50 {
                format!("{}...", &complete_uri[..47])
            } else {
                complete_uri.clone()
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
                ("client_id", client_id.as_str()),
            ];

            if let Some(ref secret) = client_secret {
                // Security (MEM-03): expose_secret() at HTTP param boundary only.
                let secret_str: &str = secret.expose_secret();
                token_params.push(("client_secret", secret_str));
            }

            // RFC 9449 §4.2: Include a fresh DPoP proof with each token request
            // so the AS can bind the issued access token to the client's key.
            let dpop_proof = signer_for_poll
                .sign_proof("POST", &token_endpoint, None)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to generate DPoP proof for token request: {e}")
                })?;

            let response = http_client
                .post(&token_endpoint)
                .header("DPoP", &dpop_proof);
            let response = if let Some(headers) = build_client_attestation_headers(
                signer_for_poll.as_ref(),
                Some(&client_attestation),
                client_id.as_str(),
                &token_endpoint,
            )
            .map_err(|e| anyhow::anyhow!("Failed to attach client attestation headers: {e}"))?
            {
                response
                    .header("OAuth-Client-Attestation", headers.attestation)
                    .header("OAuth-Client-Attestation-PoP", headers.pop)
            } else {
                response
            }
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
    .await?
}

#[allow(clippy::too_many_arguments)]
async fn run_auth_code_flow(
    authorization_endpoint: &str,
    token_endpoint: &str,
    revocation_endpoint: Option<String>,
    client_id: &str,
    client_secret: Option<&SecretString>,
    signer: &dyn DPoPSigner,
    client_attestation: &ClientAttestationConfig,
    http_timeout_secs: u64,
) -> anyhow::Result<(serde_json::Value, String, Option<String>)> {
    let (code_verifier, code_challenge) = generate_pkce();
    let state = Uuid::new_v4().to_string();
    let listener: CallbackListener = start_callback_listener(&state).await?;
    let redirect_uri = listener.redirect_uri().to_string();
    let authorization_url = build_authorization_url(
        authorization_endpoint,
        client_id,
        &redirect_uri,
        "openid",
        &state,
        &code_challenge,
    )?;

    println!("Open this URL in your browser to continue:");
    let authorization_url_str = authorization_url.to_string();
    let (safe_url, was_sanitized) = sanitize_terminal_output(&authorization_url_str);
    if was_sanitized {
        warn!("Sanitized terminal escape sequences from authorization URL");
    }
    println!("{safe_url}");
    println!();

    if let Err(e) = open::that(&authorization_url_str) {
        warn!(error = %e, "Failed to launch browser automatically");
    }

    let callback = listener
        .wait(Duration::from_secs(CALLBACK_TIMEOUT_SECS))
        .await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(http_timeout_secs))
        .build()?;
    let token_response = exchange_code(
        &client,
        signer,
        TokenExchangeRequest {
            token_endpoint,
            code: &callback.code,
            redirect_uri: &redirect_uri,
            code_verifier: &code_verifier,
            client_id,
            client_secret: client_secret.map(ExposeSecret::expose_secret),
            client_attestation: Some(client_attestation),
        },
    )
    .await?;

    Ok((
        token_response,
        token_endpoint.to_string(),
        revocation_endpoint,
    ))
}

async fn fetch_oidc_discovery(issuer: &str, timeout_secs: u64) -> anyhow::Result<OidcDiscovery> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;

    let response = client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch OIDC discovery: {e}"))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Failed to fetch OIDC discovery: HTTP {}: {}",
            response.status(),
            discovery_url
        );
    }

    response
        .json::<OidcDiscovery>()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse OIDC discovery: {e}"))
}

#[allow(clippy::too_many_arguments)]
fn persist_login_tokens(
    storage: &mut StorageRouter,
    token_result: &serde_json::Value,
    issuer: &str,
    token_endpoint: &str,
    client_id: &str,
    client_secret: Option<&SecretString>,
    signer_type: &str,
    revocation_endpoint: Option<&str>,
) -> anyhow::Result<()> {
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

    storage.store(KEY_ACCESS_TOKEN, access_token.expose_secret().as_bytes())?;

    let metadata = serde_json::json!({
        "expires_at": token_expires,
        "refresh_token": token_result["refresh_token"].as_str(),
        "issuer": issuer,
        "token_endpoint": token_endpoint,
        "client_id": client_id,
        "client_secret": client_secret.map(ExposeSecret::expose_secret),
        "signer_type": signer_type,
        "revocation_endpoint": revocation_endpoint,
    });
    storage.store(KEY_TOKEN_METADATA, metadata.to_string().as_bytes())?;
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
        println!("Run `prmana-agent login` to authenticate with a software key.");
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
    println!("Run `prmana-agent login --signer {signer_type}` to authenticate.");

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

    if storage.exists("prmana-refresh-token") {
        storage.delete("prmana-refresh-token")?;
        cleared = true;
        println!("Refresh token cleared");
    }

    if cleared {
        println!();
        println!("Logged out successfully. DPoP keypair retained.");
        println!("Run 'prmana-agent reset --force' to delete everything.");
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

    let signer_type = metadata["signer_type"].as_str().unwrap_or("software");

    // ── SPIRE sessions: re-acquire SVID instead of OAuth refresh (Codex HIGH-2) ──
    #[cfg(feature = "spire")]
    if signer_type == "spire" {
        println!("Refreshing JWT-SVID from SPIRE agent...");
        let hw_config = SignerConfig::load();
        let spire_cfg = hw_config
            .spire
            .as_ref()
            .map(|s| prmana_agent::crypto::SpireConfig {
                socket_path: s.socket_path.clone().unwrap_or_else(|| {
                    prmana_agent::crypto::spire_signer::DEFAULT_SPIRE_SOCKET.to_string()
                }),
                audience: s.audience.clone().unwrap_or_default(),
                spiffe_id: s.spiffe_id.clone(),
            })
            .unwrap_or_default();
        let spire_signer = prmana_agent::crypto::SpireSigner::new(spire_cfg)
            .map_err(|e| anyhow::anyhow!("Failed to create SpireSigner: {e}"))?;

        let (spiffe_id, svid_token) = spire_signer
            .fetch_svid_async()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to refresh JWT-SVID from SPIRE agent: {e}"))?;

        let svid_exp = prmana_agent::crypto::spire_signer::parse_jwt_exp_secs(&svid_token);
        let token_expires = svid_exp.unwrap_or_else(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            (now + 300) as i64
        });

        let access_token = SecretString::from(svid_token);
        storage.store(KEY_ACCESS_TOKEN, access_token.expose_secret().as_bytes())?;

        // Update metadata with new expiry.
        let new_metadata = serde_json::json!({
            "expires_at": token_expires,
            "refresh_token": null,
            "issuer": metadata["issuer"],
            "token_endpoint": null,
            "client_id": metadata["client_id"],
            "client_secret": null,
            "signer_type": "spire",
            "revocation_endpoint": null,
            "spiffe_id": spiffe_id,
        });
        storage.store(KEY_TOKEN_METADATA, new_metadata.to_string().as_bytes())?;

        println!("JWT-SVID refreshed successfully (expires at {token_expires})");
        return Ok(());
    }

    // ── Standard OAuth refresh path ──────────────────────────────────────────

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

    // RFC 9449 §4.2: DPoP proof must be included in token refresh requests.
    // Load the signer from storage to generate a fresh proof.
    // Codex HIGH-2: branch by signer_type so hardware signers reopen the device.
    let signer: Arc<dyn DPoPSigner> = {
        match signer_type {
            #[cfg(feature = "pqc")]
            "pqc" => {
                let pqc = load_or_create_pqc_signer(&storage)?;
                Arc::new(*pqc) as Arc<dyn DPoPSigner>
            }
            "software" | "" => {
                let sw = load_or_create_signer(&storage)?;
                Arc::new(sw) as Arc<dyn DPoPSigner>
            }
            hw_spec => {
                // Hardware signers (yubikey:<slot>, tpm): reopen via build_signer.
                let hw_config = SignerConfig::load();
                build_signer(hw_spec, &hw_config)?
            }
        }
    };

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

        // RFC 9449 §4.2: Include fresh DPoP proof in refresh requests.
        let dpop_proof = signer
            .sign_proof("POST", &token_endpoint, None)
            .map_err(|e| anyhow::anyhow!("Failed to generate DPoP proof for refresh: {e}"))?;

        let response = http_client
            .post(&token_endpoint)
            .header("DPoP", &dpop_proof)
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
        "prmana-refresh-token",
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
        Option<Arc<dyn prmana_agent::crypto::DPoPSigner>>,
        Option<String>,
    ) = match signer_type_from_metadata.as_deref() {
        None | Some("software") => {
            // No signer_type in metadata (pre-hardware-feature login) or explicit "software".
            let result = match load_or_create_signer(&storage) {
                Ok(s) => Some(Arc::new(s) as Arc<dyn prmana_agent::crypto::DPoPSigner>),
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
                Ok(s) => Some(Arc::new(*s) as Arc<dyn prmana_agent::crypto::DPoPSigner>),
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
                         `prmana-agent login --signer {}`",
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
        metrics: std::sync::Arc::new(prmana_agent::metrics::MetricsCollector::new()),
        mlock_status: None,
        storage_backend: None,
        migration_status: None,
        signer_type,
        refresh_task: None,
        refresh_failed: false,
        oidc_issuer,
        oidc_client_id,
        oidc_client_secret,
        presence_cache: prmana_agent::daemon::presence_cache::PresenceCache::new(
            prmana_agent::daemon::presence_cache::DEFAULT_PRESENCE_CACHE_TTL_SECS,
        ),
        pending_step_ups: std::collections::HashMap::new(),
        failover_runtimes: std::collections::HashMap::new(),
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
) -> anyhow::Result<Box<prmana_agent::crypto::HybridPqcSigner>> {
    let ec_bytes_opt = storage.retrieve(KEY_DPOP_PRIVATE).ok();
    let pq_seed_opt = storage.retrieve(KEY_PQ_SEED).ok();

    match (ec_bytes_opt, pq_seed_opt) {
        (Some(ec_bytes), Some(pq_seed)) => {
            info!("Loading existing PQC hybrid DPoP keypair");
            prmana_agent::crypto::HybridPqcSigner::from_key_bytes(&ec_bytes, &pq_seed)
                .map_err(|e| anyhow::anyhow!("Failed to import PQC hybrid key: {e}"))
        }
        _ => {
            info!("Generating new PQC hybrid DPoP keypair (ML-DSA-65 + ES256)");
            let signer = prmana_agent::crypto::HybridPqcSigner::generate();
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
    match insecure_decode::<TokenClaims>(token) {
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
// The template is embedded so that `prmana-agent install` works without
// requiring the contrib/ directory to be present on the target machine.
#[cfg(target_os = "macos")]
const LAUNCHD_PLIST_TEMPLATE: &str =
    include_str!("../../contrib/launchd/com.prmana.agent.plist.template");

/// Label used in the plist and in launchctl commands.
#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "com.prmana.agent";

/// Install the agent as a launchd service (macOS) or print instructions (Linux).
///
/// On macOS:
///   1. Resolves the binary path (--binary-path or current_exe()).
///   2. Determines the per-user socket path via $TMPDIR.
///   3. Substitutes {{BINARY_PATH}}, {{SOCKET_PATH}}, {{HOME}} in the template.
///   4. Writes the plist to ~/Library/LaunchAgents/com.prmana.agent.plist.
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
        let socket_path = format!("{}/prmana-agent.sock", tmpdir.trim_end_matches('/'));

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

        println!("prmana-agent installed and loaded.");
        println!();
        println!("  Plist:   {}", plist_path);
        println!("  Socket:  {}", socket_path);
        println!("  Binary:  {}", bin);
        println!("  Logs:    {}/Library/Logs/prmana-agent.log", home);
        println!();
        println!("The agent will start automatically at login.");
        println!("Run `prmana-agent login` to authenticate.");

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
        println!("  cp contrib/systemd/prmana-agent.service ~/.config/systemd/user/");
        println!("  cp contrib/systemd/prmana-agent.socket   ~/.config/systemd/user/");
        println!("  systemctl --user daemon-reload");
        println!("  systemctl --user enable --now prmana-agent.socket");

        Ok(())
    }
}

/// Uninstall the launchd service (macOS) or print instructions (Linux).
///
/// On macOS:
///   1. Runs `launchctl unload ~/Library/LaunchAgents/com.prmana.agent.plist`.
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

        println!("prmana-agent uninstalled.");
        println!();
        println!("  Removed: {}", plist_path);
        println!();
        println!("Run `prmana-agent install` to reinstall.");

        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        println!("Automatic uninstallation is only supported on macOS (launchd).");
        println!();
        println!("On Linux, disable the systemd user units:");
        println!();
        println!("  systemctl --user disable --now prmana-agent.socket");
        println!("  systemctl --user disable --now prmana-agent.service");
        println!("  rm ~/.config/systemd/user/prmana-agent.{{service,socket}}");
        println!("  systemctl --user daemon-reload");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ── F-03: --client-secret CLI exposure mitigation ─────────────────────────

    /// F-03 positive: --client-secret is hidden from help output.
    /// Users who discover it via source should prefer OIDC_CLIENT_SECRET env var.
    #[test]
    fn test_client_secret_arg_hidden_from_help() {
        use clap::CommandFactory;
        let cmd = super::Cli::command();

        // Find the "login" subcommand
        let login_cmd = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "login")
            .expect("login subcommand must exist");

        // Find the --client-secret argument
        let arg = login_cmd
            .get_arguments()
            .find(|a| a.get_id() == "client_secret")
            .expect("client_secret argument must exist");

        assert!(
            arg.is_hide_set(),
            "--client-secret must be hidden from help output to discourage CLI usage"
        );
    }

    /// F-03 negative: --client-secret is NOT shown in rendered help text.
    #[test]
    fn test_client_secret_absent_from_rendered_help() {
        use clap::CommandFactory;
        let mut cmd = super::Cli::command();
        let mut buf = Vec::new();

        // Get the login subcommand's help text
        let login_cmd = cmd
            .find_subcommand_mut("login")
            .expect("login subcommand must exist");
        login_cmd.write_help(&mut buf).unwrap();
        let help_text = String::from_utf8(buf).unwrap();

        assert!(
            !help_text.contains("--client-secret"),
            "--client-secret must not appear in help output, got:\n{help_text}"
        );
    }

    // ── launchd install ──────────────────────────────────────────────────────────
    /// Verify template substitution produces valid XML with no remaining placeholders.
    #[test]
    fn test_install_template_substitution_no_placeholders() {
        let template = include_str!("../../contrib/launchd/com.prmana.agent.plist.template");
        let substituted = template
            .replace("{{BINARY_PATH}}", "/usr/local/bin/prmana-agent")
            .replace("{{SOCKET_PATH}}", "/tmp/prmana-agent.sock")
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
        assert!(substituted.contains("com.prmana.agent"), "Label missing");
        assert!(substituted.contains("KeepAlive"), "KeepAlive missing");
        assert!(substituted.contains("RunAtLoad"), "RunAtLoad missing");
        assert!(substituted.contains("Sockets"), "Sockets dict missing");
        assert!(
            substituted.contains("/usr/local/bin/prmana-agent"),
            "Binary path not substituted"
        );
        assert!(
            substituted.contains("/tmp/prmana-agent.sock"),
            "Socket path not substituted"
        );
        assert!(
            substituted.contains("/Users/testuser"),
            "HOME not substituted"
        );
    }

    #[tokio::test]
    async fn test_device_flow_token_poll_no_attestation_headers_when_disabled() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/device"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "dev-code",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://idp.example.com/verify",
                "expires_in": 30,
                "interval": 0
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok",
                "expires_in": 3600
            })))
            .mount(&server)
            .await;

        let signer: Arc<dyn DPoPSigner> = Arc::new(SoftwareSigner::generate());
        let disabled = ClientAttestationConfig {
            enabled: false,
            lifetime_secs: 3600,
        };
        let result = run_device_flow(
            &format!("{}/device", server.uri()),
            &format!("{}/token", server.uri()),
            None,
            "prmana",
            None,
            signer,
            disabled,
            5,
        )
        .await;

        assert!(result.is_ok());
        let requests = server.received_requests().await.unwrap();
        let token_req = requests
            .iter()
            .find(|r| r.url.path() == "/token")
            .expect("token request must be sent");
        assert!(!token_req.headers.contains_key("OAuth-Client-Attestation"));
        assert!(!token_req
            .headers
            .contains_key("OAuth-Client-Attestation-PoP"));
    }
}
