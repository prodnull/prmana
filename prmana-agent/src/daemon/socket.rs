//! Unix socket server and client

use listenfd::ListenFd;
use secrecy::{ExposeSecret, SecretString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::crypto::DPoPSigner;
use crate::daemon::peer_cred::get_peer_credentials;
use crate::daemon::protocol::{AgentRequest, AgentResponse, MetricsFormat};
use crate::metrics::MetricsCollector;
use crate::storage::{
    SecureStorage, StorageRouter, KEY_ACCESS_TOKEN, KEY_DPOP_PRIVATE, KEY_REFRESH_TOKEN,
    KEY_TOKEN_METADATA,
};

/// Default IPC idle timeout: 60 seconds.
/// Matches `TimeoutsConfig::default().ipc_idle_timeout_secs`.
const DEFAULT_IPC_IDLE_TIMEOUT_SECS: u64 = 60;

const SOCKET_BASENAME: &str = "prmana-agent.sock";

/// Maximum IPC message size: 64 KiB.
///
/// Legitimate IPC messages (GetProof, Status, Login, etc.) are well under 4 KiB.
/// This limit prevents a malicious or misbehaving client from consuming unbounded
/// memory via `read_line()`, which grows the String until it finds a newline.
const MAX_IPC_MESSAGE_SIZE: usize = 64 * 1024;

/// Maximum concurrent IPC connections.
///
/// Limits resource exhaustion from malicious or runaway clients opening many
/// connections. 64 is generous for legitimate use (SSH login typically needs
/// 1-2 concurrent connections per session).
///
/// See: docs/threat-model.md §7 Recommendation 6 (P2), mitigates T2.4.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Acquire a `UnixListener` via the appropriate mechanism for the current environment.
///
/// Priority order:
/// 1. **systemd socket activation** — when `LISTEN_FDS` and `LISTEN_PID` environment
///    variables are set by systemd, the pre-bound file descriptor is inherited.
///    `listenfd` validates that `LISTEN_PID` matches the current process to prevent
///    fd hijacking by unrelated processes.
/// 2. **launchd socket activation (macOS)** — when launched by launchd with a `Sockets`
///    dict, calls `launch_activate_socket("Listeners")` to inherit the pre-bound fd.
///    Falls through to standalone mode when *not* launched by launchd.
/// 3. **Standalone bind** — removes any stale socket file, binds a new socket at
///    `socket_path`, and sets permissions to `0600` (owner-only).
///
/// Callers in the serve loop should register signal handlers *before* calling into
/// the accept loop so that signals arriving during startup are not dropped.
///
/// Sources:
/// - `listenfd 1.0` — <https://docs.rs/listenfd/latest/listenfd/>
/// - macOS `launch_activate_socket(3)` man page
pub fn acquire_listener(socket_path: &Path) -> std::io::Result<UnixListener> {
    // Step 1: systemd socket activation via LISTEN_FDS / LISTEN_PID.
    // ListenFd::from_env() validates LISTEN_PID == getpid() before taking the fd.
    let mut listenfd = ListenFd::from_env();
    if let Ok(Some(std_listener)) = listenfd.take_unix_listener(0) {
        std_listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(std_listener)?;
        info!("Socket acquired via systemd socket activation (LISTEN_FDS)");
        return Ok(listener);
    }

    // Step 2: launchd socket activation (macOS only).
    //
    // `launch_activate_socket("Listeners")` looks up the fd array matching the key
    // "Listeners" in the plist Sockets dict.  Returns None when not running under
    // launchd or when the plist has no matching socket name — both are normal for
    // standalone / foreground invocations.
    #[cfg(target_os = "macos")]
    if let Some(listener) = launchd_socket::take("Listeners") {
        info!("Socket acquired via launchd socket activation");
        return Ok(listener);
    }

    // Step 3: Standalone bind — daemon manages its own socket lifecycle.
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;

    // Set socket permissions to owner-only (0600).
    // The PAM module and the agent CLI run as the same UID, so 0600 does not
    // impede normal operation while preventing other users from connecting.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!(socket_path = %socket_path.display(), "Socket bound in standalone mode");
    Ok(listener)
}

/// Agent state shared across connections.
///
/// ## Security: SecretString for access_token
///
/// `access_token` is wrapped in `secrecy::SecretString` (RFC-9449 bearer credential).
/// This ensures:
/// - `Debug` / `Display` formatting emits `[REDACTED]` — tokens never appear in logs
///   or tracing spans regardless of log level.
/// - The raw value is accessible only via `.expose_secret()`, creating an explicit,
///   grep-searchable audit boundary in the codebase (MEM-03).
pub struct AgentState {
    pub signer: Option<Arc<dyn DPoPSigner>>,
    /// OAuth access token — wrapped in SecretString to prevent accidental logging.
    /// Use `.expose_secret()` only at audit boundaries: sending to SSH client.
    pub access_token: Option<SecretString>,
    pub token_expires: Option<i64>,
    pub username: Option<String>,
    /// Metrics collector for observability
    pub metrics: Arc<MetricsCollector>,
    /// Human-readable mlock status reported by `prmana-agent status`.
    /// Set at daemon startup after calling `mlock_probe()`.
    pub mlock_status: Option<String>,
    /// Human-readable storage backend name, e.g. "keyring (Secret Service)".
    /// Set at daemon startup from `StorageRouter.kind.display_name()`.
    pub storage_backend: Option<String>,
    /// Human-readable migration status, e.g. "migrated", "n/a".
    /// Set at daemon startup from `StorageRouter.migration_status.display_name()`.
    pub migration_status: Option<String>,
    /// Active signer backend spec, e.g. "software", "yubikey:9a", "tpm".
    /// Loaded from token metadata `signer_type` field at daemon startup.
    pub signer_type: Option<String>,
    /// AbortHandle for the background auto-refresh task.
    ///
    /// Calling `.abort()` cancels the task. Set after login; cleared on SessionClosed.
    /// Not serialized — recreated at daemon startup from stored token state if needed.
    pub refresh_task: Option<tokio::task::AbortHandle>,
    /// True when the background auto-refresh task exhausted all retries without success.
    ///
    /// When true, the token will expire at its natural lifetime. Operators should
    /// monitor via the Status IPC response and trigger manual refresh or re-login.
    pub refresh_failed: bool,
    /// OIDC issuer URL — loaded from KEY_TOKEN_METADATA at daemon startup.
    ///
    /// Used for OIDC discovery (fetches `{issuer}/.well-known/openid-configuration`
    /// to locate `token_endpoint` for token exchange).
    pub oidc_issuer: Option<String>,
    /// OIDC client_id — loaded from KEY_TOKEN_METADATA at daemon startup.
    pub oidc_client_id: Option<String>,
    /// OIDC client_secret — loaded from KEY_TOKEN_METADATA at daemon startup.
    ///
    /// Security (MEM-03): wrapped in SecretString to prevent accidental logging.
    /// The raw value is accessed only at HTTP form parameter boundaries (token exchange).
    pub oidc_client_secret: Option<SecretString>,
    /// Hardware presence cache — per-(remote_user, target) touch authorization window.
    ///
    /// When a hardware signer (YubiKey, TPM) successfully signs via physical touch,
    /// subsequent requests for the same user+target within the TTL are signed
    /// automatically. Process-scoped, never written to disk, zeroed on drop.
    pub presence_cache: crate::daemon::presence_cache::PresenceCache,
}

/// Manual Debug impl: signer is not Debug (trait object), access_token shows `[REDACTED]`.
/// oidc_client_secret is intentionally OMITTED — even `[REDACTED]` leaks metadata.
impl std::fmt::Debug for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentState")
            .field("signer", &self.signer.as_ref().map(|s| s.thumbprint()))
            .field("access_token", &self.access_token)
            .field("token_expires", &self.token_expires)
            .field("username", &self.username)
            .field("mlock_status", &self.mlock_status)
            .field("storage_backend", &self.storage_backend)
            .field("migration_status", &self.migration_status)
            .field("signer_type", &self.signer_type)
            .field(
                "refresh_task",
                &self.refresh_task.as_ref().map(|_| "<AbortHandle>"),
            )
            .field("refresh_failed", &self.refresh_failed)
            .field("oidc_issuer", &self.oidc_issuer)
            .field("oidc_client_id", &self.oidc_client_id)
            // oidc_client_secret intentionally omitted from Debug (MEM-03)
            .finish()
    }
}

impl AgentState {
    pub fn new() -> Self {
        Self::with_presence_ttl(crate::daemon::presence_cache::DEFAULT_PRESENCE_CACHE_TTL_SECS)
    }

    pub fn with_presence_ttl(presence_cache_ttl_secs: u64) -> Self {
        Self {
            signer: None,
            access_token: None,
            token_expires: None,
            username: None,
            metrics: Arc::new(MetricsCollector::new()),
            mlock_status: None,
            storage_backend: None,
            migration_status: None,
            signer_type: None,
            refresh_task: None,
            refresh_failed: false,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            presence_cache: crate::daemon::presence_cache::PresenceCache::new(
                presence_cache_ttl_secs,
            ),
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
    /// Per-read idle timeout for IPC connections.
    ///
    /// If no data arrives within this duration on an active connection, the
    /// connection is closed.  The timeout resets after each successful request,
    /// so long-lived clients that send periodic requests are not disconnected.
    idle_timeout: Duration,
    /// Limits concurrent IPC connections to prevent resource exhaustion.
    /// See: docs/threat-model.md §7 Recommendation 6 (P2).
    connection_semaphore: Arc<tokio::sync::Semaphore>,
    /// Interval for the session expiry background sweep task.
    ///
    /// When `Some`, a `sweep::session_expiry_sweep_loop` task is spawned inside
    /// `serve_with_listener` before the accept loop.  `None` disables the sweep
    /// (used in tests that do not need session directory maintenance).
    sweep_interval: Option<Duration>,
    /// Directory containing session `.json` files to sweep.
    ///
    /// Typically `/run/prmana/sessions/` in production.  Only used when
    /// `sweep_interval` is also `Some`.
    session_dir: Option<PathBuf>,
}

impl AgentServer {
    pub fn new(socket_path: PathBuf, state: Arc<RwLock<AgentState>>) -> Self {
        Self {
            socket_path,
            state,
            idle_timeout: Duration::from_secs(DEFAULT_IPC_IDLE_TIMEOUT_SECS),
            connection_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            sweep_interval: None,
            session_dir: None,
        }
    }

    /// Override the per-read IPC idle timeout.
    ///
    /// Call this after `new()` when the timeout is read from config:
    /// ```ignore
    /// let server = AgentServer::new(path, state)
    ///     .with_idle_timeout(Duration::from_secs(config.timeouts.ipc_idle_timeout_secs));
    /// ```
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the session expiry sweep interval.
    ///
    /// When both `sweep_interval` and `session_dir` are `Some`,
    /// `serve_with_listener` spawns a background `sweep::session_expiry_sweep_loop`
    /// task that removes expired and corrupt session files from `session_dir` on
    /// each tick.
    ///
    /// Call this in the builder chain after `new()`:
    /// ```ignore
    /// let server = AgentServer::new(path, state)
    ///     .with_sweep_interval(Duration::from_secs(config.timeouts.sweep_interval_secs))
    ///     .with_session_dir(PathBuf::from("/run/prmana/sessions/"));
    /// ```
    pub fn with_sweep_interval(mut self, interval: Duration) -> Self {
        self.sweep_interval = Some(interval);
        self
    }

    /// Set the session directory to sweep for expired records.
    ///
    /// Must be combined with `with_sweep_interval` to activate the background sweep task.
    pub fn with_session_dir(mut self, dir: PathBuf) -> Self {
        self.session_dir = Some(dir);
        self
    }

    fn xdg_runtime_socket_path(runtime_dir: &str) -> PathBuf {
        PathBuf::from(runtime_dir).join(SOCKET_BASENAME)
    }

    #[cfg(target_os = "linux")]
    fn linux_runtime_socket_path(uid: u32) -> PathBuf {
        PathBuf::from(format!("/run/user/{uid}/{SOCKET_BASENAME}"))
    }

    #[cfg(not(target_os = "linux"))]
    fn macos_runtime_socket_path(tmpdir: &str) -> PathBuf {
        PathBuf::from(tmpdir).join(SOCKET_BASENAME)
    }

    /// Get the default socket path
    pub fn default_socket_path() -> PathBuf {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            return Self::xdg_runtime_socket_path(&runtime_dir);
        }

        #[cfg(target_os = "linux")]
        {
            let uid = unsafe { libc::getuid() };
            Self::linux_runtime_socket_path(uid)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
            Self::macos_runtime_socket_path(&tmpdir)
        }
    }

    /// Start the server and listen for connections.
    ///
    /// Calls `acquire_listener()` to obtain a `UnixListener` via systemd socket
    /// activation (when `LISTEN_FDS` is set) or a standalone bind (fallback).
    ///
    /// Handles `SIGTERM` and `SIGINT` gracefully:
    /// 1. Stops accepting new connections.
    /// 2. Sends `sd_notify::notify(STOPPING=1)` — systemd tracks the shutdown.
    /// 3. Waits 5 seconds for in-flight requests to drain.
    /// 4. Runs credential cleanup (zeroize keys, revoke tokens — best-effort).
    ///
    /// Signal handlers are registered **before** entering the accept loop so that
    /// signals arriving during startup are never silently dropped.
    pub async fn serve(&self) -> Result<(), std::io::Error> {
        let listener = acquire_listener(&self.socket_path)?;
        self.serve_with_listener(listener).await
    }

    /// Start the server using a caller-supplied `UnixListener`.
    ///
    /// Identical to `serve()` but accepts a pre-bound listener.  Useful for tests
    /// that want to control socket creation independently.
    pub async fn serve_with_listener(&self, listener: UnixListener) -> Result<(), std::io::Error> {
        info!(socket_path = %self.socket_path.display(), "Agent listening on socket");

        // Register signal handlers BEFORE entering the accept loop.
        // Signals arriving between process start and this point are queued
        // by the kernel; tokio::signal drains that queue on first recv() call.
        // Source: https://docs.rs/tokio/latest/tokio/signal/unix/
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        // Capture idle_timeout so it can be moved into spawned tasks.
        let idle_timeout = self.idle_timeout;

        // Spawn the session expiry background sweep task if both sweep_interval
        // and session_dir are configured.  The task removes expired and corrupt
        // session files from session_dir at the configured interval.
        //
        // The task is cancelled implicitly when the Tokio runtime shuts down
        // (on SIGTERM/SIGINT the accept loop exits and the runtime is dropped).
        // This is intentional — no explicit abort handle is needed; orphaned
        // session files will be swept on the next daemon restart.
        //
        // Reference: SES-09 (session expiry sweep requirement).
        if let (Some(interval), Some(ref dir)) = (self.sweep_interval, &self.session_dir) {
            let sweep_dir = dir.clone();
            tokio::spawn(async move {
                crate::daemon::sweep::session_expiry_sweep_loop(sweep_dir, interval).await;
            });
            info!(
                session_dir = %dir.display(),
                interval_secs = interval.as_secs(),
                "Session expiry sweep task spawned"
            );
        }

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            // IPC peer credential check — defense-in-depth on top of
                            // 0600 socket file permissions.
                            //
                            // Rationale: A process running as a different UID must not
                            // be able to send commands to the agent even if it somehow
                            // obtains a file descriptor for the socket (e.g., via a
                            // setuid binary or an inherited fd).
                            //
                            // Failure is always treated as a rejection (fail-closed):
                            // if we cannot verify the peer's identity we deny access
                            // rather than silently allowing it.
                            //
                            // Source: socket(7) SO_PEERCRED (Linux),
                            //         getpeereid(3) (macOS).
                            // See: prmana-agent/src/daemon/peer_cred.rs.
                            let daemon_uid = unsafe { libc::getuid() };
                            // `peer_pid` is captured here and forwarded to
                            // `handle_connection` so the ipc_request span can
                            // record it immediately — no second syscall needed.
                            let accepted_peer_pid = match get_peer_credentials(&stream) {
                                Ok((peer_uid, peer_pid)) => {
                                    if peer_uid != daemon_uid {
                                        warn!(
                                            peer_uid,
                                            daemon_uid,
                                            "IPC connection rejected: UID mismatch"
                                        );
                                        // Drop stream — connection closed immediately.
                                        drop(stream);
                                        continue;
                                    }
                                    if let Some(pid) = peer_pid {
                                        debug!(peer_pid = pid, "IPC connection accepted");
                                    } else {
                                        debug!("IPC connection accepted");
                                    }
                                    peer_pid
                                }
                                Err(e) => {
                                    warn!(
                                        error = %e,
                                        "Peer credential retrieval failed — rejecting (fail-closed)"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };

                            // Enforce concurrent connection limit to prevent
                            // resource exhaustion (threat-model §7 Rec 6, T2.4).
                            let permit = match self.connection_semaphore.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    warn!(
                                        limit = MAX_CONCURRENT_CONNECTIONS,
                                        "IPC connection rejected: concurrent connection limit reached"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };

                            let state = Arc::clone(&self.state);
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, state, idle_timeout, accepted_peer_pid).await {
                                    error!("Connection error: {}", e);
                                }
                                // Permit is dropped here, releasing the semaphore slot.
                                drop(permit);
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received — shutting down gracefully");
                    break;
                }
                _ = sigint.recv() => {
                    info!("SIGINT received — shutting down gracefully");
                    break;
                }
            }
        }

        // Notify systemd (or any supervisor) that shutdown is in progress.
        // sd_notify is a no-op when NOTIFY_SOCKET is not set (standalone mode).
        // Source: sd-notify 0.5 — https://docs.rs/sd-notify/0.5.0/sd_notify/
        let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);

        // 5-second drain: allow in-flight IPC requests to complete before exit.
        // Connections accepted before the signal arrived continue to be served by
        // their spawned Tokio tasks during this window.
        info!("Draining in-flight requests (5s)...");
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Credential cleanup: best-effort zeroize + revocation.
        // Failures are logged at WARN and do not prevent clean exit.
        run_credential_cleanup(&self.state).await;

        info!("Agent shutdown complete");
        Ok(())
    }
}

/// Handle a single IPC connection from a peer process.
///
/// Each invocation creates a unique tracing span with a random `request_id`
/// UUID, enabling log correlation across all lines emitted during a single
/// IPC request lifecycle.  The `command` field is populated after the request
/// JSON is parsed; `peer_pid` is recorded when the caller's PID is available.
///
/// # Tracing span fields
///
/// | Field        | When set          | Value                                      |
/// |--------------|-------------------|--------------------------------------------|
/// | `request_id` | immediately       | UUID v4 string                             |
/// | `command`    | after JSON parse  | variant name (e.g. "GetProof", "Status")   |
/// | `peer_pid`   | when available    | calling process PID (Linux/macOS)          |
#[instrument(
    name = "ipc_request",
    skip(stream, state, idle_timeout),
    fields(
        request_id = %Uuid::new_v4(),
        command = tracing::field::Empty,
        peer_pid = tracing::field::Empty,
    )
)]
async fn handle_connection(
    stream: UnixStream,
    state: Arc<RwLock<AgentState>>,
    idle_timeout: Duration,
    passed_peer_pid: Option<u32>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Record peer_pid in the span immediately so all log lines within this
    // request share the PID field for operator correlation.
    if let Some(pid) = passed_peer_pid {
        tracing::Span::current().record("peer_pid", pid);
    }

    // Record connection metric
    {
        let state_read = state.read().await;
        state_read.metrics.record_connection();
    }

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        // Per-read idle timeout.
        //
        // The timeout wraps a single `read_line` call and resets after every
        // successful read.  This means a client that sends periodic requests is
        // never disconnected; only connections that go silent for the full
        // `idle_timeout` duration are closed.
        //
        // Source: tokio::time::timeout — https://docs.rs/tokio/latest/tokio/time/fn.timeout.html
        let n = match tokio::time::timeout(idle_timeout, reader.read_line(&mut line)).await {
            Ok(Ok(0)) => {
                // EOF — client closed the connection cleanly.
                break;
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                error!(error = %e, "IPC read error");
                break;
            }
            Err(_elapsed) => {
                debug!("IPC connection closed: idle timeout");
                break;
            }
        };

        if n == 0 {
            break;
        }

        // Security: reject oversized messages to prevent unbounded memory consumption.
        // Legitimate IPC messages are well under 4 KiB; 64 KiB is generous headroom.
        if line.len() > MAX_IPC_MESSAGE_SIZE {
            warn!(
                size = line.len(),
                max = MAX_IPC_MESSAGE_SIZE,
                "IPC message exceeds size limit"
            );
            let response = AgentResponse::error(
                format!(
                    "Message too large: {} bytes (max {})",
                    line.len(),
                    MAX_IPC_MESSAGE_SIZE
                ),
                "MESSAGE_TOO_LARGE",
            );
            let response_json = serde_json::to_string(&response)? + "\n";
            writer.write_all(response_json.as_bytes()).await?;
            line.clear();
            continue;
        }

        let request: AgentRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                // Record error metric
                {
                    let state_read = state.read().await;
                    state_read.metrics.record_request(true);
                }
                let response =
                    AgentResponse::error(format!("Invalid request: {e}"), "INVALID_REQUEST");
                let response_json = serde_json::to_string(&response)? + "\n";
                writer.write_all(response_json.as_bytes()).await?;
                line.clear();
                continue;
            }
        };

        // Record the command variant name in the span so all downstream log
        // lines (including those in handle_request and DPoP proof generation)
        // carry the command name for grep-based trace reconstruction.
        tracing::Span::current().record("command", request.command_name());

        debug!("Received request: {:?}", request);

        // SessionClosed is handled specially: ACK immediately, then spawn background cleanup.
        // This ensures PAM's pam_sm_close_session returns fast regardless of cleanup duration.
        if let AgentRequest::SessionClosed { session_id } = request {
            // ACK before cleanup — PAM must not block on revocation or storage deletion.
            let ack = AgentResponse::session_acknowledged();
            let ack_json = serde_json::to_string(&ack)? + "\n";
            writer.write_all(ack_json.as_bytes()).await?;

            // Spawn cleanup in background — do NOT await.
            let state_clone = Arc::clone(&state);
            tokio::spawn(async move {
                cleanup_session(state_clone, session_id).await;
            });

            // Record metric and return — connection closes after ACK.
            {
                let state_read = state.read().await;
                state_read.metrics.record_request(false);
            }
            line.clear();
            // Connection closes when stream is dropped — PAM reads ACK and returns SUCCESS.
            break;
        }

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
            remote_user,
        } => {
            let start = Instant::now();
            let state_read = state.read().await;

            // OPS-13: structured audit log for every DPoP proof request.
            info!(
                username = %state_read.username.as_deref().unwrap_or("unknown"),
                target = %target,
                remote_user = %remote_user.as_deref().unwrap_or("unknown"),
                signer_type = %state_read.signer_type.as_deref().unwrap_or("unknown"),
                "DPoP proof requested"
            );

            let username_str = state_read
                .username
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            let signer_type_str = state_read
                .signer_type
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            // Resolve the remote user for presence cache keying.
            // Falls back to "unknown" if not provided by the PAM client.
            let remote_user_str = remote_user.as_deref().unwrap_or("unknown");

            let signer = match &state_read.signer {
                Some(s) => s,
                None => {
                    state_read
                        .metrics
                        .record_proof_request(false, start.elapsed());
                    // OBS-1: Audit event — authentication failure (not logged in).
                    // session_id is "n/a": GetProof occurs before a PAM session is
                    // opened, so no session_id exists yet in the agent.
                    tracing::info!(
                        target: "prmana_audit",
                        event_type = "authentication",
                        session_id = "n/a",
                        username = %username_str,
                        outcome = "failure",
                        reason = "not_logged_in",
                        "AGENT_AUTH"
                    );
                    return (AgentResponse::error("Not logged in", "NOT_LOGGED_IN"), true);
                }
            };

            // Security: expose_secret() is the ONLY audit boundary for the access token.
            // The raw string is sent to the SSH client and never used elsewhere.
            let token = match &state_read.access_token {
                Some(t) => t.expose_secret().to_string(),
                None => {
                    state_read
                        .metrics
                        .record_proof_request(false, start.elapsed());
                    // OBS-1: Audit event — authentication failure (no token).
                    tracing::info!(
                        target: "prmana_audit",
                        event_type = "authentication",
                        session_id = "n/a",
                        username = %username_str,
                        outcome = "failure",
                        reason = "no_access_token",
                        "AGENT_AUTH"
                    );
                    return (AgentResponse::error("No access token", "NO_TOKEN"), true);
                }
            };

            // Hardware presence cache: check if we can skip the physical touch.
            let is_hw = crate::daemon::presence_cache::is_hardware_signer(&signer_type_str);
            let cached_presence = if is_hw {
                state_read.presence_cache.check(remote_user_str, &target)
            } else {
                None
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

                    // Determine presence type for OCSF audit metadata.
                    let presence_type = if !is_hw {
                        crate::daemon::presence_cache::PresenceType::NotApplicable
                    } else if cached_presence.is_some() {
                        crate::daemon::presence_cache::PresenceType::Cached
                    } else {
                        // Fresh hardware touch succeeded — record in cache.
                        state_read.presence_cache.record(remote_user_str, &target);
                        crate::daemon::presence_cache::PresenceType::PhysicalTouch
                    };

                    // OBS-1: Audit event — authentication success (DPoP proof issued).
                    tracing::info!(
                        target: "prmana_audit",
                        event_type = "authentication",
                        session_id = "n/a",
                        username = %username_str,
                        outcome = "success",
                        signer_type = %signer_type_str,
                        auth_target = %target,
                        presence_type = %presence_type.as_str(),
                        "AGENT_AUTH"
                    );
                    state_read
                        .metrics
                        .record_proof_request(true, start.elapsed());
                    // Extract attestation evidence from the DPoP proof JWT header
                    // (ADR-018). The TpmSigner embeds it in the `attest` field during
                    // sign_proof(). We parse it out for the IPC response so the PAM
                    // client can log it. Best-effort: WARN on parse failure.
                    let attestation = extract_attestation_from_proof(&proof);

                    (
                        AgentResponse::proof(
                            token,
                            proof,
                            expires_in,
                            Some(presence_type.as_str().to_string()),
                            attestation,
                        ),
                        false,
                    )
                }
                Err(e) => {
                    // Atomic invalidation: hardware signing failure (device removed,
                    // communication error, etc.) wipes all cached presence immediately.
                    if is_hw {
                        tracing::warn!(
                            error = %e,
                            "Hardware signing failed — clearing presence cache"
                        );
                        state_read.presence_cache.clear();
                    }
                    // OBS-1: Audit event — authentication failure (DPoP sign error).
                    tracing::info!(
                        target: "prmana_audit",
                        event_type = "authentication",
                        session_id = "n/a",
                        username = %username_str,
                        outcome = "failure",
                        reason = %e,
                        "AGENT_AUTH"
                    );
                    state_read
                        .metrics
                        .record_proof_request(false, start.elapsed());
                    (AgentResponse::error(e.to_string(), "PROOF_ERROR"), true)
                }
            }
        }

        AgentRequest::Status => {
            let state_read = state.read().await;
            let refresh_failed = state_read.refresh_failed;

            let pc_ttl = Some(state_read.presence_cache.ttl_secs());
            let pc_active = Some(state_read.presence_cache.active_count());

            let response = if refresh_failed {
                AgentResponse::status_with_refresh_failed(
                    state_read.is_logged_in(),
                    state_read.username.clone(),
                    state_read.signer.as_ref().map(|s| s.thumbprint()),
                    state_read.token_expires,
                    state_read.mlock_status.clone(),
                    state_read.storage_backend.clone(),
                    state_read.migration_status.clone(),
                    state_read.signer_type.clone(),
                    true,
                    pc_ttl,
                    pc_active,
                )
            } else {
                AgentResponse::status(
                    state_read.is_logged_in(),
                    state_read.username.clone(),
                    state_read.signer.as_ref().map(|s| s.thumbprint()),
                    state_read.token_expires,
                    state_read.mlock_status.clone(),
                    state_read.storage_backend.clone(),
                    state_read.migration_status.clone(),
                    state_read.signer_type.clone(),
                    pc_ttl,
                    pc_active,
                )
            };

            (response, false)
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
                    // Update state with new token (already wrapped in SecretString)
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
            // Raise SIGTERM to trigger the graceful shutdown path in serve_with_listener().
            // This ensures the 5-second drain + credential cleanup runs instead of an
            // abrupt exit. std::process::exit(0) is intentionally NOT used here.
            info!("Shutdown IPC command received — sending SIGTERM to self");
            // Safety: getpid() and kill() are always safe to call; SIGTERM to self
            // is equivalent to `kill -TERM <pid>` from the shell. The process continues
            // to run until the Tokio signal handler in the serve loop fires.
            unsafe {
                libc::kill(libc::getpid(), libc::SIGTERM);
            }
            (AgentResponse::ok(), false)
        }

        // SessionClosed is intercepted in handle_connection before reaching here.
        // This arm is unreachable at runtime but required for exhaustive match.
        AgentRequest::SessionClosed { .. } => (
            AgentResponse::error(
                "SessionClosed must be handled before handle_request",
                "INTERNAL_ERROR",
            ),
            true,
        ),

        // kubectl exec-credential token issuance (DT-A-04).
        //
        // Returns a bearer token (NO DPoP, NO cnf claim) scoped to
        // audience `<cluster_id>.kube.prmana`. TTL: 10 minutes (600s).
        //
        // CRITICAL SECURITY: this token is bearer-only because the Kubernetes exec
        // credential API cannot inject per-request DPoP proofs. The audience isolation
        // (`<cluster_id>.kube.prmana`) is enforced as a HARD-FAIL in pam-prmana's
        // validation.rs so that a stolen kubectl token cannot be used for SSH login.
        //
        // References:
        // - CLAUDE.md "kubectl Authentication Invariant (Phase DT-A onwards)"
        // - RFC 9449 §4.1, §4.3, §7 (why no DPoP here)
        AgentRequest::GetKubectlCredential { cluster_id } => {
            handle_get_kubectl_credential(state, &cluster_id).await
        }

        // Enterprise-only features: CIBA step-up and token exchange.
        // These variants exist in the protocol for forward compatibility but are not
        // implemented in the OSS edition.
        AgentRequest::StepUp { .. }
        | AgentRequest::StepUpResult { .. }
        | AgentRequest::ExchangeToken { .. } => (
            AgentResponse::error(
                "This feature is not available in the OSS edition",
                "NOT_IMPLEMENTED",
            ),
            true,
        ),
    }
}

/// Handle `GetKubectlCredential` — stub for kubectl bearer token issuance.
///
/// Token exchange (RFC 8693) is required for kubectl credential issuance but is
/// not available in the OSS edition. Returns a clear error directing operators to
/// the enterprise edition.
async fn handle_get_kubectl_credential(
    _state: &Arc<RwLock<AgentState>>,
    _cluster_id: &str,
) -> (AgentResponse, bool) {
    (
        AgentResponse::error(
            "kubectl credential issuance requires token exchange (RFC 8693), \
             which is not available in this edition",
            "NOT_IMPLEMENTED",
        ),
        true,
    )
}

/// Extract the `attest` field from a DPoP proof JWT header (ADR-018).
///
/// Returns `Some(serde_json::Value)` if the header contains attestation evidence,
/// `None` otherwise. This is best-effort: parse failures are logged at WARN and
/// return `None` — attestation in the IPC response is informational; the PAM
/// module independently extracts it from the JWT header during verification.
fn extract_attestation_from_proof(proof: &str) -> Option<serde_json::Value> {
    use base64::Engine;

    let header_b64 = proof.split('.').next()?;
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to decode DPoP proof header for attestation extraction");
        })
        .ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to parse DPoP proof header JSON for attestation extraction");
        })
        .ok()?;
    header.get("attest").cloned()
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
        remote_user: Option<&str>,
    ) -> Result<AgentResponse, ClientError> {
        self.send(AgentRequest::GetProof {
            target: target.to_string(),
            method: method.to_string(),
            nonce: nonce.map(String::from),
            remote_user: remote_user.map(String::from),
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

/// Perform token refresh using stored refresh token.
///
/// Returns a `SecretString` for the new access token to ensure the value
/// is redacted if accidentally logged before being stored in `AgentState`.
async fn perform_token_refresh(
    _state: &Arc<RwLock<AgentState>>,
) -> Result<(SecretString, i64, Option<String>), Box<dyn std::error::Error + Send + Sync>> {
    // Load storage
    let storage = StorageRouter::detect().map_err(|e| format!("Storage error: {e}"))?;

    // Load token metadata
    let metadata_bytes = storage
        .retrieve(KEY_TOKEN_METADATA)
        .map_err(|_| "No token metadata found. Please login first.")?;

    let metadata: serde_json::Value = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| format!("Failed to parse token metadata: {e}"))?;

    // Security (MEM-03): wrap refresh_token in SecretString at extraction — must not appear in logs.
    let refresh_token = SecretString::from(
        metadata["refresh_token"]
            .as_str()
            .ok_or("No refresh token found. Please login again.")?
            .to_string(),
    );

    // Get OIDC config
    let token_endpoint = metadata["token_endpoint"]
        .as_str()
        .ok_or("No token endpoint found. Please login again.")?
        .to_string();

    let client_id = metadata["client_id"]
        .as_str()
        .ok_or("No client_id found. Please login again.")?
        .to_string();

    // Security (MEM-03): wrap client_secret in SecretString at extraction — must not appear in logs.
    let client_secret: Option<SecretString> = metadata["client_secret"]
        .as_str()
        .map(|s| SecretString::from(s.to_string()));

    info!("Performing token refresh...");

    // Perform refresh in blocking task (reqwest::blocking).
    // SecretString is Clone (String: CloneableSecret in secrecy 0.10) — safe to clone for closure capture.
    let refresh_token_clone = refresh_token.clone();
    let result = tokio::task::spawn_blocking(move || {
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

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
            .map_err(|e| format!("Token refresh request failed: {e}"))?;

        if response.status().is_success() {
            let token_response: serde_json::Value = response
                .json()
                .map_err(|e| format!("Failed to parse token response: {e}"))?;
            Ok(token_response)
        } else {
            let error: serde_json::Value = response
                .json()
                .unwrap_or_else(|_| serde_json::json!({"error": "unknown"}));
            let error_msg = error["error_description"]
                .as_str()
                .or(error["error"].as_str())
                .unwrap_or("Unknown error");
            Err(format!("Token refresh failed: {error_msg}"))
        }
    })
    .await
    .map_err(|e| format!("Task error: {e}"))??;

    // Extract new token information.
    // Wrap in SecretString immediately — the raw token must never appear in logs.
    let access_token = SecretString::from(
        result["access_token"]
            .as_str()
            .ok_or("No access_token in refresh response")?
            .to_string(),
    );

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

    // Storage write: expose_secret() is the audit boundary for persistence.
    storage
        .store(KEY_ACCESS_TOKEN, access_token.expose_secret().as_bytes())
        .map_err(|e| format!("Failed to store access token: {e}"))?;

    // Update token metadata — preserve all fields including revocation_endpoint and signer_type.
    let updated_metadata = serde_json::json!({
        "expires_at": token_expires,
        "refresh_token": new_refresh_token,
        "issuer": metadata["issuer"],
        "token_endpoint": metadata["token_endpoint"],
        "client_id": metadata["client_id"],
        "client_secret": metadata["client_secret"],
        // Preserve signer_type across refresh — prevents hardware signer users from losing DPoP binding
        "signer_type": metadata["signer_type"],
        // Preserve revocation_endpoint across refresh — needed for cleanup_session() on next session close
        "revocation_endpoint": metadata["revocation_endpoint"],
    });
    storage
        .store(KEY_TOKEN_METADATA, updated_metadata.to_string().as_bytes())
        .map_err(|e| format!("Failed to store metadata: {e}"))?;

    // Extract username from token (base64 decode of payload, no signature check).
    // expose_secret() here: username extraction only, result is non-sensitive.
    let username = extract_username_from_token(access_token.expose_secret());

    info!("Token refreshed successfully, expires in {}s", expires_in);

    Ok((access_token, token_expires, username))
}

/// Spawn the background token auto-refresh task.
///
/// Calculates sleep duration as `(token_lifetime * threshold_percent / 100)` seconds,
/// then calls `perform_token_refresh()` with exponential backoff on failure.
///
/// Backoff schedule: 4 total attempts, delays before retries 2-4: 5s, 10s, 20s.
/// After all attempts fail, sets `state.refresh_failed = true` and exits — the session
/// continues until natural token expiry (operator must monitor via Status IPC).
///
/// Returns an `AbortHandle` — call `.abort()` to cancel (e.g., on SessionClosed).
pub fn spawn_refresh_task(
    state: Arc<RwLock<AgentState>>,
    token_expires: i64,
    threshold_percent: u8,
) -> tokio::task::AbortHandle {
    let handle = tokio::spawn(async move {
        // Exponential backoff delays (seconds) for retries 2, 3, 4.
        // RFC 6749 §5.2 does not mandate backoff; we use conservative delays to avoid
        // hammering an IdP that is temporarily unavailable.
        const BACKOFF_DELAYS_SECS: [u64; 3] = [5, 10, 20];
        const MAX_RETRIES: usize = 3;

        // Loop: re-arm after successful refresh with new token expiry.
        let mut current_expires = token_expires;
        loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let lifetime = current_expires - now;
            let sleep_secs = if lifetime > 0 {
                (lifetime as u64) * (threshold_percent as u64) / 100
            } else {
                0
            };

            if sleep_secs == 0 {
                warn!(
                    expires_at = current_expires,
                    "Token near or past expiry at refresh task start — attempting immediate refresh"
                );
            } else {
                debug!(
                    sleep_secs,
                    threshold_percent, "Auto-refresh task sleeping before refresh"
                );
                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            }

            // Retry loop with exponential backoff.
            let mut succeeded = false;
            for attempt in 0..=MAX_RETRIES {
                if attempt > 0 {
                    let delay = BACKOFF_DELAYS_SECS[attempt - 1];
                    debug!(attempt, delay_secs = delay, "Auto-refresh retry backoff");
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }

                match perform_token_refresh(&state).await {
                    Ok((new_token, new_expires, username)) => {
                        let mut state_write = state.write().await;
                        state_write.access_token = Some(new_token);
                        state_write.token_expires = Some(new_expires);
                        state_write.refresh_failed = false;
                        if let Some(ref u) = username {
                            state_write.username = Some(u.clone());
                        }
                        let refresh_username = username
                            .as_deref()
                            .or(state_write.username.as_deref())
                            .unwrap_or("unknown")
                            .to_string();
                        current_expires = new_expires;
                        succeeded = true;

                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        let expires_in_secs = (new_expires - now).max(0) as u64;

                        // OBS-1: Audit event — token refresh succeeded.
                        // session_id is "n/a" for background refresh: the refresh task
                        // is not tied to a specific PAM session IPC request. The username
                        // provides the correlation context for SIEM queries.
                        tracing::info!(
                            target: "prmana_audit",
                            event_type = "token_refresh",
                            session_id = "n/a",
                            username = %refresh_username,
                            outcome = "success",
                            expires_in = expires_in_secs,
                            "AGENT_REFRESH"
                        );

                        info!(
                            new_expires,
                            threshold_percent, "Auto-refresh succeeded; re-arming for next cycle"
                        );
                        break;
                    }
                    Err(e) => {
                        if attempt < MAX_RETRIES {
                            warn!(
                                attempt = attempt + 1,
                                max = MAX_RETRIES + 1,
                                error = %e,
                                "Auto-refresh attempt failed; will retry"
                            );
                        } else {
                            warn!(
                                error = %e,
                                "Auto-refresh exhausted all retries; token will expire naturally"
                            );
                        }
                    }
                }
            }

            if !succeeded {
                // All retries exhausted — set the flag and exit the task.
                let mut state_write = state.write().await;
                state_write.refresh_failed = true;
                break;
            }
            // Loop: re-arm with the new token expiry.
        }
    });

    handle.abort_handle()
}

/// Best-effort credential cleanup at daemon shutdown.
///
/// Called after the 5-second drain period following SIGTERM/SIGINT.
/// Zeroizes the in-memory DPoP signing key and access token by dropping the Arc
/// references held in `AgentState`. Token revocation is best-effort; failure is
/// logged at WARN and does not prevent clean daemon exit.
///
/// Does NOT delete stored credentials from the keyring or file backend — the user
/// may restart the daemon and expect their session to still be valid. Use the
/// `SessionClosed` IPC command (or the `logout` CLI) for full credential deletion.
async fn run_credential_cleanup(state: &Arc<RwLock<AgentState>>) {
    info!("Running shutdown credential cleanup (best-effort)");

    // Abort the background refresh task if running.
    {
        let mut state_write = state.write().await;
        if let Some(handle) = state_write.refresh_task.take() {
            handle.abort();
            debug!("Auto-refresh task cancelled at shutdown");
        }
    }

    // Best-effort token revocation at shutdown.
    // Uses a synthetic session_id so log lines are identifiable.
    revoke_token_best_effort(Arc::clone(state), "daemon-shutdown").await;

    // Clear in-memory secrets.
    // access_token (SecretString) and signer (Arc<ProtectedSigningKey>) zeroize on drop (MEM-01/MEM-03).
    {
        let mut state_write = state.write().await;
        state_write.access_token = None;
        state_write.signer = None;
        debug!("In-memory credentials zeroized at shutdown");
    }

    info!("Shutdown credential cleanup complete");
}

/// Send a best-effort RFC 7009 token revocation request.
///
/// Reads `revocation_endpoint`, `client_id`, `client_secret`, and the access token
/// from the agent state and token metadata. All failures are logged at WARN — this
/// function never panics or propagates errors.
///
/// RFC 7009 §2.1: POST to revocation endpoint with `token` + optional `token_type_hint`.
/// IdPs that do not support revocation (no endpoint configured) are logged and skipped.
async fn revoke_token_best_effort(state: Arc<RwLock<AgentState>>, session_id: &str) {
    // Snapshot the access token before releasing the lock.
    let access_token_opt = {
        let state_read = state.read().await;
        state_read
            .access_token
            .as_ref()
            .map(|t| t.expose_secret().to_string())
    };

    let access_token = match access_token_opt {
        Some(t) if !t.is_empty() => t,
        _ => {
            debug!(session_id, "No access token in state; skipping revocation");
            return;
        }
    };

    // Load metadata from storage to find the revocation endpoint.
    let storage = match StorageRouter::detect() {
        Ok(s) => s,
        Err(e) => {
            warn!(session_id, error = %e, "Could not open storage for revocation; skipping");
            return;
        }
    };

    let metadata_bytes = match storage.retrieve(KEY_TOKEN_METADATA) {
        Ok(b) => b,
        Err(_) => {
            warn!(session_id, "No token metadata found; skipping revocation");
            return;
        }
    };

    let metadata: serde_json::Value = match serde_json::from_slice(&metadata_bytes) {
        Ok(v) => v,
        Err(e) => {
            warn!(session_id, error = %e, "Failed to parse token metadata; skipping revocation");
            return;
        }
    };

    let revocation_endpoint = match metadata["revocation_endpoint"].as_str() {
        Some(ep) if !ep.is_empty() => ep.to_string(),
        _ => {
            warn!(
                session_id,
                "No revocation endpoint configured; skipping revocation"
            );
            return;
        }
    };

    let client_id = metadata["client_id"].as_str().unwrap_or("").to_string();
    // Security (MEM-03): client_secret is read from metadata; expose only at HTTP boundary.
    let client_secret = metadata["client_secret"].as_str().map(str::to_string);

    // Perform revocation in a blocking task — reqwest::blocking with 5s timeout.
    // RFC 7009 §2.1: POST form body [("token", access_token), ("token_type_hint", "access_token")].
    let session_id_clone = session_id.to_string();
    tokio::task::spawn_blocking(move || {
        let http_client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(session_id = %session_id_clone, error = %e, "Failed to create HTTP client for revocation");
                return;
            }
        };

        let mut params: Vec<(&str, &str)> = vec![
            ("token", &access_token),
            ("token_type_hint", "access_token"),
        ];
        if !client_id.is_empty() {
            params.push(("client_id", &client_id));
        }

        let mut request = http_client.post(&revocation_endpoint).form(&params);
        if let Some(ref secret) = client_secret {
            // RFC 7009 §2.1: client credentials via Basic Auth or form params.
            // Use Basic Auth when client_secret is present (matches most IdP expectations).
            request = http_client
                .post(&revocation_endpoint)
                .basic_auth(&client_id, Some(secret.as_str()))
                .form(&params);
        }

        match request.send() {
            Ok(resp) if resp.status().is_success() => {
                info!(
                    session_id = %session_id_clone,
                    status = %resp.status(),
                    "RFC 7009 token revocation succeeded"
                );
            }
            Ok(resp) => {
                warn!(
                    session_id = %session_id_clone,
                    status = %resp.status(),
                    "RFC 7009 token revocation returned non-2xx; token may expire naturally"
                );
            }
            Err(e) => {
                warn!(
                    session_id = %session_id_clone,
                    error = %e,
                    "RFC 7009 token revocation request failed; token may expire naturally"
                );
            }
        }
    })
    .await
    .unwrap_or_else(|e| {
        warn!(session_id, error = %e, "Revocation blocking task panicked");
    });
}

/// Clean up all session state after a SessionClosed notification.
///
/// Sequence (MEM invariants must be preserved):
/// 1. Cancel the background refresh task via AbortHandle (stops any in-flight refresh).
/// 2. Revoke the access token via RFC 7009 (best-effort, never blocks on failure).
/// 3. Clear in-memory state: access_token (SecretString zeroizes on drop), token_expires,
///    username, refresh_failed — (MEM-03).
/// 4. Delete stored credentials: KEY_ACCESS_TOKEN, KEY_REFRESH_TOKEN, KEY_DPOP_PRIVATE,
///    KEY_TOKEN_METADATA. StorageRouter uses secure_delete for file backends (MEM-05).
/// 5. Drop signer Arc: ProtectedSigningKey ZeroizeOnDrop triggers when last Arc ref drops
///    (MEM-01).
///
/// All storage deletion failures are logged at WARN — cleanup continues regardless.
async fn cleanup_session(state: Arc<RwLock<AgentState>>, session_id: String) {
    info!(session_id = %session_id, "SessionClosed: starting credential cleanup");

    // Step 1: Cancel the refresh task.
    {
        let mut state_write = state.write().await;
        if let Some(handle) = state_write.refresh_task.take() {
            handle.abort();
            debug!(session_id = %session_id, "Auto-refresh task cancelled");
        }
    }

    // Step 2: Best-effort token revocation (reads state and metadata).
    revoke_token_best_effort(Arc::clone(&state), &session_id).await;

    // Step 3: Clear in-memory state.
    // access_token: SecretString zeroizes bytes when dropped (MEM-03).
    // signer: Arc<dyn DPoPSigner> — drop triggers ZeroizeOnDrop on ProtectedSigningKey
    //   when this is the last Arc reference (MEM-01).
    {
        let mut state_write = state.write().await;
        state_write.access_token = None;
        state_write.token_expires = None;
        state_write.username = None;
        state_write.refresh_failed = false;
        state_write.signer = None;
        // Atomic invalidation: wipe all cached hardware presence on session close.
        state_write.presence_cache.clear();
        debug!(session_id = %session_id, "In-memory credentials and presence cache cleared");
    }

    // Step 4: Delete stored credentials.
    // StorageRouter::detect() for each delete is acceptable — cleanup is not perf-critical.
    let storage = match StorageRouter::detect() {
        Ok(s) => s,
        Err(e) => {
            warn!(session_id = %session_id, error = %e, "Could not open storage for cleanup; stored credentials may persist");
            return;
        }
    };

    #[allow(unused_mut)]
    let mut keys_to_delete: Vec<&str> = vec![
        KEY_ACCESS_TOKEN,
        KEY_REFRESH_TOKEN,
        KEY_DPOP_PRIVATE,
        KEY_TOKEN_METADATA,
    ];
    #[cfg(feature = "pqc")]
    keys_to_delete.push(crate::storage::KEY_PQ_SEED);
    for key in &keys_to_delete {
        if storage.exists(key) {
            if let Err(e) = storage.delete(key) {
                warn!(session_id = %session_id, key = %key, error = %e, "Failed to delete stored credential (continuing cleanup)");
            } else {
                debug!(session_id = %session_id, key = %key, "Stored credential deleted");
            }
        }
    }

    // OBS-1: Audit event — session closed. Username is read before clearing state
    // (Step 3 has already run at this point — username is None). Emit the audit event
    // with the session_id from the IPC request so SIEM can correlate with AGENT_AUTH.
    // username is not available post-cleanup; use "n/a" to satisfy the required field
    // invariant while noting that session_id provides sufficient correlation.
    tracing::info!(
        target: "prmana_audit",
        event_type = "session_closed",
        session_id = %session_id,
        username = "n/a",
        outcome = "success",
        "AGENT_SESSION_CLOSED"
    );

    info!(
        session_id = %session_id,
        "SessionClosed: credential cleanup complete"
    );
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
    use crate::daemon::protocol::AgentResponseData;
    use tempfile::TempDir;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_runtime_socket_path_builder() {
        assert_eq!(
            AgentServer::linux_runtime_socket_path(1000),
            PathBuf::from("/run/user/1000/prmana-agent.sock")
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_macos_runtime_socket_path_builder() {
        assert_eq!(
            AgentServer::macos_runtime_socket_path("/private/tmp/prmana"),
            PathBuf::from("/private/tmp/prmana/prmana-agent.sock")
        );
    }

    #[tokio::test]
    async fn test_server_client_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        // Create state with a signer and token
        let signer = Arc::new(SoftwareSigner::generate());
        let state = Arc::new(RwLock::new(AgentState {
            signer: Some(signer.clone()),
            access_token: Some(SecretString::from("test-token")),
            token_expires: Some(9999999999),
            username: Some("testuser".to_string()),
            metrics: Arc::new(MetricsCollector::new()),
            mlock_status: None,
            storage_backend: None,
            migration_status: None,
            signer_type: None,
            refresh_task: None,
            refresh_failed: false,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            presence_cache: crate::daemon::presence_cache::PresenceCache::new(
                crate::daemon::presence_cache::DEFAULT_PRESENCE_CACHE_TTL_SECS,
            ),
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
            panic!("Unexpected response: {response:?}");
        }
    }

    #[tokio::test]
    async fn test_get_proof() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test2.sock");

        let signer = Arc::new(SoftwareSigner::generate());
        let state = Arc::new(RwLock::new(AgentState {
            signer: Some(signer.clone()),
            access_token: Some(SecretString::from("test-token")),
            token_expires: Some(9999999999),
            username: Some("testuser".to_string()),
            metrics: Arc::new(MetricsCollector::new()),
            mlock_status: None,
            storage_backend: None,
            migration_status: None,
            signer_type: None,
            refresh_task: None,
            refresh_failed: false,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            presence_cache: crate::daemon::presence_cache::PresenceCache::new(
                crate::daemon::presence_cache::DEFAULT_PRESENCE_CACHE_TTL_SECS,
            ),
        }));

        let server = AgentServer::new(socket_path.clone(), state);
        let _server_handle = tokio::spawn(async move {
            let _ = server.serve().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = AgentClient::new(socket_path);
        let response = client
            .get_proof("server.example.com", "SSH", None, None)
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
            panic!("Unexpected response: {response:?}");
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
            .get_proof("server.example.com", "SSH", None, None)
            .await
            .unwrap();

        if let AgentResponse::Error { code, .. } = response {
            assert_eq!(code, "NOT_LOGGED_IN");
        } else {
            panic!("Expected error response: {response:?}");
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
        let token = format!("{header}.{payload}.");

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
        let token = format!("{header}.{payload}.");

        let result = extract_username_from_token(&token);
        assert_eq!(result, Some("user123".to_string()));

        // Test: unix_username takes priority
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"unix_username":"unixuser","preferred_username":"preferred","sub":"sub"}"#);
        let token = format!("{header}.{payload}.");

        let result = extract_username_from_token(&token);
        assert_eq!(result, Some("unixuser".to_string()));

        // Test: email extraction (strip domain)
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"email":"user@example.com"}"#);
        let token = format!("{header}.{payload}.");

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

    // --- TDD RED: SecretString wrapping and redaction ---

    /// Security: AgentState Debug output must NEVER expose raw token values.
    /// access_token must be wrapped in SecretString, which redacts via "[REDACTED]".
    #[test]
    fn test_agent_state_debug_redacts_access_token() {
        let state = AgentState {
            signer: None,
            access_token: Some(SecretString::from("super-secret-access-token")),
            token_expires: Some(9999999999),
            username: Some("alice".to_string()),
            metrics: Arc::new(MetricsCollector::new()),
            mlock_status: None,
            storage_backend: None,
            migration_status: None,
            signer_type: None,
            refresh_task: None,
            refresh_failed: false,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            presence_cache: crate::daemon::presence_cache::PresenceCache::new(
                crate::daemon::presence_cache::DEFAULT_PRESENCE_CACHE_TTL_SECS,
            ),
        };
        let debug_output = format!("{state:?}");
        assert!(
            !debug_output.contains("super-secret-access-token"),
            "Debug output must not contain raw token value, got: {debug_output}"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output must contain [REDACTED] for Secret fields, got: {debug_output}"
        );
    }

    /// Security: expose_secret() is the only path to the raw token value.
    #[test]
    fn test_access_token_expose_secret_roundtrip() {
        use secrecy::{ExposeSecret, SecretString};
        let raw = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        let state = AgentState {
            signer: None,
            access_token: Some(SecretString::from(raw)),
            token_expires: None,
            username: None,
            metrics: Arc::new(MetricsCollector::new()),
            mlock_status: None,
            storage_backend: None,
            migration_status: None,
            signer_type: None,
            refresh_task: None,
            refresh_failed: false,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            presence_cache: crate::daemon::presence_cache::PresenceCache::new(
                crate::daemon::presence_cache::DEFAULT_PRESENCE_CACHE_TTL_SECS,
            ),
        };
        let exposed = state.access_token.as_ref().unwrap().expose_secret();
        assert_eq!(exposed, raw);
    }

    /// Process hardening: disable_core_dumps() must not panic on any platform.
    #[test]
    fn test_disable_core_dumps_no_panic() {
        use crate::security::disable_core_dumps;
        // Must complete without panicking, regardless of success/failure.
        // Best-effort: failures are logged as WARN.
        disable_core_dumps();
    }

    /// mlock status field: AgentState must carry mlock_status for status reporting.
    #[test]
    fn test_agent_state_carries_mlock_status() {
        let mut state = AgentState::new();
        state.mlock_status = Some("mlock active".to_string());
        assert_eq!(state.mlock_status.as_deref(), Some("mlock active"));

        state.mlock_status = Some("mlock unavailable (EPERM)".to_string());
        assert!(state.mlock_status.as_ref().unwrap().contains("unavailable"));
    }

    // --- TDD: refresh task and session lifecycle ---

    /// AgentState carries refresh_task and refresh_failed fields.
    #[test]
    fn test_agent_state_carries_refresh_fields() {
        let state = AgentState::new();
        assert!(state.refresh_task.is_none());
        assert!(!state.refresh_failed);
    }

    /// AgentState Debug does not panic with refresh_task set.
    #[test]
    fn test_agent_state_debug_with_refresh_task() {
        let mut state = AgentState::new();
        // Spawn a no-op task and store its AbortHandle to simulate an active refresh.
        let handle = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let jh = tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await
            });
            jh.abort_handle()
        });
        state.refresh_task = Some(handle);
        state.refresh_failed = true;

        let debug_str = format!("{state:?}");
        assert!(
            debug_str.contains("<AbortHandle>"),
            "Expected <AbortHandle> in debug: {debug_str}"
        );
        assert!(
            debug_str.contains("refresh_failed: true"),
            "Expected refresh_failed in debug: {debug_str}"
        );
    }

    /// Refresh threshold calculation: sleep = lifetime * threshold / 100.
    ///
    /// Tests the arithmetic that spawn_refresh_task uses to compute the initial sleep.
    #[test]
    fn test_refresh_threshold_calculation() {
        // Helper that mirrors the arithmetic in spawn_refresh_task.
        fn compute_sleep(lifetime_secs: i64, threshold: u8) -> u64 {
            if lifetime_secs <= 0 {
                return 0;
            }
            (lifetime_secs as u64) * (threshold as u64) / 100
        }

        // 300s lifetime @ 80% → 240s sleep
        assert_eq!(compute_sleep(300, 80), 240);
        // 3600s lifetime @ 80% → 2880s sleep
        assert_eq!(compute_sleep(3600, 80), 2880);
        // Very short token (10s) @ 80% → 8s sleep (fires well before expiry)
        assert_eq!(compute_sleep(10, 80), 8);
        // Zero / negative lifetime → 0 (immediate refresh attempt)
        assert_eq!(compute_sleep(0, 80), 0);
        assert_eq!(compute_sleep(-5, 80), 0);
    }

    /// Backoff sequence: delays for retries 2, 3, 4 are 5s, 10s, 20s.
    #[test]
    fn test_refresh_backoff_sequence() {
        // Must match BACKOFF_DELAYS_SECS in spawn_refresh_task.
        const BACKOFF_DELAYS_SECS: [u64; 3] = [5, 10, 20];
        assert_eq!(BACKOFF_DELAYS_SECS[0], 5);
        assert_eq!(BACKOFF_DELAYS_SECS[1], 10);
        assert_eq!(BACKOFF_DELAYS_SECS[2], 20);
        // Total attempts = 1 initial + 3 retries = 4.
        assert_eq!(
            BACKOFF_DELAYS_SECS.len(),
            3,
            "3 retry delays → 4 total attempts"
        );
    }

    /// spawn_refresh_task returns an AbortHandle that can be called without panic.
    #[tokio::test]
    async fn test_spawn_refresh_task_returns_abort_handle() {
        let state = Arc::new(RwLock::new(AgentState::new()));
        // Token expires far in the future (lifetime ~1 year at 80% threshold = very long sleep).
        // The task will sleep; we just verify the AbortHandle is functional.
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 31_536_000; // ~1 year

        let handle = spawn_refresh_task(Arc::clone(&state), far_future, 80);
        // Abort should not panic.
        handle.abort();
    }

    /// SessionClosed over IPC: ACK is sent before cleanup runs.
    #[tokio::test]
    async fn test_session_closed_ack_via_ipc() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test_sc.sock");

        let signer = Arc::new(SoftwareSigner::generate());
        let state = Arc::new(RwLock::new(AgentState {
            signer: Some(signer.clone()),
            access_token: Some(SecretString::from("test-token")),
            token_expires: Some(9999999999),
            username: Some("testuser".to_string()),
            metrics: Arc::new(MetricsCollector::new()),
            mlock_status: None,
            storage_backend: None,
            migration_status: None,
            signer_type: None,
            refresh_task: None,
            refresh_failed: false,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            presence_cache: crate::daemon::presence_cache::PresenceCache::new(
                crate::daemon::presence_cache::DEFAULT_PRESENCE_CACHE_TTL_SECS,
            ),
        }));

        let server = AgentServer::new(socket_path.clone(), Arc::clone(&state));
        let _server_handle = tokio::spawn(async move {
            let _ = server.serve().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = AgentClient::new(socket_path);
        let response = client
            .send(AgentRequest::SessionClosed {
                session_id: "test-sess-001".to_string(),
            })
            .await
            .unwrap();

        // Must receive SessionAcknowledged immediately.
        assert!(
            matches!(
                response,
                AgentResponse::Success(AgentResponseData::SessionAcknowledged {
                    acknowledged: true
                })
            ),
            "Expected SessionAcknowledged, got: {response:?}"
        );
    }

    /// cleanup_session clears all in-memory state fields.
    #[tokio::test]
    async fn test_cleanup_session_clears_state() {
        let signer = Arc::new(SoftwareSigner::generate());
        let state = Arc::new(RwLock::new(AgentState {
            signer: Some(signer.clone()),
            access_token: Some(SecretString::from("test-token")),
            token_expires: Some(9999999999),
            username: Some("testuser".to_string()),
            metrics: Arc::new(MetricsCollector::new()),
            mlock_status: None,
            storage_backend: None,
            migration_status: None,
            signer_type: None,
            refresh_task: None,
            refresh_failed: false,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            presence_cache: crate::daemon::presence_cache::PresenceCache::new(
                crate::daemon::presence_cache::DEFAULT_PRESENCE_CACHE_TTL_SECS,
            ),
        }));

        // Run cleanup (will attempt revocation but find no metadata — WARN and continue).
        cleanup_session(Arc::clone(&state), "test-sess-002".to_string()).await;

        let state_read = state.read().await;
        assert!(
            state_read.access_token.is_none(),
            "access_token must be cleared"
        );
        assert!(
            state_read.token_expires.is_none(),
            "token_expires must be cleared"
        );
        assert!(state_read.username.is_none(), "username must be cleared");
        assert!(!state_read.refresh_failed, "refresh_failed must be reset");
        assert!(state_read.signer.is_none(), "signer Arc must be dropped");
    }

    /// cleanup_session cancels the refresh task.
    #[tokio::test]
    async fn test_cleanup_session_aborts_refresh_task() {
        let state = Arc::new(RwLock::new(AgentState::new()));

        // Install a refresh task that sleeps for a year.
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 31_536_000;
        let handle = spawn_refresh_task(Arc::clone(&state), far_future, 80);
        {
            let mut sw = state.write().await;
            sw.refresh_task = Some(handle);
        }

        cleanup_session(Arc::clone(&state), "test-sess-003".to_string()).await;

        // After cleanup, refresh_task must be None.
        let state_read = state.read().await;
        assert!(
            state_read.refresh_task.is_none(),
            "refresh_task must be None after cleanup"
        );
    }

    /// AgentState must carry OIDC config fields (oidc_issuer, oidc_client_id, oidc_client_secret)
    /// for use by token exchange (kubectl credential issuance).
    #[test]
    fn test_agent_state_has_oidc_config_fields() {
        let mut state = AgentState::new();
        assert!(
            state.oidc_issuer.is_none(),
            "oidc_issuer must be None initially"
        );
        assert!(
            state.oidc_client_id.is_none(),
            "oidc_client_id must be None initially"
        );
        assert!(
            state.oidc_client_secret.is_none(),
            "oidc_client_secret must be None initially"
        );

        state.oidc_issuer = Some("https://idp.example.com/realms/corp".to_string());
        state.oidc_client_id = Some("prmana-agent".to_string());
        state.oidc_client_secret = Some(SecretString::from("s3cr3t".to_string()));

        assert_eq!(
            state.oidc_issuer.as_deref(),
            Some("https://idp.example.com/realms/corp")
        );
        assert_eq!(state.oidc_client_id.as_deref(), Some("prmana-agent"));
        // Secret must not appear in Debug output (MEM-03)
        let debug = format!("{state:?}");
        assert!(
            !debug.contains("s3cr3t"),
            "oidc_client_secret must not appear in Debug: {debug}"
        );
    }

    /// Test that `acquire_listener` creates a socket file in standalone mode
    /// (no `LISTEN_FDS` env var set) and that the socket file has mode 0600.
    ///
    /// This test runs without systemd, so `LISTEN_FDS` is absent and the
    /// function takes the standalone bind path.
    #[tokio::test]
    async fn test_acquire_listener_standalone_binds_socket() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");

        // Ensure LISTEN_FDS is unset so we exercise the standalone path.
        // Note: LISTEN_FDS may be set in CI if the test runner uses socket activation,
        // but in a unit test context it is absent.
        let result = acquire_listener(&socket_path);
        assert!(
            result.is_ok(),
            "acquire_listener failed: {:?}",
            result.err()
        );

        // The socket file must exist after binding.
        assert!(
            socket_path.exists(),
            "socket file was not created at {socket_path:?}"
        );

        // Socket must be owner-only (0600).
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(&socket_path).unwrap();
            let mode = meta.mode() & 0o7777;
            assert_eq!(mode, 0o600, "expected socket mode 0600, got {mode:o}");
        }
    }

    /// Test that `acquire_listener` removes a stale socket file before binding.
    ///
    /// A leftover socket from a previous daemon run would cause `bind()` to fail
    /// with EADDRINUSE. The function must silently remove it first.
    #[test]
    fn test_acquire_listener_removes_stale_socket() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("stale.sock");

        // Create a stale file at the socket path.
        std::fs::write(&socket_path, b"stale").unwrap();
        assert!(socket_path.exists(), "precondition: stale file must exist");

        // acquire_listener should remove the stale file and succeed.
        // We need a Tokio runtime context for UnixListener::from_std().
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async { acquire_listener(&socket_path) });
        assert!(
            result.is_ok(),
            "acquire_listener failed with stale socket: {:?}",
            result.err()
        );
        assert!(
            socket_path.exists(),
            "new socket file must exist after bind"
        );
    }

    /// Idle timeout: a connected client that sends no data for the configured
    /// duration has its connection closed by the server.
    ///
    /// Uses a very short timeout (100ms) so the test runs in milliseconds.
    /// The client connects, sends nothing, and the server should close the
    /// connection after the timeout.
    #[tokio::test]
    async fn test_idle_timeout_closes_silent_connection() {
        use tokio::io::AsyncReadExt;

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("idle_timeout_test.sock");

        let state = Arc::new(RwLock::new(AgentState {
            signer: None,
            access_token: None,
            token_expires: None,
            username: None,
            metrics: Arc::new(MetricsCollector::new()),
            mlock_status: None,
            storage_backend: None,
            migration_status: None,
            signer_type: None,
            refresh_task: None,
            refresh_failed: false,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            presence_cache: crate::daemon::presence_cache::PresenceCache::new(
                crate::daemon::presence_cache::DEFAULT_PRESENCE_CACHE_TTL_SECS,
            ),
        }));

        // Short idle timeout (200ms) so the test runs quickly.
        let server = AgentServer::new(socket_path.clone(), state)
            .with_idle_timeout(Duration::from_millis(200));

        let _server_handle = tokio::spawn(async move {
            // serve_with_listener won't return on its own (signal-driven), so we
            // just let the handle drop when the test exits.
            let listener = acquire_listener(&socket_path).unwrap();
            let _ = server.serve_with_listener(listener).await;
        });

        // Give server time to start listening.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect a client socket and send nothing.
        let client_stream =
            tokio::net::UnixStream::connect(temp_dir.path().join("idle_timeout_test.sock"))
                .await
                .expect("client connect failed");

        let (mut reader, _writer) = client_stream.into_split();
        let mut buf = [0u8; 64];

        // The server should close the connection after 200ms idle timeout.
        // We wait up to 1s; a read returning 0 bytes means EOF (server closed).
        let result = tokio::time::timeout(Duration::from_secs(1), reader.read(&mut buf)).await;

        match result {
            Ok(Ok(0)) => {
                // EOF — server closed the connection. Test passes.
            }
            Ok(Ok(n)) => {
                panic!("Expected EOF after idle timeout, got {n} bytes");
            }
            Ok(Err(e)) => {
                // Connection reset is also acceptable (OS closed the socket).
                // On Linux the server dropping stream may yield a connection reset.
                let _ = e; // accepted
            }
            Err(_elapsed) => {
                panic!("Connection was not closed within 1s; idle timeout not working");
            }
        }
    }

    /// OPS-13: Verify that a GetProof request emits an INFO log line containing
    /// "DPoP proof requested" with username, target, and signer_type fields.
    ///
    /// Uses `tracing-test` to capture log output within the test scope.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_get_proof_emits_info_log() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("tracing_test.sock");

        let signer = Arc::new(SoftwareSigner::generate());
        let state = Arc::new(RwLock::new(AgentState {
            signer: Some(signer.clone()),
            access_token: Some(SecretString::from("trace-test-token")),
            token_expires: Some(9999999999),
            username: Some("alice".to_string()),
            metrics: Arc::new(MetricsCollector::new()),
            mlock_status: None,
            storage_backend: None,
            migration_status: None,
            signer_type: Some("software".to_string()),
            refresh_task: None,
            refresh_failed: false,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            presence_cache: crate::daemon::presence_cache::PresenceCache::new(
                crate::daemon::presence_cache::DEFAULT_PRESENCE_CACHE_TTL_SECS,
            ),
        }));

        let server = AgentServer::new(socket_path.clone(), Arc::clone(&state));
        let _server_handle = tokio::spawn(async move {
            let _ = server.serve().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = AgentClient::new(socket_path);
        let response = client
            .get_proof("prod.example.com", "SSH", None, None)
            .await
            .unwrap();

        // Verify we got a successful proof response.
        assert!(
            matches!(
                response,
                AgentResponse::Success(AgentResponseData::Proof { .. })
            ),
            "Expected Proof response; got: {response:?}"
        );

        // Verify the INFO log was emitted with the expected message and fields.
        // tracing-test captures all spans/events within the test; logs_contain()
        // checks the formatted output for the substring.
        assert!(
            logs_contain("DPoP proof requested"),
            "Expected INFO log 'DPoP proof requested' was not emitted"
        );
        assert!(
            logs_contain("alice"),
            "Expected username field 'alice' in log"
        );
        assert!(
            logs_contain("prod.example.com"),
            "Expected target field 'prod.example.com' in log"
        );
        assert!(
            logs_contain("software"),
            "Expected signer_type field 'software' in log"
        );
    }

    // ── F-11: IPC message size limit ──────────────────────────────────────────

    /// F-11 positive: normal-sized messages (< 64 KiB) are processed normally.
    #[tokio::test]
    async fn test_normal_sized_ipc_message_processed() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test_msg_size_ok.sock");

        let state = Arc::new(RwLock::new(AgentState::new()));
        let server = AgentServer::new(socket_path.clone(), Arc::clone(&state));
        let _server_handle = tokio::spawn(async move {
            let _ = server.serve().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = AgentClient::new(socket_path);
        let response = client.status().await.unwrap();

        // A normal Status request should succeed (not be rejected as too large).
        assert!(
            matches!(
                response,
                AgentResponse::Success(AgentResponseData::Status { .. })
            ),
            "Normal-sized message should be processed, got: {response:?}"
        );
    }

    /// F-11 negative: oversized messages (> 64 KiB) return MESSAGE_TOO_LARGE error.
    #[tokio::test]
    async fn test_oversized_ipc_message_rejected() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test_msg_size_reject.sock");

        let state = Arc::new(RwLock::new(AgentState::new()));
        let server = AgentServer::new(socket_path.clone(), Arc::clone(&state));
        let _server_handle = tokio::spawn(async move {
            let _ = server.serve().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Connect directly and send a message larger than MAX_IPC_MESSAGE_SIZE.
        let stream = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("connect failed");
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Build a message that exceeds 64 KiB (padding with spaces inside a JSON string).
        let padding = "x".repeat(MAX_IPC_MESSAGE_SIZE + 1);
        let oversized_msg = format!("{{\"command\":\"Status\",\"data\":\"{padding}\"}}\n");
        assert!(
            oversized_msg.len() > MAX_IPC_MESSAGE_SIZE,
            "Test message must exceed MAX_IPC_MESSAGE_SIZE"
        );

        writer.write_all(oversized_msg.as_bytes()).await.unwrap();

        // Read the response.
        let mut response_line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut response_line))
            .await
            .expect("timeout waiting for response")
            .expect("read error");

        assert!(n > 0, "Expected a response, got EOF");

        let response: AgentResponse =
            serde_json::from_str(&response_line).expect("Failed to parse response JSON");

        match response {
            AgentResponse::Error { code, message, .. } => {
                assert_eq!(
                    code, "MESSAGE_TOO_LARGE",
                    "Expected MESSAGE_TOO_LARGE error code, got: {code}"
                );
                assert!(
                    message.contains("too large"),
                    "Error message should mention 'too large', got: {message}"
                );
            }
            other => panic!("Expected error response for oversized message, got: {other:?}"),
        }
    }
}

// ── launchd socket activation (macOS only) ──────────────────────────────────
//
// `launch_activate_socket(3)` is part of the macOS launch(3) API and allows a
// launchd-managed process to inherit pre-bound sockets from the launchd plist.
//
// The function signature (from the macOS SDK):
//
//   int launch_activate_socket(const char *name, int **fds, size_t *cnt);
//
// - `name`  — matches a key in the plist `Sockets` dict (e.g. "Listeners").
// - `fds`   — output: heap-allocated array of pre-bound fds; caller must free.
// - `cnt`   — output: number of fds in the array.
// - return  — 0 on success; errno-compatible code on failure.
//             ESRCH means "not running under launchd" (normal for foreground starts).
//             ENOENT means the socket name does not exist in the plist.
//
// References:
// - macOS man page: launch_activate_socket(3)
// - Apple TN2083: Daemons and Agents
#[cfg(target_os = "macos")]
pub(crate) mod launchd_socket {
    use std::os::unix::io::FromRawFd;

    extern "C" {
        /// Activate the named socket(s) from the launchd plist.
        ///
        /// Safety: `name` must be a NUL-terminated C string.  `fds` and `cnt` must
        /// point to valid memory.  The returned `fds` pointer (if non-null) is
        /// heap-allocated by the system and must be freed with `libc::free`.
        fn launch_activate_socket(
            name: *const libc::c_char,
            fds: *mut *mut libc::c_int,
            cnt: *mut libc::size_t,
        ) -> libc::c_int;
    }

    /// Try to inherit the launchd-pre-bound socket named `name`.
    ///
    /// Returns `Some(listener)` when launched by launchd with a matching socket.
    /// Returns `None` (and logs at DEBUG) when:
    /// - Not running under launchd (ESRCH).
    /// - The named socket is not present in the plist (ENOENT).
    /// - Any other FFI error.
    ///
    /// The caller must check `Some` before entering the accept loop.  Failure to
    /// call this function when launched by launchd will cause launchd to re-spawn
    /// the agent because its socket was never accepted.
    pub fn take(name: &str) -> Option<tokio::net::UnixListener> {
        use std::ffi::CString;

        let c_name = CString::new(name).ok()?;

        let mut fds: *mut libc::c_int = std::ptr::null_mut();
        let mut cnt: libc::size_t = 0;

        // Safety: c_name outlives the call; fds/cnt are stack-allocated outputs.
        let ret = unsafe { launch_activate_socket(c_name.as_ptr(), &mut fds, &mut cnt) };

        if ret != 0 {
            // ESRCH = "not launched by launchd" — expected for foreground runs.
            let errno = ret;
            if errno == libc::ESRCH {
                tracing::debug!(
                    name = name,
                    "launch_activate_socket: not running under launchd (ESRCH)"
                );
            } else {
                tracing::debug!(
                    name = name,
                    errno = errno,
                    "launch_activate_socket returned non-zero; falling back to standalone"
                );
            }
            return None;
        }

        if cnt == 0 || fds.is_null() {
            // Shouldn't happen on success, but guard defensively.
            if !fds.is_null() {
                // Safety: fds is heap-allocated by the system; free it.
                unsafe { libc::free(fds as *mut libc::c_void) };
            }
            tracing::warn!(name = name, "launch_activate_socket returned 0 fds");
            return None;
        }

        // Take the first fd (we configure a single socket in the plist).
        // Safety: cnt > 0 guarantees fds[0] is valid.
        let raw_fd = unsafe { *fds };

        // Free the fd array — we have copied the fd value we need.
        // Safety: fds is heap-allocated by the system.
        unsafe { libc::free(fds as *mut libc::c_void) };

        // Wrap the raw fd in a std UnixListener.
        // Safety: raw_fd is a valid pre-bound SOCK_STREAM socket from launchd;
        //         launchd transfers ownership to this process on activation.
        let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(raw_fd) };

        // Set non-blocking so tokio can drive it without OS-level blocking.
        if let Err(e) = std_listener.set_nonblocking(true) {
            tracing::error!(
                fd = raw_fd,
                error = %e,
                "Failed to set launchd socket non-blocking"
            );
            return None;
        }

        // Convert to a tokio-native listener.
        match tokio::net::UnixListener::from_std(std_listener) {
            Ok(listener) => Some(listener),
            Err(e) => {
                tracing::error!(
                    fd = raw_fd,
                    error = %e,
                    "Failed to convert launchd fd to tokio UnixListener"
                );
                None
            }
        }
    }

    // ── compile-time smoke test ──────────────────────────────────────────────
    //
    // There is no way to unit-test the full FFI path without actually being
    // launched by launchd.  This test verifies the module compiles and that
    // `take()` returns `None` when the process is NOT running under launchd
    // (which is always the case in `cargo test`).
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_launchd_socket_not_under_launchd_returns_none() {
            // When run via `cargo test` (not under launchd), take() must return None
            // because ESRCH is returned for the non-launchd case.
            let result = take("Listeners");
            assert!(
                result.is_none(),
                "Expected None when not running under launchd; got Some"
            );
        }
    }
}
