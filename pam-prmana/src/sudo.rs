//! Sudo step-up authentication.
//!
//! This module provides step-up authentication for sudo commands using
//! OIDC step-up flows plus Phase 44 risk-aware privilege policy decisions.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::audit::AuditEvent;
use crate::device_flow::{DeviceFlowClient, DeviceFlowError, TokenResponse};
use crate::oidc::{TokenValidator, ValidationConfig, ValidationError};
use crate::policy::config::SecurityModes;
use crate::policy::{
    config::SudoPolicyAction, rules::SudoPolicyDecision, PolicyConfig, PolicyRules, StepUpMethod,
    SudoStepUpRequirements,
};
use crate::sssd::groups::{check_group_policy, GroupPolicyError};
use crate::sssd::{get_user_info, UserError};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Check if test mode is explicitly enabled.
/// Security: Only accepts explicit "true" or "1" values, not just presence of the variable.
#[cfg(feature = "test-mode")]
fn is_test_mode_enabled() -> bool {
    std::env::var("PRMANA_TEST_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

#[derive(Debug, Error)]
pub enum SudoError {
    #[error("Policy error: {0}")]
    Policy(#[from] crate::policy::PolicyError),

    #[error("Device flow error: {0}")]
    DeviceFlow(#[from] DeviceFlowError),

    #[error("Token validation error: {0}")]
    TokenValidation(#[from] ValidationError),

    #[error("Step-up denied by user")]
    Denied,

    #[error("Privilege policy denied command: {reason}")]
    PolicyDenied { reason: String },

    #[error("Step-up timeout ({method} exceeded {timeout_secs}s)")]
    Timeout { method: String, timeout_secs: u64 },

    #[error("Configuration error: {0}")]
    Config(String),

    /// CIBA step-up via agent IPC failed (socket error, agent error, or protocol error).
    #[error("Step-up IPC error: {0}")]
    StepUp(String),

    #[error("User mismatch: token user {token_user} != sudo user {sudo_user}")]
    UserMismatch {
        token_user: String,
        sudo_user: String,
    },

    /// User's NSS groups do not intersect with the configured sudo_groups allow-list.
    #[error("Sudo group policy denied step-up: {0}")]
    GroupDenied(String),

    /// User lookup failed during group policy check (NSS resolution error).
    #[error("User resolution failed during group policy check: {0}")]
    UserResolution(#[from] UserError),
}

/// Context for a sudo authentication request.
#[derive(Debug, Clone)]
pub struct SudoContext {
    /// The user requesting sudo
    pub user: String,
    /// The command being executed
    pub command: String,
    /// The TTY (if available)
    pub tty: Option<String>,
    /// Session ID for audit logging
    pub session_id: String,
}

impl SudoContext {
    pub fn new(user: &str, command: &str, tty: Option<&str>) -> Result<Self, SudoError> {
        let session_id = generate_session_id()
            .map_err(|e| SudoError::Config(format!("CSPRNG unavailable for session ID: {e}")))?;
        Ok(Self {
            user: user.to_string(),
            command: command.to_string(),
            tty: tty.map(String::from),
            session_id,
        })
    }
}

/// Result of a successful sudo step-up authentication.
#[derive(Debug)]
pub struct SudoAuthResult {
    /// Session ID for audit trail
    pub session_id: String,
    /// ACR level achieved
    pub acr: Option<String>,
    /// Time taken to complete step-up (ms)
    pub response_time_ms: u64,
}

/// File-backed record of a recent successful sudo step-up.
///
/// This is intentionally simple and per-process agnostic: PAM runs in forked
/// sshd/sudo processes, so in-memory grace windows would not survive across
/// invocations. A tiny root-owned cache in `/run` is sufficient and avoids
/// introducing a new daemon just for Phase 44 grace-period reuse.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RecentStepUpRecord {
    username: String,
    host_classification: String,
    matched_rule_name: Option<String>,
    command: String,
    completed_at_unix_secs: u64,
}

/// Callback for displaying step-up prompts to the user.
pub trait StepUpDisplay {
    /// Display the device flow prompt to the user.
    fn show_device_flow_prompt(&self, verification_uri: &str, user_code: &str);

    /// Update the waiting message during polling.
    fn show_waiting(&self, elapsed_seconds: u64, timeout_seconds: u64);

    /// Show success message.
    fn show_success(&self);

    /// Show failure message.
    fn show_failure(&self, reason: &str);
}

/// Authenticate sudo command with step-up if required.
///
/// Returns Ok(None) if step-up is not required.
/// Returns Ok(Some(result)) if step-up succeeded.
/// Returns Err if step-up failed or was denied.
pub fn authenticate_sudo(
    ctx: &SudoContext,
    policy: &PolicyConfig,
    display: &dyn StepUpDisplay,
) -> Result<Option<SudoAuthResult>, SudoError> {
    let rules = PolicyRules::new(policy);
    let decision = rules.evaluate_sudo(&ctx.command);

    // Dry-run lets operators observe richer Phase 44 policy logic while the
    // runtime still follows the legacy boolean model. This is the safest way to
    // roll out deny and grace-window policy without surprise production impact.
    if decision.dry_run {
        log_privilege_policy_decision(ctx, &decision, false);
        return authenticate_sudo_legacy(ctx, policy, display);
    }

    let requirements = match decision.action {
        SudoPolicyAction::Allow => {
            log_privilege_policy_decision(ctx, &decision, false);
            return Ok(None);
        }
        SudoPolicyAction::Deny => {
            log_privilege_policy_decision(ctx, &decision, false);
            let reason = format!(
                "matched deny rule {}",
                decision
                    .matched_rule_name
                    .as_deref()
                    .unwrap_or("<unnamed-rule>")
            );
            return Err(SudoError::PolicyDenied { reason });
        }
        SudoPolicyAction::StepUp => decision.step_up.clone().ok_or_else(|| {
            SudoError::Config(
                "phase-44 policy evaluation bug: step_up action missing requirements".to_string(),
            )
        })?,
    };

    if requirements.grace_period_secs > 0
        && recent_step_up_satisfies(
            &ctx.user,
            &ctx.command,
            decision.matched_rule_name.as_deref(),
            decision.host_classification,
            requirements.grace_period_secs,
        )
    {
        log_privilege_policy_decision(ctx, &decision, true);
        return Ok(None);
    }

    // Enforce sudo_groups policy before initiating step-up.
    //
    // Only check if sudo_groups is non-empty (empty = no restriction, backward compat).
    // This runs BEFORE the device flow to avoid issuing a browser challenge to a user
    // who will be denied regardless.
    if !policy.sudo.sudo_groups.is_empty() {
        let user_info = get_user_info(&ctx.user)?;
        let modes = policy.effective_security_modes();

        check_group_policy(
            &ctx.user,
            user_info.gid,
            &policy.sudo.sudo_groups,
            modes.groups_enforcement,
        )
        .map_err(|e: GroupPolicyError| {
            tracing::warn!(
                username = %ctx.user,
                error = %e,
                "Sudo group policy denied step-up"
            );
            log_step_up_failed(
                ctx,
                "device_flow",
                "user not in sudo_groups",
                Some(&decision),
            );
            SudoError::GroupDenied(e.to_string())
        })?;
    }

    log_privilege_policy_decision(ctx, &decision, false);

    // Log step-up initiation
    log_step_up_initiated(ctx, &requirements, Some(&decision));

    // Perform step-up authentication
    let security_modes = policy.effective_security_modes();
    let start = std::time::Instant::now();
    let result = match perform_step_up(ctx, &requirements, display, policy, &security_modes) {
        Ok(r) => r,
        Err(e) => {
            // Log failure
            log_step_up_failed(ctx, "device_flow", &e.to_string(), Some(&decision));
            return Err(e);
        }
    };
    let response_time_ms = start.elapsed().as_millis() as u64;

    // Log success
    log_step_up_success(ctx, &result, response_time_ms, Some(&decision));
    record_recent_step_up(
        &ctx.user,
        &ctx.command,
        decision.matched_rule_name.as_deref(),
        decision.host_classification,
        SystemTime::now(),
    );

    Ok(Some(SudoAuthResult {
        session_id: ctx.session_id.clone(),
        acr: result.acr,
        response_time_ms,
    }))
}

/// Legacy pre-Phase-44 behavior retained for dry-run mode and compatibility.
fn authenticate_sudo_legacy(
    ctx: &SudoContext,
    policy: &PolicyConfig,
    display: &dyn StepUpDisplay,
) -> Result<Option<SudoAuthResult>, SudoError> {
    let rules = PolicyRules::new(policy);
    let requirements = match rules.check_sudo(&ctx.command) {
        Some(req) => req,
        None => return Ok(None),
    };

    if !policy.sudo.sudo_groups.is_empty() {
        let user_info = get_user_info(&ctx.user)?;
        let modes = policy.effective_security_modes();

        check_group_policy(
            &ctx.user,
            user_info.gid,
            &policy.sudo.sudo_groups,
            modes.groups_enforcement,
        )
        .map_err(|e: GroupPolicyError| {
            tracing::warn!(
                username = %ctx.user,
                error = %e,
                "Sudo group policy denied step-up"
            );
            log_step_up_failed(ctx, "device_flow", "user not in sudo_groups", None);
            SudoError::GroupDenied(e.to_string())
        })?;
    }

    log_step_up_initiated(ctx, &requirements, None);
    let security_modes = policy.effective_security_modes();
    let start = std::time::Instant::now();
    let result = match perform_step_up(ctx, &requirements, display, policy, &security_modes) {
        Ok(r) => r,
        Err(e) => {
            log_step_up_failed(ctx, "device_flow", &e.to_string(), None);
            return Err(e);
        }
    };
    let response_time_ms = start.elapsed().as_millis() as u64;
    log_step_up_success(ctx, &result, response_time_ms, None);

    Ok(Some(SudoAuthResult {
        session_id: ctx.session_id.clone(),
        acr: result.acr,
        response_time_ms,
    }))
}

/// Perform the step-up authentication.
///
/// Routes to the appropriate step-up method:
/// - `StepUpMethod::Push` and `StepUpMethod::Fido2` route through agent IPC (CIBA).
/// - `StepUpMethod::DeviceFlow` uses the existing device-flow client.
fn perform_step_up(
    ctx: &SudoContext,
    requirements: &SudoStepUpRequirements,
    _display: &dyn StepUpDisplay,
    policy: &PolicyConfig,
    security_modes: &SecurityModes,
) -> Result<StepUpResult, SudoError> {
    // Prefer Push/Fido2 (CIBA) when available — lower friction than device flow.
    if requirements.allowed_methods.contains(&StepUpMethod::Push) {
        let socket_path = agent_socket_path();
        return perform_step_up_via_ipc(
            ctx,
            requirements,
            policy,
            &socket_path,
            StepUpMethod::Push,
            security_modes,
        );
    }

    if requirements.allowed_methods.contains(&StepUpMethod::Fido2) {
        let socket_path = agent_socket_path();
        return perform_step_up_via_ipc(
            ctx,
            requirements,
            policy,
            &socket_path,
            StepUpMethod::Fido2,
            security_modes,
        );
    }

    if !requirements
        .allowed_methods
        .contains(&StepUpMethod::DeviceFlow)
    {
        return Err(SudoError::Config(
            "No supported step-up method available".to_string(),
        ));
    }

    perform_device_flow_step_up(ctx, requirements, _display)
}

/// Resolve the agent socket path for privileged PAM paths (sudo, session close).
///
/// Security (Codex finding 3): In root-context PAM paths, environment variables
/// (`PRMANA_AGENT_SOCKET`, `XDG_RUNTIME_DIR`) are user-influenced and MUST NOT
/// be trusted — an attacker could redirect root to a malicious socket.
///
/// Resolution order:
/// 1. **Test-mode only**: `PRMANA_AGENT_SOCKET` env var (for integration tests).
/// 2. `/run/user/{uid}/prmana-agent.sock` — canonical path derived from the
///    target user's UID, not from environment variables.
///
/// The UID-based path matches the agent daemon's socket creation convention and
/// does not depend on any user-controllable input.
fn agent_socket_path() -> String {
    // In test-mode, allow env override for integration tests.
    #[cfg(feature = "test-mode")]
    if let Ok(path) = std::env::var("PRMANA_AGENT_SOCKET") {
        return path;
    }

    // Production: derive from real UID of the calling process.
    // In sudo context, EUID is root but RUID is the original user.
    let uid = uzers::get_current_uid();
    format!("/run/user/{uid}/prmana-agent.sock")
}

/// Resolve the directory for recent sudo step-up cache entries.
///
/// The default location is `/run/prmana/sudo-step-up-cache`, which keeps the
/// state ephemeral across reboot and root-owned across users. Tests can
/// override it with `PRMANA_SUDO_STEPUP_CACHE_DIR`.
fn recent_step_up_cache_dir() -> PathBuf {
    std::env::var("PRMANA_SUDO_STEPUP_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/prmana/sudo-step-up-cache"))
}

/// Best-effort ensure the cache directory exists with restrictive permissions.
fn ensure_recent_step_up_cache_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(dir, perms);
    }
    Ok(())
}

/// Build a stable cache key for a user + host class + matched policy rule.
fn recent_step_up_cache_key(
    username: &str,
    command: &str,
    matched_rule_name: Option<&str>,
    host_classification: crate::policy::config::HostClassification,
) -> String {
    use sha2::Digest;

    // We deliberately key by matched rule first and command second. This lets
    // a rule such as "service_restart" share a grace window across multiple
    // concrete service names when the operator chooses a broad pattern.
    let input = format!(
        "{username}\n{:?}\n{}\n{command}",
        host_classification,
        matched_rule_name.unwrap_or("<no-rule>")
    );
    let digest = sha2::Sha256::digest(input.as_bytes());
    hex::encode(&digest[..16])
}

fn recent_step_up_cache_path(
    username: &str,
    command: &str,
    matched_rule_name: Option<&str>,
    host_classification: crate::policy::config::HostClassification,
) -> PathBuf {
    recent_step_up_cache_dir().join(format!(
        "{}.json",
        recent_step_up_cache_key(username, command, matched_rule_name, host_classification)
    ))
}

/// Return `true` when a recent successful step-up still satisfies the grace window.
fn recent_step_up_satisfies(
    username: &str,
    command: &str,
    matched_rule_name: Option<&str>,
    host_classification: crate::policy::config::HostClassification,
    grace_period_secs: u64,
) -> bool {
    if grace_period_secs == 0 {
        return false;
    }

    let path = recent_step_up_cache_path(username, command, matched_rule_name, host_classification);
    let Ok(bytes) = std::fs::read(&path) else {
        return false;
    };
    let Ok(record) = serde_json::from_slice::<RecentStepUpRecord>(&bytes) else {
        tracing::warn!(path = %path.display(), "Ignoring corrupt recent step-up cache record");
        return false;
    };
    let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) else {
        return false;
    };

    now.as_secs().saturating_sub(record.completed_at_unix_secs) <= grace_period_secs
}

/// Persist a successful step-up completion for future grace-window reuse.
fn record_recent_step_up(
    username: &str,
    command: &str,
    matched_rule_name: Option<&str>,
    host_classification: crate::policy::config::HostClassification,
    completed_at: SystemTime,
) {
    let dir = recent_step_up_cache_dir();
    if let Err(e) = ensure_recent_step_up_cache_dir(&dir) {
        tracing::warn!(dir = %dir.display(), error = %e, "Could not prepare recent step-up cache directory");
        return;
    }

    let completed_at_unix_secs = match completed_at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(ts) => ts.as_secs(),
        Err(_) => return,
    };

    let record = RecentStepUpRecord {
        username: username.to_string(),
        host_classification: format!("{host_classification:?}"),
        matched_rule_name: matched_rule_name.map(str::to_string),
        command: command.to_string(),
        completed_at_unix_secs,
    };
    let Ok(json) = serde_json::to_vec(&record) else {
        return;
    };
    let path = recent_step_up_cache_path(username, command, matched_rule_name, host_classification);
    let tmp = path.with_extension("json.tmp");

    if let Err(e) = std::fs::write(&tmp, json) {
        tracing::warn!(path = %tmp.display(), error = %e, "Could not write recent step-up cache tmp file");
        return;
    }
    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(&tmp, perms);
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        tracing::warn!(path = %path.display(), error = %e, "Could not persist recent step-up cache record");
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Perform CIBA step-up authentication via agent IPC.
///
/// Sends a `StepUp` IPC request to the agent, then polls `StepUpResult` at the
/// returned `poll_interval_secs` until the agent reports complete, timed-out, or
/// denied. The total PAM-side wall time is bounded by `requirements.timeout`.
///
/// ## Protocol
///
/// Each IPC call is a short blocking request (2s timeout) — the 30–120s CIBA poll
/// loop runs entirely in the agent's async Tokio runtime. This avoids blocking PAM
/// for the full CIBA window (Pitfall 3 from 10-RESEARCH.md: LoginGraceTime race).
pub(crate) fn perform_step_up_via_ipc(
    ctx: &SudoContext,
    requirements: &SudoStepUpRequirements,
    policy: &PolicyConfig,
    socket_path: &str,
    method: StepUpMethod,
    security_modes: &SecurityModes,
) -> Result<StepUpResult, SudoError> {
    let method_str = match method {
        StepUpMethod::Push => "push",
        StepUpMethod::Fido2 => "fido2",
        StepUpMethod::DeviceFlow => "device_flow",
    };

    // Resolve hostname (gethostname crate is available in pam-prmana).
    let hostname = gethostname::gethostname().to_string_lossy().to_string();

    // ── Resolve parent session ID from environment (OBS-3) ───────────────────
    //
    // The parent SSH session ID is set by pam_sm_open_session via PAM putenv
    // (PRMANA_SESSION_ID). In a sudo PAM context this env var may be absent
    // (older pam-prmana versions, non-SSH sudo invocations, or environments
    // where PRMANA_SESSION_ID was not exported to the sudo session). Fall
    // back to None with a debug log — absence never fails authentication.
    //
    // Reference: Phase 09 session correlation design (Phase 09 decision in STATE.md):
    // "Session correlation via PAM putenv/getenv is best-effort: failure never fails auth"
    let parent_session_id: Option<String> = std::env::var("PRMANA_SESSION_ID").ok().filter(|s| !s.is_empty()).map(|s| {
        tracing::debug!(parent_session_id = %s, "Resolved parent SSH session ID for step-up audit correlation");
        s
    });
    if parent_session_id.is_none() {
        tracing::debug!("PRMANA_SESSION_ID not set in sudo PAM context; parent_session_id will be absent from step-up audit event");
    }

    let active_issuer = std::env::var("PRMANA_ISSUER")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|iss| policy.issuer_by_url(&iss));

    // ── Step 1: Send StepUp request ───────────────────────────────────────────
    let mut step_up_msg = serde_json::json!({
        "action": "step_up",
        "username": ctx.user,
        "command": ctx.command,
        "hostname": hostname,
        "method": method_str,
        "timeout_secs": requirements.timeout,
    });
    // Add parent_session_id only when present (skip_serializing_if = None semantics)
    if let Some(ref psid) = parent_session_id {
        step_up_msg["parent_session_id"] = serde_json::Value::String(psid.clone());
    }
    if let Some(issuer) = active_issuer {
        if let Some(scope) = issuer.ciba_scope.as_ref() {
            step_up_msg["scope"] = serde_json::Value::String(scope.clone());
        }
        if let Some(login_hint_claim) = issuer.ciba_login_hint_claim.as_ref() {
            step_up_msg["login_hint_claim"] = serde_json::Value::String(login_hint_claim.clone());
        }
    }

    let correlation_id = {
        let mut stream = connect_agent_socket(socket_path)?;
        send_ipc_message(&mut stream, &step_up_msg)?;
        let response_json = read_ipc_response(&mut stream)?;
        let response: serde_json::Value = serde_json::from_str(&response_json)
            .map_err(|e| SudoError::StepUp(format!("Failed to parse StepUp response: {e}")))?;

        if response["status"] == "error" {
            let msg = response["message"].as_str().unwrap_or("unknown error");
            return Err(SudoError::StepUp(format!("Agent StepUp error: {msg}")));
        }

        // Extract correlation_id from StepUpPending response.
        response["correlation_id"]
            .as_str()
            .ok_or_else(|| {
                SudoError::StepUp("No correlation_id in StepUpPending response".to_string())
            })?
            .to_string()
    };

    let poll_interval_secs = requirements.poll_interval_secs.max(1);
    let method_timeout = requirements
        .method_timeouts
        .timeout_for(&method, requirements.timeout);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(method_timeout);

    tracing::info!(
        method = method_str,
        timeout_secs = method_timeout,
        poll_interval_secs,
        "Starting step-up poll loop"
    );

    // ── Step 2: Poll for result ───────────────────────────────────────────────
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(SudoError::Timeout {
                method: method_str.to_string(),
                timeout_secs: method_timeout,
            });
        }

        std::thread::sleep(std::time::Duration::from_secs(poll_interval_secs));

        if std::time::Instant::now() >= deadline {
            return Err(SudoError::Timeout {
                method: method_str.to_string(),
                timeout_secs: method_timeout,
            });
        }

        let step_up_result_msg = serde_json::json!({
            "action": "step_up_result",
            "correlation_id": correlation_id,
        });

        let mut stream = match connect_agent_socket(socket_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to poll StepUpResult from agent (continuing)");
                continue;
            }
        };

        if let Err(e) = send_ipc_message(&mut stream, &step_up_result_msg) {
            tracing::warn!(error = %e, "Failed to send StepUpResult IPC (continuing)");
            continue;
        }

        let response_json = match read_ipc_response(&mut stream) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to read StepUpResult IPC response (continuing)");
                continue;
            }
        };

        let response: serde_json::Value = match serde_json::from_str(&response_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse StepUpResult response (continuing)");
                continue;
            }
        };

        if response["status"] == "error" {
            let code = response["code"].as_str().unwrap_or("");
            if code == "STEP_UP_NOT_FOUND" {
                // Correlation ID expired — treat as timeout.
                return Err(SudoError::Timeout {
                    method: method_str.to_string(),
                    timeout_secs: method_timeout,
                });
            }
            let msg = response["message"].as_str().unwrap_or("unknown");
            return Err(SudoError::StepUp(format!("Agent poll error: {msg}")));
        }

        // Distinguish response type by presence of unique fields.
        if response.get("session_id").is_some() {
            // StepUpComplete: { acr, session_id, id_token? }
            //
            // Phase 30 (D-14 through D-16): validate the CIBA ID token via
            // TokenValidator before extracting the ACR claim. This eliminates
            // the unverified base64-decode path that was vulnerable to a
            // compromised agent injecting arbitrary ACR values (T-30-11).
            let id_token = response.get("id_token").and_then(|v| v.as_str());
            let require_id_token = security_modes.step_up_require_id_token;

            let (acr, id_token_verified) = match (id_token, require_id_token) {
                (Some(token_str), _) => {
                    // D-14: Validate using existing TokenValidator infrastructure.
                    // Build ValidationConfig from environment (same pattern as
                    // perform_device_flow_step_up — reads OIDC_ISSUER / OIDC_CLIENT_ID).
                    let issuer = std::env::var("OIDC_ISSUER").map_err(|_| {
                        SudoError::Config(
                            "OIDC_ISSUER not set (required for CIBA ID token validation)"
                                .to_string(),
                        )
                    })?;
                    let client_id =
                        std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| "prmana".to_string());

                    let validation_config = ValidationConfig {
                        issuer,
                        client_id,
                        required_acr: None, // ACR check happens after extraction
                        max_auth_age: None,
                        jti_enforcement: crate::policy::config::EnforcementMode::Warn,
                        clock_skew_tolerance_secs: 60,
                        allowed_algorithms: None,
                    };

                    #[cfg(feature = "test-mode")]
                    let validator = {
                        if is_test_mode_enabled() {
                            TokenValidator::new_insecure_for_testing(validation_config)
                        } else {
                            TokenValidator::new(validation_config)
                        }
                    };
                    #[cfg(not(feature = "test-mode"))]
                    let validator = TokenValidator::new(validation_config);

                    // D-14: validate signature; D-15: extract ACR only after verification
                    let claims = validator.validate(token_str).map_err(|e| {
                        tracing::error!(
                            error = %e,
                            "CIBA step-up: ID token validation failed"
                        );
                        // Emit audit event with specific validation failure before returning Err.
                        // This makes the cryptographic failure visible in the OCSF audit stream.
                        AuditEvent::step_up_failed(
                            &ctx.user,
                            Some(ctx.command.as_str()),
                            "ciba",
                            &format!("CIBA ID token validation failed: {e}"),
                            Some(&e.to_string()),
                            None,
                            Some("step_up"),
                            None,
                            Some(requirements.grace_period_secs),
                            false,
                        )
                        .log();
                        SudoError::StepUp(format!("CIBA ID token validation failed: {e}"))
                    })?;

                    // D-15: ACR extracted ONLY after signature verification.
                    // id_token_verified=true: signature, issuer, audience, expiry all passed.
                    (claims.acr, true)
                }
                (None, true) => {
                    // D-16: missing ID token when step_up_require_id_token=true — hard-fail
                    tracing::error!(
                        "CIBA step-up: id_token absent in agent response, \
                         step_up_require_id_token=true — hard-failing"
                    );
                    emit_ciba_syslog_crit(
                        "prmana: CIBA step-up failed - id_token required but not \
                         received from agent; set step_up_require_id_token=false to \
                         allow unverified ACR fallback (not recommended)",
                    );
                    return Err(SudoError::StepUp(
                        "Step-up ID token required but not received from agent".to_string(),
                    ));
                }
                (None, false) => {
                    // D-16 permissive: fall back to deprecated agent-asserted ACR.
                    // LOG_CRIT so the degradation is SIEM-visible.
                    // id_token_verified=false: no cryptographic verification performed.
                    tracing::error!(
                        "CIBA step-up: id_token absent, falling back to agent-asserted ACR \
                         (step_up_require_id_token=false) — LOG_CRIT emitted to syslog"
                    );
                    emit_ciba_syslog_crit(
                        "prmana: CIBA step-up using unverified agent-asserted ACR — \
                         set step_up_require_id_token=true to enforce cryptographic \
                         verification (D-16)",
                    );
                    (
                        response
                            .get("acr")
                            .and_then(|v| v.as_str())
                            .map(str::to_string),
                        false,
                    )
                }
            };

            return Ok(StepUpResult {
                acr,
                jti: None, // CIBA does not produce a JTI at the PAM layer.
                method: method_str,
                id_token_verified,
            });
        }

        if response.get("reason").is_some() {
            // StepUpTimedOut: { reason, user_message }
            let reason = response["reason"].as_str().unwrap_or("unknown");
            match reason {
                "timeout" => {
                    return Err(SudoError::Timeout {
                        method: method_str.to_string(),
                        timeout_secs: method_timeout,
                    })
                }
                "denied" => return Err(SudoError::Denied),
                _ => return Err(SudoError::StepUp(format!("Step-up failed: {reason}"))),
            }
        }

        // StepUpPending — still waiting. Continue polling.
        tracing::debug!(correlation_id = %correlation_id, "Step-up pending; will poll again");
    }
}

/// Emit a LOG_CRIT message to syslog (`LOG_AUTH` facility) for CIBA step-up
/// security events that must be SIEM-visible regardless of tracing log level.
///
/// Modelled after `emit_syslog_crit` in `security::jti_cache`. Failures are
/// silently ignored — syslog unavailability must never block authentication.
fn emit_ciba_syslog_crit(message: &str) {
    use syslog::{Facility, Formatter3164};

    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTH,
        hostname: None,
        process: "prmana".to_string(),
        pid: std::process::id(),
    };

    if let Ok(mut logger) = syslog::unix(formatter) {
        let _ = logger.crit(message);
    }
}

/// Connect to the agent Unix socket with a 2s timeout.
fn connect_agent_socket(socket_path: &str) -> Result<std::os::unix::net::UnixStream, SudoError> {
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path).map_err(|e| {
        SudoError::StepUp(format!(
            "Failed to connect to agent socket '{socket_path}': {e}"
        ))
    })?;

    // Set 2s read/write timeout — same as Phase 09 SessionClosed pattern.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .ok();

    Ok(stream)
}

/// Write a JSON message to an agent socket stream, followed by newline.
///
/// Sends JSON + "\n" in a single `write_all` call so that the reader sees
/// a complete newline-delimited frame atomically. Splitting into two writes
/// (json then \n) creates a race window where the server reads the JSON
/// without the terminating newline, closes the connection, and the second
/// write fails with EPIPE.
fn send_ipc_message(
    stream: &mut std::os::unix::net::UnixStream,
    msg: &serde_json::Value,
) -> Result<(), SudoError> {
    use std::io::Write;

    let mut frame = serde_json::to_string(msg)
        .map_err(|e| SudoError::StepUp(format!("Failed to serialize IPC message: {e}")))?;
    frame.push('\n');
    stream
        .write_all(frame.as_bytes())
        .map_err(|e| SudoError::StepUp(format!("Failed to write IPC message: {e}")))?;
    Ok(())
}

/// Read a newline-delimited JSON response from an agent socket stream.
fn read_ipc_response(stream: &mut std::os::unix::net::UnixStream) -> Result<String, SudoError> {
    use std::io::BufRead;

    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| SudoError::StepUp(format!("Failed to read IPC response: {e}")))?;
    Ok(line)
}

/// Perform device-flow step-up authentication (existing implementation, extracted from perform_step_up).
fn perform_device_flow_step_up(
    ctx: &SudoContext,
    requirements: &SudoStepUpRequirements,
    display: &dyn StepUpDisplay,
) -> Result<StepUpResult, SudoError> {
    // Get OIDC configuration from environment
    let issuer = std::env::var("OIDC_ISSUER")
        .map_err(|_| SudoError::Config("OIDC_ISSUER not set".to_string()))?;
    let client_id = std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| "prmana".to_string());
    let client_secret = std::env::var("OIDC_CLIENT_SECRET").ok();

    // Create device flow client (returns Result — propagate rather than panic)
    let client = DeviceFlowClient::new(&issuer, &client_id, client_secret.as_deref())?;

    // Start device authorization
    let acr_values = requirements.minimum_acr.as_deref();
    let auth_response = client.start_authorization(Some("openid"), acr_values)?;

    // Display prompt to user
    display.show_device_flow_prompt(&auth_response.verification_uri, &auth_response.user_code);

    // Create polling display wrapper
    let timeout = Duration::from_secs(requirements.timeout);
    let poll_display = PollDisplay::new(display, timeout.as_secs());

    // Poll for token with display updates
    let token_response = poll_with_display(
        &client,
        &auth_response.device_code,
        auth_response.interval,
        timeout,
        &poll_display,
    )?;

    // Validate the token.
    // For sudo step-up, we use Warn mode (same as v1.0 default) so that environments
    // whose IdP omits JTI can still use step-up without reconfiguring policy.yaml.
    // Strict mode can be configured via policy.yaml if replay protection is critical.
    let validation_config = ValidationConfig {
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        required_acr: requirements.minimum_acr.clone(),
        max_auth_age: None, // Fresh auth, no max age check needed
        jti_enforcement: crate::policy::config::EnforcementMode::Warn,
        clock_skew_tolerance_secs: 60,
        allowed_algorithms: None,
    };

    // Create validator
    #[cfg(feature = "test-mode")]
    let validator = {
        let test_mode = is_test_mode_enabled();
        if test_mode {
            // WARNING: This skips signature verification - for testing only!
            TokenValidator::new_insecure_for_testing(validation_config)
        } else {
            TokenValidator::new(validation_config)
        }
    };

    #[cfg(not(feature = "test-mode"))]
    let validator = TokenValidator::new(validation_config);

    // Get the access token or ID token
    let token_to_validate = token_response
        .id_token
        .as_deref()
        .unwrap_or(&token_response.access_token);

    let claims = validator.validate(token_to_validate)?;

    // Verify username matches.
    //
    // SBUG-03: When preferred_username is absent (OIDC Core §5.1 makes it optional),
    // fall back to the `sub` claim which is ALWAYS present per OIDC Core §2.
    // This prevents empty-string comparisons ("" != "alice" → UserMismatch with confusing
    // error message "token user '' does not match sudo user 'alice'").
    // Using `sub` as the fallback matches common IdP practice (Google, Azure AD in some
    // configurations) and produces a legible error message with the actual identity.
    let token_user_str = claims.preferred_username.as_deref().unwrap_or(&claims.sub);
    if token_user_str != ctx.user {
        return Err(SudoError::UserMismatch {
            token_user: token_user_str.to_string(),
            sudo_user: ctx.user.clone(),
        });
    }

    display.show_success();

    Ok(StepUpResult {
        acr: claims.acr,
        jti: claims.jti,
        method: "device_flow",
        // Device-flow always validates the token via TokenValidator before reaching here.
        id_token_verified: true,
    })
}

#[derive(Debug)]
pub(crate) struct StepUpResult {
    acr: Option<String>,
    /// JTI from device-flow token; unused at the PAM layer post-validation.
    #[allow(dead_code)]
    jti: Option<String>,
    /// Step-up method that completed the authentication.
    method: &'static str,
    /// Whether the CIBA ID token was cryptographically verified via `TokenValidator`.
    /// `true` = signature, issuer, audience, expiry all checked.
    /// `false` = legacy agent-asserted ACR path (step_up_require_id_token=false).
    id_token_verified: bool,
}

struct PollDisplay<'a> {
    display: &'a dyn StepUpDisplay,
    timeout_seconds: u64,
}

impl<'a> PollDisplay<'a> {
    fn new(display: &'a dyn StepUpDisplay, timeout_seconds: u64) -> Self {
        Self {
            display,
            timeout_seconds,
        }
    }

    fn update(&self, elapsed_seconds: u64) {
        self.display
            .show_waiting(elapsed_seconds, self.timeout_seconds);
    }
}

fn poll_with_display(
    client: &DeviceFlowClient,
    device_code: &str,
    interval: u64,
    timeout: Duration,
    display: &PollDisplay,
) -> Result<TokenResponse, SudoError> {
    let start = std::time::Instant::now();
    let mut current_interval = Duration::from_secs(interval);

    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            display
                .display
                .show_failure("Timeout waiting for device flow authentication");
            return Err(SudoError::Timeout {
                method: "device_flow".to_string(),
                timeout_secs: timeout.as_secs(),
            });
        }

        // Update display
        display.update(elapsed.as_secs());

        // Wait before polling
        std::thread::sleep(current_interval);

        // Poll for token
        match client.poll_for_token(device_code, interval, timeout - elapsed) {
            Ok(token) => return Ok(token),
            Err(DeviceFlowError::AuthorizationPending) => {
                continue;
            }
            Err(DeviceFlowError::SlowDown) => {
                current_interval += Duration::from_secs(5);
                continue;
            }
            Err(DeviceFlowError::AccessDenied) => {
                display.display.show_failure("Access denied by user");
                return Err(SudoError::Denied);
            }
            Err(DeviceFlowError::Timeout) => {
                display
                    .display
                    .show_failure("Timeout waiting for device flow authentication");
                return Err(SudoError::Timeout {
                    method: "device_flow".to_string(),
                    timeout_secs: timeout.as_secs(),
                });
            }
            Err(e) => {
                display.display.show_failure(&e.to_string());
                return Err(e.into());
            }
        }
    }
}

fn log_privilege_policy_decision(
    ctx: &SudoContext,
    decision: &SudoPolicyDecision,
    grace_period_applied: bool,
) {
    AuditEvent::privilege_policy_decision(
        &ctx.user,
        &ctx.command,
        match decision.action {
            SudoPolicyAction::Allow => "allow",
            SudoPolicyAction::StepUp => "step_up",
            SudoPolicyAction::Deny => "deny",
        },
        decision.matched_rule_name.as_deref(),
        match decision.host_classification {
            crate::policy::config::HostClassification::Standard => "standard",
            crate::policy::config::HostClassification::Elevated => "elevated",
            crate::policy::config::HostClassification::Critical => "critical",
        },
        decision.grace_period_secs,
        grace_period_applied,
        decision.dry_run,
    )
    .log();
}

fn log_step_up_initiated(
    ctx: &SudoContext,
    requirements: &SudoStepUpRequirements,
    decision: Option<&SudoPolicyDecision>,
) {
    // Priority matches perform_step_up() dispatch order: Push > Fido2 > DeviceFlow.
    let method = if requirements.allowed_methods.contains(&StepUpMethod::Push) {
        "push"
    } else if requirements.allowed_methods.contains(&StepUpMethod::Fido2) {
        "fido2"
    } else if requirements
        .allowed_methods
        .contains(&StepUpMethod::DeviceFlow)
    {
        "device_flow"
    } else {
        "unknown"
    };

    AuditEvent::step_up_initiated(
        &ctx.user,
        Some(&ctx.command),
        method,
        None,
        decision.and_then(|d| d.matched_rule_name.as_deref()),
        decision.map(|d| match d.action {
            SudoPolicyAction::Allow => "allow",
            SudoPolicyAction::StepUp => "step_up",
            SudoPolicyAction::Deny => "deny",
        }),
        decision.map(|d| match d.host_classification {
            crate::policy::config::HostClassification::Standard => "standard",
            crate::policy::config::HostClassification::Elevated => "elevated",
            crate::policy::config::HostClassification::Critical => "critical",
        }),
        Some(requirements.grace_period_secs),
        decision.is_some_and(|d| d.dry_run),
    )
    .log();
}

fn log_step_up_success(
    ctx: &SudoContext,
    result: &StepUpResult,
    _response_time_ms: u64,
    decision: Option<&SudoPolicyDecision>,
) {
    AuditEvent::step_up_success(
        &ctx.user,
        Some(&ctx.command),
        result.method,
        &ctx.session_id,
        result.acr.as_deref(),
        None, // auth_time is in the token claims, not passed here
        result.id_token_verified,
        decision.and_then(|d| d.matched_rule_name.as_deref()),
        decision.map(|d| match d.action {
            SudoPolicyAction::Allow => "allow",
            SudoPolicyAction::StepUp => "step_up",
            SudoPolicyAction::Deny => "deny",
        }),
        decision.map(|d| match d.host_classification {
            crate::policy::config::HostClassification::Standard => "standard",
            crate::policy::config::HostClassification::Elevated => "elevated",
            crate::policy::config::HostClassification::Critical => "critical",
        }),
        decision.map(|d| d.grace_period_secs),
        false,
        decision.is_some_and(|d| d.dry_run),
    )
    .log();
}

fn log_step_up_failed(
    ctx: &SudoContext,
    method: &str,
    reason: &str,
    decision: Option<&SudoPolicyDecision>,
) {
    // verification_failure is None here — CIBA ID token validation failures emit their
    // own audit event with the specific reason at the callsite (perform_step_up_via_ipc).
    AuditEvent::step_up_failed(
        &ctx.user,
        Some(&ctx.command),
        method,
        reason,
        None,
        decision.and_then(|d| d.matched_rule_name.as_deref()),
        decision.map(|d| match d.action {
            SudoPolicyAction::Allow => "allow",
            SudoPolicyAction::StepUp => "step_up",
            SudoPolicyAction::Deny => "deny",
        }),
        decision.map(|d| match d.host_classification {
            crate::policy::config::HostClassification::Standard => "standard",
            crate::policy::config::HostClassification::Elevated => "elevated",
            crate::policy::config::HostClassification::Critical => "critical",
        }),
        decision.map(|d| d.grace_period_secs),
        decision.is_some_and(|d| d.dry_run),
    )
    .log();
}

fn generate_session_id() -> Result<String, getrandom::Error> {
    crate::security::session::generate_sudo_session_id()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ui::terminal::QuietDisplay;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static SUDO_TEST_ENV_MUTEX: Mutex<()> = Mutex::new(());

    // ── TDD RED: CIBA step-up via agent IPC ───────────────────────────────────

    /// SudoError::StepUp variant exists and carries a descriptive message.
    #[test]
    fn test_sudo_error_step_up_variant() {
        let err = SudoError::StepUp("agent socket not reachable".to_string());
        let msg = err.to_string();
        assert!(
            msg.contains("agent socket"),
            "SudoError::StepUp must include the detail message, got: {msg}"
        );
    }

    /// challenge_timeout default is 120 (satisfies STP-07: configurable, default 120s).
    #[test]
    fn test_challenge_timeout_defaults_to_120() {
        use crate::policy::config::SudoConfig;
        let config = SudoConfig::default();
        assert_eq!(
            config.challenge_timeout, 120,
            "challenge_timeout must default to 120 (STP-07)"
        );
    }

    /// log_step_up_initiated includes step-up method in audit log (no-panic test).
    #[test]
    fn test_log_step_up_initiated_includes_method() {
        let ctx = SudoContext::new("alice", "/usr/bin/id", Some("/dev/pts/0")).unwrap();
        let reqs = SudoStepUpRequirements {
            allowed_methods: vec![StepUpMethod::Push],
            timeout: 120,
            method_timeouts: crate::policy::config::MethodTimeouts::default(),
            poll_interval_secs: 5,
            minimum_acr: None,
            grace_period_secs: 0,
        };
        // Must not panic; method is extracted from allowed_methods.
        log_step_up_initiated(&ctx, &reqs, None);
    }

    fn test_policy() -> PolicyConfig {
        PolicyConfig::default()
    }

    fn sudo_ctx(command: &str) -> SudoContext {
        SudoContext::new("alice", command, None).unwrap()
    }

    fn test_display() -> QuietDisplay {
        QuietDisplay::new()
    }

    fn phase44_policy(yaml: &str) -> PolicyConfig {
        serde_yaml::from_str(yaml).unwrap()
    }

    /// perform_step_up_via_ipc returns SudoError::StepUp on IPC connection failure.
    #[test]
    fn test_perform_step_up_via_ipc_connection_refused() {
        let ctx = SudoContext::new("alice", "/usr/bin/ls", None).unwrap();
        let reqs = SudoStepUpRequirements {
            allowed_methods: vec![StepUpMethod::Push],
            timeout: 5,
            method_timeouts: crate::policy::config::MethodTimeouts::default(),
            poll_interval_secs: 5,
            minimum_acr: None,
            grace_period_secs: 0,
        };
        // Point to a non-existent socket.
        let socket_path = "/tmp/prmana-agent-test-nonexistent-12345.sock";

        let modes = crate::policy::config::SecurityModes {
            step_up_require_id_token: false,
            ..Default::default()
        };
        let result = perform_step_up_via_ipc(
            &ctx,
            &reqs,
            &test_policy(),
            socket_path,
            StepUpMethod::Push,
            &modes,
        );
        assert!(
            matches!(result, Err(SudoError::StepUp(_))),
            "Expected SudoError::StepUp on connection refused, got: {result:?}"
        );
    }

    /// Mock IPC test: StepUpPending then StepUpComplete → Ok(StepUpResult).
    ///
    /// Creates a temporary Unix socket server that replies with canned JSON.
    #[test]
    fn test_step_up_ipc_pending_then_complete() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let socket_path = temp.path().join("mock-agent.sock");

        // Spawn a mock agent that responds with StepUpPending, then StepUpComplete.
        let socket_path_clone = socket_path.clone();
        std::thread::spawn(move || {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            for mut stream in listener.incoming().filter_map(Result::ok) {
                let mut buf = vec![0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let msg = String::from_utf8_lossy(&buf[..n]);
                if msg.contains("step_up\"") {
                    // First call: respond with StepUpPending.
                    let resp = serde_json::json!({
                        "status": "success",
                        "correlation_id": "test-corr-id",
                        "expires_in": 120,
                        "poll_interval_secs": 1
                    });
                    let _ = stream.write_all(format!("{resp}\n").as_bytes());
                } else if msg.contains("step_up_result") {
                    // Second call: respond with StepUpComplete.
                    let resp = serde_json::json!({
                        "status": "success",
                        "acr": null,
                        "session_id": "sess-test-001"
                    });
                    let _ = stream.write_all(format!("{resp}\n").as_bytes());
                }
            }
        });

        // Give server time to bind.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let ctx = SudoContext::new("alice", "/usr/bin/ls", None).unwrap();
        let reqs = SudoStepUpRequirements {
            allowed_methods: vec![StepUpMethod::Push],
            timeout: 10,
            method_timeouts: crate::policy::config::MethodTimeouts::default(),
            poll_interval_secs: 5,
            minimum_acr: None,
            grace_period_secs: 0,
        };

        // step_up_require_id_token=false: mock agent returns no id_token, test
        // verifies the permissive fallback path (agent-asserted ACR).
        let modes = crate::policy::config::SecurityModes {
            step_up_require_id_token: false,
            ..Default::default()
        };
        let result = perform_step_up_via_ipc(
            &ctx,
            &reqs,
            &test_policy(),
            socket_path.to_str().unwrap(),
            StepUpMethod::Push,
            &modes,
        );
        assert!(result.is_ok(), "Expected Ok on Complete, got: {result:?}");
    }

    /// Mock IPC test: StepUpTimedOut(reason="timeout") → SudoError::Timeout.
    #[test]
    fn test_step_up_ipc_timed_out_reason_timeout() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let socket_path = temp.path().join("mock-agent-timeout.sock");

        let socket_path_clone = socket_path.clone();
        std::thread::spawn(move || {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            for mut stream in listener.incoming().filter_map(Result::ok) {
                let mut buf = vec![0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let msg = String::from_utf8_lossy(&buf[..n]);
                if msg.contains("step_up\"") {
                    let resp = serde_json::json!({
                        "status": "success",
                        "correlation_id": "corr-timeout",
                        "expires_in": 120,
                        "poll_interval_secs": 1
                    });
                    let _ = stream.write_all(format!("{resp}\n").as_bytes());
                } else if msg.contains("step_up_result") {
                    let resp = serde_json::json!({
                        "status": "success",
                        "reason": "timeout",
                        "user_message": "Approval timed out"
                    });
                    let _ = stream.write_all(format!("{resp}\n").as_bytes());
                }
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(50));

        let ctx = SudoContext::new("alice", "/usr/bin/ls", None).unwrap();
        let reqs = SudoStepUpRequirements {
            allowed_methods: vec![StepUpMethod::Push],
            timeout: 10,
            method_timeouts: crate::policy::config::MethodTimeouts::default(),
            poll_interval_secs: 5,
            minimum_acr: None,
            grace_period_secs: 0,
        };

        let modes = crate::policy::config::SecurityModes {
            step_up_require_id_token: false,
            ..Default::default()
        };
        let result = perform_step_up_via_ipc(
            &ctx,
            &reqs,
            &test_policy(),
            socket_path.to_str().unwrap(),
            StepUpMethod::Push,
            &modes,
        );
        assert!(
            matches!(result, Err(SudoError::Timeout { .. })),
            "Expected SudoError::Timeout, got: {result:?}"
        );
    }

    /// Mock IPC test: StepUpTimedOut(reason="denied") → SudoError::Denied.
    #[test]
    fn test_step_up_ipc_denied() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let socket_path = temp.path().join("mock-agent-denied.sock");

        let socket_path_clone = socket_path.clone();
        std::thread::spawn(move || {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            for mut stream in listener.incoming().filter_map(Result::ok) {
                let mut buf = vec![0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let msg = String::from_utf8_lossy(&buf[..n]);
                if msg.contains("step_up\"") {
                    let resp = serde_json::json!({
                        "status": "success",
                        "correlation_id": "corr-denied",
                        "expires_in": 120,
                        "poll_interval_secs": 1
                    });
                    let _ = stream.write_all(format!("{resp}\n").as_bytes());
                } else if msg.contains("step_up_result") {
                    let resp = serde_json::json!({
                        "status": "success",
                        "reason": "denied",
                        "user_message": "User denied the request"
                    });
                    let _ = stream.write_all(format!("{resp}\n").as_bytes());
                }
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(50));

        let ctx = SudoContext::new("alice", "/usr/bin/ls", None).unwrap();
        let reqs = SudoStepUpRequirements {
            allowed_methods: vec![StepUpMethod::Push],
            timeout: 10,
            method_timeouts: crate::policy::config::MethodTimeouts::default(),
            poll_interval_secs: 5,
            minimum_acr: None,
            grace_period_secs: 0,
        };

        let modes = crate::policy::config::SecurityModes {
            step_up_require_id_token: false,
            ..Default::default()
        };
        let result = perform_step_up_via_ipc(
            &ctx,
            &reqs,
            &test_policy(),
            socket_path.to_str().unwrap(),
            StepUpMethod::Push,
            &modes,
        );
        assert!(
            matches!(result, Err(SudoError::Denied)),
            "Expected SudoError::Denied, got: {result:?}"
        );
    }

    #[test]
    fn test_sudo_context_creation() {
        let ctx = SudoContext::new(
            "testuser",
            "/usr/bin/systemctl restart nginx",
            Some("/dev/pts/0"),
        )
        .unwrap();

        assert_eq!(ctx.user, "testuser");
        assert_eq!(ctx.command, "/usr/bin/systemctl restart nginx");
        assert_eq!(ctx.tty, Some("/dev/pts/0".to_string()));
        assert!(ctx.session_id.starts_with("sudo-"));
    }

    #[test]
    fn test_sudo_context_without_tty() {
        let ctx = SudoContext::new("admin", "/usr/bin/apt update", None).unwrap();

        assert_eq!(ctx.user, "admin");
        assert_eq!(ctx.command, "/usr/bin/apt update");
        assert!(ctx.tty.is_none());
    }

    /// F-04 positive: generated session ID has CSPRNG randomness in expected format.
    #[test]
    fn test_generate_session_id_format_with_csprng() {
        let id = generate_session_id().unwrap();
        assert!(id.starts_with("sudo-"), "must start with sudo- prefix");

        // Format: sudo-{timestamp_hex}-{16_hex_chars_of_randomness}
        let parts: Vec<&str> = id.split('-').collect();
        // "sudo" + timestamp + random = at least 3 parts
        assert!(
            parts.len() >= 3,
            "expected at least 3 dash-separated parts, got: {id}"
        );
        assert_eq!(parts[0], "sudo");

        // Last part is 32 hex chars (16 bytes / 128 bits of CSPRNG randomness)
        let random_part = parts.last().unwrap();
        assert_eq!(
            random_part.len(),
            32,
            "random part must be 32 hex chars, got: {random_part}"
        );
        assert!(
            random_part.chars().all(|c| c.is_ascii_hexdigit()),
            "random part must be valid hex, got: {random_part}"
        );
    }

    /// F-04 negative: two IDs generated in quick succession are NOT equal (CSPRNG randomness).
    #[test]
    fn test_generate_session_id_uniqueness_from_csprng() {
        let id1 = generate_session_id().unwrap();
        let id2 = generate_session_id().unwrap();

        assert_ne!(
            id1, id2,
            "two session IDs must differ due to CSPRNG randomness"
        );

        // Even the random suffix alone must differ (not just the timestamp)
        let random1 = id1.split('-').next_back().unwrap();
        let random2 = id2.split('-').next_back().unwrap();
        assert_ne!(
            random1, random2,
            "random components must differ with 64 bits of entropy"
        );
    }

    #[test]
    fn test_sudo_error_display() {
        let err = SudoError::Denied;
        assert!(err.to_string().contains("denied"));

        let err = SudoError::Timeout {
            method: "fido2".to_string(),
            timeout_secs: 30,
        };
        assert!(err.to_string().contains("fido2"));
        assert!(err.to_string().contains("30s"));

        let err = SudoError::UserMismatch {
            token_user: "alice".to_string(),
            sudo_user: "bob".to_string(),
        };
        assert!(err.to_string().contains("alice"));
        assert!(err.to_string().contains("bob"));

        let err = SudoError::Config("invalid config".to_string());
        assert!(err.to_string().contains("invalid config"));

        // Phase 8: GroupDenied variant
        let err = SudoError::GroupDenied("user not in wheel".to_string());
        assert!(
            err.to_string().contains("Sudo group policy denied"),
            "GroupDenied must include 'Sudo group policy denied' in message"
        );
        assert!(err.to_string().contains("wheel"));
    }

    #[test]
    fn test_sudo_error_group_denied_is_descriptive() {
        // Ensure GroupDenied carries the full detail from GroupPolicyError.
        let msg = "User 'alice' is not a member of any allowed group. \
                   User groups: [unix-users]. Allowed groups: [wheel]";
        let err = SudoError::GroupDenied(msg.to_string());
        assert!(err.to_string().contains("alice"));
        assert!(err.to_string().contains("wheel"));
    }

    #[test]
    fn test_sudo_config_empty_sudo_groups_permits_all() {
        // Empty sudo_groups = no restriction. Verify the gate is bypassed for root
        // (who definitely exists in NSS) when sudo_groups is empty.
        use crate::policy::config::PolicyConfig;

        let policy = PolicyConfig::default();
        assert!(
            policy.sudo.sudo_groups.is_empty(),
            "default policy must have empty sudo_groups (no restriction)"
        );
        // The authenticate_sudo gate: `if !policy.sudo.sudo_groups.is_empty()` →
        // with empty list the check is skipped entirely, so no NSS lookup occurs.
        // This is the backward-compat invariant.
    }

    #[test]
    fn test_sudo_auth_result() {
        let result = SudoAuthResult {
            session_id: "sudo-123".to_string(),
            acr: Some("urn:mfa".to_string()),
            response_time_ms: 5000,
        };

        assert_eq!(result.session_id, "sudo-123");
        assert_eq!(result.acr, Some("urn:mfa".to_string()));
        assert_eq!(result.response_time_ms, 5000);
    }

    #[test]
    fn test_authenticate_sudo_policy_allow_skips_step_up() {
        let policy = phase44_policy(
            r#"
sudo:
  step_up_required: true
  default_action: allow
"#,
        );

        let result = authenticate_sudo(&sudo_ctx("/usr/bin/id"), &policy, &test_display()).unwrap();
        assert!(result.is_none(), "allow action must not initiate step-up");
    }

    #[test]
    fn test_authenticate_sudo_policy_deny_blocks_command() {
        let policy = phase44_policy(
            r#"
sudo:
  step_up_required: true
  default_action: deny
  commands:
    - name: "destructive"
      pattern: "/usr/bin/userdel *"
      action: deny
"#,
        );

        let err = authenticate_sudo(
            &sudo_ctx("/usr/bin/userdel alice"),
            &policy,
            &test_display(),
        )
        .expect_err("deny action must fail closed");
        match err {
            SudoError::PolicyDenied { reason } => {
                assert!(reason.contains("destructive") || reason.contains("deny"));
            }
            other => panic!("expected PolicyDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_authenticate_sudo_dry_run_falls_back_to_legacy_behavior() {
        let policy = phase44_policy(
            r#"
sudo:
  step_up_required: false
  default_action: deny
  dry_run: true
"#,
        );

        let result = authenticate_sudo(&sudo_ctx("/usr/bin/id"), &policy, &test_display()).unwrap();
        assert!(
            result.is_none(),
            "dry-run must preserve legacy no-step-up behavior instead of enforcing deny"
        );
    }

    #[test]
    fn test_recent_step_up_grace_window_satisfies_matching_rule() {
        let _guard = SUDO_TEST_ENV_MUTEX.lock().unwrap();
        let temp = TempDir::new().unwrap();
        std::env::set_var("PRMANA_SUDO_STEPUP_CACHE_DIR", temp.path());

        let policy = phase44_policy(
            r#"
host:
  classification: critical
sudo:
  step_up_required: true
  commands:
    - name: "service-restart"
      pattern: "/usr/bin/systemctl restart *"
      action: step_up
      grace_period_secs: 300
      host_classification: critical
"#,
        );

        record_recent_step_up(
            "alice",
            "/usr/bin/systemctl restart nginx",
            Some("service-restart"),
            crate::policy::config::HostClassification::Critical,
            SystemTime::now(),
        );

        let result = authenticate_sudo(
            &sudo_ctx("/usr/bin/systemctl restart nginx"),
            &policy,
            &test_display(),
        )
        .unwrap();

        std::env::remove_var("PRMANA_SUDO_STEPUP_CACHE_DIR");
        assert!(
            result.is_none(),
            "fresh grace record must suppress repeat step-up"
        );
    }

    #[test]
    fn test_recent_step_up_grace_zero_never_satisfies() {
        let _guard = SUDO_TEST_ENV_MUTEX.lock().unwrap();
        let temp = TempDir::new().unwrap();
        std::env::set_var("PRMANA_SUDO_STEPUP_CACHE_DIR", temp.path());

        record_recent_step_up(
            "alice",
            "/usr/bin/systemctl restart nginx",
            Some("service-restart"),
            crate::policy::config::HostClassification::Critical,
            SystemTime::now(),
        );

        let satisfied = recent_step_up_satisfies(
            "alice",
            "/usr/bin/systemctl restart nginx",
            Some("service-restart"),
            crate::policy::config::HostClassification::Critical,
            0,
        );

        std::env::remove_var("PRMANA_SUDO_STEPUP_CACHE_DIR");
        assert!(
            !satisfied,
            "zero grace period must force a fresh challenge every time"
        );
    }
}
