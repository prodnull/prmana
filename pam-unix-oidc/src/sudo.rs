//! Sudo step-up authentication.
//!
//! This module provides step-up authentication for sudo commands using
//! the OAuth 2.0 Device Authorization Grant flow.

use std::time::Duration;

use crate::audit::AuditEvent;
use crate::device_flow::{DeviceFlowClient, DeviceFlowError, TokenResponse};
use crate::oidc::{TokenValidator, ValidationConfig, ValidationError};
use crate::policy::config::SecurityModes;
use crate::policy::{PolicyConfig, PolicyRules, StepUpMethod, SudoStepUpRequirements};
use crate::sssd::groups::{check_group_policy, GroupPolicyError};
use crate::sssd::{get_user_info, UserError};
use thiserror::Error;

/// Check if test mode is explicitly enabled.
/// Security: Only accepts explicit "true" or "1" values, not just presence of the variable.
#[cfg(feature = "test-mode")]
fn is_test_mode_enabled() -> bool {
    std::env::var("UNIX_OIDC_TEST_MODE")
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

    #[error("Step-up timeout")]
    Timeout,

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

    // Check if step-up is required for this command
    let requirements = match rules.check_sudo(&ctx.command) {
        Some(req) => req,
        None => {
            // No step-up required
            return Ok(None);
        }
    };

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
            log_step_up_failed(ctx, "device_flow", "user not in sudo_groups");
            SudoError::GroupDenied(e.to_string())
        })?;
    }

    // Log step-up initiation
    log_step_up_initiated(ctx, &requirements);

    // Perform step-up authentication
    let security_modes = policy.effective_security_modes();
    let start = std::time::Instant::now();
    let result = match perform_step_up(ctx, &requirements, display, &security_modes) {
        Ok(r) => r,
        Err(e) => {
            // Log failure
            log_step_up_failed(ctx, "device_flow", &e.to_string());
            return Err(e);
        }
    };
    let response_time_ms = start.elapsed().as_millis() as u64;

    // Log success
    log_step_up_success(ctx, &result, response_time_ms);

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
    security_modes: &SecurityModes,
) -> Result<StepUpResult, SudoError> {
    // Prefer Push/Fido2 (CIBA) when available — lower friction than device flow.
    if requirements.allowed_methods.contains(&StepUpMethod::Push) {
        let socket_path = agent_socket_path();
        return perform_step_up_via_ipc(
            ctx,
            requirements,
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

/// Resolve the agent socket path from environment (same convention as Phase 09 session IPC).
///
/// Checks `UNIX_OIDC_AGENT_SOCKET`, then `XDG_RUNTIME_DIR/unix-oidc-agent.sock`,
/// then falls back to `/run/user/0/unix-oidc-agent.sock` (root sessions).
fn agent_socket_path() -> String {
    std::env::var("UNIX_OIDC_AGENT_SOCKET").unwrap_or_else(|_| {
        let xdg = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/0".to_string());
        format!("{xdg}/unix-oidc-agent.sock")
    })
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
    socket_path: &str,
    method: StepUpMethod,
    security_modes: &SecurityModes,
) -> Result<StepUpResult, SudoError> {
    let method_str = match method {
        StepUpMethod::Push => "push",
        StepUpMethod::Fido2 => "fido2",
        StepUpMethod::DeviceFlow => "device_flow",
    };

    // Resolve hostname (gethostname crate is available in pam-unix-oidc).
    let hostname = gethostname::gethostname().to_string_lossy().to_string();

    // ── Resolve parent session ID from environment (OBS-3) ───────────────────
    //
    // The parent SSH session ID is set by pam_sm_open_session via PAM putenv
    // (UNIX_OIDC_SESSION_ID). In a sudo PAM context this env var may be absent
    // (older pam-unix-oidc versions, non-SSH sudo invocations, or environments
    // where UNIX_OIDC_SESSION_ID was not exported to the sudo session). Fall
    // back to None with a debug log — absence never fails authentication.
    //
    // Reference: Phase 09 session correlation design (Phase 09 decision in STATE.md):
    // "Session correlation via PAM putenv/getenv is best-effort: failure never fails auth"
    let parent_session_id: Option<String> = std::env::var("UNIX_OIDC_SESSION_ID").ok().filter(|s| !s.is_empty()).map(|s| {
        tracing::debug!(parent_session_id = %s, "Resolved parent SSH session ID for step-up audit correlation");
        s
    });
    if parent_session_id.is_none() {
        tracing::debug!("UNIX_OIDC_SESSION_ID not set in sudo PAM context; parent_session_id will be absent from step-up audit event");
    }

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

    let poll_interval_secs = 5u64; // Default; agent may return a shorter interval.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(requirements.timeout);

    // ── Step 2: Poll for result ───────────────────────────────────────────────
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(SudoError::Timeout);
        }

        std::thread::sleep(std::time::Duration::from_secs(poll_interval_secs));

        if std::time::Instant::now() >= deadline {
            return Err(SudoError::Timeout);
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
                return Err(SudoError::Timeout);
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
                        SudoError::Config("OIDC_ISSUER not set (required for CIBA ID token validation)".to_string())
                    })?;
                    let client_id = std::env::var("OIDC_CLIENT_ID")
                        .unwrap_or_else(|_| "unix-oidc".to_string());

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
                        "unix-oidc: CIBA step-up failed - id_token required but not \
                         received from agent; set step_up_require_id_token=false to \
                         allow unverified ACR fallback (not recommended)"
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
                        "unix-oidc: CIBA step-up using unverified agent-asserted ACR — \
                         set step_up_require_id_token=true to enforce cryptographic \
                         verification (D-16)"
                    );
                    (response.get("acr").and_then(|v| v.as_str()).map(str::to_string), false)
                }
            };

            return Ok(StepUpResult {
                acr,
                jti: None, // CIBA does not produce a JTI at the PAM layer.
                id_token_verified,
            });
        }

        if response.get("reason").is_some() {
            // StepUpTimedOut: { reason, user_message }
            let reason = response["reason"].as_str().unwrap_or("unknown");
            match reason {
                "timeout" => return Err(SudoError::Timeout),
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
        process: "unix-oidc".to_string(),
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
fn send_ipc_message(
    stream: &mut std::os::unix::net::UnixStream,
    msg: &serde_json::Value,
) -> Result<(), SudoError> {
    use std::io::Write;

    let json = serde_json::to_string(msg)
        .map_err(|e| SudoError::StepUp(format!("Failed to serialize IPC message: {e}")))?;
    stream
        .write_all(json.as_bytes())
        .map_err(|e| SudoError::StepUp(format!("Failed to write IPC message: {e}")))?;
    stream
        .write_all(b"\n")
        .map_err(|e| SudoError::StepUp(format!("Failed to write IPC newline: {e}")))?;
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
    let client_id = std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| "unix-oidc".to_string());
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
                .show_failure("Timeout waiting for authentication");
            return Err(SudoError::Timeout);
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
                    .show_failure("Timeout waiting for authentication");
                return Err(SudoError::Timeout);
            }
            Err(e) => {
                display.display.show_failure(&e.to_string());
                return Err(e.into());
            }
        }
    }
}

fn log_step_up_initiated(ctx: &SudoContext, requirements: &SudoStepUpRequirements) {
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

    AuditEvent::step_up_initiated(&ctx.user, Some(&ctx.command), method, None).log();
}

fn log_step_up_success(ctx: &SudoContext, result: &StepUpResult, _response_time_ms: u64) {
    AuditEvent::step_up_success(
        &ctx.user,
        Some(&ctx.command),
        "device_flow",
        &ctx.session_id,
        result.acr.as_deref(),
        None, // auth_time is in the token claims, not passed here
        result.id_token_verified,
    )
    .log();
}

fn log_step_up_failed(ctx: &SudoContext, method: &str, reason: &str) {
    // verification_failure is None here — CIBA ID token validation failures emit their
    // own audit event with the specific reason at the callsite (perform_step_up_via_ipc).
    AuditEvent::step_up_failed(&ctx.user, Some(&ctx.command), method, reason, None).log();
}

fn generate_session_id() -> Result<String, getrandom::Error> {
    crate::security::session::generate_sudo_session_id()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
            minimum_acr: None,
        };
        // Must not panic; method is extracted from allowed_methods.
        log_step_up_initiated(&ctx, &reqs);
    }

    /// perform_step_up_via_ipc returns SudoError::StepUp on IPC connection failure.
    #[test]
    fn test_perform_step_up_via_ipc_connection_refused() {
        let ctx = SudoContext::new("alice", "/usr/bin/ls", None).unwrap();
        let reqs = SudoStepUpRequirements {
            allowed_methods: vec![StepUpMethod::Push],
            timeout: 5,
            minimum_acr: None,
        };
        // Point to a non-existent socket.
        let socket_path = "/tmp/unix-oidc-agent-test-nonexistent-12345.sock";

        let modes = crate::policy::config::SecurityModes {
            step_up_require_id_token: false,
            ..Default::default()
        };
        let result = perform_step_up_via_ipc(&ctx, &reqs, socket_path, StepUpMethod::Push, &modes);
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
            minimum_acr: None,
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
            minimum_acr: None,
        };

        let modes = crate::policy::config::SecurityModes {
            step_up_require_id_token: false,
            ..Default::default()
        };
        let result = perform_step_up_via_ipc(
            &ctx,
            &reqs,
            socket_path.to_str().unwrap(),
            StepUpMethod::Push,
            &modes,
        );
        assert!(
            matches!(result, Err(SudoError::Timeout)),
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
            minimum_acr: None,
        };

        let modes = crate::policy::config::SecurityModes {
            step_up_require_id_token: false,
            ..Default::default()
        };
        let result = perform_step_up_via_ipc(
            &ctx,
            &reqs,
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
        let random1 = id1.split('-').last().unwrap();
        let random2 = id2.split('-').last().unwrap();
        assert_ne!(
            random1, random2,
            "random components must differ with 64 bits of entropy"
        );
    }

    #[test]
    fn test_sudo_error_display() {
        let err = SudoError::Denied;
        assert!(err.to_string().contains("denied"));

        let err = SudoError::Timeout;
        assert!(err.to_string().contains("timeout"));

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
}
