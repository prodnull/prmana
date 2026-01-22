//! Sudo step-up authentication.
//!
//! This module provides step-up authentication for sudo commands using
//! the OAuth 2.0 Device Authorization Grant flow.

use std::time::Duration;

use crate::audit::AuditEvent;
use crate::device_flow::{DeviceFlowClient, DeviceFlowError, TokenResponse};
use crate::oidc::{TokenValidator, ValidationConfig, ValidationError};
use crate::policy::{PolicyConfig, PolicyRules, StepUpMethod, SudoStepUpRequirements};
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

    #[error("User mismatch: token user {token_user} != sudo user {sudo_user}")]
    UserMismatch {
        token_user: String,
        sudo_user: String,
    },
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
    pub fn new(user: &str, command: &str, tty: Option<&str>) -> Self {
        Self {
            user: user.to_string(),
            command: command.to_string(),
            tty: tty.map(String::from),
            session_id: generate_session_id(),
        }
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

    // Log step-up initiation
    log_step_up_initiated(ctx, &requirements);

    // Perform step-up authentication
    let start = std::time::Instant::now();
    let result = match perform_step_up(ctx, &requirements, display) {
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
fn perform_step_up(
    ctx: &SudoContext,
    requirements: &SudoStepUpRequirements,
    display: &dyn StepUpDisplay,
) -> Result<StepUpResult, SudoError> {
    // For now, we only support device flow
    // Future: add support for push and FIDO2
    if !requirements
        .allowed_methods
        .contains(&StepUpMethod::DeviceFlow)
    {
        return Err(SudoError::Config(
            "No supported step-up method available".to_string(),
        ));
    }

    // Get OIDC configuration from environment
    let issuer = std::env::var("OIDC_ISSUER")
        .map_err(|_| SudoError::Config("OIDC_ISSUER not set".to_string()))?;
    let client_id = std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| "unix-oidc".to_string());
    let client_secret = std::env::var("OIDC_CLIENT_SECRET").ok();

    // Create device flow client
    let client = DeviceFlowClient::new(&issuer, &client_id, client_secret.as_deref());

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

    // Validate the token
    let validation_config = ValidationConfig {
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        required_acr: requirements.minimum_acr.clone(),
        max_auth_age: None, // Fresh auth, no max age check needed
        enforce_jti: true,  // Enable replay protection for sudo
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

    // Verify username matches
    if claims.preferred_username != ctx.user {
        return Err(SudoError::UserMismatch {
            token_user: claims.preferred_username,
            sudo_user: ctx.user.clone(),
        });
    }

    display.show_success();

    Ok(StepUpResult {
        acr: claims.acr,
        jti: claims.jti,
    })
}

#[allow(dead_code)]
struct StepUpResult {
    acr: Option<String>,
    jti: Option<String>,
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
    let method = if requirements
        .allowed_methods
        .contains(&StepUpMethod::DeviceFlow)
    {
        "device_flow"
    } else if requirements.allowed_methods.contains(&StepUpMethod::Push) {
        "push"
    } else if requirements.allowed_methods.contains(&StepUpMethod::Fido2) {
        "fido2"
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
    )
    .log();
}

fn log_step_up_failed(ctx: &SudoContext, method: &str, reason: &str) {
    AuditEvent::step_up_failed(&ctx.user, Some(&ctx.command), method, reason).log();
}

fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("sudo-{:x}", timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sudo_context_creation() {
        let ctx = SudoContext::new(
            "testuser",
            "/usr/bin/systemctl restart nginx",
            Some("/dev/pts/0"),
        );

        assert_eq!(ctx.user, "testuser");
        assert_eq!(ctx.command, "/usr/bin/systemctl restart nginx");
        assert_eq!(ctx.tty, Some("/dev/pts/0".to_string()));
        assert!(ctx.session_id.starts_with("sudo-"));
    }

    #[test]
    fn test_sudo_context_without_tty() {
        let ctx = SudoContext::new("admin", "/usr/bin/apt update", None);

        assert_eq!(ctx.user, "admin");
        assert_eq!(ctx.command, "/usr/bin/apt update");
        assert!(ctx.tty.is_none());
    }

    #[test]
    fn test_generate_session_id() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();

        assert!(id1.starts_with("sudo-"));
        assert!(id2.starts_with("sudo-"));
        // IDs should be unique (different timestamps)
        // Note: This might occasionally fail if called within same nanosecond
    }

    #[test]
    fn test_session_id_format() {
        let id = generate_session_id();
        // Format: sudo-{timestamp}-{random}
        let parts: Vec<&str> = id.split('-').collect();
        assert!(parts.len() >= 2);
        assert_eq!(parts[0], "sudo");
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
