//! Multi-IdP failover state machine (Phase 41, ADR-020).
//!
//! Provides active-passive primary/secondary OIDC issuer failover for
//! high-availability enterprise deployments. Failover triggers ONLY on
//! availability-class failures (connect timeout, TLS failure, 5xx) — never
//! on policy, crypto, or validation failures.
//!
//! Security invariants:
//! - Failover is availability-only. Policy/crypto errors are hard failures.
//! - JWKS caches remain issuer-scoped (MIDP-07 preserved).
//! - In-flight requests are never switched mid-stream.
//!
//! References:
//! - docs/plans/2026-04-10-phase-41-multi-idp-redundancy.md
//! - ADR-020: Active-Passive IdP Redundancy

use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{info, warn};

// ── Failure classification ──────────────────────────────────────────────────

/// Whether an error should trigger failover or be treated as a hard failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Availability failure — triggers failover to secondary.
    Availability,
    /// Policy/protocol/security failure — no failover, hard fail.
    NonFailover,
}

/// Classify an HTTP status code for failover purposes.
///
/// Only 5xx responses trigger failover. 4xx responses indicate the issuer is
/// reachable and returning a deliberate error — failing over would risk turning
/// a security rejection into a fail-open.
pub fn classify_http_status(status: u16) -> FailureClass {
    if status >= 500 {
        FailureClass::Availability
    } else {
        FailureClass::NonFailover
    }
}

/// Classify a reqwest error for failover purposes.
///
/// Connect, timeout, and TLS errors are availability failures.
/// Decode/body errors indicate a reachable but misbehaving issuer.
pub fn classify_reqwest_error(err: &reqwest::Error) -> FailureClass {
    if err.is_connect() || err.is_timeout() {
        FailureClass::Availability
    } else if err.is_request() {
        // Request errors include DNS, TLS, and connection refused.
        FailureClass::Availability
    } else {
        // Body/decode errors: issuer is reachable but returned garbage.
        // This is "malformed response from a reachable endpoint" — no failover.
        FailureClass::NonFailover
    }
}

// ── Failover pair configuration ─────────────────────────────────────────────

/// Configuration for a primary/secondary OIDC issuer failover pair.
///
/// Both `primary_issuer_url` and `secondary_issuer_url` must reference
/// issuers already present in the `issuers` array (validated at load time).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverPairConfig {
    /// Primary issuer URL (must exist in issuers array).
    pub primary_issuer_url: String,
    /// Secondary issuer URL (must exist in issuers array).
    pub secondary_issuer_url: String,
    /// HTTP request timeout for failover-aware requests (seconds). Default: 10.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    /// Seconds to remain on secondary before retrying primary. Default: 60.
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
}

fn default_request_timeout() -> u64 {
    10
}
fn default_cooldown() -> u64 {
    60
}

/// Validation errors for failover pair configuration.
#[derive(Debug, thiserror::Error)]
pub enum FailoverConfigError {
    #[error("Failover pair references unknown issuer URL: {0}")]
    UnknownIssuer(String),
    #[error("Primary and secondary issuer URLs must differ, got: {0}")]
    SameIssuer(String),
    #[error("Issuer URL appears as primary in multiple failover pairs: {0}")]
    DuplicatePrimary(String),
    #[error("request_timeout_secs must be > 0")]
    ZeroTimeout,
    #[error("cooldown_secs must be > 0")]
    ZeroCooldown,
}

impl FailoverPairConfig {
    /// Validate this failover pair against a set of known issuer URLs.
    pub fn validate(&self, known_issuers: &[String]) -> Result<(), FailoverConfigError> {
        if self.request_timeout_secs == 0 {
            return Err(FailoverConfigError::ZeroTimeout);
        }
        if self.cooldown_secs == 0 {
            return Err(FailoverConfigError::ZeroCooldown);
        }

        let primary_normalized = self.primary_issuer_url.trim_end_matches('/');
        let secondary_normalized = self.secondary_issuer_url.trim_end_matches('/');

        if primary_normalized == secondary_normalized {
            return Err(FailoverConfigError::SameIssuer(
                self.primary_issuer_url.clone(),
            ));
        }

        let known_normalized: Vec<String> = known_issuers
            .iter()
            .map(|u| u.trim_end_matches('/').to_string())
            .collect();

        if !known_normalized.contains(&primary_normalized.to_string()) {
            return Err(FailoverConfigError::UnknownIssuer(
                self.primary_issuer_url.clone(),
            ));
        }
        if !known_normalized.contains(&secondary_normalized.to_string()) {
            return Err(FailoverConfigError::UnknownIssuer(
                self.secondary_issuer_url.clone(),
            ));
        }

        Ok(())
    }
}

/// Validate a set of failover pairs for cross-pair constraints.
///
/// Rejects duplicate primary URLs across pairs (each issuer can only be
/// primary in one pair). Secondary can appear in multiple pairs (shared standby).
pub fn validate_failover_pairs(
    pairs: &[FailoverPairConfig],
    known_issuers: &[String],
) -> Result<(), FailoverConfigError> {
    let mut seen_primaries = std::collections::HashSet::new();

    for pair in pairs {
        pair.validate(known_issuers)?;

        let primary_normalized = pair.primary_issuer_url.trim_end_matches('/').to_string();
        if !seen_primaries.insert(primary_normalized.clone()) {
            return Err(FailoverConfigError::DuplicatePrimary(
                pair.primary_issuer_url.clone(),
            ));
        }
    }

    Ok(())
}

// ── Failover state machine ──────────────────────────────────────────────────

/// Active issuer state for a failover pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverState {
    /// Primary issuer is active and healthy.
    Primary,
    /// Failed over to secondary. Includes the instant when failover occurred.
    Secondary,
    /// Both issuers unavailable. Fail closed.
    Exhausted,
}

/// Runtime failover state for a single failover pair.
///
/// Thread-safety: this struct is designed to be wrapped in a `Mutex` or
/// `RwLock` by the caller. The daemon's `AgentState` should hold a
/// `HashMap<String, Mutex<FailoverRuntime>>` keyed by primary issuer URL.
pub struct FailoverRuntime {
    config: FailoverPairConfig,
    state: FailoverState,
    /// When failover to secondary occurred — used for cooldown calculation.
    failover_at: Option<Instant>,
}

/// Result of resolving which issuer to use for a new request.
#[derive(Debug, Clone)]
pub struct ResolvedIssuer {
    /// The issuer URL to use for this request.
    pub issuer_url: String,
    /// Whether this is the secondary (failover is active).
    pub failover_active: bool,
}

impl FailoverRuntime {
    /// Create a new runtime state for a failover pair, starting with primary.
    pub fn new(config: FailoverPairConfig) -> Self {
        Self {
            config,
            state: FailoverState::Primary,
            failover_at: None,
        }
    }

    /// Get the current failover state.
    pub fn state(&self) -> FailoverState {
        self.state
    }

    /// Get the failover pair config.
    pub fn config(&self) -> &FailoverPairConfig {
        &self.config
    }

    /// Resolve which issuer URL to use for a new request.
    ///
    /// Implements lazy cooldown-based recovery: if we're on secondary and
    /// cooldown has expired, returns primary (giving it a retry chance).
    /// The caller must then call `record_success()` or `record_failure()`
    /// based on the outcome.
    pub fn resolve_issuer(&self) -> ResolvedIssuer {
        match self.state {
            FailoverState::Primary => ResolvedIssuer {
                issuer_url: self.config.primary_issuer_url.clone(),
                failover_active: false,
            },
            FailoverState::Secondary => {
                // Check if cooldown has expired — if so, try primary again.
                if let Some(failover_at) = self.failover_at {
                    let elapsed = failover_at.elapsed().as_secs();
                    if elapsed >= self.config.cooldown_secs {
                        // Cooldown expired: return primary for a retry attempt.
                        // State is NOT changed here — caller must call
                        // record_success() or record_failure() after the attempt.
                        return ResolvedIssuer {
                            issuer_url: self.config.primary_issuer_url.clone(),
                            failover_active: true, // still technically in failover mode
                        };
                    }
                }
                ResolvedIssuer {
                    issuer_url: self.config.secondary_issuer_url.clone(),
                    failover_active: true,
                }
            }
            FailoverState::Exhausted => {
                // Both down. Check cooldown to see if we should retry primary.
                if let Some(failover_at) = self.failover_at {
                    let elapsed = failover_at.elapsed().as_secs();
                    if elapsed >= self.config.cooldown_secs {
                        return ResolvedIssuer {
                            issuer_url: self.config.primary_issuer_url.clone(),
                            failover_active: true,
                        };
                    }
                }
                // Still within cooldown — return primary anyway, caller will
                // get an error and we'll stay exhausted. This is fail-closed.
                ResolvedIssuer {
                    issuer_url: self.config.primary_issuer_url.clone(),
                    failover_active: true,
                }
            }
        }
    }

    /// Record a successful request to the given issuer URL.
    ///
    /// If we were on secondary and primary succeeds (cooldown retry), transitions
    /// back to Primary and returns `Some(RecoveryEvent)`.
    pub fn record_success(&mut self, issuer_url: &str) -> Option<FailoverEvent> {
        let primary_normalized = self.config.primary_issuer_url.trim_end_matches('/');
        let issuer_normalized = issuer_url.trim_end_matches('/');

        match self.state {
            FailoverState::Secondary | FailoverState::Exhausted
                if issuer_normalized == primary_normalized =>
            {
                // Primary recovered after cooldown retry.
                let previous_state = self.state;
                self.state = FailoverState::Primary;
                self.failover_at = None;
                info!(
                    primary = %self.config.primary_issuer_url,
                    previous_state = ?previous_state,
                    "IdP failover recovered: primary is healthy again"
                );
                Some(FailoverEvent::Recovered {
                    primary_issuer: self.config.primary_issuer_url.clone(),
                    secondary_issuer: self.config.secondary_issuer_url.clone(),
                })
            }
            _ => None,
        }
    }

    /// Record an availability failure against the given issuer URL.
    ///
    /// Returns a failover event if the state transitions.
    pub fn record_failure(
        &mut self,
        issuer_url: &str,
        reason: &str,
    ) -> Option<FailoverEvent> {
        let primary_normalized = self.config.primary_issuer_url.trim_end_matches('/');
        let secondary_normalized = self.config.secondary_issuer_url.trim_end_matches('/');
        let issuer_normalized = issuer_url.trim_end_matches('/');

        match self.state {
            FailoverState::Primary if issuer_normalized == primary_normalized => {
                // Primary failed — failover to secondary.
                self.state = FailoverState::Secondary;
                self.failover_at = Some(Instant::now());
                warn!(
                    primary = %self.config.primary_issuer_url,
                    secondary = %self.config.secondary_issuer_url,
                    reason = reason,
                    "IdP failover activated: switching to secondary"
                );
                Some(FailoverEvent::Activated {
                    failed_issuer: self.config.primary_issuer_url.clone(),
                    secondary_issuer: self.config.secondary_issuer_url.clone(),
                    reason: reason.to_string(),
                })
            }
            FailoverState::Secondary if issuer_normalized == secondary_normalized => {
                // Secondary also failed — exhausted.
                self.state = FailoverState::Exhausted;
                // Keep failover_at for cooldown-based recovery attempt.
                self.failover_at = Some(Instant::now());
                warn!(
                    primary = %self.config.primary_issuer_url,
                    secondary = %self.config.secondary_issuer_url,
                    reason = reason,
                    "IdP failover exhausted: both issuers unavailable"
                );
                Some(FailoverEvent::Exhausted {
                    primary_issuer: self.config.primary_issuer_url.clone(),
                    secondary_issuer: self.config.secondary_issuer_url.clone(),
                    reason: reason.to_string(),
                })
            }
            FailoverState::Secondary if issuer_normalized == primary_normalized => {
                // Primary failed again during cooldown retry — stay on secondary,
                // reset cooldown timer.
                self.failover_at = Some(Instant::now());
                info!(
                    primary = %self.config.primary_issuer_url,
                    reason = reason,
                    "Primary retry failed during cooldown — remaining on secondary"
                );
                None // No new event — we're already in Secondary state.
            }
            FailoverState::Exhausted => {
                // Both issuers still down — reset cooldown timer.
                self.failover_at = Some(Instant::now());
                None
            }
            _ => None,
        }
    }
}

/// Events emitted by the failover state machine for audit logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverEvent {
    /// Primary failed, switched to secondary.
    Activated {
        failed_issuer: String,
        secondary_issuer: String,
        reason: String,
    },
    /// Primary recovered after cooldown.
    Recovered {
        primary_issuer: String,
        secondary_issuer: String,
    },
    /// Both issuers unavailable.
    Exhausted {
        primary_issuer: String,
        secondary_issuer: String,
        reason: String,
    },
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> FailoverPairConfig {
        FailoverPairConfig {
            primary_issuer_url: "https://primary.example.com/realms/corp".to_string(),
            secondary_issuer_url: "https://secondary.example.com/realms/corp".to_string(),
            request_timeout_secs: 10,
            cooldown_secs: 60,
        }
    }

    fn known_issuers() -> Vec<String> {
        vec![
            "https://primary.example.com/realms/corp".to_string(),
            "https://secondary.example.com/realms/corp".to_string(),
        ]
    }

    // ── Config validation tests ─────────────────────────────────────────

    #[test]
    fn test_valid_config() {
        let config = test_config();
        assert!(config.validate(&known_issuers()).is_ok());
    }

    #[test]
    fn test_config_rejects_same_primary_secondary() {
        let config = FailoverPairConfig {
            primary_issuer_url: "https://primary.example.com/realms/corp".to_string(),
            secondary_issuer_url: "https://primary.example.com/realms/corp".to_string(),
            ..test_config()
        };
        assert!(matches!(
            config.validate(&known_issuers()),
            Err(FailoverConfigError::SameIssuer(_))
        ));
    }

    #[test]
    fn test_config_rejects_same_with_trailing_slash() {
        let config = FailoverPairConfig {
            primary_issuer_url: "https://primary.example.com/realms/corp".to_string(),
            secondary_issuer_url: "https://primary.example.com/realms/corp/".to_string(),
            ..test_config()
        };
        assert!(matches!(
            config.validate(&known_issuers()),
            Err(FailoverConfigError::SameIssuer(_))
        ));
    }

    #[test]
    fn test_config_rejects_unknown_primary() {
        let config = FailoverPairConfig {
            primary_issuer_url: "https://unknown.example.com".to_string(),
            ..test_config()
        };
        assert!(matches!(
            config.validate(&known_issuers()),
            Err(FailoverConfigError::UnknownIssuer(_))
        ));
    }

    #[test]
    fn test_config_rejects_unknown_secondary() {
        let config = FailoverPairConfig {
            secondary_issuer_url: "https://unknown.example.com".to_string(),
            ..test_config()
        };
        assert!(matches!(
            config.validate(&known_issuers()),
            Err(FailoverConfigError::UnknownIssuer(_))
        ));
    }

    #[test]
    fn test_config_rejects_zero_timeout() {
        let config = FailoverPairConfig {
            request_timeout_secs: 0,
            ..test_config()
        };
        assert!(matches!(
            config.validate(&known_issuers()),
            Err(FailoverConfigError::ZeroTimeout)
        ));
    }

    #[test]
    fn test_config_rejects_zero_cooldown() {
        let config = FailoverPairConfig {
            cooldown_secs: 0,
            ..test_config()
        };
        assert!(matches!(
            config.validate(&known_issuers()),
            Err(FailoverConfigError::ZeroCooldown)
        ));
    }

    #[test]
    fn test_validate_pairs_rejects_duplicate_primary() {
        let pairs = vec![
            test_config(),
            FailoverPairConfig {
                primary_issuer_url: "https://primary.example.com/realms/corp".to_string(),
                secondary_issuer_url: "https://secondary.example.com/realms/corp".to_string(),
                ..test_config()
            },
        ];
        assert!(matches!(
            validate_failover_pairs(&pairs, &known_issuers()),
            Err(FailoverConfigError::DuplicatePrimary(_))
        ));
    }

    // ── State machine tests ─────────────────────────────────────────────

    #[test]
    fn test_initial_state_is_primary() {
        let rt = FailoverRuntime::new(test_config());
        assert_eq!(rt.state(), FailoverState::Primary);
    }

    #[test]
    fn test_resolve_returns_primary_initially() {
        let rt = FailoverRuntime::new(test_config());
        let resolved = rt.resolve_issuer();
        assert_eq!(
            resolved.issuer_url,
            "https://primary.example.com/realms/corp"
        );
        assert!(!resolved.failover_active);
    }

    #[test]
    fn test_primary_failure_activates_secondary() {
        let mut rt = FailoverRuntime::new(test_config());
        let event = rt.record_failure(
            "https://primary.example.com/realms/corp",
            "connect timeout",
        );
        assert_eq!(rt.state(), FailoverState::Secondary);
        assert!(matches!(event, Some(FailoverEvent::Activated { .. })));

        let resolved = rt.resolve_issuer();
        assert_eq!(
            resolved.issuer_url,
            "https://secondary.example.com/realms/corp"
        );
        assert!(resolved.failover_active);
    }

    #[test]
    fn test_secondary_failure_exhausts() {
        let mut rt = FailoverRuntime::new(test_config());
        rt.record_failure(
            "https://primary.example.com/realms/corp",
            "connect timeout",
        );
        let event = rt.record_failure(
            "https://secondary.example.com/realms/corp",
            "TLS failure",
        );
        assert_eq!(rt.state(), FailoverState::Exhausted);
        assert!(matches!(event, Some(FailoverEvent::Exhausted { .. })));
    }

    #[test]
    fn test_primary_success_after_failover_recovers() {
        let mut rt = FailoverRuntime::new(FailoverPairConfig {
            cooldown_secs: 0, // immediate cooldown for test
            ..test_config()
        });
        rt.record_failure(
            "https://primary.example.com/realms/corp",
            "connect timeout",
        );
        assert_eq!(rt.state(), FailoverState::Secondary);

        // Simulate cooldown expiry and successful primary retry
        let event = rt.record_success("https://primary.example.com/realms/corp");
        assert_eq!(rt.state(), FailoverState::Primary);
        assert!(matches!(event, Some(FailoverEvent::Recovered { .. })));
    }

    #[test]
    fn test_primary_retry_failure_stays_secondary() {
        let mut rt = FailoverRuntime::new(test_config());
        rt.record_failure(
            "https://primary.example.com/realms/corp",
            "connect timeout",
        );
        assert_eq!(rt.state(), FailoverState::Secondary);

        // Primary fails again (cooldown retry)
        let event = rt.record_failure(
            "https://primary.example.com/realms/corp",
            "still down",
        );
        assert_eq!(rt.state(), FailoverState::Secondary);
        assert!(event.is_none()); // No new event
    }

    #[test]
    fn test_recovery_from_exhausted() {
        let mut rt = FailoverRuntime::new(FailoverPairConfig {
            cooldown_secs: 0, // immediate cooldown for test
            ..test_config()
        });
        rt.record_failure(
            "https://primary.example.com/realms/corp",
            "connect timeout",
        );
        rt.record_failure(
            "https://secondary.example.com/realms/corp",
            "TLS failure",
        );
        assert_eq!(rt.state(), FailoverState::Exhausted);

        // Primary recovers
        let event = rt.record_success("https://primary.example.com/realms/corp");
        assert_eq!(rt.state(), FailoverState::Primary);
        assert!(matches!(event, Some(FailoverEvent::Recovered { .. })));
    }

    #[test]
    fn test_secondary_success_does_not_change_state() {
        let mut rt = FailoverRuntime::new(test_config());
        rt.record_failure(
            "https://primary.example.com/realms/corp",
            "connect timeout",
        );
        assert_eq!(rt.state(), FailoverState::Secondary);

        // Successful request to secondary — no state change.
        let event = rt.record_success("https://secondary.example.com/realms/corp");
        assert_eq!(rt.state(), FailoverState::Secondary);
        assert!(event.is_none());
    }

    #[test]
    fn test_policy_failure_does_not_trigger_failover() {
        // This tests the failure classification, not the state machine.
        assert_eq!(classify_http_status(400), FailureClass::NonFailover);
        assert_eq!(classify_http_status(401), FailureClass::NonFailover);
        assert_eq!(classify_http_status(403), FailureClass::NonFailover);
        assert_eq!(classify_http_status(404), FailureClass::NonFailover);
    }

    #[test]
    fn test_server_error_triggers_failover() {
        assert_eq!(classify_http_status(500), FailureClass::Availability);
        assert_eq!(classify_http_status(502), FailureClass::Availability);
        assert_eq!(classify_http_status(503), FailureClass::Availability);
        assert_eq!(classify_http_status(504), FailureClass::Availability);
    }

    #[test]
    fn test_cooldown_blocks_primary_retry() {
        let mut rt = FailoverRuntime::new(FailoverPairConfig {
            cooldown_secs: 3600, // very long cooldown
            ..test_config()
        });
        rt.record_failure(
            "https://primary.example.com/realms/corp",
            "connect timeout",
        );
        assert_eq!(rt.state(), FailoverState::Secondary);

        // Within cooldown — should resolve to secondary.
        let resolved = rt.resolve_issuer();
        assert_eq!(
            resolved.issuer_url,
            "https://secondary.example.com/realms/corp"
        );
        assert!(resolved.failover_active);
    }

    #[test]
    fn test_cooldown_expiry_retries_primary() {
        let mut rt = FailoverRuntime::new(FailoverPairConfig {
            cooldown_secs: 0, // immediate expiry
            ..test_config()
        });
        rt.record_failure(
            "https://primary.example.com/realms/corp",
            "connect timeout",
        );
        assert_eq!(rt.state(), FailoverState::Secondary);

        // Cooldown expired — should resolve to primary for retry.
        let resolved = rt.resolve_issuer();
        assert_eq!(
            resolved.issuer_url,
            "https://primary.example.com/realms/corp"
        );
        // Still technically in failover mode until record_success().
        assert!(resolved.failover_active);
    }

    #[test]
    fn test_failover_event_contains_reason() {
        let mut rt = FailoverRuntime::new(test_config());
        let event = rt
            .record_failure(
                "https://primary.example.com/realms/corp",
                "HTTP 503 Service Unavailable",
            )
            .unwrap();
        match event {
            FailoverEvent::Activated { reason, .. } => {
                assert_eq!(reason, "HTTP 503 Service Unavailable");
            }
            _ => panic!("Expected Activated event"),
        }
    }
}
