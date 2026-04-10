// Fault injection state machine for the idp-proxy CI tool.
//
// Security posture: fault state is in-memory only. Restarting the proxy
// unconditionally clears all faults. No persistence, no inter-process
// fault leakage.
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// The set of injectable fault modes. `Off` means transparent pass-through.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case", tag = "mode")]
pub enum FaultMode {
    Off,
    Status503,
    Slow { latency_ms: u64 },
    MalformedJwks,
    DropConnection,
}

impl FaultMode {
    /// String name used in CLI and log output.
    pub fn as_str(&self) -> &'static str {
        match self {
            FaultMode::Off => "off",
            FaultMode::Status503 => "503",
            FaultMode::Slow { .. } => "slow",
            FaultMode::MalformedJwks => "malformed-jwks",
            FaultMode::DropConnection => "drop-connection",
        }
    }
}

/// Holds the active fault mode and its optional expiry.
pub struct FaultState {
    mode: FaultMode,
    /// When `Some`, the fault expires at this instant and reverts to `Off`.
    expires_at: Option<Instant>,
}

/// Thread-safe shared fault state used by both proxy and control plane.
pub type SharedFaultState = Arc<RwLock<FaultState>>;

impl FaultState {
    /// Create a new `FaultState` in the `Off` (pass-through) mode.
    pub fn new() -> Self {
        FaultState {
            mode: FaultMode::Off,
            expires_at: None,
        }
    }

    /// Apply a fault mode, optionally with a duration after which it auto-expires.
    ///
    /// If `duration` is `None`, the fault is permanent until the next `apply` call.
    pub fn apply(&mut self, mode: FaultMode, duration: Option<Duration>) {
        self.mode = mode;
        self.expires_at = duration.map(|d| Instant::now() + d);
    }

    /// Return the currently active fault mode.
    ///
    /// If the fault had a duration and that duration has elapsed, returns `Off`.
    pub fn current(&self) -> FaultMode {
        if let Some(expiry) = self.expires_at {
            if Instant::now() >= expiry {
                return FaultMode::Off;
            }
        }
        self.mode.clone()
    }
}

impl Default for FaultState {
    fn default() -> Self {
        FaultState::new()
    }
}

/// JSON body accepted by `POST /fault` on the control plane.
#[derive(Debug, Deserialize)]
pub struct FaultRequest {
    pub mode: String,
    /// Duration in seconds; `None` means permanent until next command.
    pub duration_secs: Option<u64>,
    /// Latency in milliseconds; only meaningful for `slow` mode.
    pub latency_ms: Option<u64>,
}

impl FaultRequest {
    /// Parse the request into a `FaultMode`.
    ///
    /// Returns `Err` with a human-readable message if `mode` is unrecognised.
    pub fn into_mode(self) -> Result<FaultMode, String> {
        match self.mode.to_ascii_lowercase().as_str() {
            "503" | "status503" => Ok(FaultMode::Status503),
            "slow" => Ok(FaultMode::Slow {
                latency_ms: self.latency_ms.unwrap_or(30_000),
            }),
            "malformed-jwks" | "malformed_jwks" => Ok(FaultMode::MalformedJwks),
            "drop-connection" | "drop_connection" => Ok(FaultMode::DropConnection),
            "off" => Ok(FaultMode::Off),
            unknown => Err(format!(
                "unknown fault mode '{}'; valid modes: 503, slow, malformed-jwks, drop-connection, off",
                unknown
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fault_state_new_is_off() {
        let state = FaultState::new();
        assert_eq!(state.current(), FaultMode::Off);
    }

    #[test]
    fn test_apply_503_permanent() {
        let mut state = FaultState::new();
        state.apply(FaultMode::Status503, None);
        assert_eq!(state.current(), FaultMode::Status503);
    }

    #[test]
    fn test_apply_off_clears_fault() {
        let mut state = FaultState::new();
        state.apply(FaultMode::Status503, None);
        assert_eq!(state.current(), FaultMode::Status503);
        state.apply(FaultMode::Off, None);
        assert_eq!(state.current(), FaultMode::Off);
    }

    #[test]
    fn test_apply_503_with_future_expiry_returns_503() {
        let mut state = FaultState::new();
        state.apply(FaultMode::Status503, Some(Duration::from_secs(60)));
        // Immediately after apply, should still be Status503
        assert_eq!(state.current(), FaultMode::Status503);
    }

    #[test]
    fn test_apply_503_with_expired_returns_off() {
        let mut state = FaultState::new();
        // Apply a fault that has already expired (1 ns in the past by sleeping
        // 10 ms after setting a 1 ms expiry).
        state.apply(FaultMode::Status503, Some(Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(state.current(), FaultMode::Off);
    }

    #[test]
    fn test_apply_slow_mode() {
        let mut state = FaultState::new();
        state.apply(FaultMode::Slow { latency_ms: 500 }, None);
        assert_eq!(state.current(), FaultMode::Slow { latency_ms: 500 });
    }

    #[test]
    fn test_fault_request_parses_503() {
        let req = FaultRequest {
            mode: "503".to_string(),
            duration_secs: Some(60),
            latency_ms: None,
        };
        assert_eq!(req.into_mode().unwrap(), FaultMode::Status503);
    }

    #[test]
    fn test_fault_request_parses_slow() {
        let req = FaultRequest {
            mode: "slow".to_string(),
            duration_secs: None,
            latency_ms: Some(500),
        };
        assert_eq!(req.into_mode().unwrap(), FaultMode::Slow { latency_ms: 500 });
    }

    #[test]
    fn test_fault_request_parses_malformed_jwks() {
        let req = FaultRequest {
            mode: "malformed-jwks".to_string(),
            duration_secs: None,
            latency_ms: None,
        };
        assert_eq!(req.into_mode().unwrap(), FaultMode::MalformedJwks);
    }

    #[test]
    fn test_fault_request_parses_drop_connection() {
        let req = FaultRequest {
            mode: "drop-connection".to_string(),
            duration_secs: None,
            latency_ms: None,
        };
        assert_eq!(req.into_mode().unwrap(), FaultMode::DropConnection);
    }

    #[test]
    fn test_fault_request_parses_off() {
        let req = FaultRequest {
            mode: "off".to_string(),
            duration_secs: None,
            latency_ms: None,
        };
        assert_eq!(req.into_mode().unwrap(), FaultMode::Off);
    }

    #[test]
    fn test_fault_request_rejects_unknown_mode() {
        let req = FaultRequest {
            mode: "banana".to_string(),
            duration_secs: None,
            latency_ms: None,
        };
        assert!(req.into_mode().is_err());
    }
}
