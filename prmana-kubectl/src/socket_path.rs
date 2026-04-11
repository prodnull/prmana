//! Unix socket path resolution for prmana-agent IPC.
//!
//! Resolution order:
//! 1. `PRMANA_SOCKET` environment variable (highest priority — test override)
//! 2. `$XDG_RUNTIME_DIR/prmana-agent.sock` (user session socket via systemd)
//! 3. `/run/prmana/agent.sock` (system-level daemon socket)
//! 4. `/tmp/prmana-agent.sock` (last-resort fallback)
//!
//! This matches the socket path priority defined in the prmana-agent socket
//! acquisition code (`daemon/socket.rs: acquire_listener`).

use std::path::PathBuf;

/// Resolve the prmana-agent socket path using the priority chain.
///
/// Reads environment variables at call time. In production use `resolve()`.
/// In tests, set `PRMANA_SOCKET` before calling to override the socket path.
pub fn resolve() -> anyhow::Result<PathBuf> {
    resolve_with_env(
        std::env::var("PRMANA_SOCKET").ok().as_deref(),
        std::env::var("XDG_RUNTIME_DIR").ok().as_deref(),
    )
}

/// Core resolution logic, parameterized for testability.
pub(crate) fn resolve_with_env(
    prmana_socket: Option<&str>,
    xdg_runtime_dir: Option<&str>,
) -> anyhow::Result<PathBuf> {
    // 1. Explicit override (used in tests and CI)
    if let Some(path) = prmana_socket {
        return Ok(PathBuf::from(path));
    }

    // 2. XDG runtime directory (typical user session under systemd)
    if let Some(xdg) = xdg_runtime_dir {
        let candidate = PathBuf::from(xdg).join("prmana-agent.sock");
        return Ok(candidate);
    }

    // 3. System-level socket (when agent runs as a system service)
    let system_path = PathBuf::from("/run/prmana/agent.sock");
    if system_path.exists() {
        return Ok(system_path);
    }

    // 4. Last-resort fallback
    Ok(PathBuf::from("/tmp/prmana-agent.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PRMANA_SOCKET takes priority over everything.
    #[test]
    fn test_env_override_takes_priority() {
        let path =
            resolve_with_env(Some("/custom/agent.sock"), Some("/run/user/1000")).unwrap();
        assert_eq!(path, PathBuf::from("/custom/agent.sock"));
    }

    /// XDG_RUNTIME_DIR used when PRMANA_SOCKET is not set.
    #[test]
    fn test_xdg_runtime_dir_used() {
        let path = resolve_with_env(None, Some("/run/user/1000")).unwrap();
        assert_eq!(path, PathBuf::from("/run/user/1000/prmana-agent.sock"));
    }

    /// Falls through to /tmp fallback when no env vars and no system socket.
    #[test]
    fn test_fallback_returned_when_no_env() {
        let path = resolve_with_env(None, None).unwrap();
        // Will be either /run/prmana/agent.sock (if exists) or /tmp/prmana-agent.sock
        assert!(
            path.to_str().unwrap().contains("prmana"),
            "fallback path must contain prmana: {path:?}"
        );
    }
}
