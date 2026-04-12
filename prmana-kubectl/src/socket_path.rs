//! Unix socket path resolution for prmana-agent IPC.
//!
//! Resolution order:
//! 1. `PRMANA_SOCKET` environment variable (highest priority — test override)
//! 2. `$XDG_RUNTIME_DIR/prmana-agent.sock` (user session socket via systemd)
//! 3. `/run/user/<uid>/prmana-agent.sock` (canonical per-user Linux fallback)
//! 4. `$TMPDIR/prmana-agent.sock` (macOS user-session fallback)
//! 5. Error on unsupported platforms without an explicit override
//!
//! This matches the default socket selection in `prmana-agent`.

use std::path::PathBuf;

const SOCKET_BASENAME: &str = "prmana-agent.sock";

fn xdg_runtime_socket_path(xdg_runtime_dir: &str) -> PathBuf {
    PathBuf::from(xdg_runtime_dir).join(SOCKET_BASENAME)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_runtime_socket_path(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}/{SOCKET_BASENAME}"))
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_runtime_socket_path(tmpdir: &str) -> PathBuf {
    PathBuf::from(tmpdir).join(SOCKET_BASENAME)
}

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
        return Ok(xdg_runtime_socket_path(xdg));
    }

    // 3. Canonical per-user platform fallback when XDG_RUNTIME_DIR is absent.
    // Exactly one of the three cfg blocks below is the function's trailing
    // expression on any given target, so no `return` keyword is needed.
    #[cfg(target_os = "linux")]
    {
        let uid = unsafe { libc::getuid() };
        Ok(linux_runtime_socket_path(uid))
    }

    #[cfg(target_os = "macos")]
    {
        let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        Ok(macos_runtime_socket_path(&tmpdir))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(anyhow::anyhow!(
            "cannot resolve prmana-agent socket path without PRMANA_SOCKET or XDG_RUNTIME_DIR"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PRMANA_SOCKET takes priority over everything.
    #[test]
    fn test_env_override_takes_priority() {
        let path = resolve_with_env(Some("/custom/agent.sock"), Some("/run/user/1000")).unwrap();
        assert_eq!(path, PathBuf::from("/custom/agent.sock"));
    }

    /// XDG_RUNTIME_DIR used when PRMANA_SOCKET is not set.
    #[test]
    fn test_xdg_runtime_dir_used() {
        let path = resolve_with_env(None, Some("/run/user/1000")).unwrap();
        assert_eq!(path, PathBuf::from("/run/user/1000/prmana-agent.sock"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_runtime_socket_path_builder() {
        assert_eq!(
            linux_runtime_socket_path(1000),
            PathBuf::from("/run/user/1000/prmana-agent.sock")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_runtime_socket_path_builder() {
        assert_eq!(
            macos_runtime_socket_path("/private/tmp/prmana"),
            PathBuf::from("/private/tmp/prmana/prmana-agent.sock")
        );
    }

    /// Falls through to the canonical per-user runtime path when no env vars are set.
    #[test]
    fn test_fallback_returned_when_no_env() {
        let path = resolve_with_env(None, None).unwrap();
        assert!(
            path.to_str().unwrap().contains("prmana-agent.sock"),
            "fallback path must end in prmana-agent.sock: {path:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_host_fallback_uses_linux_runtime_dir() {
        let path = resolve_with_env(None, None).unwrap();
        let uid = unsafe { libc::getuid() };
        assert_eq!(path, linux_runtime_socket_path(uid));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_host_fallback_uses_tmpdir() {
        let path = resolve_with_env(None, None).unwrap();
        let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        assert_eq!(path, macos_runtime_socket_path(&tmpdir));
    }
}
