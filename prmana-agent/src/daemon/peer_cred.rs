//! IPC peer credential extraction.
//!
//! Provides [`get_peer_credentials`], which reads the UID (and, on Linux, PID)
//! of the process on the other end of a connected Unix-domain socket.
//!
//! ## Platform support
//!
//! | Platform | Syscall          | PID available |
//! |----------|------------------|---------------|
//! | Linux    | `SO_PEERCRED`    | Yes           |
//! | macOS    | `getpeereid(3)`  | No            |
//! | Other    | N/A              | Err (fail-closed) |
//!
//! ## Security rationale
//!
//! The agent socket is protected by `0600` file-system permissions, which already
//! prevents other users from *connecting*.  Peer credential checking adds a
//! defense-in-depth layer: even if an attacker obtains a file descriptor for the
//! socket (e.g., via a setuid binary or inherited fd), the kernel credential check
//! rejects any connection from a process running as a different UID.
//!
//! Failure to retrieve credentials is treated as a rejection (fail-closed).
//! This is consistent with the security invariant in CLAUDE.md: if a security
//! check cannot be performed, log it prominently and deny access.
//!
//! ## Accepted trust model: same-UID equivalence (SSH-agent model)
//!
//! **Design decision (reviewed April 2026, Codex finding 2):** Any process
//! running as the same UID is treated as fully trusted. This matches the
//! well-established `ssh-agent` trust model used by OpenSSH.
//!
//! **Implication:** A same-UID process can request DPoP proofs, trigger token
//! refresh, shut down the daemon, or wipe credentials. If your threat model
//! includes malware running under the authenticated user's account, mitigate
//! with hardware-bound keys (TPM/YubiKey), SELinux/AppArmor confinement, or
//! full-disk encryption.
//!
//! **v3.1 plan:** IPC channel separation — crypto operations (GetProof) on one
//! socket, admin operations (Shutdown, SessionClosed) on a root-only socket.
//! See `docs/security-audit-2026-04.md` Finding 2 for details.
//!
//! ## References
//!
//! - `socket(7)` Linux man page, `SO_PEERCRED` option.
//! - `getpeereid(3)` BSD/macOS man page.
//! - libc 0.2 — <https://docs.rs/libc/latest/libc/>

use std::os::unix::io::AsRawFd;

/// Extract the UID (and optionally PID) of the connected peer.
///
/// Returns `(uid, Option<pid>)`:
/// - `uid`: effective UID of the peer process.
/// - `pid`: PID of the peer process on Linux; `None` on macOS (`getpeereid` does
///   not expose PID).
///
/// # Errors
///
/// Returns `Err` with `ErrorKind::Unsupported` on platforms other than Linux and
/// macOS.  Returns `Err` with the OS error if the underlying syscall fails.
///
/// Callers must treat any `Err` as a connection rejection (fail-closed).
pub fn get_peer_credentials(
    stream: &tokio::net::UnixStream,
) -> std::io::Result<(u32, Option<u32>)> {
    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        // SO_PEERCRED returns a `ucred` struct with pid, uid, gid.
        // Source: socket(7), `SO_PEERCRED` option.
        let mut ucred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // Safety: fd is valid (comes from a live tokio UnixStream), ucred and len
        // are valid stack variables with correct sizes.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut ucred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        return Ok((ucred.uid, Some(ucred.pid as u32)));
    }

    #[cfg(target_os = "macos")]
    {
        // getpeereid(3) returns uid and gid but not PID.
        // Source: getpeereid(3) macOS man page.
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // Safety: fd is valid; uid/gid are valid mutable references.
        let ret = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        return Ok((uid, None));
    }

    // Fail-closed on unsupported platforms: deny the connection rather than
    // silently allowing it without a credential check.
    #[allow(unreachable_code)]
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "peer credential check not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// get_peer_credentials returns the current process UID on a connected socket pair.
    ///
    /// Uses `std::os::unix::net::UnixStream::pair()` to create a connected pair,
    /// wraps one end in a tokio `UnixStream`, and asserts that the returned UID
    /// matches the process's effective UID.
    #[tokio::test]
    async fn test_peer_cred_returns_current_uid() {
        use std::os::unix::net::UnixStream as StdUnixStream;

        let (std_stream_a, _std_stream_b) = StdUnixStream::pair().expect("socketpair failed");
        std_stream_a
            .set_nonblocking(true)
            .expect("set_nonblocking failed");

        let tokio_stream = tokio::net::UnixStream::from_std(std_stream_a).expect("from_std failed");

        let result = get_peer_credentials(&tokio_stream);
        assert!(
            result.is_ok(),
            "get_peer_credentials failed: {:?}",
            result.err()
        );

        let (peer_uid, _peer_pid) = result.unwrap();
        let expected_uid = unsafe { libc::getuid() };
        assert_eq!(
            peer_uid, expected_uid,
            "peer UID should match current process UID"
        );
    }

    /// get_peer_credentials returns the current process UID (same-process pair).
    ///
    /// Both ends of the socket pair are in the same process, so the peer UID
    /// is always the daemon UID. Validates that the UID check would pass.
    #[tokio::test]
    async fn test_peer_uid_matches_daemon_uid() {
        use std::os::unix::net::UnixStream as StdUnixStream;

        let (std_stream_a, _std_stream_b) = StdUnixStream::pair().expect("socketpair failed");
        std_stream_a
            .set_nonblocking(true)
            .expect("set_nonblocking failed");

        let tokio_stream = tokio::net::UnixStream::from_std(std_stream_a).expect("from_std failed");

        let (peer_uid, _) = get_peer_credentials(&tokio_stream).unwrap();
        let daemon_uid = unsafe { libc::getuid() };

        assert_eq!(
            peer_uid, daemon_uid,
            "same-process pair: peer UID must equal daemon UID"
        );
    }

    /// On Linux, get_peer_credentials returns Some(pid); on macOS, None.
    #[tokio::test]
    async fn test_peer_cred_pid_platform_behavior() {
        use std::os::unix::net::UnixStream as StdUnixStream;

        let (std_stream_a, _std_stream_b) = StdUnixStream::pair().expect("socketpair failed");
        std_stream_a
            .set_nonblocking(true)
            .expect("set_nonblocking failed");

        let tokio_stream = tokio::net::UnixStream::from_std(std_stream_a).expect("from_std failed");

        let (_, peer_pid) = get_peer_credentials(&tokio_stream).unwrap();

        #[cfg(target_os = "linux")]
        {
            assert!(peer_pid.is_some(), "Linux: SO_PEERCRED must provide PID");
            // PID should be the current process PID (same-process pair).
            let expected_pid = std::process::id();
            assert_eq!(
                peer_pid.unwrap(),
                expected_pid,
                "Linux: peer PID should match current process PID"
            );
        }

        #[cfg(target_os = "macos")]
        {
            assert!(peer_pid.is_none(), "macOS: getpeereid does not provide PID");
        }
    }
}
