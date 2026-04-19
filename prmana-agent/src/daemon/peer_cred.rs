//! IPC peer credential extraction.
//!
//! Provides [`get_peer_credentials`], which reads the UID (and, on Linux, PID)
//! of the process on the other end of a connected Unix-domain socket.
//!
//! ## Platform support and per-platform semantics
//!
//! | Platform | Syscall          | PID available | Snapshot point             | What "UID" means |
//! |----------|------------------|---------------|----------------------------|---------------------|
//! | Linux    | `SO_PEERCRED`    | Yes           | `connect(2)` / `socketpair(2)` | Peer's effective UID at connect time (from `struct ucred`; `socket(7)`) |
//! | macOS    | `getpeereid(3)`  | No            | `connect(2)`                   | Peer's effective UID at connect time (`getpeereid(3)`) |
//! | Other    | N/A              | Err (fail-closed) | — | — |
//!
//! Both mechanisms snapshot the peer's effective credentials at the moment the
//! connection is established. Subsequent UID changes in the peer (e.g. a later
//! `seteuid(2)`) do NOT propagate to the reported value. This is a load-bearing
//! property for ADR-025: the connector child calls `setuid(target_user)` **before**
//! calling `connect(2)`, so the agent's credential check sees the target user's
//! UID — not the root UID of the PAM parent process.
//!
//! **Documentation correction (2026-04-17, Codex tb7-review finding 1):** prior
//! revisions of this comment collapsed the two platforms into one "effective UID"
//! abstraction. That was imprecise: `SO_PEERCRED` returns `struct ucred` which on
//! Linux also exposes PID and GID, while `getpeereid(3)` returns only effective
//! UID + GID. Both are "effective-UID-at-connect-time" for our purposes, but
//! callers that reason about PID (e.g. audit correlation) only get it on Linux.
//!
//! ## Security rationale
//!
//! The agent socket is protected by `0600` file-system permissions, which already
//! prevents other users from *connecting*. Peer credential checking adds a
//! defense-in-depth layer: even if an attacker obtains a file descriptor for the
//! socket (e.g., via a setuid binary or inherited fd), the kernel credential check
//! rejects any connection from a process running as a different UID.
//!
//! Failure to retrieve credentials is treated as a rejection (fail-closed).
//! This is consistent with the security invariant in CLAUDE.md: if a security
//! check cannot be performed, log it prominently and deny access.
//!
//! ## Trust model and its scope
//!
//! **Scope (ADR-013):** Any process running as the same UID as the daemon is
//! treated as fully trusted. This matches the well-established `ssh-agent` trust
//! model used by OpenSSH.
//!
//! **Implication:** A same-UID process can request DPoP proofs, trigger token
//! refresh, shut down the daemon, or wipe credentials. If your threat model
//! includes malware running under the authenticated user's account, mitigate
//! with hardware-bound keys (TPM/YubiKey), SELinux/AppArmor confinement, or
//! full-disk encryption.
//!
//! **Out of scope (ADR-025):** ADR-013 does NOT authorize root callers. The
//! sudo PAM path runs as root; if sudo PAM tried to connect here directly, the
//! credential check below would reject it (correctly). Sudo PAM must instead
//! go through the non-SUID connector child defined in ADR-025, which calls
//! `setuid(target_user)` before connecting — the agent then sees a same-UID
//! peer. Do not "widen" this check to accept root to accommodate sudo: ADR-013
//! keeps its scope, ADR-025 owns the sudo boundary.
//!
//! **v3.1 plan:** IPC channel separation — crypto operations (GetProof) on one
//! socket, admin operations (Shutdown, SessionClosed) on a root-only socket.
//! See `docs/security-audit-2026-04.md` Finding 2 for details.
//!
//! ## References
//!
//! - `socket(7)` Linux man page, `SO_PEERCRED` option — explicitly defines the
//!   peer credential as "that which was in effect at the time of the call to
//!   `connect(2)`, `listen(2)`, or `socketpair(2)`."
//! - `getpeereid(3)` BSD/macOS man page — "returns the effective user and group
//!   IDs of the peer connected to a UNIX-domain socket."
//! - ADR-013 (`docs/adr/013-same-uid-ipc-trust-model.md`) — scope statement.
//! - ADR-025 (`docs/adr/025-sudo-ipc-boundary.md`) — sudo PAM → agent boundary
//!   via non-SUID connector child.
//! - libc 0.2 — <https://docs.rs/libc/latest/libc/>

use std::os::unix::io::AsRawFd;

/// Extract the UID (and optionally PID) of the connected peer.
///
/// Returns `(uid, Option<pid>)`:
/// - `uid`: the peer's effective UID **at the time the connection was established**.
///   On Linux this comes from `SO_PEERCRED`'s `struct ucred.uid`; on macOS from
///   `getpeereid(3)`. Both snapshot at `connect(2)` / `socketpair(2)`; later UID
///   changes in the peer do not propagate.
/// - `pid`: PID of the peer process on Linux (from `struct ucred.pid`);
///   `None` on macOS (`getpeereid(3)` does not expose PID).
///
/// # Errors
///
/// Returns `Err` with `ErrorKind::Unsupported` on platforms other than Linux and
/// macOS. Returns `Err` with the OS error if the underlying syscall fails.
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
