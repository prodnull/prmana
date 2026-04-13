//! Process hardening for the agent daemon
//!
//! Provides OS-level protections that should be applied at daemon startup,
//! before any sensitive key material is loaded into memory.
//!
//! ## `disable_core_dumps`
//!
//! Prevents the OS from generating core dump files that could expose token
//! material and DPoP private keys to any local user with read access to the
//! core dump directory.
//!
//! - **Linux**: `prctl(PR_SET_DUMPABLE, 0)` — marks this process as non-dumpable.
//!   The kernel will refuse to produce a core dump and `/proc/PID/mem` access
//!   from non-privileged processes will be denied. See `prctl(2)`.
//! - **macOS**: `ptrace(PT_DENY_ATTACH, 0, NULL, 0)` — prevents debugger attach
//!   and core dump generation. See `ptrace(2)`.
//! - **Other platforms**: logs a warning; no action taken.
//!
//! Both calls are best-effort: a failure is logged as WARN and the daemon
//! continues normally. We do NOT fail-fast on these failures because:
//! 1. Some container environments (e.g., sandboxed CI) legitimately deny prctl.
//! 2. Failing to start the daemon is worse than running without this hardening.

/// Disable core dumps for the current process.
///
/// Call this once at daemon startup, before loading any key material.
/// Best-effort: logs failures at WARN and always returns (never panics).
pub fn disable_core_dumps() {
    #[cfg(target_os = "linux")]
    {
        // Security: prctl(PR_SET_DUMPABLE, 0) marks the process as non-dumpable.
        // This prevents core dumps and restricts /proc/PID/mem access.
        // Reference: man prctl(2), Linux kernel Documentation/security/dumpable.txt
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if ret == 0 {
            tracing::info!("Process hardening: core dumps disabled via prctl(PR_SET_DUMPABLE, 0)");
        } else {
            let errno = unsafe { *libc::__errno_location() };
            tracing::warn!(
                errno = errno,
                "Process hardening: prctl(PR_SET_DUMPABLE, 0) failed; core dumps may be possible"
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Security: ptrace(PT_DENY_ATTACH, 0, NULL, 0) prevents debugger attachment
        // and marks the process so the kernel won't produce a core dump.
        // Reference: man ptrace(2) on macOS / XNU source
        let ret = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if ret == 0 {
            tracing::info!("Process hardening: core dumps disabled via ptrace(PT_DENY_ATTACH)");
        } else {
            let errno = unsafe { *libc::__error() };
            tracing::warn!(
                errno = errno,
                "Process hardening: ptrace(PT_DENY_ATTACH) failed; core dumps may be possible"
            );
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        tracing::warn!(
            "Process hardening: core dump disabling not supported on this platform; \
             key material may appear in core dumps"
        );
    }
}
