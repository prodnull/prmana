// Copyright 2025 Avinash H. Duduskar
// SPDX-License-Identifier: Apache-2.0

// SAFETY: this module wraps Linux syscalls (add_key, keyctl,
// __errno_location) that have no safe std equivalent. Each unsafe block
// below is annotated with the precise contract it relies on.
#![allow(unsafe_code)]

//! Kernel-keyring publication of authenticated session metadata.
//!
//! After a successful authentication, this module writes a small,
//! printable-ASCII payload (selected token-derived claims) into a
//! kernel-managed key (see `keyrings(7)`) and exposes its serial
//! number through PAM environment so that subsequent stages of the
//! same PAM transaction — including those that run in a separately
//! forked sshd session worker — can fetch the payload back from the
//! kernel rather than from process state that does not survive the
//! privsep boundary.
//!
//! Security properties (see prodnull/prmana#14 review):
//!
//!   * The key is first published to the process keyring (`@p`) where
//!     only the current process can access it. `KEYCTL_SETPERM` and
//!     `KEYCTL_SET_TIMEOUT` are applied before the key is linked into
//!     the session keyring, closing the TOCTOU window between
//!     `add_key` and `SETPERM`.
//!
//!   * If the session keyring resolves to the shared user-session
//!     keyring (`@us`), publication is refused. `@us` is shared
//!     across all concurrent sessions for the same UID; publishing
//!     there widens the blast radius. The operator must run
//!     `pam_keyinit.so` (with `force revoke`) before prmana in the
//!     PAM stack to ensure an isolated session keyring.
//!
//!   * The payload is versioned (`v=1;`) and values are
//!     percent-encoded for `;`, `=`, `%`, NUL, CR, LF to prevent
//!     injection via claim values.
//!
//! No new crate dependency: all syscalls are issued through `libc`.

use std::ffi::CString;
use std::os::raw::c_long;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyringError {
    #[error("payload contains a NUL byte")]
    PayloadHasNul,
    #[error("payload exceeds {max} bytes (got {got})")]
    PayloadTooLong { max: usize, got: usize },
    #[error("add_key failed: errno {0}")]
    AddKey(i32),
    #[error("keyctl({op}) failed: errno {errno}")]
    Keyctl { op: &'static str, errno: i32 },
    #[error("session keyring is the shared @us keyring — pam_keyinit.so must run first")]
    SharedSessionKeyring,
}

/// Maximum payload length we publish. Keep small so the entry comfortably
/// fits any sane keyring quota and the consumer's per-key buffer.
pub const MAX_PAYLOAD: usize = 256;

/// `key_serial_t` from `<linux/keyctl.h>`. The kernel ABI uses `int32_t`.
pub type KeySerial = i32;

// keyctl(2) opcodes — the subset we use.
const KEYCTL_GET_KEYRING_ID: c_long = 0;
const KEYCTL_REVOKE: c_long = 3;
const KEYCTL_SETPERM: c_long = 5;
const KEYCTL_LINK: c_long = 8;
const KEYCTL_UNLINK: c_long = 9;
const KEYCTL_SET_TIMEOUT: c_long = 15;

// Special keyring IDs.
const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
const KEY_SPEC_SESSION_KEYRING: i32 = -3;
const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;

// Permission bits — see KEYCTL_SETPERM in keyctl(2).
const KEY_POS_VIEW: u32 = 0x0100_0000;
const KEY_POS_READ: u32 = 0x0200_0000;
const KEY_POS_SEARCH: u32 = 0x0800_0000;

/// Where to anchor a published key. Production code should use
/// `Session`; tests use `Process` so a key written by the test thread
/// is automatically reaped on exit.
#[derive(Debug, Clone, Copy)]
pub enum Anchor {
    Session,
    Process,
}

/// Returns true if the current session keyring resolves to the shared
/// user-session keyring (`@us`). When this is the case, any key we
/// publish is visible to all concurrent sessions for the same UID.
fn is_shared_user_session_keyring() -> bool {
    let sess = keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING as c_long, 0, 0, 0);
    let us = keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_USER_SESSION_KEYRING as c_long, 0, 0, 0);
    match (sess, us) {
        (Ok(s), Ok(u)) => s == u,
        _ => false, // can't tell — assume isolated
    }
}

/// Validate, then publish `payload` as a "user"-type key.
///
/// For `Anchor::Session`: the key is first created in the process
/// keyring (`@p`), permissions and timeout are applied there (closing
/// the TOCTOU window), then the key is linked into the session keyring
/// and unlinked from `@p`. If the session keyring is the shared `@us`,
/// publication is refused with `SharedSessionKeyring`.
///
/// For `Anchor::Process`: the key stays in `@p` (used by tests).
///
/// On success the serial number is returned.
pub fn publish(
    description: &str,
    payload: &[u8],
    anchor: Anchor,
    ttl_secs: u32,
) -> Result<KeySerial, KeyringError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(KeyringError::PayloadTooLong {
            max: MAX_PAYLOAD,
            got: payload.len(),
        });
    }
    if payload.contains(&0) {
        return Err(KeyringError::PayloadHasNul);
    }

    // For Session anchor, check that we have an isolated session keyring
    // before we create any kernel state.
    if matches!(anchor, Anchor::Session) && is_shared_user_session_keyring() {
        return Err(KeyringError::SharedSessionKeyring);
    }

    // SAFETY: CString::new fails only on interior NUL, ruled out above.
    let key_type = CString::new("user").unwrap();
    let desc = CString::new(description).map_err(|_| KeyringError::PayloadHasNul)?;

    // Always publish to the process keyring first. The key is only
    // accessible to this process until we explicitly link it elsewhere.
    // SAFETY: pointers and lengths are valid for the call duration.
    let serial = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            key_type.as_ptr(),
            desc.as_ptr(),
            payload.as_ptr() as *const libc::c_void,
            payload.len(),
            KEY_SPEC_PROCESS_KEYRING as libc::c_ulong,
        )
    };
    if serial < 0 {
        return Err(KeyringError::AddKey(errno()));
    }
    let serial = serial as KeySerial;

    // Set timeout BEFORE dropping SETATTR via SETPERM — once SETATTR is
    // revoked the kernel rejects further KEYCTL_SET_TIMEOUT with EACCES.
    if ttl_secs > 0 {
        if let Err(e) = keyctl(KEYCTL_SET_TIMEOUT, serial as c_long, ttl_secs as c_long, 0, 0) {
            // Cleanup: revoke the key so no partial state escapes.
            let _ = keyctl(KEYCTL_REVOKE, serial as c_long, 0, 0, 0);
            return Err(KeyringError::Keyctl { op: "SET_TIMEOUT", errno: e });
        }
    }

    // UID-only view|read|search; deny everything to group/other and deny
    // SETATTR so timeout/perms cannot be widened by another process.
    let perms: u32 = KEY_POS_VIEW | KEY_POS_READ | KEY_POS_SEARCH;
    if let Err(e) = keyctl(KEYCTL_SETPERM, serial as c_long, perms as c_long, 0, 0) {
        // Cleanup: revoke so no partial state escapes from @p.
        let _ = keyctl(KEYCTL_REVOKE, serial as c_long, 0, 0, 0);
        return Err(KeyringError::Keyctl { op: "SETPERM", errno: e });
    }

    // Now the key is locked down. Link it into the target keyring.
    if matches!(anchor, Anchor::Session) {
        if let Err(e) = keyctl(
            KEYCTL_LINK,
            serial as c_long,
            KEY_SPEC_SESSION_KEYRING as c_long,
            0,
            0,
        ) {
            let _ = keyctl(KEYCTL_REVOKE, serial as c_long, 0, 0, 0);
            return Err(KeyringError::Keyctl { op: "LINK", errno: e });
        }
        // Remove from @p — the key now lives only in the session keyring.
        let _ = keyctl(
            KEYCTL_UNLINK,
            serial as c_long,
            KEY_SPEC_PROCESS_KEYRING as c_long,
            0,
            0,
        );
    }

    Ok(serial)
}

/// Revoke a published key. Failures are logged and ignored at call sites
/// per the PAM "no panics, no fatal cleanup" rule.
pub fn revoke(serial: KeySerial) -> Result<(), KeyringError> {
    keyctl(KEYCTL_REVOKE, serial as c_long, 0, 0, 0)
        .map(|_| ())
        .map_err(|errno| KeyringError::Keyctl { op: "REVOKE", errno })
}

fn keyctl(op: c_long, a: c_long, b: c_long, c: c_long, d: c_long) -> Result<c_long, i32> {
    // SAFETY: keyctl is variadic; we always pass five ulong-sized args.
    let r = unsafe { libc::syscall(libc::SYS_keyctl, op, a, b, c, d) };
    if r < 0 {
        Err(errno())
    } else {
        Ok(r)
    }
}

fn errno() -> i32 {
    // SAFETY: __errno_location is thread-local and always returns a valid pointer.
    unsafe { *libc::__errno_location() }
}

/// Percent-encode characters that would corrupt the `k=v;` wire format.
/// Encoded: `;`, `=`, `%`, NUL, CR, LF.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'%' => out.push_str("%25"),
            b';' => out.push_str("%3B"),
            b'=' => out.push_str("%3D"),
            0 => out.push_str("%00"),
            b'\r' => out.push_str("%0D"),
            b'\n' => out.push_str("%0A"),
            _ => out.push(b as char),
        }
    }
    out
}

/// Format a versioned payload from common token-derived claims. The
/// output is `v=1;key=value;...` pairs separated by `;`, trimmed to
/// MAX_PAYLOAD. Empty values are omitted. Values are percent-encoded
/// for `;`, `=`, `%`, NUL, CR, LF to prevent injection.
pub fn format_claims(pairs: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(MAX_PAYLOAD);
    out.push_str("v=1");
    for (k, v) in pairs {
        if v.is_empty() {
            continue;
        }
        out.push(';');
        out.push_str(&percent_encode(k));
        out.push('=');
        out.push_str(&percent_encode(v));
        if out.len() >= MAX_PAYLOAD {
            out.truncate(MAX_PAYLOAD);
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_and_read_back() {
        let payload = b"v=1;jti=abc123;exp=1735689600;iss=https://idp.example/realm";
        let serial = match publish("prmana_test_key", payload, Anchor::Process, 60) {
            Ok(s) => s,
            Err(KeyringError::AddKey(errno)) => {
                eprintln!("skipping: add_key denied (errno={errno})");
                return;
            }
            Err(e) => panic!("publish failed: {e}"),
        };
        assert!(serial > 0);

        let mut buf = [0u8; MAX_PAYLOAD * 2];
        // KEYCTL_READ = 11
        let n = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                11_i64,
                serial as i64,
                buf.as_mut_ptr() as i64,
                buf.len() as i64,
                0_i64,
            )
        };
        assert!(n > 0, "keyctl_read returned {n}");
        let got = &buf[..n as usize];
        assert_eq!(got, payload);

        let _ = revoke(serial);
    }

    #[test]
    fn format_claims_versioned_and_encoded() {
        let s = format_claims(&[
            ("jti", "abc"),
            ("exp", ""),
            ("iss", "https://idp"),
            ("scope", "admin"),
        ]);
        assert_eq!(s, "v=1;jti=abc;iss=https://idp;scope=admin");
    }

    #[test]
    fn format_claims_encodes_semicolons_and_equals() {
        let s = format_claims(&[("iss", "a]b;c=d%e")]);
        assert_eq!(s, "v=1;iss=a]b%3Bc%3Dd%25e");
    }

    #[test]
    fn format_claims_truncates_at_max() {
        let big_iss = "x".repeat(400);
        let s = format_claims(&[("iss", &big_iss)]);
        assert!(s.len() <= MAX_PAYLOAD);
        assert!(s.starts_with("v=1;"));
    }

    #[test]
    fn percent_encode_round_trip() {
        assert_eq!(percent_encode("hello"), "hello");
        assert_eq!(percent_encode("a;b=c%d\r\n\0"), "a%3Bb%3Dc%25d%0D%0A%00");
    }
}
