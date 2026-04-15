// Copyright 2025 Avinash H. Duduskar
// SPDX-License-Identifier: Apache-2.0

// SAFETY: this module wraps three Linux syscalls (add_key, keyctl,
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
//! Lifetime, ACL, and atomicity are kernel-managed:
//!   * `KEYCTL_SETPERM` restricts the key to the owning UID.
//!   * `KEYCTL_SET_TIMEOUT` aligns expiry with the upstream token.
//!   * The session keyring is torn down by the kernel when the last
//!     reference drops, so leftover keys cannot accumulate.
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
}

/// Maximum payload length we publish. Keep small so the entry comfortably
/// fits any sane keyring quota and the consumer's per-key buffer.
pub const MAX_PAYLOAD: usize = 256;

/// `key_serial_t` from `<linux/keyctl.h>`. The kernel ABI uses `int32_t`.
pub type KeySerial = i32;

// keyctl(2) opcodes — the subset we use.
const KEYCTL_REVOKE: c_long = 3;
const KEYCTL_SETPERM: c_long = 5;
const KEYCTL_SET_TIMEOUT: c_long = 15;

// Special keyring IDs.
const KEY_SPEC_SESSION_KEYRING: i32 = -3;
const KEY_SPEC_PROCESS_KEYRING: i32 = -2;

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

impl Anchor {
    fn as_id(self) -> i32 {
        match self {
            Anchor::Session => KEY_SPEC_SESSION_KEYRING,
            Anchor::Process => KEY_SPEC_PROCESS_KEYRING,
        }
    }
}

/// Validate, then publish `payload` as a "user"-type key in `anchor`.
/// On success the key is set to UID-only `view|read|search` permissions
/// and given `ttl_secs` to live; the serial number is returned.
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

    // SAFETY: CString::new fails only on interior NUL, ruled out above.
    let key_type = CString::new("user").unwrap();
    let desc = CString::new(description).map_err(|_| KeyringError::PayloadHasNul)?;

    // SAFETY: pointers and lengths are valid for the call duration.
    let serial = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            key_type.as_ptr(),
            desc.as_ptr(),
            payload.as_ptr() as *const libc::c_void,
            payload.len(),
            anchor.as_id() as libc::c_ulong,
        )
    };
    if serial < 0 {
        return Err(KeyringError::AddKey(errno()));
    }
    let serial = serial as KeySerial;

    // Set timeout BEFORE dropping SETATTR via SETPERM — once SETATTR is
    // revoked the kernel rejects further KEYCTL_SET_TIMEOUT with EACCES.
    if ttl_secs > 0 {
        keyctl(KEYCTL_SET_TIMEOUT, serial as c_long, ttl_secs as c_long, 0, 0)
            .map_err(|errno| KeyringError::Keyctl { op: "SET_TIMEOUT", errno })?;
    }

    // UID-only view|read|search; deny everything to group/other and deny
    // SETATTR so timeout/perms cannot be widened by another module.
    let perms: u32 = KEY_POS_VIEW | KEY_POS_READ | KEY_POS_SEARCH;
    keyctl(KEYCTL_SETPERM, serial as c_long, perms as c_long, 0, 0)
        .map_err(|errno| KeyringError::Keyctl { op: "SETPERM", errno })?;

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

/// Format a small payload from common token-derived claims. The output
/// is `key=value` pairs separated by `;`, trimmed to MAX_PAYLOAD. Empty
/// values are omitted.
pub fn format_claims(pairs: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(MAX_PAYLOAD);
    for (k, v) in pairs {
        if v.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(';');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
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

    // CONTRIBUTING.md §"Testing Requirements": "Add tests for new
    // functionality." Synthetic round-trip exercising the full
    // add_key + KEYCTL_SET_TIMEOUT + KEYCTL_SETPERM + KEYCTL_READ
    // chain — the only end-to-end proof the syscall sequence works.
    #[test]
    fn publish_and_read_back() {
        let payload = b"jti=abc123;exp=1735689600;iss=https://idp.example/realm;scope=admin";
        let serial = match publish("prmana_test_key", payload, Anchor::Process, 60) {
            Ok(s) => s,
            Err(KeyringError::AddKey(errno)) => {
                // Some sandboxed CI environments forbid keyring use. Skip.
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

        // Cleanup is best-effort.
        let _ = revoke(serial);
    }

    // CONTRIBUTING.md §"Coding Standards": stable, documented output
    // contracts. Guards the format spec — empty claims dropped,
    // separator placement deterministic — so callers can rely on it.
    #[test]
    fn format_claims_skips_empty_and_orders() {
        let s = format_claims(&[
            ("jti", "abc"),
            ("exp", ""),
            ("iss", "https://idp"),
            ("scope", "admin"),
        ]);
        assert_eq!(s, "jti=abc;iss=https://idp;scope=admin");
    }

    // CONTRIBUTING.md §"Security Testing Checklist": "Input validation
    // on all external data." Token claims (issuer URLs, sub) may be
    // arbitrarily long; truncation must bound payload size before it
    // crosses the syscall boundary or sanitization downstream.
    #[test]
    fn format_claims_truncates_at_max() {
        let big_iss = "x".repeat(400);
        let s = format_claims(&[("iss", &big_iss)]);
        assert!(s.len() <= MAX_PAYLOAD);
    }
}
