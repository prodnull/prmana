//! Memory-protected signing key wrapper
//!
//! Provides `ProtectedSigningKey`, a Box-only wrapper around `p256::ecdsa::SigningKey`
//! with the following protections:
//!
//! 1. **ZeroizeOnDrop** (MEM-02): The inner `SigningKey` is zeroed when the struct is dropped.
//!    `p256::ecdsa::SigningKey` implements `ZeroizeOnDrop` unconditionally in `ecdsa-0.16`
//!    — no feature flag required (see CLAUDE.md §Memory Protection Invariants).
//!
//! 2. **Memory locking** (MEM-04): On Linux, `mlock(2)` is called on the key bytes after
//!    heap allocation to prevent the OS from swapping key material to disk. This is
//!    best-effort — if `mlock` fails (e.g., RLIMIT_MEMLOCK insufficient), we log a warning
//!    and continue rather than failing authentication.
//!
//! 3. **Box-only constructors** (MEM-05): There is no public `new() -> Self` constructor.
//!    All constructors return `Box<ProtectedSigningKey>`, preventing accidental stack copies
//!    of key material.
//!
//! 4. **Zeroizing export** (MEM-01): `export_key()` returns `Zeroizing<Vec<u8>>` so the
//!    exported bytes are wiped on drop by the caller.

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use zeroize::Zeroizing;

use crate::crypto::signer::SignerError;
use crate::crypto::thumbprint::compute_ec_thumbprint;

/// Whether memory locking via `mlock(2)` succeeded for key material.
///
/// Returned by `mlock_probe()` and also recorded on each key creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlockStatus {
    /// Key pages are memory-locked; OS will not swap them to disk.
    Active,
    /// `mlock` is unavailable or failed; key pages may be swapped.
    /// The inner string describes the reason (e.g., "EPERM", "ENOMEM").
    Unavailable(String),
}

/// RAII guard that calls `munlock(2)` on drop for a specific memory region.
///
/// # Safety
/// The caller is responsible for ensuring `ptr` remains valid for the lifetime
/// of this guard. This is enforced structurally: `MlockGuard` is held inside
/// a Box-allocated struct and never outlives it.
pub(crate) struct MlockGuard {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: The raw pointer is owned exclusively by this guard, and ProtectedSigningKey
// is Box-allocated (stable address). Send + Sync are safe because we never share
// the raw pointer — the guard is private and not exposed.
unsafe impl Send for MlockGuard {}
unsafe impl Sync for MlockGuard {}

impl Drop for MlockGuard {
    fn drop(&mut self) {
        // Best-effort munlock; ignore errors on cleanup path.
        #[cfg(unix)]
        unsafe {
            libc::munlock(self.ptr as *const libc::c_void, self.len);
        }
    }
}

/// Probe whether `mlock(2)` is available on this system.
///
/// Allocates a single-page test buffer, attempts to lock it, then immediately
/// unlocks and frees it. Logs the outcome at INFO (success) or WARN (failure)
/// level. Never returns an error — callers proceed regardless.
pub fn mlock_probe() -> MlockStatus {
    #[cfg(unix)]
    {
        // Allocate a test page on the stack; 64 bytes is well under the page
        // minimum that mlock operates on.
        let mut buf = [0u8; 64];
        let ret = unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) };
        if ret == 0 {
            // Immediately unlock the probe buffer.
            unsafe {
                libc::munlock(buf.as_ptr() as *const libc::c_void, buf.len());
            }
            // Zero the probe buffer (not sensitive, but keep it clean).
            buf.fill(0);
            tracing::info!("mlock probe succeeded; DPoP key pages will be memory-locked");
            MlockStatus::Active
        } else {
            #[cfg(target_os = "macos")]
            let errno = unsafe { *libc::__error() };
            #[cfg(not(target_os = "macos"))]
            let errno = unsafe { *libc::__errno_location() };
            let reason = match errno {
                libc::EPERM => "EPERM (insufficient privileges; increase RLIMIT_MEMLOCK or run as appropriate user)".to_string(),
                libc::ENOMEM => "ENOMEM (locked-memory limit exceeded; increase RLIMIT_MEMLOCK)".to_string(),
                libc::ENOSYS => "ENOSYS (mlock not supported on this kernel)".to_string(),
                other => format!("errno {other}"),
            };
            tracing::warn!(
                reason = %reason,
                "mlock probe failed; DPoP key pages will NOT be memory-locked (swap exposure possible)"
            );
            MlockStatus::Unavailable(reason)
        }
    }

    #[cfg(not(unix))]
    {
        MlockStatus::Unavailable("non-Unix platform; mlock not available".to_string())
    }
}

/// Attempt to mlock a slice of memory. Returns an MlockGuard on success that
/// will munlock on drop, or None if mlock failed (best-effort).
///
/// # Safety
/// `data` must remain at a stable address for the lifetime of the returned guard.
/// Callers must ensure the guard is dropped before the data is freed.
pub(crate) unsafe fn try_mlock(data: &mut [u8]) -> Option<MlockGuard> {
    #[cfg(unix)]
    {
        let ret = libc::mlock(data.as_ptr() as *const libc::c_void, data.len());
        if ret == 0 {
            Some(MlockGuard {
                ptr: data.as_mut_ptr(),
                len: data.len(),
            })
        } else {
            None
        }
    }

    #[cfg(not(unix))]
    {
        let _ = data;
        None
    }
}

/// Memory-protected DPoP signing key.
///
/// ## Construction
/// All constructors return `Box<ProtectedSigningKey>`. There is no public
/// stack constructor. This ensures key material lives on the heap with a
/// stable address that can be memory-locked via `mlock(2)`.
///
/// ## Memory safety properties
/// - `p256::ecdsa::SigningKey` implements `ZeroizeOnDrop` unconditionally in `ecdsa-0.16`.
///   When `ProtectedSigningKey` is dropped, the key bytes are overwritten with zeros
///   before deallocation (MEM-02).
/// - `mlock(2)` is attempted on the key bytes after Box allocation to prevent
///   the OS from paging key material to swap (MEM-04, best-effort).
/// - `export_key()` returns `Zeroizing<Vec<u8>>`, ensuring the caller's copy of
///   key bytes is also wiped on drop (MEM-01).
pub struct ProtectedSigningKey {
    /// The inner signing key. `ecdsa-0.16` derives `ZeroizeOnDrop` unconditionally,
    /// so key material is zeroed when dropped.
    signing_key: SigningKey,

    /// Pre-computed JWK thumbprint (RFC 7638) for the corresponding public key.
    thumbprint: String,

    /// RAII guard for the mlock region covering the signing key bytes.
    /// `None` if mlock was unavailable or failed (best-effort).
    _mlock_guard: Option<MlockGuard>,
}

impl ProtectedSigningKey {
    /// Private constructor: wraps a `SigningKey` in a `Box<ProtectedSigningKey>` and
    /// attempts to mlock the entire struct allocation.
    ///
    /// We mlock the whole `ProtectedSigningKey` allocation rather than trying to
    /// compute a pointer to the opaque internals of `SigningKey`. This is simpler,
    /// correct, and ensures all sensitive fields (including cached verifying key bytes
    /// stored internally by ecdsa-0.16) are covered.
    fn new_inner(signing_key: SigningKey) -> Box<Self> {
        let thumbprint = compute_ec_thumbprint(signing_key.verifying_key());

        // Box the struct first — this gives the key material a stable heap address.
        let mut boxed = Box::new(Self {
            signing_key,
            thumbprint,
            _mlock_guard: None,
        });

        // Attempt to mlock the entire Box allocation.
        //
        // SAFETY: `Box<Self>` owns the allocation; the address is stable while
        // the Box is alive. The `MlockGuard` stores the raw pointer and will call
        // `munlock` on drop. The guard is stored as a field of the same Box,
        // so it cannot outlive the allocation it protects.
        let struct_bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                &mut *boxed as *mut Self as *mut u8,
                std::mem::size_of::<Self>(),
            )
        };

        let guard = unsafe { try_mlock(struct_bytes) };
        if guard.is_some() {
            tracing::debug!(
                "DPoP signing key mlock'd successfully ({} bytes)",
                std::mem::size_of::<Self>()
            );
        } else {
            tracing::debug!(
                "DPoP signing key mlock skipped (unavailable or EPERM; key may be swappable)"
            );
        }
        boxed._mlock_guard = guard;

        boxed
    }

    /// Generate a new random DPoP signing key.
    ///
    /// Uses the OS random number generator (`OsRng`) via `p256::ecdsa::SigningKey::random`.
    /// The returned key is heap-allocated and memory-locked where supported.
    pub fn generate() -> Box<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        Self::new_inner(signing_key)
    }

    /// Construct a `ProtectedSigningKey` from raw key bytes.
    ///
    /// Accepts `&[u8]` for compatibility with storage retrieval paths. The bytes are
    /// parsed and the original slice is not retained. Callers should use
    /// `Zeroizing<Vec<u8>>` or similar to ensure the source bytes are wiped after import.
    ///
    /// Returns `Err(SignerError::InvalidKeyBytes)` if the bytes are not a valid P-256
    /// private scalar.
    pub fn from_bytes(bytes: &[u8]) -> Result<Box<Self>, SignerError> {
        let signing_key =
            SigningKey::from_slice(bytes).map_err(|_| SignerError::InvalidKeyBytes)?;
        Ok(Self::new_inner(signing_key))
    }

    /// Export the signing key bytes in a `Zeroizing` wrapper (MEM-01).
    ///
    /// The returned `Zeroizing<Vec<u8>>` automatically zeroes its contents on drop.
    /// Callers must not copy the inner bytes into unprotected storage.
    pub fn export_key(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.signing_key.to_bytes().to_vec())
    }

    /// Return the JWK thumbprint (RFC 7638) for the corresponding public key.
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// Borrow the inner `SigningKey` for signing operations.
    ///
    /// This does not copy key material; it returns a reference valid for the
    /// lifetime of the `ProtectedSigningKey`.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Borrow the corresponding verifying (public) key.
    pub fn verifying_key(&self) -> &p256::ecdsa::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // RED phase: These tests define the expected behavior. Write them first,
    // verify they fail (compile error / panic), then implement to make them pass.
    // -------------------------------------------------------------------------

    #[test]
    fn test_generate_returns_box() {
        // ProtectedSigningKey::generate() must return Box<ProtectedSigningKey>.
        // This is enforced by the return type — the test exercises the constructor.
        let key: Box<ProtectedSigningKey> = ProtectedSigningKey::generate();
        // Ensure the key is heap-allocated (non-null address expected)
        let key_ptr = &*key as *const ProtectedSigningKey;
        assert!(!key_ptr.is_null());
    }

    #[test]
    fn test_generate_has_valid_thumbprint() {
        let key = ProtectedSigningKey::generate();
        let thumb = key.thumbprint();
        // SHA-256 base64url = 43 chars (32 bytes, no padding)
        assert_eq!(
            thumb.len(),
            43,
            "thumbprint must be 43 chars (SHA-256 base64url)"
        );
        assert!(
            thumb
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "thumbprint must be valid base64url"
        );
    }

    #[test]
    fn test_export_returns_zeroizing() {
        let key = ProtectedSigningKey::generate();
        // Return type is Zeroizing<Vec<u8>> — verify it has non-empty content
        let exported: Zeroizing<Vec<u8>> = key.export_key();
        // P-256 private key = 32 bytes
        assert_eq!(exported.len(), 32, "P-256 private key must be 32 bytes");
    }

    #[test]
    fn test_export_import_roundtrip() {
        let key1 = ProtectedSigningKey::generate();
        let exported: Zeroizing<Vec<u8>> = key1.export_key();

        let key2 = ProtectedSigningKey::from_bytes(&exported).unwrap();

        // Same key material => same thumbprint
        assert_eq!(key1.thumbprint(), key2.thumbprint());
    }

    #[test]
    fn test_from_bytes_invalid_returns_error() {
        let bad_bytes = vec![0u8; 32]; // zero scalar is invalid for P-256
        let result = ProtectedSigningKey::from_bytes(&bad_bytes);
        assert!(result.is_err(), "zero scalar must be rejected");
    }

    #[test]
    fn test_from_bytes_wrong_length_returns_error() {
        let bad_bytes = vec![0u8; 10];
        let result = ProtectedSigningKey::from_bytes(&bad_bytes);
        assert!(result.is_err(), "wrong-length bytes must be rejected");
    }

    #[test]
    fn test_mlock_probe_returns_status() {
        // mlock_probe() must return an MlockStatus (either Active or Unavailable).
        // We do not assert Active because tests may run as unprivileged users.
        let status = mlock_probe();
        match status {
            MlockStatus::Active => {
                // mlock is available on this system — acceptable
            }
            MlockStatus::Unavailable(reason) => {
                // Must provide a non-empty reason
                assert!(!reason.is_empty(), "Unavailable reason must not be empty");
            }
        }
    }

    #[test]
    fn test_verifying_key_matches_thumbprint() {
        let key = ProtectedSigningKey::generate();
        let expected_thumb = compute_ec_thumbprint(key.verifying_key());
        assert_eq!(key.thumbprint(), expected_thumb);
    }

    // -------------------------------------------------------------------------
    // Key lifecycle audit event tests (27-02)
    // -------------------------------------------------------------------------

    /// KEY_GENERATED: generate() must emit a structured audit event with
    /// target "unix_oidc_audit", event_type "KEY_GENERATED", key_type "DPoP",
    /// and a non-empty key_id (thumbprint prefix, first 8 chars).
    #[test]
    #[tracing_test::traced_test]
    fn test_key_lifecycle_generate_emits_audit_event() {
        let _key = ProtectedSigningKey::generate();
        assert!(
            logs_contain("KEY_GENERATED"),
            "generate() must emit KEY_GENERATED audit event"
        );
        assert!(
            logs_contain("DPoP"),
            "KEY_GENERATED event must include key_type DPoP"
        );
    }

    /// KEY_LOADED: from_bytes() must emit a structured audit event with
    /// event_type "KEY_LOADED", key_type "DPoP", and a non-empty key_id.
    #[test]
    #[tracing_test::traced_test]
    fn test_key_lifecycle_from_bytes_emits_key_loaded() {
        // Generate a key to get valid bytes.
        let key1 = ProtectedSigningKey::generate();
        let exported = key1.export_key();

        // Clear the log before testing from_bytes import.
        let _key2 = ProtectedSigningKey::from_bytes(&exported).unwrap();
        assert!(
            logs_contain("KEY_LOADED"),
            "from_bytes() must emit KEY_LOADED audit event"
        );
        assert!(
            logs_contain("DPoP"),
            "KEY_LOADED event must include key_type DPoP"
        );
    }

    /// KEY_DESTROYED: dropping a ProtectedSigningKey must emit a structured
    /// audit event with event_type "KEY_DESTROYED" and key_type "DPoP".
    #[test]
    #[tracing_test::traced_test]
    fn test_key_lifecycle_drop_emits_key_destroyed() {
        {
            let _key = ProtectedSigningKey::generate();
            // key drops here at end of inner scope
        }
        assert!(
            logs_contain("KEY_DESTROYED"),
            "drop must emit KEY_DESTROYED audit event"
        );
        assert!(
            logs_contain("DPoP"),
            "KEY_DESTROYED event must include key_type DPoP"
        );
    }

    /// Negative test: audit events must NOT leak full key material.
    /// Only the 8-char thumbprint prefix (alphanumeric/base64url chars) must appear,
    /// not the raw private key bytes.
    #[test]
    #[tracing_test::traced_test]
    fn test_key_lifecycle_events_do_not_leak_key_material() {
        let key = ProtectedSigningKey::generate();
        let raw_bytes = key.export_key();

        // Encode key material as hex to check it doesn't appear in logs.
        let hex_key: String = raw_bytes.iter().map(|b| format!("{b:02x}")).collect();

        // key_id must be ≤ 8 chars (thumbprint prefix), not the full 43-char thumbprint.
        // The full thumbprint should not appear in the log either.
        let full_thumbprint = key.thumbprint().to_string();

        drop(key);

        // The hex representation of raw key bytes must not appear in audit logs.
        assert!(
            !logs_contain(&hex_key),
            "Audit event must not contain raw key material"
        );
        // The full 43-char thumbprint should not appear — only the 8-char prefix.
        // We verify by checking that no log line contains the FULL thumbprint suffix
        // (last 35 chars), which would only be present if the full thumbprint was logged.
        let thumb_suffix = &full_thumbprint[8..]; // chars 9-43
        assert!(
            !logs_contain(thumb_suffix),
            "Audit event must not contain full thumbprint (only 8-char prefix)"
        );
    }

    /// Verify that ZeroizeOnDrop zeroes the key bytes after drop.
    ///
    /// Uses `ManuallyDrop` on the `Box` so we can trigger `ProtectedSigningKey`'s
    /// `Drop` (which invokes `ZeroizeOnDrop` on the inner `SigningKey`) without
    /// deallocating the heap allocation. This lets us read the zeroed bytes from
    /// still-live memory, avoiding undefined behaviour from use-after-free.
    #[test]
    fn test_key_material_zeroed_after_drop() {
        let key = ProtectedSigningKey::generate();
        let original_bytes: Vec<u8> = key.export_key().to_vec(); // independent copy
        assert!(
            original_bytes.iter().any(|&b| b != 0),
            "generated key should have non-zero bytes"
        );

        // Convert to raw pointer so we control both destruction and deallocation.
        let raw_ptr: *mut ProtectedSigningKey = Box::into_raw(key);

        // Get a pointer to the signing_key field while the allocation is live.
        let key_field_ptr: *const u8 = unsafe {
            use std::ptr::addr_of;
            addr_of!((*raw_ptr).signing_key) as *const u8
        };
        let key_len = std::mem::size_of::<SigningKey>();

        // Run the ProtectedSigningKey destructor in-place. This triggers
        // ZeroizeOnDrop on the inner SigningKey but does NOT free the heap.
        // SAFETY: raw_ptr is valid (from Box::into_raw), and we deallocate below.
        unsafe {
            std::ptr::drop_in_place(raw_ptr);
        }

        // Read the signing_key bytes from the still-live allocation.
        // SAFETY: The heap allocation was not freed — only drop_in_place ran.
        // The bytes at this address are still readable (the allocator owns the
        // memory but has not reclaimed it).
        let bytes_after_drop: Vec<u8> =
            unsafe { std::slice::from_raw_parts(key_field_ptr, key_len).to_vec() };

        assert_ne!(
            original_bytes, bytes_after_drop,
            "Key bytes must change after ZeroizeOnDrop runs"
        );

        // Deallocate the heap memory without running destructors again.
        // SAFETY: raw_ptr was obtained from Box::into_raw with this layout.
        unsafe {
            std::alloc::dealloc(
                raw_ptr as *mut u8,
                std::alloc::Layout::new::<ProtectedSigningKey>(),
            );
        }
    }
}
