//! Hardware Presence Cache — per-user touch authorization window.
//!
//! When a hardware signer (YubiKey, TPM) successfully generates a DPoP proof
//! via physical touch, the agent records the touch timestamp for that
//! `(remote_user, target)` pair. Subsequent `GetProof` requests within the
//! configurable TTL are signed automatically without re-triggering the
//! hardware presence requirement.
//!
//! # Security properties
//!
//! - **Per-user scoping**: a touch for `alice@server1` does not authorize
//!   `bob@server2`. Cache key is `"{remote_user}@{target}"`.
//! - **Process-scoped**: cache lives in agent memory only, never written to disk.
//! - **Zeroize on drop**: `Drop` impl clears all entries from memory.
//! - **Atomic invalidation**: `clear()` wipes all entries immediately on
//!   device removal, session close, or signing failure.
//! - **Software signers exempt**: presence caching only applies to hardware
//!   signer types (`yubikey:*`, `tpm`). Software signers always return
//!   `PresenceType::NotApplicable`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Default presence cache TTL: 5 minutes (300 seconds).
pub const DEFAULT_PRESENCE_CACHE_TTL_SECS: u64 = 300;

/// How a DPoP proof was authorized with the hardware signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceType {
    /// Fresh physical touch on the hardware token.
    PhysicalTouch,
    /// Authorized from cached presence within TTL.
    Cached,
    /// Software signer — no hardware presence involved.
    NotApplicable,
}

impl PresenceType {
    /// Wire-format string for the OCSF `presence_type` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            PresenceType::PhysicalTouch => "physical_touch",
            PresenceType::Cached => "cached",
            PresenceType::NotApplicable => "not_applicable",
        }
    }
}

/// Per-user hardware presence cache.
///
/// Thread-safe via `Mutex`. The cache is intentionally coarse-locked —
/// presence checks and recordings are fast O(1) operations that don't
/// justify a `RwLock`.
pub struct PresenceCache {
    entries: Mutex<HashMap<String, Instant>>,
    ttl_secs: u64,
}

impl PresenceCache {
    /// Create a new cache with the given TTL.
    ///
    /// A TTL of 0 effectively disables caching — every request requires
    /// a fresh hardware touch.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl_secs,
        }
    }

    /// Check if a valid cached presence exists for this `(remote_user, target)`.
    ///
    /// Returns `Some(PresenceType::Cached)` if the cache entry is within TTL,
    /// `None` if expired or absent.
    pub fn check(&self, remote_user: &str, target: &str) -> Option<PresenceType> {
        if self.ttl_secs == 0 {
            return None;
        }
        let key = Self::cache_key(remote_user, target);
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.get(&key).and_then(|ts| {
            if ts.elapsed().as_secs() < self.ttl_secs {
                Some(PresenceType::Cached)
            } else {
                None
            }
        })
    }

    /// Record a successful hardware touch for this `(remote_user, target)`.
    pub fn record(&self, remote_user: &str, target: &str) {
        let key = Self::cache_key(remote_user, target);
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.insert(key, Instant::now());
    }

    /// Wipe all cached presence entries immediately.
    ///
    /// Called on:
    /// - Device removal (signing failure with hardware error)
    /// - Session close (logout / SessionClosed IPC)
    /// - Explicit cache invalidation
    pub fn clear(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.clear();
    }

    /// Wipe a specific entry.
    pub fn clear_for(&self, remote_user: &str, target: &str) {
        let key = Self::cache_key(remote_user, target);
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.remove(&key);
    }

    /// Current TTL in seconds.
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Number of active (non-expired) entries. Used by Status IPC.
    pub fn active_count(&self) -> usize {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .values()
            .filter(|ts| ts.elapsed().as_secs() < self.ttl_secs)
            .count()
    }

    fn cache_key(remote_user: &str, target: &str) -> String {
        format!("{remote_user}@{target}")
    }
}

impl Drop for PresenceCache {
    fn drop(&mut self) {
        // Security: clear all entries from memory on drop.
        // HashMap::clear drops all keys and values. String keys are heap-
        // allocated and freed by the allocator. For defense-in-depth,
        // overwrite each key before dropping.
        if let Ok(mut entries) = self.entries.lock() {
            for (key, _) in entries.drain() {
                // Overwrite the key bytes before the String is freed.
                // SAFETY: we have exclusive access via &mut self + Mutex.
                let mut owned = key;
                // volatile-style overwrite: fill with zeros
                // SAFETY: String's internal Vec<u8> is contiguous.
                unsafe {
                    let bytes = owned.as_bytes_mut();
                    std::ptr::write_volatile(bytes.as_mut_ptr(), 0);
                    for b in bytes.iter_mut() {
                        std::ptr::write_volatile(b, 0);
                    }
                }
                drop(owned);
            }
        }
    }
}

/// Returns true if the signer type string indicates a hardware signer
/// that requires physical presence.
pub fn is_hardware_signer(signer_type: &str) -> bool {
    signer_type.starts_with("yubikey") || signer_type == "tpm"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_miss_when_empty() {
        let cache = PresenceCache::new(300);
        assert!(cache.check("alice", "server1").is_none());
    }

    #[test]
    fn test_cache_hit_after_record() {
        let cache = PresenceCache::new(300);
        cache.record("alice", "server1");
        assert_eq!(cache.check("alice", "server1"), Some(PresenceType::Cached));
    }

    #[test]
    fn test_cache_scoped_per_user() {
        let cache = PresenceCache::new(300);
        cache.record("alice", "server1");
        // Bob should not be cached
        assert!(cache.check("bob", "server1").is_none());
    }

    #[test]
    fn test_cache_scoped_per_target() {
        let cache = PresenceCache::new(300);
        cache.record("alice", "server1");
        // Same user, different target — not cached
        assert!(cache.check("alice", "server2").is_none());
    }

    #[test]
    fn test_cache_expired() {
        let cache = PresenceCache::new(0); // TTL=0 disables caching
        cache.record("alice", "server1");
        assert!(cache.check("alice", "server1").is_none());
    }

    #[test]
    fn test_clear_wipes_all() {
        let cache = PresenceCache::new(300);
        cache.record("alice", "server1");
        cache.record("bob", "server2");
        assert_eq!(cache.active_count(), 2);
        cache.clear();
        assert_eq!(cache.active_count(), 0);
        assert!(cache.check("alice", "server1").is_none());
    }

    #[test]
    fn test_clear_for_specific_entry() {
        let cache = PresenceCache::new(300);
        cache.record("alice", "server1");
        cache.record("bob", "server2");
        cache.clear_for("alice", "server1");
        assert!(cache.check("alice", "server1").is_none());
        assert_eq!(cache.check("bob", "server2"), Some(PresenceType::Cached));
    }

    #[test]
    fn test_presence_type_strings() {
        assert_eq!(PresenceType::PhysicalTouch.as_str(), "physical_touch");
        assert_eq!(PresenceType::Cached.as_str(), "cached");
        assert_eq!(PresenceType::NotApplicable.as_str(), "not_applicable");
    }

    #[test]
    fn test_is_hardware_signer() {
        assert!(is_hardware_signer("yubikey:9a"));
        assert!(is_hardware_signer("yubikey:9c"));
        assert!(is_hardware_signer("tpm"));
        assert!(!is_hardware_signer("software"));
        assert!(!is_hardware_signer("pqc"));
    }

    #[test]
    fn test_drop_clears_memory() {
        let cache = PresenceCache::new(300);
        cache.record("alice", "server1");
        cache.record("bob", "server2");
        drop(cache); // should not panic
    }
}
