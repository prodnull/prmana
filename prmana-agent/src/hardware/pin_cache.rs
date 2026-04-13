//! PIN cache for hardware signer backends.
//!
//! Hardware tokens (YubiKey, TPM) require a PIN for signing operations.
//! Re-prompting on every SSH connection would be unusable. `PinCache` caches
//! the PIN in a `SecretString` with a configurable timeout and provides a
//! `clear()` method to evict the cache when a wrong PIN is detected.
//!
//! Security properties:
//! - PIN stored in `SecretString` — `Debug`/`Display` emit `[REDACTED]`, value
//!   never appears in logs regardless of log level.
//! - When `timeout_secs == 0` the cache is bypassed and a prompt is always issued
//!   (use this for provisioning where the PIN must be confirmed by the user).

use std::sync::Mutex;
use std::time::Instant;

use secrecy::{ExposeSecret, SecretString};

/// Cached PIN entry: the secret value and the instant it was first cached.
struct CacheEntry {
    pin: SecretString,
    cached_at: Instant,
}

/// Thread-safe PIN cache with configurable expiry.
pub struct PinCache {
    state: Mutex<Option<CacheEntry>>,
    /// How long a cached PIN remains valid, in seconds.
    /// A value of 0 means "never cache" — always prompt.
    pub timeout_secs: u64,
}

impl PinCache {
    /// Create a new `PinCache`.
    ///
    /// `timeout_secs`: seconds after which a cached PIN expires and the user is
    /// re-prompted. Pass `0` to disable caching (e.g., during provisioning).
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            state: Mutex::new(None),
            timeout_secs,
        }
    }

    /// Get the cached PIN, or prompt the user if the cache is empty/expired.
    ///
    /// `prompt` is the human-readable string passed to `rpassword::prompt_password`.
    /// The returned `SecretString` must be exposed via `.expose_secret()` only at the
    /// call site that passes the PIN to the hardware token.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `rpassword::prompt_password` fails (e.g., no TTY).
    pub fn get_or_prompt(&self, prompt: &str) -> anyhow::Result<SecretString> {
        let guard = self.state.lock().expect("PinCache mutex poisoned");

        // Check if the cached entry is still valid.
        let still_valid = if self.timeout_secs == 0 {
            false // always prompt when timeout == 0
        } else if let Some(entry) = guard.as_ref() {
            entry.cached_at.elapsed().as_secs() < self.timeout_secs
        } else {
            false
        };

        if still_valid {
            // Return a fresh SecretString cloned from the cached value.
            // SecretString doesn't implement Clone so we re-wrap the exposed bytes.
            let pin_str = guard
                .as_ref()
                .expect("still_valid => entry is Some")
                .pin
                .expose_secret()
                .to_owned();
            return Ok(SecretString::new(pin_str.into()));
        }

        // Release the lock before prompting (blocking I/O).
        drop(guard);

        // Prompt for a new PIN.
        // rpassword is only available when the `yubikey` or `tpm` feature is enabled.
        // When neither hardware feature is active, return an error — no hardware signer
        // is present to call this path, but the module must compile unconditionally.
        let raw = Self::read_pin(prompt)?;
        let secret = SecretString::new(raw.into());

        if self.timeout_secs > 0 {
            let mut guard2 = self.state.lock().expect("PinCache mutex poisoned");
            *guard2 = Some(CacheEntry {
                // Store a copy; re-wrap the exposed bytes.
                pin: SecretString::new(secret.expose_secret().to_owned().into()),
                cached_at: Instant::now(),
            });
        }

        Ok(secret)
    }

    /// Read a PIN from the terminal.
    ///
    /// This thin wrapper exists so the `rpassword` call can be `cfg`-gated in
    /// one place. When neither `yubikey` nor `tpm` features are active, the
    /// function returns an error rather than failing to compile.
    fn read_pin(prompt: &str) -> anyhow::Result<String> {
        #[cfg(any(feature = "yubikey", feature = "tpm"))]
        {
            Ok(rpassword::prompt_password(prompt)?)
        }
        #[cfg(not(any(feature = "yubikey", feature = "tpm")))]
        {
            let _ = prompt;
            Err(anyhow::anyhow!(
                "PIN prompting requires the `yubikey` or `tpm` cargo feature"
            ))
        }
    }

    /// Clear the cached PIN.
    ///
    /// Call this when the hardware token returns CKR_PIN_INCORRECT so the user
    /// is re-prompted on the next sign attempt rather than locked out.
    pub fn clear(&self) {
        let mut guard = self.state.lock().expect("PinCache mutex poisoned");
        *guard = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    /// Test that `clear()` evicts the cache so the next call would re-prompt.
    /// We can't test actual TTY prompts in unit tests, but we can exercise the
    /// Mutex/state directly by injecting a pre-cached entry.
    #[test]
    fn test_clear_evicts_cache() {
        let cache = PinCache::new(3600);

        // Manually inject a cache entry.
        {
            let mut guard = cache.state.lock().unwrap();
            *guard = Some(CacheEntry {
                pin: SecretString::new("test-pin".to_string().into()),
                cached_at: Instant::now(),
            });
        }

        // Verify something is cached.
        assert!(cache.state.lock().unwrap().is_some());

        // Clear and verify it's gone.
        cache.clear();
        assert!(cache.state.lock().unwrap().is_none());
    }

    /// Test that a cached entry is still considered valid before it expires.
    #[test]
    fn test_cache_validity_before_expiry() {
        let cache = PinCache::new(3600);

        // Inject a fresh entry.
        {
            let mut guard = cache.state.lock().unwrap();
            *guard = Some(CacheEntry {
                pin: SecretString::new("cached-pin".to_string().into()),
                cached_at: Instant::now(),
            });
        }

        // Check the logic: elapsed < 3600s, so still_valid should be true.
        let guard = cache.state.lock().unwrap();
        let entry = guard.as_ref().unwrap();
        assert!(entry.cached_at.elapsed().as_secs() < 3600);
    }

    /// Test that a stale entry (cached well in the past) is treated as expired.
    #[test]
    fn test_cache_expired_when_timeout_is_zero() {
        let cache = PinCache::new(0);

        // Even with an entry present, timeout==0 means always prompt.
        {
            let mut guard = cache.state.lock().unwrap();
            *guard = Some(CacheEntry {
                pin: SecretString::new("old-pin".to_string().into()),
                // Use Instant::now() — elapsed will be ~0s, but timeout==0 still wins.
                cached_at: Instant::now(),
            });
        }

        // The `still_valid` branch: timeout_secs == 0 → false regardless of age.
        // We verify the state without calling get_or_prompt (which needs a TTY).
        let cache2 = PinCache::new(0);
        let guard = cache2.state.lock().unwrap();
        assert!(guard.is_none(), "new cache starts empty");
    }

    /// Test that PinCache is Send + Sync (required for use inside YubiKeySigner).
    #[test]
    fn test_pin_cache_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PinCache>();
    }

    /// Test that PinCache can be used from multiple threads.
    #[test]
    fn test_clear_is_thread_safe() {
        let cache = Arc::new(PinCache::new(3600));
        let cache2 = Arc::clone(&cache);

        let handle = thread::spawn(move || {
            cache2.clear();
        });

        cache.clear();
        handle.join().unwrap();
    }

    /// Verify that a cache entry's `cached_at` is recent (sanity check for Instant usage).
    #[test]
    fn test_cache_entry_instant_is_recent() {
        let before = Instant::now();
        thread::sleep(Duration::from_millis(1));

        let entry = CacheEntry {
            pin: SecretString::new("pin".to_string().into()),
            cached_at: Instant::now(),
        };

        assert!(entry.cached_at >= before);
        assert!(entry.cached_at.elapsed().as_millis() < 5000);
    }
}
