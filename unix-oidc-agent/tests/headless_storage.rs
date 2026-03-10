//! Headless storage integration tests.
//!
//! These tests verify the keyutils fallback path used in headless (no-D-Bus)
//! server deployments. They require:
//!   - Linux with the kernel keyutils subsystem (`keyctl` available)
//!   - The `linux-native` Cargo feature (unconditionally enabled in Cargo.toml)
//!
//! Run explicitly in CI with:
//!   cargo test --test headless_storage -- --ignored --nocapture
//!
//! They are marked `#[ignore]` so the default `cargo test` run does not attempt
//! them on macOS or environments without the kernel keyring subsystem.

#[cfg(target_os = "linux")]
mod linux {
    use unix_oidc_agent::storage::{BackendKind, StorageRouter};

    /// Verify that when `DBUS_SESSION_BUS_ADDRESS` is empty (no D-Bus session bus
    /// available), `StorageRouter::detect()` falls back to the keyutils user keyring.
    ///
    /// This test models the typical headless server deployment where Secret Service
    /// is unavailable because no D-Bus session daemon is running.
    #[test]
    #[ignore = "Requires Linux keyutils (CI Docker)"]
    fn test_headless_fallback_to_keyutils() {
        // Force the Secret Service probe to fail by clearing the D-Bus session bus
        // address. keyring's sync-secret-service backend checks this env var when
        // establishing a D-Bus connection.
        //
        // Safety: test environment only — never set in production code.
        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", "");
        // Ensure UNIX_OIDC_STORAGE_BACKEND is not set (would override auto-detection).
        std::env::remove_var("UNIX_OIDC_STORAGE_BACKEND");

        let router = StorageRouter::detect().expect("detect should succeed even without D-Bus");

        assert!(
            matches!(router.kind, BackendKind::KeyutilsUser),
            "expected keyutils fallback when D-Bus is absent, got {:?}",
            router.kind
        );

        // Full store/retrieve/delete round-trip.
        let key = "headless-test-key";
        let value = b"test-key-material-headless";

        router.store(key, value).expect("store should work with keyutils");
        let retrieved = router.retrieve(key).expect("retrieve should work with keyutils");
        assert_eq!(
            retrieved, value,
            "retrieved value must match stored value"
        );

        // Cleanup: best-effort, do not fail the test on cleanup error.
        router.delete(key).ok();
    }

    /// Verify that credentials stored via a `StorageRouter` instance persist when a
    /// new `StorageRouter` is constructed (simulating a daemon restart).
    ///
    /// This is critical for keyutils: the user keyring (`@u`) is persistent across
    /// processes within the same login session. Credentials must survive the daemon
    /// being stopped and restarted without requiring re-authentication.
    #[test]
    #[ignore = "Requires Linux keyutils (CI Docker)"]
    fn test_headless_credentials_persist_across_restart() {
        // Same setup as test_headless_fallback_to_keyutils.
        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", "");
        std::env::remove_var("UNIX_OIDC_STORAGE_BACKEND");

        let key = "headless-persist-test-key";
        let value = b"persistent-credential-value";

        // First router instance: stores a credential, then is dropped.
        {
            let router_first = StorageRouter::detect()
                .expect("first detect should succeed");
            assert!(
                matches!(router_first.kind, BackendKind::KeyutilsUser),
                "first router should use keyutils, got {:?}",
                router_first.kind
            );
            router_first
                .store(key, value)
                .expect("first store should succeed");
        }
        // `router_first` is dropped here — simulating daemon stop.

        // Second router instance: simulates daemon restart.
        {
            let router_second = StorageRouter::detect()
                .expect("second detect (simulated restart) should succeed");
            assert!(
                matches!(router_second.kind, BackendKind::KeyutilsUser),
                "second router should use keyutils, got {:?}",
                router_second.kind
            );

            let retrieved = router_second
                .retrieve(key)
                .expect("credential must be retrievable after simulated restart");
            assert_eq!(
                retrieved, value,
                "credential value must survive simulated daemon restart"
            );

            // Cleanup.
            router_second.delete(key).ok();
        }
    }
}
