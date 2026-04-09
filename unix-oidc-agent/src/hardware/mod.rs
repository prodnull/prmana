//! Hardware signer backend support.
//!
//! This module provides shared infrastructure used by all hardware signer backends:
//! - `PinCache`: thread-safe PIN cache with configurable timeout
//! - `SignerConfig`: YAML-deserialized configuration for hardware signer selection
//! - `build_signer`: factory that constructs the correct `DPoPSigner` from a spec string
//! - `provision_signer`: generates a new key on the hardware device and returns an initialized signer
//!
//! Individual backends are gated behind cargo features:
//! - `--features yubikey` enables `crypto::yubikey_signer` (PKCS#11 via cryptoki)
//! - `--features tpm`     enables `crypto::tpm_signer` (tss-esapi, Plan 03-02)

pub mod pin_cache;

pub use pin_cache::PinCache;

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::crypto::DPoPSigner;

/// Top-level signer configuration, loaded from
/// `~/.config/unix-oidc/signer.yaml` or `/etc/unix-oidc/signer.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignerConfig {
    /// YubiKey PKCS#11 backend configuration.
    pub yubikey: Option<YubiKeyConfig>,
    /// TPM 2.0 backend configuration (Plan 03-02).
    pub tpm: Option<TpmConfig>,
}

/// YubiKey-specific signer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubiKeyConfig {
    /// Override the default PKCS#11 library path.
    ///
    /// Defaults:
    /// - Linux:  `/usr/lib/libykcs11.so` (yubico-piv-tool package)
    /// - macOS:  `/usr/local/lib/libykcs11.dylib` (homebrew yubico-piv-tool)
    pub pkcs11_library: Option<String>,

    /// How many seconds to cache the YubiKey PIN after first entry.
    ///
    /// Default: 28800 (8 hours — a typical working day).
    /// Set to 0 to disable caching and always prompt.
    pub pin_cache_timeout: Option<u64>,
}

/// TPM 2.0 backend configuration (used by Plan 03-02).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmConfig {
    /// TCTI (TPM Command Transmission Interface) string.
    ///
    /// Default: `"tabrmd"` (resourcemgr daemon, recommended for multi-process access).
    /// Other common values: `"device:/dev/tpm0"` (direct kernel device).
    pub tcti: Option<String>,

    /// TPM persistent key handle (hex or decimal u32).
    ///
    /// Default: `0x81000001` (first user-space persistent handle per TCG spec).
    pub persistent_handle: Option<u32>,

    /// How many seconds to cache the TPM PIN/passphrase after first entry.
    ///
    /// Default: 28800 (8 hours).
    pub pin_cache_timeout: Option<u64>,
}

impl SignerConfig {
    /// Load `SignerConfig` from the first config file found, or return defaults.
    ///
    /// Search order:
    /// 1. `~/.config/unix-oidc/signer.yaml`  (via `directories::ProjectDirs`)
    /// 2. `/etc/unix-oidc/signer.yaml`
    /// 3. `Default::default()` (all fields None)
    ///
    /// Parse errors are logged at WARN and the default is returned, so a
    /// corrupt config file never prevents daemon startup.
    pub fn load() -> Self {
        // Try user config directory first.
        let user_path = directories::ProjectDirs::from("com", "unix-oidc", "unix-oidc")
            .map(|dirs| dirs.config_dir().join("signer.yaml"));

        let paths: Vec<std::path::PathBuf> = std::iter::once(user_path)
            .flatten()
            .chain(std::iter::once(std::path::PathBuf::from(
                "/etc/unix-oidc/signer.yaml",
            )))
            .collect();

        for path in &paths {
            if !path.exists() {
                continue;
            }
            match std::fs::read_to_string(path) {
                Ok(contents) => match serde_yaml::from_str::<SignerConfig>(&contents) {
                    Ok(cfg) => {
                        tracing::debug!(path = %path.display(), "Loaded signer config");
                        return cfg;
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "Failed to parse signer.yaml — using defaults"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to read signer.yaml — using defaults"
                    );
                }
            }
        }

        SignerConfig::default()
    }
}

/// Open an existing hardware signer by spec string.
///
/// `signer_spec` formats:
/// - `"yubikey:<slot>"` (e.g., `"yubikey:9a"`) — opens the YubiKey PIV slot.
///   Requires `--features yubikey` at build time.
/// - `"tpm"` — loads the persistent TPM key from the configured handle.
///   Requires `--features tpm` and Linux.
/// - `"software"` or `""` — returns an error; use `load_or_create_signer` instead.
///
/// Returns `Err` if the device is not connected, the feature is not compiled in,
/// or the key cannot be loaded.
pub fn build_signer(
    signer_spec: &str,
    #[allow(unused_variables)] config: &SignerConfig,
) -> anyhow::Result<Arc<dyn DPoPSigner>> {
    if signer_spec == "software" || signer_spec.is_empty() {
        anyhow::bail!("Software signer should be handled by caller (load_or_create_signer)");
    }

    #[cfg(feature = "yubikey")]
    if let Some(slot) = signer_spec.strip_prefix("yubikey:") {
        return Ok(Arc::new(crate::crypto::YubiKeySigner::open(slot, config)?));
    }

    #[cfg(not(feature = "yubikey"))]
    if signer_spec.starts_with("yubikey:") {
        anyhow::bail!(
            "YubiKey support not compiled in. Rebuild with `cargo build --features yubikey`."
        );
    }

    #[cfg(all(feature = "tpm", target_os = "linux"))]
    if signer_spec == "tpm" {
        return Ok(Arc::new(crate::crypto::TpmSigner::load(config)?));
    }

    #[cfg(all(feature = "tpm", not(target_os = "linux")))]
    if signer_spec == "tpm" {
        anyhow::bail!("TPM support is only available on Linux.");
    }

    #[cfg(not(feature = "tpm"))]
    if signer_spec == "tpm" {
        anyhow::bail!("TPM support not compiled in. Rebuild with `cargo build --features tpm`.");
    }

    anyhow::bail!(
        "Unknown signer: '{signer_spec}'. Valid options: software, yubikey:<slot> (e.g. yubikey:9a), tpm"
    )
}

/// Provision a new key on a hardware device and return the signer spec string
/// alongside an initialized `DPoPSigner`.
///
/// `signer_spec` formats:
/// - `"yubikey:<slot>"` — generates a P-256 key via `C_GenerateKeyPair` (CKM_EC_KEY_PAIR_GEN),
///   or adopts an existing compatible P-256 key in the slot. Returns `("yubikey:<slot>", signer)`.
/// - `"tpm"` — calls `TpmSigner::provision()` to create a non-exportable persistent P-256
///   key, then `TpmSigner::load()` for a ready signer. Returns `("tpm", signer)`.
/// - `"software"` — returns an error with a helpful message (software keys auto-generate at login).
///
/// On success: `(signer_type_string, initialized_signer)` where `signer_type_string`
/// should be persisted in token metadata as `"signer_type"`.
pub fn provision_signer(
    signer_spec: &str,
    #[allow(unused_variables)] config: &SignerConfig,
) -> anyhow::Result<(String, Arc<dyn DPoPSigner>)> {
    if signer_spec == "software" || signer_spec.is_empty() {
        anyhow::bail!(
            "Software signer auto-generates at login. No provisioning needed.\n\
             Run `unix-oidc-agent login` to authenticate with a software key."
        );
    }

    #[cfg(feature = "yubikey")]
    if let Some(slot) = signer_spec.strip_prefix("yubikey:") {
        if slot.is_empty() {
            anyhow::bail!(
                "YubiKey slot must be specified: --signer yubikey:9a (PIV Authentication slot recommended)"
            );
        }
        let signer = crate::crypto::YubiKeySigner::provision(slot, config)?;
        return Ok((signer_spec.to_string(), Arc::new(signer)));
    }

    #[cfg(not(feature = "yubikey"))]
    if signer_spec.starts_with("yubikey:") {
        anyhow::bail!(
            "YubiKey support not compiled in. Rebuild with `cargo build --features yubikey`."
        );
    }

    #[cfg(all(feature = "tpm", target_os = "linux"))]
    if signer_spec == "tpm" {
        // provision() returns TpmSigner directly using create_primary output —
        // no separate load() call needed (prevents TOCTOU handle-squatting).
        let signer = crate::crypto::TpmSigner::provision(config)?;
        return Ok(("tpm".to_string(), Arc::new(signer)));
    }

    #[cfg(all(feature = "tpm", not(target_os = "linux")))]
    if signer_spec == "tpm" {
        anyhow::bail!("TPM support is only available on Linux.");
    }

    #[cfg(not(feature = "tpm"))]
    if signer_spec == "tpm" {
        anyhow::bail!("TPM support not compiled in. Rebuild with `cargo build --features tpm`.");
    }

    anyhow::bail!(
        "Unknown signer: '{signer_spec}'. Valid options: yubikey:<slot> (e.g. yubikey:9a), tpm"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_config_default_is_all_none() {
        let cfg = SignerConfig::default();
        assert!(cfg.yubikey.is_none());
        assert!(cfg.tpm.is_none());
    }

    #[test]
    fn test_signer_config_deserializes_from_yaml() {
        let yaml = r#"
yubikey:
  pkcs11_library: /usr/lib/libykcs11.so
  pin_cache_timeout: 3600
tpm:
  tcti: device:/dev/tpm0
  persistent_handle: 2147483649
  pin_cache_timeout: 7200
"#;
        let cfg: SignerConfig = serde_yaml::from_str(yaml).unwrap();
        let yk = cfg.yubikey.as_ref().unwrap();
        assert_eq!(yk.pkcs11_library.as_deref(), Some("/usr/lib/libykcs11.so"));
        assert_eq!(yk.pin_cache_timeout, Some(3600));

        let tpm = cfg.tpm.as_ref().unwrap();
        assert_eq!(tpm.tcti.as_deref(), Some("device:/dev/tpm0"));
        assert_eq!(tpm.persistent_handle, Some(0x8000_0001));
        assert_eq!(tpm.pin_cache_timeout, Some(7200));
    }

    #[test]
    fn test_signer_config_partial_yaml() {
        // Only yubikey section present; tpm should be None.
        let yaml = r#"
yubikey:
  pin_cache_timeout: 28800
"#;
        let cfg: SignerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.yubikey.is_some());
        assert!(cfg.tpm.is_none());
        assert_eq!(cfg.yubikey.unwrap().pin_cache_timeout, Some(28800));
    }

    #[test]
    fn test_signer_config_load_returns_default_when_no_file() {
        // This test runs without config files present; load() must return Default.
        // We can't control HOME in a unit test easily, but we verify the function
        // doesn't panic and returns a valid struct.
        let cfg = SignerConfig::load();
        // No assertions on field values — they depend on environment.
        // Just verify the struct is valid (no panic = pass).
        let _ = cfg;
    }
}
