//! TPM 2.0 hardware signer backend (RFC 9449, HW-02).
//!
//! This module is compiled when `--features tpm` is passed. The core TPM
//! implementation (`TpmSigner`) uses `tss-esapi` which requires `libtss2-esys`
//! (Linux only). On macOS, the feature compiles cleanly but only the
//! `pad_to_32` helper and its tests are active; TPMs are not present on macOS.
//!
//! # Design
//!
//! Each `sign_proof()` call opens a fresh TPM `Context`, performs the signing
//! operation, and drops the context (parallel to the YubiKey open-sign-close
//! pattern). This avoids holding a TPM session open across SSH connections and
//! makes error recovery simpler.
//!
//! The DPoP signing key is stored as a non-exportable persistent P-256 key at
//! a configurable TPM persistent handle (default `0x81000001`). The handle
//! survives reboots; re-provisioning is needed only if the handle is explicitly
//! evicted.
//!
//! # P-256 capability probe (HW-05)
//!
//! `TpmSigner::probe_p256()` queries the TPM for its supported ECC curves via
//! `TPM2_CC_GetCapability(ECC_CURVES)`. If `TPM_ECC_NIST_P256` is absent, a
//! descriptive error is returned before any key operation is attempted. This
//! matters for cloud vTPMs (e.g., AWS Nitro, some Azure vTPMs) that may only
//! advertise a subset of curves.
//!
//! # r‖s left-padding
//!
//! tss-esapi returns ECDSA signature scalars as `BigNum`-style byte slices that
//! may be shorter than 32 bytes if the leading bytes are zero. RFC 9449 §4.2
//! requires exactly 64 bytes (32 for r, 32 for s). `pad_to_32()` left-pads each
//! component to exactly 32 bytes before concatenation.

// ── Platform-independent helper (no tss-esapi dependency) ───────────────────

/// Left-pad a P-256 scalar byte slice to exactly 32 bytes.
///
/// TPM ECDSA signatures return r and s as `BigNum`-style slices where leading
/// zero bytes may be omitted. RFC 9449 §4.2 requires exactly 32 bytes each.
///
/// - If `bytes.len() < 32`: the result is right-aligned with zero padding on
///   the left.
/// - If `bytes.len() == 32`: returned unchanged.
/// - If `bytes.len() > 32`: only the rightmost 32 bytes are used (defensive;
///   a well-behaved P-256 TPM will never produce > 32 bytes).
pub fn pad_to_32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let take = bytes.len().min(32);
    let start = 32 - take;
    out[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    out
}

// ── Linux-only TPM implementation (requires libtss2-esys) ───────────────────

#[cfg(target_os = "linux")]
mod linux_impl {
    use anyhow::{anyhow, bail, Context as AnyhowContext};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    use tss_esapi::{
        handles::{KeyHandle, PersistentTpmHandle, TpmHandle},
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            ecc::EccCurve,
            resource_handles::{Hierarchy, Provision},
        },
        structures::{
            CreatePrimaryKeyResult, Digest as TpmDigest, EccScheme, HashScheme, Public,
            PublicBuilder, PublicEccParametersBuilder, SignatureScheme,
        },
        tcti_ldr::{DeviceConfig, NetworkTPMConfig, TabrmdConfig, TctiNameConf},
        Context,
    };

    use crate::crypto::dpop::{assemble_dpop_proof, build_dpop_message, DPoPError};
    use crate::crypto::signer::DPoPSigner;
    use crate::crypto::tpm_signer::pad_to_32;
    use crate::hardware::{PinCache, SignerConfig};

    /// Default TPM TCTI connection string.
    const DEFAULT_TCTI: &str = "tabrmd";

    /// Default persistent key handle (first user-space handle per TCG reference).
    const DEFAULT_HANDLE: u32 = 0x81000001;

    // ── Error types ─────────────────────────────────────────────────────────

    /// TPM signer error conditions with actionable messages.
    #[derive(Debug, thiserror::Error)]
    pub enum TpmSignerError {
        /// TPM not reachable via the configured TCTI.
        #[error(
            "TPM not available: {0}. Check that tpm2-abrmd is running \
             (`systemctl status tpm2-abrmd`) or specify a different TCTI in signer.yaml."
        )]
        TpmNotAvailable(String),

        /// TPM does not support P-256 (NistP256 ECC curve).
        #[error(
            "This TPM does not support P-256 (NistP256 ECC curve). DPoP requires ES256 (P-256 \
             ECDSA). Cloud vTPMs may not support all curves."
        )]
        P256NotSupported,

        /// Persistent key handle not found.
        #[error(
            "Persistent key handle {0:#010x} not found in TPM. \
             Run `unix-oidc-agent provision --signer tpm` to create a key."
        )]
        KeyNotFound(u32),

        /// Signing operation failed.
        #[error("TPM signing failed: {0}")]
        SigningFailed(String),

        /// Key provisioning failed.
        #[error("TPM key provisioning failed: {0}")]
        ProvisionFailed(String),
    }

    impl From<TpmSignerError> for DPoPError {
        fn from(e: TpmSignerError) -> DPoPError {
            DPoPError::HardwareSigner(e.to_string())
        }
    }

    // ── TpmSigner ───────────────────────────────────────────────────────────

    /// TPM 2.0-backed DPoP signer.
    ///
    /// The P-256 signing key is stored as a non-exportable persistent object at
    /// `persistent_handle`. The private key never leaves the TPM; all signing
    /// operations are performed inside the TPM.
    pub struct TpmSigner {
        persistent_handle: u32,
        tcti_conf: String,
        pin_cache: PinCache,
        thumbprint: String,
        public_key_jwk: serde_json::Value,
    }

    // PinCache is Send+Sync; all other fields are String/Value — also Send+Sync.
    unsafe impl Send for TpmSigner {}
    unsafe impl Sync for TpmSigner {}

    impl TpmSigner {
        /// Probe the TPM to verify it supports P-256 (NistP256 ECC curve).
        ///
        /// Called before any key creation or provisioning step (HW-05).
        ///
        /// # Errors
        ///
        /// - `TpmSignerError::TpmNotAvailable` if the TPM cannot be reached.
        /// - `TpmSignerError::P256NotSupported` if NistP256 is absent from the
        ///   TPM's ECC curve list.
        pub fn probe_p256(tcti: &str) -> anyhow::Result<()> {
            let tcti_conf = parse_tcti(tcti)?;
            let mut ctx = Context::new(tcti_conf)
                .map_err(|e| TpmSignerError::TpmNotAvailable(e.to_string()))?;

            let (capability_data, _more_data) = ctx
                .get_capability(tss_esapi::constants::CapabilityType::EccCurves, 0, 32)
                .context("Failed to query TPM ECC capabilities")?;

            let curves = match capability_data {
                tss_esapi::structures::CapabilityData::EccCurves(list) => list,
                _ => bail!("Unexpected capability response type from TPM"),
            };

            let has_p256 = curves.iter().any(|c| *c == EccCurve::NistP256);

            if !has_p256 {
                return Err(TpmSignerError::P256NotSupported.into());
            }

            Ok(())
        }

        /// Provision a new P-256 signing key and make it persistent.
        ///
        /// Creates an unrestricted P-256 ECDSA key under the Owner hierarchy and
        /// stores it at `config.tpm.persistent_handle` (default `0x81000001`).
        ///
        /// Returns `(handle, jwk, thumbprint)` for the newly created key.
        ///
        /// # Errors
        ///
        /// Returns `TpmSignerError::P256NotSupported` if the TPM lacks NistP256,
        /// or `TpmSignerError::ProvisionFailed` on any TPM error.
        pub fn provision(
            config: &SignerConfig,
        ) -> anyhow::Result<(u32, serde_json::Value, String)> {
            let tpm_cfg = config.tpm.as_ref();
            let tcti = tpm_cfg
                .and_then(|t| t.tcti.as_deref())
                .unwrap_or(DEFAULT_TCTI);
            let handle_val = tpm_cfg
                .and_then(|t| t.persistent_handle)
                .unwrap_or(DEFAULT_HANDLE);

            Self::probe_p256(tcti)?;

            let tcti_conf = parse_tcti(tcti)?;
            let mut ctx = Context::new(tcti_conf)
                .map_err(|e| TpmSignerError::TpmNotAvailable(e.to_string()))?;

            let key_pub = build_p256_key_public()?;

            let CreatePrimaryKeyResult {
                key_handle,
                out_public,
                ..
            } = ctx
                .execute_with_nullauth_session(|ctx| {
                    ctx.create_primary(Hierarchy::Owner, key_pub, None, None, None, None)
                })
                .map_err(|e| TpmSignerError::ProvisionFailed(e.to_string()))?;

            let persistent_handle = PersistentTpmHandle::new(handle_val)
                .map_err(|e| TpmSignerError::ProvisionFailed(e.to_string()))?;

            ctx.execute_with_nullauth_session(|ctx| {
                ctx.evict_control(
                    Provision::Owner,
                    key_handle.into(),
                    tss_esapi::handles::ObjectHandle::from(persistent_handle),
                )
            })
            .map_err(|e| TpmSignerError::ProvisionFailed(e.to_string()))?;

            let (jwk, thumbprint) = extract_p256_jwk_from_public(&out_public)?;

            Ok((handle_val, jwk, thumbprint))
        }

        /// Load an existing P-256 key from its persistent handle.
        ///
        /// Reads the public area from the TPM to reconstruct the JWK and thumbprint.
        ///
        /// # Errors
        ///
        /// - `TpmSignerError::TpmNotAvailable` if the TPM cannot be reached.
        /// - `TpmSignerError::KeyNotFound` if the handle has no object.
        pub fn load(config: &SignerConfig) -> anyhow::Result<Self> {
            let tpm_cfg = config.tpm.as_ref();
            let tcti = tpm_cfg
                .and_then(|t| t.tcti.as_deref())
                .unwrap_or(DEFAULT_TCTI)
                .to_owned();
            let handle_val = tpm_cfg
                .and_then(|t| t.persistent_handle)
                .unwrap_or(DEFAULT_HANDLE);
            let pin_timeout = tpm_cfg.and_then(|t| t.pin_cache_timeout).unwrap_or(28800);

            let tcti_conf = parse_tcti(&tcti)?;
            let mut ctx = Context::new(tcti_conf)
                .map_err(|e| TpmSignerError::TpmNotAvailable(e.to_string()))?;

            let persistent_tpm_handle = PersistentTpmHandle::new(handle_val).map_err(|e| {
                anyhow::anyhow!(TpmSignerError::KeyNotFound(handle_val)).context(e.to_string())
            })?;
            let tpm_handle = TpmHandle::Persistent(persistent_tpm_handle);
            let key_handle: KeyHandle = ctx
                .tr_from_tpm_public(tpm_handle)
                .map_err(|_| TpmSignerError::KeyNotFound(handle_val))?
                .into();

            let (out_public, _, _) = ctx.read_public(key_handle).map_err(|e| {
                anyhow::anyhow!(TpmSignerError::KeyNotFound(handle_val)).context(e.to_string())
            })?;

            let (jwk, thumbprint) = extract_p256_jwk_from_public(&out_public)?;

            Ok(Self {
                persistent_handle: handle_val,
                tcti_conf: tcti,
                pin_cache: PinCache::new(pin_timeout),
                thumbprint,
                public_key_jwk: jwk,
            })
        }
    }

    impl DPoPSigner for TpmSigner {
        fn thumbprint(&self) -> String {
            self.thumbprint.clone()
        }

        fn public_key_jwk(&self) -> serde_json::Value {
            self.public_key_jwk.clone()
        }

        fn sign_proof(
            &self,
            method: &str,
            target: &str,
            nonce: Option<&str>,
        ) -> Result<String, DPoPError> {
            // Step 1: Build the unsigned DPoP message.
            let message = build_dpop_message(&self.public_key_jwk, method, target, nonce)?;

            // Step 2: SHA-256 hash of the message.
            // Unrestricted signing keys use a pre-computed digest + null hash-check ticket.
            let hash_bytes = Sha256::digest(message.as_bytes());
            let digest = TpmDigest::try_from(hash_bytes.as_slice())
                .map_err(|e| DPoPError::HardwareSigner(e.to_string()))?;

            // Step 3: Open a fresh TPM context per call (no persistent context — HW-04 pattern).
            let tcti_conf = parse_tcti(&self.tcti_conf)
                .map_err(|e| DPoPError::HardwareSigner(e.to_string()))?;
            let mut ctx =
                Context::new(tcti_conf).map_err(|e| DPoPError::HardwareSigner(e.to_string()))?;

            // Step 4: Load the key handle from the persistent handle.
            let persistent_tpm_handle = PersistentTpmHandle::new(self.persistent_handle)
                .map_err(|e| DPoPError::HardwareSigner(e.to_string()))?;
            let tpm_handle = TpmHandle::Persistent(persistent_tpm_handle);
            let key_handle: KeyHandle = ctx
                .tr_from_tpm_public(tpm_handle)
                .map_err(|_| {
                    DPoPError::HardwareSigner(
                        TpmSignerError::KeyNotFound(self.persistent_handle).to_string(),
                    )
                })?
                .into();

            // Step 5: Build signing scheme (ECDSA + SHA-256).
            let scheme = SignatureScheme::EcDsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            };

            // Step 6: Build null hash-check ticket.
            // Unrestricted signing keys do not require a TPM-internal hash check
            // (the TPM does not verify the hash itself). Pass a null ticket.
            let validation = tss_esapi::structures::HashcheckTicket::try_from(
                tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
                    tag: tss_esapi::constants::StructureTag::Hashcheck.into(),
                    hierarchy: Hierarchy::Null.into(),
                    digest: Default::default(),
                },
            )
            .map_err(|e| DPoPError::HardwareSigner(e.to_string()))?;

            let signature = ctx
                .execute_with_nullauth_session(|ctx| {
                    ctx.sign(key_handle, digest, scheme, validation)
                })
                .map_err(|e| {
                    DPoPError::HardwareSigner(
                        TpmSignerError::SigningFailed(e.to_string()).to_string(),
                    )
                })?;

            // Step 7: Extract r‖s from the EcDsa signature, left-padding each to 32 bytes.
            let sig_bytes = match signature {
                tss_esapi::structures::Signature::EcDsa(ecc_sig) => {
                    let r = ecc_sig.signature_r().value();
                    let s = ecc_sig.signature_s().value();
                    let r_padded = pad_to_32(r);
                    let s_padded = pad_to_32(s);
                    let mut out = [0u8; 64];
                    out[..32].copy_from_slice(&r_padded);
                    out[32..].copy_from_slice(&s_padded);
                    out.to_vec()
                }
                other => {
                    return Err(DPoPError::HardwareSigner(format!(
                        "Expected EcDsa signature from TPM, got {:?}",
                        other
                    )));
                }
            };

            // Step 8: Assemble the final DPoP JWT.
            assemble_dpop_proof(&message, &sig_bytes)
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    /// Parse a TCTI string into a `TctiNameConf`.
    fn parse_tcti(tcti: &str) -> anyhow::Result<TctiNameConf> {
        let lower = tcti.trim().to_lowercase();
        if lower == "tabrmd" {
            Ok(TctiNameConf::Tabrmd(TabrmdConfig::default()))
        } else if lower.starts_with("device") {
            Ok(TctiNameConf::Device(DeviceConfig::default()))
        } else if lower == "mssim" || lower == "swtpm" {
            Ok(TctiNameConf::Mssim(NetworkTPMConfig::default()))
        } else {
            bail!(
                "Unknown TCTI '{}'. Supported values: tabrmd, device, mssim. \
                 See `man tss2-tcti` for advanced TCTI strings.",
                tcti
            )
        }
    }

    /// Build the public area for an unrestricted P-256 ECDSA signing key.
    fn build_p256_key_public() -> anyhow::Result<Public> {
        let ecc_params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(EccCurve::NistP256)
            .with_is_signing_key(true)
            .with_is_decryption_key(false)
            .with_restricted(false)
            .build()
            .context("Building P-256 key parameters")?;

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(Default::default())
            .build()
            .context("Building P-256 key public area")
    }

    /// Extract (JWK, thumbprint) from a tss-esapi `Public` ECC key.
    fn extract_p256_jwk_from_public(
        public: &Public,
    ) -> anyhow::Result<(serde_json::Value, String)> {
        let ecc_point = match public {
            Public::Ecc { unique, .. } => unique,
            _ => bail!("Expected ECC public key type from TPM"),
        };

        let x_bytes = ecc_point.x().value();
        let y_bytes = ecc_point.y().value();

        let x_padded = pad_to_32(x_bytes);
        let y_padded = pad_to_32(y_bytes);

        let x_b64 = URL_SAFE_NO_PAD.encode(x_padded);
        let y_b64 = URL_SAFE_NO_PAD.encode(y_padded);

        // RFC 7638 §3.3: canonical JSON with lexicographic key order.
        // Security: hardcoded field names — never use user-supplied kty/crv.
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            x_b64, y_b64
        );
        let digest = Sha256::digest(canonical.as_bytes());
        let thumbprint = URL_SAFE_NO_PAD.encode(digest);

        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64
        });

        Ok((jwk, thumbprint))
    }

    // ── Integration tests (require real TPM hardware or swtpm) ──────────────

    #[cfg(test)]
    mod integration_tests {
        use super::*;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        #[test]
        #[ignore = "Requires TPM 2.0 with tpm2-abrmd running"]
        fn test_tpm_probe_p256() {
            TpmSigner::probe_p256("tabrmd")
                .expect("P-256 probe must succeed on a P-256-capable TPM");
        }

        #[test]
        #[ignore = "Requires TPM 2.0 with tpm2-abrmd running"]
        fn test_tpm_sign_proof() {
            let config = SignerConfig::default();
            let signer = TpmSigner::load(&config)
                .expect("TpmSigner::load requires an existing key at handle 0x81000001");

            let thumbprint = signer.thumbprint();
            assert_eq!(
                thumbprint.len(),
                43,
                "thumbprint must be 43 chars (base64url SHA-256)"
            );

            let proof = signer
                .sign_proof("SSH", "server.example.com", None)
                .expect("sign_proof failed");

            let parts: Vec<&str> = proof.split('.').collect();
            assert_eq!(parts.len(), 3, "JWT must have 3 parts");

            let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
            assert_eq!(sig.len(), 64, "P-256 r‖s signature must be 64 bytes");

            let header = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
            let header_json: serde_json::Value = serde_json::from_slice(&header).unwrap();
            let jwk = &header_json["jwk"];
            assert_eq!(jwk["kty"], "EC");
            assert_eq!(jwk["crv"], "P-256");
        }
    }
}

// Re-export TpmSigner at the module level on Linux.
#[cfg(target_os = "linux")]
pub use linux_impl::{TpmSigner, TpmSignerError};

// ── Platform-independent unit tests for pad_to_32 ───────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Short input (< 32 bytes) must be left-padded with zeros.
    #[test]
    fn test_pad_to_32_short() {
        let input = vec![0x01u8; 30]; // 30 bytes
        let result = pad_to_32(&input);
        assert_eq!(result.len(), 32);
        assert_eq!(result[0], 0x00, "first padding byte must be zero");
        assert_eq!(result[1], 0x00, "second padding byte must be zero");
        assert_eq!(&result[2..], &input[..]);
    }

    /// Exactly 32 bytes must pass through unchanged.
    #[test]
    fn test_pad_to_32_exact() {
        let input: Vec<u8> = (0u8..32).collect();
        let result = pad_to_32(&input);
        assert_eq!(result.len(), 32);
        assert_eq!(result.as_slice(), input.as_slice());
    }

    /// Empty input must produce all-zero output.
    #[test]
    fn test_pad_to_32_empty() {
        let result = pad_to_32(&[]);
        assert_eq!(result, [0u8; 32], "empty input must produce all zeros");
    }

    /// Single byte must appear in the rightmost position.
    #[test]
    fn test_pad_to_32_single_byte() {
        let result = pad_to_32(&[0x42]);
        assert_eq!(result[31], 0x42, "single byte must be in last position");
        assert_eq!(&result[..31], &[0u8; 31], "all leading bytes must be zero");
    }

    /// Input longer than 32 bytes must use only the rightmost 32 bytes.
    #[test]
    fn test_pad_to_32_truncates_from_left() {
        // 33-byte input: leading 0xFF then bytes 0..32
        let mut input = vec![0xFFu8];
        input.extend(0u8..32);
        assert_eq!(input.len(), 33);
        let result = pad_to_32(&input);
        assert_eq!(result.len(), 32);
        assert!(
            !result.contains(&0xFF),
            "leading byte must be truncated, result: {:?}",
            result
        );
        assert_eq!(result.as_slice(), &input[1..33]);
    }
}
