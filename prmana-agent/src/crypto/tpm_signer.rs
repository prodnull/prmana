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

/// TPM key attestation evidence produced by `TPM2_CC_Certify`.
///
/// Proves that the DPoP signing key was created by and is resident in
/// a specific TPM. The PAM module verifies this evidence to enforce
/// hardware-bound key requirements (ADR-018).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttestationEvidence {
    /// TPMS_ATTEST structure (base64url-encoded, no padding).
    /// Contains TPMS_CERTIFY_INFO with the certified key's Name.
    pub certify_info: String,
    /// ECDSA signature over certify_info by the Attestation Key (base64url-encoded).
    pub signature: String,
    /// Public area of the transient Attestation Key (base64url-encoded).
    /// Needed by the verifier to check the signature.
    pub ak_public: String,
}

// ── Platform-independent helper (no tss-esapi dependency) ───────────────────

/// Left-pad a P-256 scalar byte slice to exactly 32 bytes.
///
/// TPM ECDSA signatures return r and s as `BigNum`-style slices where leading
/// zero bytes may be omitted. RFC 9449 §4.2 requires exactly 32 bytes each.
///
/// - If `bytes.len() < 32`: the result is right-aligned with zero padding on
///   the left.
/// - If `bytes.len() == 32`: returned unchanged.
/// - If `bytes.len() > 32`: returns `Err` — a well-behaved P-256 TPM will
///   never produce > 32 bytes. Silent truncation would violate the project's
///   "never silently fail" invariant.
pub fn pad_to_32(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() > 32 {
        return Err(format!(
            "P-256 scalar is {} bytes (expected ≤32). \
             The TPM returned an oversized value — this indicates a \
             malfunctioning or non-conformant TPM.",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(bytes);
    Ok(out)
}

// ── Linux-only TPM implementation (requires libtss2-esys) ───────────────────

#[cfg(target_os = "linux")]
mod linux_impl {
    use anyhow::{bail, Context as AnyhowContext};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        constants::{ecc::EccCurveIdentifier, tss::TPM2_RH_NULL},
        handles::{KeyHandle, PersistentTpmHandle, TpmHandle},
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            dynamic_handles::Persistent,
            ecc::EccCurve,
            resource_handles::{Hierarchy, Provision},
        },
        structures::{
            CreatePrimaryKeyResult, Data, Digest as TpmDigest, EccScheme, HashScheme,
            KeyDerivationFunctionScheme, Public, PublicBuilder, PublicEccParametersBuilder,
            SignatureScheme,
        },
        tcti_ldr::{DeviceConfig, NetworkTPMConfig, TabrmdConfig, TctiNameConf},
        traits::Marshall,
        Context,
    };

    use std::str::FromStr;

    use crate::crypto::dpop::{
        assemble_dpop_proof, build_dpop_message_with_attestation, DPoPError,
    };
    use crate::crypto::signer::DPoPSigner;
    use crate::crypto::tpm_signer::pad_to_32;
    use crate::hardware::SignerConfig;

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
             Run `prmana-agent provision --signer tpm` to create a key."
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
    ///
    /// No `tss_esapi::Context` is stored — each `sign_proof()` call opens a
    /// fresh context (open-sign-close pattern). If a `Context` field is ever
    /// added, the `unsafe impl Send/Sync` below must be re-evaluated because
    /// `tss_esapi::Context` is `!Send`.
    pub struct TpmSigner {
        persistent_handle: u32,
        tcti_conf: String,
        thumbprint: String,
        public_key_jwk: serde_json::Value,
    }

    // All fields are String/u32/serde_json::Value — all Send+Sync.
    // No tss_esapi::Context is stored; contexts are ephemeral per sign_proof() call.
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

            let has_p256 = curves.contains(&EccCurveIdentifier::NistP256);

            if !has_p256 {
                return Err(TpmSignerError::P256NotSupported.into());
            }

            Ok(())
        }

        /// Provision a new P-256 signing key, persist it, and return a ready signer.
        ///
        /// Creates an unrestricted P-256 ECDSA key under the Owner hierarchy and
        /// stores it at `config.tpm.persistent_handle` (default `0x81000001`).
        ///
        /// Returns a fully initialized `TpmSigner` using the `out_public` from
        /// `create_primary` directly — no second TPM read is needed, which
        /// eliminates a TOCTOU race where an attacker could swap the persistent
        /// handle between provision and load.
        ///
        /// # Security
        ///
        /// The Owner hierarchy must have a password set in production deployments.
        /// Without it, any process that can reach the TPM can evict and replace
        /// this key. See `docs/hardware-key-setup.md` for deployment guidance.
        ///
        /// # Errors
        ///
        /// Returns `TpmSignerError::P256NotSupported` if the TPM lacks NistP256,
        /// or `TpmSignerError::ProvisionFailed` on any TPM error.
        pub fn provision(config: &SignerConfig) -> anyhow::Result<Self> {
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

            // Evict any existing key at this persistent handle before persisting the
            // new one. Without this, concurrent or repeated provisioning (e.g.,
            // integration tests sharing the same swtpm) fails with "NV Index or
            // persistent object already defined."
            //
            // tr_from_tpm_public returns Ok if an object exists at the handle; we
            // then evict it. If nothing exists, tr_from_tpm_public returns Err and
            // we proceed directly to persist the new key.
            if let Ok(existing_handle) =
                ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))
            {
                tracing::debug!(
                    handle = %format!("{handle_val:#010x}"),
                    "Evicting existing key at persistent handle before re-provisioning"
                );
                let _ = ctx.execute_with_nullauth_session(|ctx| {
                    ctx.evict_control(
                        Provision::Owner,
                        existing_handle,
                        Persistent::Persistent(persistent_handle),
                    )
                });
            }

            ctx.execute_with_nullauth_session(|ctx| {
                ctx.evict_control(
                    Provision::Owner,
                    key_handle.into(),
                    Persistent::Persistent(persistent_handle),
                )
            })
            .map_err(|e| TpmSignerError::ProvisionFailed(e.to_string()))?;

            // Derive JWK + thumbprint from the create_primary output directly,
            // not from a second TPM read (prevents TOCTOU handle-squatting).
            let (jwk, thumbprint) = extract_p256_jwk_from_public(&out_public)?;

            Ok(Self {
                persistent_handle: handle_val,
                tcti_conf: tcti.to_owned(),
                thumbprint,
                public_key_jwk: jwk,
            })
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

            // Validate persistent handle range (TCG TPM 2.0 Part 2, Table 28).
            if !(0x81000000..=0x81FFFFFF).contains(&handle_val) {
                bail!(
                    "Invalid persistent handle {handle_val:#010x}: must be in range \
                     0x81000000–0x81FFFFFF (owner hierarchy persistent objects)"
                );
            }

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
                thumbprint,
                public_key_jwk: jwk,
            })
        }
    }

    impl TpmSigner {
        /// Produce attestation evidence for this signing key via TPM2_CC_Certify.
        ///
        /// Creates a transient Attestation Key (AK) under the Endorsement Hierarchy,
        /// certifies the persistent signing key, and returns the evidence.
        ///
        /// The AK is ephemeral — it's created, used for certification, and dropped.
        ///
        /// # Security
        ///
        /// The certify_info contains the signing key's `Name` — a hash of its
        /// public area. The PAM module computes the expected Name from the DPoP
        /// proof's JWK and verifies it matches. This proves the DPoP key is
        /// TPM-resident without trusting client software.
        ///
        /// # Errors
        ///
        /// Returns error if the TPM is unreachable or certification fails.
        pub fn certify(&self) -> anyhow::Result<super::AttestationEvidence> {
            let tcti_conf = parse_tcti(&self.tcti_conf)?;
            let mut ctx = Context::new(tcti_conf)
                .map_err(|e| TpmSignerError::TpmNotAvailable(e.to_string()))?;

            // Load the persistent signing key (returns ObjectHandle).
            let persistent_tpm_handle = PersistentTpmHandle::new(self.persistent_handle)
                .context("Invalid persistent handle for certify")?;
            let signing_key_handle = ctx
                .tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
                .context("Failed to load persistent key for certification")?;

            // Create a transient AK under the Endorsement Hierarchy.
            // Same P-256 key template as the signing key — we just need any key
            // that can sign the TPMS_ATTEST structure.
            let ak_template = build_p256_key_public()?;
            let CreatePrimaryKeyResult {
                key_handle: ak_handle,
                out_public: ak_public,
                ..
            } = ctx
                .execute_with_nullauth_session(|ctx| {
                    ctx.create_primary(Hierarchy::Endorsement, ak_template, None, None, None, None)
                })
                .context("Failed to create attestation key under Endorsement hierarchy")?;

            // Certify the signing key using the AK.
            // SignatureScheme::Null tells the TPM to use the AK's default scheme (ECDSA-SHA256).
            let qualifying_data = Data::default();
            let (attest, sig) = ctx
                .execute_with_nullauth_session(|ctx| {
                    ctx.certify(
                        signing_key_handle,
                        ak_handle,
                        qualifying_data,
                        SignatureScheme::Null,
                    )
                })
                .context("TPM2_CC_Certify failed")?;

            // Serialize TPMS_ATTEST via Marshall trait.
            let attest_bytes = attest
                .marshall()
                .context("Failed to marshall TPMS_ATTEST")?;
            let certify_info = URL_SAFE_NO_PAD.encode(&attest_bytes);

            // Serialize AK signature (r||s, padded to 64 bytes).
            let sig_bytes = match sig {
                tss_esapi::structures::Signature::EcDsa(ecc_sig) => {
                    let r = pad_to_32(ecc_sig.signature_r().value())
                        .map_err(|e| anyhow::anyhow!("Attestation sig r: {e}"))?;
                    let s = pad_to_32(ecc_sig.signature_s().value())
                        .map_err(|e| anyhow::anyhow!("Attestation sig s: {e}"))?;
                    let mut out = [0u8; 64];
                    out[..32].copy_from_slice(&r);
                    out[32..].copy_from_slice(&s);
                    out.to_vec()
                }
                other => bail!("Expected EcDsa attestation signature, got {other:?}"),
            };
            let signature = URL_SAFE_NO_PAD.encode(&sig_bytes);

            // Serialize AK public area via Marshall trait.
            let ak_public_bytes = ak_public
                .marshall()
                .context("Failed to marshall AK public area")?;
            let ak_public_b64 = URL_SAFE_NO_PAD.encode(&ak_public_bytes);

            // Flush the transient AK (it was only needed for this certification).
            let _ = ctx.flush_context(ak_handle.into());

            Ok(super::AttestationEvidence {
                certify_info,
                signature,
                ak_public: ak_public_b64,
            })
        }
    }

    impl DPoPSigner for TpmSigner {
        fn thumbprint(&self) -> String {
            self.thumbprint.clone()
        }

        fn sign_jwt_es256(&self, message: &str) -> Result<Vec<u8>, DPoPError> {
            let hash_bytes = Sha256::digest(message.as_bytes());
            let digest = TpmDigest::try_from(hash_bytes.as_ref())
                .map_err(|e| DPoPError::HardwareSigner(e.to_string()))?;

            let tcti_conf = parse_tcti(&self.tcti_conf)
                .map_err(|e| DPoPError::HardwareSigner(e.to_string()))?;
            let mut ctx =
                Context::new(tcti_conf).map_err(|e| DPoPError::HardwareSigner(e.to_string()))?;

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

            let scheme = SignatureScheme::EcDsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            };

            let validation = tss_esapi::structures::HashcheckTicket::try_from(
                tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
                    tag: tss_esapi::constants::StructureTag::Hashcheck.into(),
                    hierarchy: TPM2_RH_NULL,
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

            let sig_bytes = match signature {
                tss_esapi::structures::Signature::EcDsa(ecc_sig) => {
                    let r = ecc_sig.signature_r().value();
                    let s = ecc_sig.signature_s().value();
                    let r_padded = pad_to_32(r)
                        .map_err(|e| DPoPError::HardwareSigner(format!("r scalar: {e}")))?;
                    let s_padded = pad_to_32(s)
                        .map_err(|e| DPoPError::HardwareSigner(format!("s scalar: {e}")))?;
                    let mut out = [0u8; 64];
                    out[..32].copy_from_slice(&r_padded);
                    out[32..].copy_from_slice(&s_padded);
                    out.to_vec()
                }
                other => {
                    return Err(DPoPError::HardwareSigner(format!(
                        "Expected EcDsa signature from TPM, got {other:?}"
                    )));
                }
            };

            Ok(sig_bytes)
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
            // Step 1: Attempt attestation (best-effort — ADR-018).
            // certify() opens its own ephemeral TPM context (open-certify-close).
            // On failure, proceed without attestation; WARN is logged.
            let attestation_json = match self.certify() {
                Ok(evidence) => match serde_json::to_value(&evidence) {
                    Ok(v) => {
                        tracing::debug!("TPM attestation evidence produced for DPoP proof");
                        Some(v)
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Failed to serialize TPM attestation evidence — proceeding without"
                        );
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "TPM certify failed — proceeding without attestation evidence"
                    );
                    None
                }
            };

            // Step 2: Build the unsigned DPoP message, with attestation if available.
            let message = build_dpop_message_with_attestation(
                &self.public_key_jwk,
                method,
                target,
                nonce,
                attestation_json.as_ref(),
            )?;

            let sig_bytes = self.sign_jwt_es256(&message)?;
            assemble_dpop_proof(&message, &sig_bytes)
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    /// Parse a TCTI string into a `TctiNameConf`.
    ///
    /// Security: `mssim`/`swtpm` (software TPM simulators) are only available in
    /// test builds. In production, an attacker who can write to signer.yaml could
    /// redirect the TCTI to a simulator they control, defeating the hardware
    /// non-exportability guarantee. See threat model: "Fake TPM Simulator Attack."
    fn parse_tcti(tcti: &str) -> anyhow::Result<TctiNameConf> {
        let lower = tcti.trim().to_lowercase();
        if lower == "tabrmd" {
            Ok(TctiNameConf::Tabrmd(TabrmdConfig::default()))
        } else if lower.starts_with("device") {
            // Parse optional path: "device:/dev/tpmrm0" → DeviceConfig with that path
            if let Some(path) = lower.strip_prefix("device:") {
                let path = path.trim();
                if path.is_empty() {
                    Ok(TctiNameConf::Device(DeviceConfig::default()))
                } else {
                    Ok(TctiNameConf::Device(
                        DeviceConfig::from_str(path)
                            .context(format!("Invalid device path: {path}"))?,
                    ))
                }
            } else {
                Ok(TctiNameConf::Device(DeviceConfig::default()))
            }
        } else if lower == "mssim" || lower == "swtpm" {
            // Software TPM simulators provide no hardware security guarantees.
            // Only allow in test builds to prevent "Fake TPM" substitution attacks.
            #[cfg(any(test, feature = "test-mode"))]
            {
                tracing::warn!(
                    tcti = tcti,
                    "Using software TPM simulator — no hardware security guarantees"
                );
                if lower == "swtpm" {
                    Ok(TctiNameConf::Swtpm(NetworkTPMConfig::default()))
                } else {
                    Ok(TctiNameConf::Mssim(NetworkTPMConfig::default()))
                }
            }
            #[cfg(not(any(test, feature = "test-mode")))]
            {
                bail!(
                    "Software TPM simulators (mssim/swtpm) are disabled in production builds. \
                     They provide no hardware key protection. \
                     Use 'tabrmd' or 'device' for a real TPM."
                )
            }
        } else {
            bail!(
                "Unknown TCTI '{tcti}'. Supported values: tabrmd, device. \
                 See `man tss2-tcti` for advanced TCTI strings."
            )
        }
    }

    /// Build the public area for an unrestricted P-256 ECDSA signing key.
    ///
    /// Security: the object attributes enforce non-exportability at the hardware
    /// level. These flags are HARD-FAIL requirements — without them the key can
    /// be duplicated out of the TPM, defeating the entire DPoP binding guarantee.
    ///
    /// - `fixed_tpm`:              key cannot be moved to a different TPM
    /// - `fixed_parent`:           key cannot be re-parented (prevents duplication)
    /// - `sensitive_data_origin`:  TPM generated the key internally (not injected)
    /// - `user_with_auth`:         required for sign without a policy session
    /// - `no_da`:                  no dictionary-attack lockout on signing (DPoP has no PIN)
    /// - `sign_encrypt`:           this is a signing key
    fn build_p256_key_public() -> anyhow::Result<Public> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_no_da(true)
            .with_sign_encrypt(true)
            .build()
            .context("Building P-256 object attributes")?;

        let ecc_params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(EccCurve::NistP256)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_is_signing_key(true)
            .with_is_decryption_key(false)
            .with_restricted(false)
            .build()
            .context("Building P-256 key parameters")?;

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_object_attributes(object_attributes)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(Default::default())
            .build()
            .context("Building P-256 key public area")
    }

    /// Extract (JWK, thumbprint) from a tss-esapi `Public` ECC key.
    ///
    /// Verifies the key is P-256 (NistP256) — rejects any other curve to
    /// prevent silent misuse of P-384/P-521 keys at the same handle.
    fn extract_p256_jwk_from_public(
        public: &Public,
    ) -> anyhow::Result<(serde_json::Value, String)> {
        let (ecc_point, parameters) = match public {
            Public::Ecc {
                unique, parameters, ..
            } => (unique, parameters),
            _ => bail!("Expected ECC public key type from TPM"),
        };

        // MED-1: Verify the loaded key is actually P-256, not a different curve.
        if parameters.ecc_curve() != EccCurve::NistP256 {
            bail!(
                "TPM key at handle is {:?}, not P-256. DPoP requires ES256 (P-256 ECDSA).",
                parameters.ecc_curve()
            );
        }

        let x_bytes = ecc_point.x().value();
        let y_bytes = ecc_point.y().value();

        let x_padded = pad_to_32(x_bytes).map_err(|e| anyhow::anyhow!("TPM x-coordinate: {e}"))?;
        let y_padded = pad_to_32(y_bytes).map_err(|e| anyhow::anyhow!("TPM y-coordinate: {e}"))?;

        let x_b64 = URL_SAFE_NO_PAD.encode(x_padded);
        let y_b64 = URL_SAFE_NO_PAD.encode(y_padded);

        // RFC 7638 §3.3: canonical JSON with lexicographic key order.
        // Security: hardcoded field names — never use user-supplied kty/crv.
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x_b64}","y":"{y_b64}"}}"#);
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
    //
    // Set PRMANA_TPM_TCTI to override the default TCTI for CI with swtpm.
    // Example: PRMANA_TPM_TCTI=swtpm cargo test --features tpm,test-mode -- --ignored

    #[cfg(test)]
    mod integration_tests {
        use super::*;
        use crate::hardware::TpmConfig;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        fn test_tcti() -> String {
            std::env::var("PRMANA_TPM_TCTI").unwrap_or_else(|_| "tabrmd".to_string())
        }

        /// Build a test config pinned to a caller-chosen persistent handle so
        /// each integration test gets its own slot. Running against a shared
        /// swtpm (the CI pattern) means DEFAULT_HANDLE state from one test
        /// would otherwise collide with another: re-provisioning through the
        /// same handle relies on `evict_control(Owner, …)` succeeding, and a
        /// silent evict failure leaves the slot occupied — the next test
        /// then fails with `TPM_RC_NV_DEFINED`. Unique handles per test
        /// sidesteps that entirely.
        fn test_config_with_handle(handle: u32) -> SignerConfig {
            SignerConfig {
                tpm: Some(TpmConfig {
                    tcti: Some(test_tcti()),
                    persistent_handle: Some(handle),
                    pin_cache_timeout: None,
                }),
                ..Default::default()
            }
        }

        /// RAII helper that evicts a test's persistent handle on drop so
        /// the swtpm state is clean for the next `cargo test` invocation.
        struct HandleGuard {
            tcti: String,
            handle: u32,
        }

        impl HandleGuard {
            fn new(tcti: String, handle: u32) -> Self {
                Self { tcti, handle }
            }
        }

        impl Drop for HandleGuard {
            fn drop(&mut self) {
                let Ok(tcti_conf) = parse_tcti(&self.tcti) else {
                    return;
                };
                let Ok(mut ctx) = Context::new(tcti_conf) else {
                    return;
                };
                let Ok(persistent) = PersistentTpmHandle::new(self.handle) else {
                    return;
                };
                if let Ok(existing) = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)) {
                    let _ = ctx.execute_with_nullauth_session(|c| {
                        c.evict_control(
                            Provision::Owner,
                            existing,
                            Persistent::Persistent(persistent),
                        )
                    });
                }
            }
        }

        #[test]
        #[ignore = "Requires TPM 2.0 or swtpm (set PRMANA_TPM_TCTI=swtpm for CI)"]
        fn test_tpm_probe_p256() {
            TpmSigner::probe_p256(&test_tcti())
                .expect("P-256 probe must succeed on a P-256-capable TPM");
        }

        #[test]
        #[ignore = "Requires TPM 2.0 or swtpm (set PRMANA_TPM_TCTI=swtpm for CI)"]
        fn test_tpm_provision_and_sign() {
            // Unique handle so test state doesn't collide with other tests
            // sharing the same swtpm.
            let handle = 0x8100_0010;
            let config = test_config_with_handle(handle);
            let _guard = HandleGuard::new(test_tcti(), handle);

            // Provision — returns TpmSigner directly (CRIT-2 fix).
            let signer = TpmSigner::provision(&config).expect("TpmSigner::provision failed");

            let thumbprint = signer.thumbprint();
            assert_eq!(
                thumbprint.len(),
                43,
                "thumbprint must be 43 chars (base64url SHA-256)"
            );

            // Verify thumbprint matches independent computation from JWK.
            // Reconstruct VerifyingKey from JWK x,y coordinates for cross-check.
            let jwk = signer.public_key_jwk();
            let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwk["x"].as_str().unwrap())
                .unwrap();
            let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwk["y"].as_str().unwrap())
                .unwrap();
            // Build SEC1 uncompressed point: 0x04 || x || y
            let mut sec1 = vec![0x04];
            sec1.extend_from_slice(&x_bytes);
            sec1.extend_from_slice(&y_bytes);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .expect("reconstruct VerifyingKey from JWK");
            let recomputed = crate::crypto::thumbprint::compute_ec_thumbprint(&vk);
            assert_eq!(
                thumbprint, recomputed,
                "TPM thumbprint must match compute_ec_thumbprint"
            );

            // Sign a DPoP proof.
            let proof = signer
                .sign_proof("SSH", "server.example.com", None)
                .expect("sign_proof failed");

            let parts: Vec<&str> = proof.split('.').collect();
            assert_eq!(parts.len(), 3, "JWT must have 3 parts");

            let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
            assert_eq!(sig.len(), 64, "P-256 r‖s signature must be 64 bytes");

            let header = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
            let header_json: serde_json::Value = serde_json::from_slice(&header).unwrap();
            let jwk_header = &header_json["jwk"];
            assert_eq!(jwk_header["kty"], "EC");
            assert_eq!(jwk_header["crv"], "P-256");
        }

        #[test]
        #[ignore = "Requires TPM 2.0 or swtpm (set PRMANA_TPM_TCTI=swtpm for CI)"]
        fn test_tpm_load_existing_key() {
            // Unique handle + self-provision so this test doesn't depend on
            // execution order or leftover state from other tests.
            let handle = 0x8100_0011;
            let config = test_config_with_handle(handle);
            let _guard = HandleGuard::new(test_tcti(), handle);

            TpmSigner::provision(&config).expect("setup: provision failed");

            // Now load the key we just provisioned.
            let signer = TpmSigner::load(&config)
                .expect("TpmSigner::load failed for a handle we just provisioned");

            let proof = signer
                .sign_proof("SSH", "server.example.com", Some("test-nonce"))
                .expect("sign_proof with nonce failed");

            let parts: Vec<&str> = proof.split('.').collect();
            assert_eq!(parts.len(), 3, "JWT must have 3 parts");
        }

        #[test]
        #[ignore = "Requires TPM 2.0 or swtpm (set PRMANA_TPM_TCTI=swtpm for CI)"]
        fn test_certify_returns_attestation_evidence() {
            let handle = 0x8100_0012;
            let config = test_config_with_handle(handle);
            let _guard = HandleGuard::new(test_tcti(), handle);
            let signer = TpmSigner::provision(&config).unwrap();
            let evidence = match signer.certify() {
                Ok(e) => e,
                Err(e) if e.to_string().contains("Certify") => {
                    eprintln!(
                        "TPM2_CC_Certify not supported by this simulator — \
                         apt swtpm may lack Endorsement Hierarchy AK support. \
                         Skipping. Error: {e}"
                    );
                    return;
                }
                Err(e) => panic!("Unexpected certify error: {e}"),
            };

            // All fields must be non-empty base64url strings.
            assert!(
                !evidence.certify_info.is_empty(),
                "certify_info must not be empty"
            );
            assert!(
                !evidence.signature.is_empty(),
                "signature must not be empty"
            );
            assert!(
                !evidence.ak_public.is_empty(),
                "ak_public must not be empty"
            );

            // Verify base64url decodes successfully.
            let certify_bytes = URL_SAFE_NO_PAD
                .decode(&evidence.certify_info)
                .expect("certify_info must be valid base64url");
            assert!(
                certify_bytes.len() > 64,
                "TPMS_ATTEST should be > 64 bytes, got {}",
                certify_bytes.len()
            );

            let sig_bytes = URL_SAFE_NO_PAD
                .decode(&evidence.signature)
                .expect("signature must be valid base64url");
            assert_eq!(
                sig_bytes.len(),
                64,
                "ECDSA P-256 signature should be 64 bytes (r||s)"
            );
        }

        #[test]
        #[ignore = "Requires TPM 2.0 or swtpm (set PRMANA_TPM_TCTI=swtpm for CI)"]
        fn test_certify_evidence_serializes_to_json() {
            let handle = 0x8100_0013;
            let config = test_config_with_handle(handle);
            let _guard = HandleGuard::new(test_tcti(), handle);
            let signer = TpmSigner::provision(&config).unwrap();
            let evidence = match signer.certify() {
                Ok(e) => e,
                Err(e) if e.to_string().contains("Certify") => {
                    eprintln!(
                        "TPM2_CC_Certify not supported by this simulator — skipping. Error: {e}"
                    );
                    return;
                }
                Err(e) => panic!("Unexpected certify error: {e}"),
            };

            let json = serde_json::to_string(&evidence).unwrap();
            assert!(json.contains("certify_info"));
            assert!(json.contains("signature"));
            assert!(json.contains("ak_public"));

            // Round-trip.
            let parsed: super::super::AttestationEvidence = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.certify_info, evidence.certify_info);
            assert_eq!(parsed.signature, evidence.signature);
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
        let result = pad_to_32(&input).unwrap();
        assert_eq!(result.len(), 32);
        assert_eq!(result[0], 0x00, "first padding byte must be zero");
        assert_eq!(result[1], 0x00, "second padding byte must be zero");
        assert_eq!(&result[2..], &input[..]);
    }

    /// Exactly 32 bytes must pass through unchanged.
    #[test]
    fn test_pad_to_32_exact() {
        let input: Vec<u8> = (0u8..32).collect();
        let result = pad_to_32(&input).unwrap();
        assert_eq!(result.len(), 32);
        assert_eq!(result.as_slice(), input.as_slice());
    }

    /// Empty input must produce all-zero output.
    #[test]
    fn test_pad_to_32_empty() {
        let result = pad_to_32(&[]).unwrap();
        assert_eq!(result, [0u8; 32], "empty input must produce all zeros");
    }

    /// Single byte must appear in the rightmost position.
    #[test]
    fn test_pad_to_32_single_byte() {
        let result = pad_to_32(&[0x42]).unwrap();
        assert_eq!(result[31], 0x42, "single byte must be in last position");
        assert_eq!(&result[..31], &[0u8; 31], "all leading bytes must be zero");
    }

    /// Input longer than 32 bytes must return an error (not silently truncate).
    #[test]
    fn test_pad_to_32_rejects_overlong() {
        let input = vec![0xFFu8; 33];
        let result = pad_to_32(&input);
        assert!(result.is_err(), "overlong input must return Err");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("33 bytes"),
            "error must include actual length: {msg}"
        );
    }

    /// AttestationEvidence round-trips through JSON without data loss.
    #[test]
    fn test_attestation_evidence_serde_roundtrip() {
        let evidence = AttestationEvidence {
            certify_info: "dGVzdC1jZXJ0aWZ5LWluZm8".into(),
            signature: "dGVzdC1zaWduYXR1cmU".into(),
            ak_public: "dGVzdC1hay1wdWJsaWM".into(),
        };
        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: AttestationEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.certify_info, evidence.certify_info);
        assert_eq!(parsed.signature, evidence.signature);
        assert_eq!(parsed.ak_public, evidence.ak_public);
    }
}
