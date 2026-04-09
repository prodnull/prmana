//! SPIRE-backed DPoP signer (ADR-015, ADR-016, ADR-017).
//!
//! `SpireSigner` fetches JWT-SVIDs from a local SPIRE agent via the Workload API
//! (gRPC over Unix domain socket) and signs DPoP proofs with an **ephemeral**
//! P-256 key pair — the SVID private key is never used for DPoP (ADR-016).
//!
//! Architecture:
//! - JWT-SVID = access token (fetched from SPIRE, cached until near-expiry)
//! - DPoP proof = signed with ephemeral key (reuses SoftwareSigner infrastructure)
//! - SPIRE trust domain registered as standard OIDC issuer in PAM config (ADR-015)
//!
//! The SPIRE Workload API uses workload attestation (kernel PID/cgroup) for
//! identity — no client-side credentials are needed. The `workload.spiffe.io: true`
//! metadata header is required on every gRPC call.
//!
//! # Security boundaries
//!
//! - gRPC buffers are normal heap allocations — never mlock'd.
//! - Ephemeral DPoP key material is mlock'd via `ProtectedSigningKey`.
//! - JWT-SVIDs are wrapped in `SecretString` and zeroized on refresh/drop.
//! - Socket path ownership and permissions are the caller's responsibility
//!   (SPIRE agent sets 0770 on the UDS by default).

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use secrecy::{ExposeSecret, SecretString};

use crate::crypto::dpop::{generate_dpop_proof, DPoPError};
use crate::crypto::protected_key::ProtectedSigningKey;
use crate::crypto::signer::{DPoPSigner, SignerError};
use crate::spire::workload_api::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use crate::spire::workload_api::JwtSvidRequest;

/// Default SPIRE agent Workload API socket path.
pub const DEFAULT_SPIRE_SOCKET: &str = "/tmp/spire-agent/public/api.sock";

/// Refresh the SVID when it has less than this fraction of its lifetime remaining.
/// At 0.5, a 60-minute SVID refreshes at 30 minutes.
const SVID_REFRESH_FRACTION: f64 = 0.5;

/// gRPC call timeout.
const GRPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Cached JWT-SVID with expiry tracking.
struct CachedSvid {
    /// The JWT-SVID token (bearer material — SecretString for zeroize-on-drop).
    token: SecretString,
    /// The SPIFFE ID from the SVID.
    spiffe_id: String,
    /// When this SVID was fetched (monotonic reference for refresh calculation).
    fetched_at: SystemTime,
    /// SVID expiry (from `exp` claim). `None` if unparseable.
    expires_at: Option<SystemTime>,
}

impl CachedSvid {
    /// Returns true if the SVID should be refreshed.
    fn needs_refresh(&self) -> bool {
        let now = SystemTime::now();
        match self.expires_at {
            Some(exp) => {
                let total = exp
                    .duration_since(self.fetched_at)
                    .unwrap_or(Duration::ZERO);
                let refresh_at = self.fetched_at
                    + Duration::from_secs_f64(total.as_secs_f64() * SVID_REFRESH_FRACTION);
                now >= refresh_at
            }
            // No parseable expiry — always refresh.
            None => true,
        }
    }
}

/// Configuration for connecting to a SPIRE agent.
#[derive(Debug, Clone)]
pub struct SpireConfig {
    /// Path to the SPIRE agent Workload API Unix domain socket.
    pub socket_path: String,
    /// Audience(s) to request in JWT-SVIDs.
    pub audience: Vec<String>,
    /// Optional: request SVIDs for a specific SPIFFE ID only.
    pub spiffe_id: Option<String>,
}

impl Default for SpireConfig {
    fn default() -> Self {
        Self {
            socket_path: DEFAULT_SPIRE_SOCKET.to_string(),
            audience: Vec::new(),
            spiffe_id: None,
        }
    }
}

/// SPIRE-backed DPoP signer.
///
/// Combines two independent concerns:
/// 1. **Token acquisition**: JWT-SVID from SPIRE Workload API (cached, auto-refreshed)
/// 2. **DPoP signing**: Ephemeral P-256 key pair (mlock'd, zeroed on drop)
///
/// The signer is `Send + Sync` — the SVID cache uses interior mutability via `Mutex`.
pub struct SpireSigner {
    /// Ephemeral DPoP signing key (mlock'd, ZeroizeOnDrop).
    dpop_key: Box<ProtectedSigningKey>,
    /// SPIRE connection configuration.
    config: SpireConfig,
    /// Cached JWT-SVID (refreshed automatically when near expiry).
    cached_svid: Mutex<Option<CachedSvid>>,
    /// Tokio runtime handle for async gRPC calls from sync trait methods.
    rt_handle: tokio::runtime::Handle,
}

impl SpireSigner {
    /// Create a new SpireSigner with a fresh ephemeral DPoP key.
    ///
    /// Uses `Handle::try_current()` — returns `Err` if called outside a tokio
    /// runtime. Use `with_handle()` from synchronous contexts.
    ///
    /// Does NOT fetch the SVID immediately — the first `sign_proof()` or
    /// `fetch_svid()` call will connect to the SPIRE agent.
    pub fn new(config: SpireConfig) -> Result<Self, SignerError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            SignerError::Storage(
                "SpireSigner::new() requires a tokio runtime. \
                 Use SpireSigner::with_handle() from synchronous contexts."
                    .to_string(),
            )
        })?;
        Ok(Self {
            dpop_key: ProtectedSigningKey::generate(),
            config,
            cached_svid: Mutex::new(None),
            rt_handle: handle,
        })
    }

    /// Create a SpireSigner with an explicit runtime handle.
    ///
    /// Use this when constructing outside of a tokio runtime context
    /// (e.g., in tests or from a synchronous CLI path).
    pub fn with_handle(config: SpireConfig, handle: tokio::runtime::Handle) -> Self {
        Self {
            dpop_key: ProtectedSigningKey::generate(),
            config,
            cached_svid: Mutex::new(None),
            rt_handle: handle,
        }
    }

    /// Fetch or return a cached JWT-SVID (sync wrapper).
    ///
    /// Uses `block_in_place` to safely bridge from sync to async when called
    /// within a tokio runtime. For async callers, use `fetch_svid_async()` directly.
    ///
    /// Returns `(spiffe_id, svid_token)`. The token is exposed via `SecretString`
    /// — callers must not log or persist the raw value.
    pub fn fetch_svid(&self) -> Result<(String, String), SignerError> {
        // Check cache first (no async needed).
        if let Some(result) = self.try_cache()? {
            return Ok(result);
        }

        // Cache miss — bridge to async via block_in_place (safe inside tokio runtime).
        let svid =
            tokio::task::block_in_place(|| self.rt_handle.block_on(self.fetch_svid_from_spire()))?;

        let spiffe_id = svid.spiffe_id.clone();
        let token = svid.token.expose_secret().to_string();
        self.update_cache(svid)?;
        Ok((spiffe_id, token))
    }

    /// Fetch or return a cached JWT-SVID (async).
    ///
    /// Preferred API for callers already in an async context (e.g., `run_login`,
    /// `run_refresh`). Avoids the sync-over-async bridge entirely.
    pub async fn fetch_svid_async(&self) -> Result<(String, String), SignerError> {
        // Check cache first.
        if let Some(result) = self.try_cache()? {
            return Ok(result);
        }

        // Cache miss — fetch directly (already async).
        let svid = self.fetch_svid_from_spire().await?;

        let spiffe_id = svid.spiffe_id.clone();
        let token = svid.token.expose_secret().to_string();
        self.update_cache(svid)?;
        Ok((spiffe_id, token))
    }

    /// Check cache for a valid (non-expired) SVID.
    fn try_cache(&self) -> Result<Option<(String, String)>, SignerError> {
        let cache = self
            .cached_svid
            .lock()
            .map_err(|e| SignerError::Storage(format!("SVID cache mutex poisoned: {e}")))?;
        if let Some(ref cached) = *cache {
            if !cached.needs_refresh() {
                return Ok(Some((
                    cached.spiffe_id.clone(),
                    cached.token.expose_secret().to_string(),
                )));
            }
        }
        Ok(None)
    }

    /// Update the SVID cache after a successful fetch.
    fn update_cache(&self, svid: CachedSvid) -> Result<(), SignerError> {
        let mut cache = self
            .cached_svid
            .lock()
            .map_err(|e| SignerError::Storage(format!("SVID cache mutex poisoned: {e}")))?;
        *cache = Some(svid);
        Ok(())
    }

    /// Internal async implementation of SVID fetch via gRPC.
    async fn fetch_svid_from_spire(&self) -> Result<CachedSvid, SignerError> {
        let socket_path = self.config.socket_path.clone();
        let channel = self.connect_uds(&socket_path).await.map_err(|e| {
            SignerError::Storage(format!(
                "Failed to connect to SPIRE agent at {socket_path}: {e}"
            ))
        })?;

        let mut client = SpiffeWorkloadApiClient::new(channel);

        let request = tonic::Request::new(JwtSvidRequest {
            audience: self.config.audience.clone(),
            spiffe_id: self.config.spiffe_id.clone().unwrap_or_default(),
        });

        let response = tokio::time::timeout(GRPC_TIMEOUT, client.fetch_jwt_svid(request))
            .await
            .map_err(|_| {
                SignerError::Storage(format!(
                    "Timeout ({GRPC_TIMEOUT:?}) fetching JWT-SVID from SPIRE agent"
                ))
            })?
            .map_err(|e| SignerError::Storage(format!("SPIRE FetchJWTSVID failed: {e}")))?;

        let svids = response.into_inner().svids;
        let svid = svids.into_iter().next().ok_or_else(|| {
            SignerError::Storage(
                "SPIRE returned empty SVID list — workload may not be registered".to_string(),
            )
        })?;

        if svid.svid.is_empty() {
            return Err(SignerError::Storage(
                "SPIRE returned SVID with empty token".to_string(),
            ));
        }

        let expires_at = parse_jwt_exp(&svid.svid);
        let now = SystemTime::now();

        tracing::info!(
            spiffe_id = %svid.spiffe_id,
            expires_in_secs = expires_at
                .and_then(|e| e.duration_since(now).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "Fetched JWT-SVID from SPIRE agent"
        );

        Ok(CachedSvid {
            token: SecretString::from(svid.svid),
            spiffe_id: svid.spiffe_id,
            fetched_at: now,
            expires_at,
        })
    }

    /// Connect to the SPIRE agent via Unix domain socket.
    async fn connect_uds(
        &self,
        path: &str,
    ) -> Result<tonic::transport::Channel, tonic::transport::Error> {
        let path = path.to_string();

        // tonic requires a valid URI for the Endpoint, but the actual connection
        // goes through the UDS connector. We use a dummy HTTP URI.
        let channel = tonic::transport::Endpoint::try_from("http://[::1]:0")
            .expect("static URI must parse")
            .connect_with_connector(tower::service_fn(move |_| {
                let path = path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(&path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await?;

        Ok(channel)
    }
}

impl DPoPSigner for SpireSigner {
    fn thumbprint(&self) -> String {
        self.dpop_key.thumbprint().to_owned()
    }

    fn sign_proof(
        &self,
        method: &str,
        target: &str,
        nonce: Option<&str>,
    ) -> Result<String, DPoPError> {
        generate_dpop_proof(self.dpop_key.signing_key(), method, target, nonce)
    }

    fn public_key_jwk(&self) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let point = self.dpop_key.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y"));

        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        })
    }
}

/// Extract `exp` claim from a JWT as a Unix timestamp (seconds since epoch).
///
/// Public for use by the login path to set SVID metadata expiry.
pub fn parse_jwt_exp_secs(jwt: &str) -> Option<i64> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims.get("exp")?.as_i64()
}

/// Extract `exp` claim from a JWT without full validation.
///
/// This is intentionally minimal — no signature check, just base64-decode the
/// payload and read `exp`. The PAM module does the real validation.
fn parse_jwt_exp(jwt: &str) -> Option<SystemTime> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let exp = claims.get("exp")?.as_u64()?;
    Some(UNIX_EPOCH + Duration::from_secs(exp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    #[test]
    fn test_parse_jwt_exp_valid() {
        let header = URL_SAFE_NO_PAD.encode(b"{}");
        let payload = URL_SAFE_NO_PAD.encode(b"{\"exp\":1700000000}");
        let jwt = format!("{header}.{payload}.sig");

        let exp = parse_jwt_exp(&jwt).unwrap();
        let expected = UNIX_EPOCH + Duration::from_secs(1700000000);
        assert_eq!(exp, expected);
    }

    #[test]
    fn test_parse_jwt_exp_missing() {
        let header = URL_SAFE_NO_PAD.encode(b"{}");
        let payload = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"test\"}");
        let jwt = format!("{header}.{payload}.sig");

        assert!(parse_jwt_exp(&jwt).is_none());
    }

    #[test]
    fn test_parse_jwt_exp_malformed() {
        assert!(parse_jwt_exp("not.a.jwt").is_none());
        assert!(parse_jwt_exp("only-one-part").is_none());
        assert!(parse_jwt_exp("").is_none());
    }

    #[test]
    fn test_cached_svid_needs_refresh_when_expired() {
        let svid = CachedSvid {
            token: SecretString::from("token".to_string()),
            spiffe_id: "spiffe://td/sa/test".to_string(),
            fetched_at: SystemTime::now() - Duration::from_secs(3600),
            expires_at: Some(SystemTime::now() - Duration::from_secs(1)),
        };
        assert!(svid.needs_refresh());
    }

    #[test]
    fn test_cached_svid_no_refresh_when_fresh() {
        let svid = CachedSvid {
            token: SecretString::from("token".to_string()),
            spiffe_id: "spiffe://td/sa/test".to_string(),
            fetched_at: SystemTime::now(),
            expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
        };
        assert!(!svid.needs_refresh());
    }

    #[test]
    fn test_cached_svid_refresh_when_no_expiry() {
        let svid = CachedSvid {
            token: SecretString::from("token".to_string()),
            spiffe_id: "spiffe://td/sa/test".to_string(),
            fetched_at: SystemTime::now(),
            expires_at: None,
        };
        assert!(svid.needs_refresh());
    }

    #[test]
    fn test_spire_config_default() {
        let cfg = SpireConfig::default();
        assert_eq!(cfg.socket_path, DEFAULT_SPIRE_SOCKET);
        assert!(cfg.audience.is_empty());
        assert!(cfg.spiffe_id.is_none());
    }

    #[test]
    fn test_spire_signer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SpireSigner>();
    }

    #[test]
    fn test_spire_signer_dpop_key_independent() {
        // Verify that two SpireSigners have different ephemeral keys
        let rt = tokio::runtime::Runtime::new().unwrap();
        let cfg = SpireConfig::default();
        let s1 = SpireSigner::with_handle(cfg.clone(), rt.handle().clone());
        let s2 = SpireSigner::with_handle(cfg, rt.handle().clone());
        assert_ne!(s1.thumbprint(), s2.thumbprint());
    }

    #[test]
    fn test_spire_signer_signs_proof() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let signer = SpireSigner::with_handle(SpireConfig::default(), rt.handle().clone());

        let proof = signer
            .sign_proof("SSH", "server.example.com", None)
            .unwrap();
        assert_eq!(proof.split('.').count(), 3, "DPoP proof must be valid JWT");
    }

    #[test]
    fn test_spire_signer_jwk_format() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let signer = SpireSigner::with_handle(SpireConfig::default(), rt.handle().clone());
        let jwk = signer.public_key_jwk();

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["x"].is_string());
        assert!(jwk["y"].is_string());
    }
}
