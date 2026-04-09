//! Integration tests for SpireSigner and SPIRE Workload API client.
//!
//! Tests marked `#[ignore]` require a running SPIRE agent (real or Docker).
//! Non-ignored tests use mock infrastructure and run in CI.

#![cfg(feature = "spire")]

use std::sync::Arc;
use unix_oidc_agent::crypto::{DPoPSigner, SpireConfig, SpireSigner};

/// SpireSigner implements DPoPSigner and can be used behind Arc<dyn DPoPSigner>.
#[test]
fn test_spire_signer_as_trait_object() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let signer: Arc<dyn DPoPSigner> = Arc::new(SpireSigner::with_handle(
        SpireConfig::default(),
        rt.handle().clone(),
    ));

    // Thumbprint should be valid SHA-256 base64url (43 chars).
    assert_eq!(signer.thumbprint().len(), 43);

    // JWK should have correct EC P-256 fields.
    let jwk = signer.public_key_jwk();
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["crv"], "P-256");
}

/// Each SpireSigner generates a unique ephemeral DPoP key — never reuses keys.
#[test]
fn test_spire_signer_unique_keys_per_instance() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let signers: Vec<SpireSigner> = (0..5)
        .map(|_| SpireSigner::with_handle(SpireConfig::default(), rt.handle().clone()))
        .collect();

    let thumbprints: Vec<String> = signers.iter().map(|s| s.thumbprint()).collect();
    // All thumbprints must be unique.
    let unique: std::collections::HashSet<&str> = thumbprints.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        unique.len(),
        thumbprints.len(),
        "Each SpireSigner must have a unique ephemeral key"
    );
}

/// DPoP proofs are valid JWTs regardless of SVID state.
#[test]
fn test_spire_signer_proof_valid_jwt() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let signer = SpireSigner::with_handle(SpireConfig::default(), rt.handle().clone());

    let proof = signer
        .sign_proof("SSH", "server.example.com", None)
        .unwrap();
    let parts: Vec<&str> = proof.split('.').collect();
    assert_eq!(parts.len(), 3, "DPoP proof must be a 3-part JWT");

    // Header should be parseable JSON with alg=ES256.
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "dpop+jwt");
}

/// DPoP proof with nonce includes the nonce in the payload.
#[test]
fn test_spire_signer_proof_with_nonce() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let signer = SpireSigner::with_handle(SpireConfig::default(), rt.handle().clone());

    let proof = signer
        .sign_proof("SSH", "server.example.com", Some("test-nonce-123"))
        .unwrap();

    let parts: Vec<&str> = proof.split('.').collect();
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(payload["nonce"], "test-nonce-123");
}

/// fetch_svid fails gracefully when SPIRE agent socket doesn't exist.
///
/// `fetch_svid()` uses `block_on` internally, so we run it on a dedicated
/// thread to avoid nesting tokio runtimes.
#[test]
fn test_spire_signer_fetch_svid_no_socket() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = SpireConfig {
        socket_path: "/tmp/nonexistent-spire-socket-test.sock".to_string(),
        audience: vec!["test-audience".to_string()],
        spiffe_id: None,
    };
    let handle = rt.handle().clone();

    let result = std::thread::spawn(move || {
        let signer = SpireSigner::with_handle(config, handle);
        signer.fetch_svid()
    })
    .join()
    .expect("thread should not panic");

    assert!(
        result.is_err(),
        "fetch_svid must fail when socket is absent"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Failed to connect") || err.contains("nonexistent"),
        "Error should mention connection failure, got: {err}"
    );
}

/// SpireConfig from signer.yaml deserialization round-trip.
#[test]
fn test_spire_yaml_config_deserialization() {
    use unix_oidc_agent::hardware::SpireYamlConfig;

    let yaml = r#"
socket_path: /run/spire/agent.sock
audience:
  - spiffe://example.com/server
  - ssh://prod-cluster
spiffe_id: spiffe://example.com/ns/prod/sa/ml-agent
"#;
    let cfg: SpireYamlConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cfg.socket_path.as_deref(), Some("/run/spire/agent.sock"));
    assert_eq!(cfg.audience.as_ref().unwrap().len(), 2);
    assert_eq!(
        cfg.spiffe_id.as_deref(),
        Some("spiffe://example.com/ns/prod/sa/ml-agent")
    );
}

/// Full signer.yaml with spire section deserializes correctly.
#[test]
fn test_signer_config_with_spire_section() {
    use unix_oidc_agent::hardware::SignerConfig;

    let yaml = r#"
yubikey:
  pin_cache_timeout: 3600
spire:
  socket_path: /run/spire/agent.sock
  audience:
    - spiffe://td/server
"#;
    let cfg: SignerConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(cfg.yubikey.is_some());
    assert!(cfg.tpm.is_none());
    let spire = cfg.spire.unwrap();
    assert_eq!(spire.socket_path.as_deref(), Some("/run/spire/agent.sock"));
    assert_eq!(spire.audience.as_ref().unwrap(), &["spiffe://td/server"]);
}

// ── Integration tests (require real SPIRE agent) ────────────────────────────

/// Fetch a real JWT-SVID from a running SPIRE agent.
///
/// Run with: `cargo test -p unix-oidc-agent --features spire -- --ignored spire`
/// Requires: SPIRE agent running with workload registered for this process.
/// Set `UNIX_OIDC_SPIRE_SOCKET` to override the default socket path.
#[tokio::test]
#[ignore = "Requires running SPIRE agent"]
async fn test_spire_live_fetch_svid() {
    let socket = std::env::var("UNIX_OIDC_SPIRE_SOCKET").unwrap_or_else(|_| {
        unix_oidc_agent::crypto::spire_signer::DEFAULT_SPIRE_SOCKET.to_string()
    });

    let config = SpireConfig {
        socket_path: socket,
        audience: vec!["unix-oidc-test".to_string()],
        spiffe_id: None,
    };
    let signer = SpireSigner::new(config).expect("SpireSigner::new in tokio runtime");

    let (spiffe_id, token) = signer
        .fetch_svid()
        .expect("Should fetch SVID from live SPIRE agent");
    assert!(
        spiffe_id.starts_with("spiffe://"),
        "SPIFFE ID must start with spiffe://, got: {spiffe_id}"
    );
    assert_eq!(token.split('.').count(), 3, "JWT-SVID must be a 3-part JWT");

    // DPoP proof should work independently of the SVID.
    let proof = signer.sign_proof("SSH", "server.test", None).unwrap();
    assert_eq!(proof.split('.').count(), 3);
}

/// Verify SVID caching — second fetch should return cached value.
#[tokio::test]
#[ignore = "Requires running SPIRE agent"]
async fn test_spire_live_svid_caching() {
    let socket = std::env::var("UNIX_OIDC_SPIRE_SOCKET").unwrap_or_else(|_| {
        unix_oidc_agent::crypto::spire_signer::DEFAULT_SPIRE_SOCKET.to_string()
    });

    let config = SpireConfig {
        socket_path: socket,
        audience: vec!["unix-oidc-cache-test".to_string()],
        spiffe_id: None,
    };
    let signer = SpireSigner::new(config).expect("SpireSigner::new in tokio runtime");

    let (id1, tok1) = signer.fetch_svid().unwrap();
    let (id2, tok2) = signer.fetch_svid().unwrap();

    assert_eq!(id1, id2, "Cached SVID should return same SPIFFE ID");
    assert_eq!(tok1, tok2, "Cached SVID should return same token");
}

use base64::Engine;
