//! Cross-crate PQC integration tests: agent signs hybrid proofs, PAM validates them.
//!
//! These tests verify the end-to-end roundtrip of composite ML-DSA-65+ES256 DPoP
//! proofs between the agent-side `HybridPqcSigner` and the PAM-side
//! `validate_dpop_proof()` with `#[cfg(feature = "pqc")]`.
//!
//! Run with: `cargo test -p prmana-agent --features pqc --test pqc_integration`

#![cfg(feature = "pqc")]

use prmana_agent::crypto::signer::DPoPSigner;
use prmana_agent::crypto::HybridPqcSigner;

use pam_prmana::oidc::dpop::{validate_dpop_proof, verify_dpop_binding, DPoPConfig};

/// Agent signs a hybrid proof → PAM validates it (full roundtrip).
#[test]
fn pqc_hybrid_sign_and_validate_roundtrip() {
    let signer = HybridPqcSigner::generate();
    let proof = signer
        .sign_proof("SSH", "server.example.com", None)
        .expect("sign_proof should succeed");

    let config = DPoPConfig {
        max_proof_age: 60,
        clock_skew_future_secs: 5,
        require_nonce: false,
        expected_nonce: None,
        expected_method: "SSH".to_string(),
        expected_target: "server.example.com".to_string(),
    };

    let result = validate_dpop_proof(&proof, &config).expect("validation should succeed");

    // Thumbprint from validation must match the signer's thumbprint.
    assert_eq!(
        result.thumbprint,
        signer.thumbprint(),
        "composite thumbprint must match between signer and verifier"
    );

    // DPoP binding check should also pass.
    verify_dpop_binding(&result.thumbprint, &signer.thumbprint())
        .expect("DPoP binding verification should succeed");
}

/// Hybrid proof with nonce roundtrip.
#[test]
fn pqc_hybrid_roundtrip_with_nonce() {
    let signer = HybridPqcSigner::generate();
    let proof = signer
        .sign_proof("SSH", "nonce-test.example.com", Some("server-nonce-42"))
        .expect("sign_proof with nonce should succeed");

    let config = DPoPConfig {
        max_proof_age: 60,
        clock_skew_future_secs: 5,
        require_nonce: true,
        expected_nonce: Some("server-nonce-42".to_string()),
        expected_method: "SSH".to_string(),
        expected_target: "nonce-test.example.com".to_string(),
    };

    let result =
        validate_dpop_proof(&proof, &config).expect("validation with nonce should succeed");
    assert_eq!(result.nonce.as_deref(), Some("server-nonce-42"));
}

/// Non-PQC verifier rejects a hybrid proof with UnsupportedAlgorithm when
/// the `pqc` feature is not compiled into the PAM crate.
///
/// Since this test file is `#[cfg(feature = "pqc")]`, we can't easily test the
/// non-PQC rejection path here. Instead, we verify that the composite signature
/// format is correct by checking the signature structure.
#[test]
fn pqc_composite_signature_structure() {
    let signer = HybridPqcSigner::generate();
    let proof = signer
        .sign_proof("SSH", "format-test.example.com", None)
        .expect("sign_proof should succeed");

    // JWT has 3 parts
    let parts: Vec<&str> = proof.split('.').collect();
    assert_eq!(parts.len(), 3, "proof must be a 3-part JWT");

    // Decode header and verify algorithm
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "ML-DSA-65-ES256");
    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(header["jwk"]["kty"], "COMPOSITE");

    // Decode signature and verify composite format:
    // 2-byte BE length prefix + ML-DSA-65 sig (3309) + ES256 sig (64)
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    assert_eq!(sig_bytes.len(), 2 + 3309 + 64);
    let pq_len = u16::from_be_bytes([sig_bytes[0], sig_bytes[1]]) as usize;
    assert_eq!(pq_len, 3309);
}

/// Different signers produce different thumbprints — DPoP binding rejects mismatched keys.
#[test]
fn pqc_binding_rejects_wrong_key() {
    let signer1 = HybridPqcSigner::generate();
    let signer2 = HybridPqcSigner::generate();

    let proof = signer1
        .sign_proof("SSH", "binding-test.example.com", None)
        .unwrap();

    let config = DPoPConfig {
        max_proof_age: 60,
        clock_skew_future_secs: 5,
        require_nonce: false,
        expected_nonce: None,
        expected_method: "SSH".to_string(),
        expected_target: "binding-test.example.com".to_string(),
    };

    let result = validate_dpop_proof(&proof, &config).unwrap();

    // Binding against signer2's thumbprint should fail.
    assert!(
        verify_dpop_binding(&result.thumbprint, &signer2.thumbprint()).is_err(),
        "binding should reject mismatched PQC key"
    );
}

/// Key export/import roundtrip preserves signing capability and thumbprint.
#[test]
fn pqc_key_persistence_roundtrip() {
    let signer1 = HybridPqcSigner::generate();
    let ec_bytes = signer1.export_ec_key();
    let pq_seed = signer1.export_pq_seed();

    let signer2 = HybridPqcSigner::from_key_bytes(&ec_bytes, &pq_seed)
        .expect("from_key_bytes should succeed");

    // Same thumbprint
    assert_eq!(signer1.thumbprint(), signer2.thumbprint());

    // Proof from restored signer validates
    let proof = signer2
        .sign_proof("SSH", "persist-test.example.com", None)
        .unwrap();

    let config = DPoPConfig {
        max_proof_age: 60,
        clock_skew_future_secs: 5,
        require_nonce: false,
        expected_nonce: None,
        expected_method: "SSH".to_string(),
        expected_target: "persist-test.example.com".to_string(),
    };

    let result =
        validate_dpop_proof(&proof, &config).expect("restored signer proof should validate");
    assert_eq!(result.thumbprint, signer1.thumbprint());
}
