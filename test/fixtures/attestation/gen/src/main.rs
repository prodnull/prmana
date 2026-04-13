//! Generate synthetic TPM attestation test fixtures with real P-256 cryptography.
//!
//! Produces 4 JSON fixture files:
//! 1. valid_attestation.json — cryptographically valid, all checks should pass
//! 2. tampered_certify_info.json — flipped byte, AK signature fails
//! 3. wrong_ak_signature.json — signed by different key, signature mismatch
//! 4. name_mismatch.json — valid AK sig but certified Name ≠ DPoP JWK

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::io::Write;

/// Build a minimal TPMT_PUBLIC for a P-256 ECDSA key.
/// TCG TPM2 Part 2, Table 199.
fn build_tpmt_public(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut pub_area = Vec::new();
    pub_area.extend_from_slice(&0x0023u16.to_be_bytes()); // type: ECC
    pub_area.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg: SHA-256
    pub_area.extend_from_slice(&0x000600F2u32.to_be_bytes()); // objectAttributes
    pub_area.extend_from_slice(&0x0000u16.to_be_bytes()); // authPolicy: empty
    pub_area.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric: NULL
    pub_area.extend_from_slice(&0x0018u16.to_be_bytes()); // scheme: ECDSA
    pub_area.extend_from_slice(&0x000Bu16.to_be_bytes()); // scheme hash: SHA-256
    pub_area.extend_from_slice(&0x0003u16.to_be_bytes()); // curveID: P-256
    pub_area.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf: NULL
    pub_area.extend_from_slice(&0x0020u16.to_be_bytes()); // x length: 32
    pub_area.extend_from_slice(x);
    pub_area.extend_from_slice(&0x0020u16.to_be_bytes()); // y length: 32
    pub_area.extend_from_slice(y);
    pub_area
}

/// Compute TPM Name = 0x000B || SHA256(TPMT_PUBLIC)
fn compute_tpm_name(public_area: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(public_area);
    let mut name = Vec::with_capacity(34);
    name.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA-256 algorithm ID
    name.extend_from_slice(&hash);
    name
}

/// Build TPMS_ATTEST structure (TCG Part 2, Table 131) for ATTEST_CERTIFY.
fn build_tpms_attest(ak_name: &[u8], certified_key_name: &[u8]) -> Vec<u8> {
    let mut attest = Vec::new();

    // magic: TPM_GENERATED_VALUE
    attest.extend_from_slice(&0xFF544347u32.to_be_bytes());
    // type: TPM_ST_ATTEST_CERTIFY
    attest.extend_from_slice(&0x8017u16.to_be_bytes());
    // qualifiedSigner: TPM2B_NAME (AK identity)
    attest.extend_from_slice(&(ak_name.len() as u16).to_be_bytes());
    attest.extend_from_slice(ak_name);
    // extraData: TPM2B_DATA (empty — no server nonce in Phase 37)
    attest.extend_from_slice(&0x0000u16.to_be_bytes());
    // clockInfo: TPMS_CLOCK_INFO (17 bytes)
    attest.extend_from_slice(&1000u64.to_be_bytes()); // clock
    attest.extend_from_slice(&0u32.to_be_bytes()); // resetCount
    attest.extend_from_slice(&0u32.to_be_bytes()); // restartCount
    attest.push(1u8); // safe
    // firmwareVersion
    attest.extend_from_slice(&0x0000000000070002u64.to_be_bytes());
    // attested: TPMS_CERTIFY_INFO
    //   name: TPM2B_NAME (the key being certified)
    attest.extend_from_slice(&(certified_key_name.len() as u16).to_be_bytes());
    attest.extend_from_slice(certified_key_name);
    //   qualifiedName: TPM2B_NAME (same as name for primary keys)
    attest.extend_from_slice(&(certified_key_name.len() as u16).to_be_bytes());
    attest.extend_from_slice(certified_key_name);

    attest
}

fn main() {
    let out_dir = std::path::Path::new("test/fixtures/attestation");
    std::fs::create_dir_all(out_dir).unwrap();

    // === DPoP signing key (the certified key) ===
    let dpop_sk = SigningKey::random(&mut OsRng);
    let dpop_vk = dpop_sk.verifying_key();
    let dpop_pt = dpop_vk.to_encoded_point(false);
    let dpop_x = dpop_pt.x().unwrap();
    let dpop_y = dpop_pt.y().unwrap();

    let x_b64 = URL_SAFE_NO_PAD.encode(dpop_x);
    let y_b64 = URL_SAFE_NO_PAD.encode(dpop_y);

    // JWK thumbprint (RFC 7638)
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, x_b64, y_b64);
    let thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));

    let dpop_public = build_tpmt_public(dpop_x, dpop_y);
    let dpop_name = compute_tpm_name(&dpop_public);

    // === Attestation Key (AK) ===
    let ak_sk = SigningKey::random(&mut OsRng);
    let ak_vk = ak_sk.verifying_key();
    let ak_pt = ak_vk.to_encoded_point(false);
    let ak_x = ak_pt.x().unwrap();
    let ak_y = ak_pt.y().unwrap();

    let ak_public = build_tpmt_public(ak_x, ak_y);
    let ak_name = compute_tpm_name(&ak_public);

    // === Build TPMS_ATTEST with DPoP key name ===
    let attest = build_tpms_attest(&ak_name, &dpop_name);

    // === Sign with AK ===
    let sig: Signature = ak_sk.sign(&attest);
    let sig_bytes = sig.to_bytes();

    // === Fixture 1: Valid attestation ===
    let valid = serde_json::json!({
        "_comment": "Cryptographically valid synthetic TPM attestation fixture",
        "attestation_evidence": {
            "certify_info": URL_SAFE_NO_PAD.encode(&attest),
            "signature": URL_SAFE_NO_PAD.encode(&sig_bytes),
            "ak_public": URL_SAFE_NO_PAD.encode(&ak_public)
        },
        "dpop_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64
        },
        "jwk_thumbprint": thumbprint,
        "tpm_name_hex": hex::encode(&dpop_name),
        "dpop_key_public_area_hex": hex::encode(&dpop_public),
        "ak_public_hex": hex::encode(&ak_public),
        "certify_info_hex": hex::encode(&attest),
        "signature_hex": hex::encode(sig_bytes.as_slice()),
        "parsing_guide": {
            "tpms_attest_layout": [
                {"offset": 0, "size": 4, "field": "magic", "value": "FF544347"},
                {"offset": 4, "size": 2, "field": "type", "value": "8017 (ATTEST_CERTIFY)"},
                {"offset": 6, "size": "2+34", "field": "qualifiedSigner (TPM2B_NAME of AK)"},
                {"offset": 42, "size": 2, "field": "extraData length (0000 = empty)"},
                {"offset": 44, "size": 17, "field": "clockInfo (clock:8 + resetCount:4 + restartCount:4 + safe:1)"},
                {"offset": 61, "size": 8, "field": "firmwareVersion"},
                {"offset": 69, "size": "2+34", "field": "attested.name (TPM2B_NAME of DPoP key) — MATCH THIS"},
                {"offset": 105, "size": "2+34", "field": "attested.qualifiedName"}
            ],
            "tpm_name_format": "0x000B (SHA-256 alg ID, 2 bytes) || SHA256(TPMT_PUBLIC) (32 bytes) = 34 bytes total",
            "tpmt_public_layout": "type(2) nameAlg(2) attrs(4) authPolicy(2+0) sym(2) scheme(2) schemeHash(2) curve(2) kdf(2) x(2+32) y(2+32) = 86 bytes",
            "verification_algorithm": [
                "1. base64url-decode certify_info, signature, ak_public",
                "2. Verify certify_info[0..4] == FF544347 (TPM_GENERATED_VALUE)",
                "3. Verify certify_info[4..6] == 8017 (ATTEST_CERTIFY)",
                "4. Parse past qualifiedSigner(2+N), extraData(2+N), clockInfo(17), firmwareVersion(8)",
                "5. Read attested.name: 2-byte length, then hash_alg(2) + hash(32)",
                "6. Extract AK EC point from ak_public: skip 18 bytes of header, read x(2+32), y(2+32)",
                "7. Build VerifyingKey from AK (x, y), verify ECDSA(ak, certify_info) == signature",
                "8. Build expected TPMT_PUBLIC from DPoP JWK (same 86-byte structure)",
                "9. Compute expected Name = 0x000B || SHA256(expected_TPMT_PUBLIC)",
                "10. Compare attested.name == expected Name"
            ]
        }
    });

    // === Fixture 2: Tampered certify_info ===
    let mut tampered = attest.clone();
    tampered[50] ^= 0xFF;
    let tampered_fixture = serde_json::json!({
        "_comment": "Flipped byte in certify_info — AK signature MUST fail",
        "attestation_evidence": {
            "certify_info": URL_SAFE_NO_PAD.encode(&tampered),
            "signature": URL_SAFE_NO_PAD.encode(&sig_bytes),
            "ak_public": URL_SAFE_NO_PAD.encode(&ak_public)
        }
    });

    // === Fixture 3: Wrong AK signature ===
    let wrong_sk = SigningKey::random(&mut OsRng);
    let wrong_sig: Signature = wrong_sk.sign(&attest);
    let wrong_fixture = serde_json::json!({
        "_comment": "Valid certify_info but signed by WRONG AK — signature mismatch",
        "attestation_evidence": {
            "certify_info": URL_SAFE_NO_PAD.encode(&attest),
            "signature": URL_SAFE_NO_PAD.encode(wrong_sig.to_bytes()),
            "ak_public": URL_SAFE_NO_PAD.encode(&ak_public)
        }
    });

    // === Fixture 4: Name mismatch ===
    let other_sk = SigningKey::random(&mut OsRng);
    let other_vk = other_sk.verifying_key();
    let other_pt = other_vk.to_encoded_point(false);
    let other_pub = build_tpmt_public(other_pt.x().unwrap(), other_pt.y().unwrap());
    let other_name = compute_tpm_name(&other_pub);

    let mismatch_attest = build_tpms_attest(&ak_name, &other_name);
    let mismatch_sig: Signature = ak_sk.sign(&mismatch_attest);

    let mismatch_fixture = serde_json::json!({
        "_comment": "Valid AK signature, but certified Name does NOT match DPoP JWK thumbprint",
        "attestation_evidence": {
            "certify_info": URL_SAFE_NO_PAD.encode(&mismatch_attest),
            "signature": URL_SAFE_NO_PAD.encode(mismatch_sig.to_bytes()),
            "ak_public": URL_SAFE_NO_PAD.encode(&ak_public)
        },
        "dpop_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64
        },
        "jwk_thumbprint": thumbprint,
        "expected_failure": "attested.name does not match SHA256(DPoP key TPMT_PUBLIC)"
    });

    // Write fixtures
    for (name, val) in [
        ("valid_attestation.json", &valid),
        ("tampered_certify_info.json", &tampered_fixture),
        ("wrong_ak_signature.json", &wrong_fixture),
        ("name_mismatch.json", &mismatch_fixture),
    ] {
        let path = out_dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(serde_json::to_string_pretty(val).unwrap().as_bytes())
            .unwrap();
        eprintln!("Wrote {}", path.display());
    }

    eprintln!(
        "\nTPMS_ATTEST: {} bytes, AK public: {} bytes, TPM Name: {} bytes",
        attest.len(),
        ak_public.len(),
        dpop_name.len()
    );
}
