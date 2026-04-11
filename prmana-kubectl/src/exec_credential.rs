//! Kubernetes ExecCredential JSON emitter.
//!
//! Implements the `client.authentication.k8s.io/v1` ExecCredential format
//! consumed by kubectl to supply a bearer token for cluster authentication.
//!
//! References:
//! - https://kubernetes.io/docs/reference/config-api/client-authentication.v1/
//! - CONTEXT.md decision G: `expirationTimestamp` = JWT exp - 30s

use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;

/// ExecCredential v1 response printed to stdout by exec credential plugins.
///
/// kubectl reads this JSON from the plugin's stdout after each invocation.
/// The `status.token` is used as the `Authorization: Bearer <token>` header
/// on Kubernetes API requests.
///
/// CRITICAL: `clientCertificateData` and `clientKeyData` MUST NOT be present
/// in this struct. This is a bearer-token-only response (no mTLS until DT-E).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecCredential {
    pub api_version: String,
    pub kind: String,
    pub status: ExecStatus,
}

/// The `status` block of ExecCredential.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecStatus {
    /// RFC 3339 timestamp when the token expires.
    ///
    /// Set to JWT `exp` - 30 seconds (CONTEXT.md decision G).
    /// This forces kubectl to re-invoke the plugin 30s before expiry,
    /// preventing mid-request 401s on long-running operations.
    pub expiration_timestamp: String,

    /// Bearer token with audience `<cluster_id>.kube.prmana`.
    pub token: String,
}

/// Build an ExecCredential from a bearer token and its JWT expiry timestamp.
///
/// # Arguments
/// - `token` — the bearer token string
/// - `exp_unix` — the JWT `exp` claim (Unix timestamp, seconds)
///
/// # Returns
/// ExecCredential with `expirationTimestamp` = exp_unix - 30s (RFC 3339 UTC).
pub fn build(token: String, exp_unix: i64) -> ExecCredential {
    // Subtract 30 seconds per CONTEXT.md decision G:
    // "forces kubectl to re-invoke the plugin before the token expires,
    //  preventing mid-request 401s."
    let adjusted = exp_unix.saturating_sub(30);
    let ts: DateTime<Utc> = Utc.timestamp_opt(adjusted, 0).single().unwrap_or_else(|| {
        Utc.timestamp_opt(exp_unix, 0)
            .single()
            .unwrap_or_else(Utc::now)
    });

    ExecCredential {
        api_version: "client.authentication.k8s.io/v1".to_string(),
        kind: "ExecCredential".to_string(),
        status: ExecStatus {
            expiration_timestamp: ts.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            token,
        },
    }
}

/// Serialize and print ExecCredential JSON to stdout.
///
/// A trailing newline is emitted after the JSON object. kubectl accepts
/// both newline-terminated and non-terminated JSON; we follow convention.
pub fn emit_stdout(cred: &ExecCredential) -> Result<()> {
    let json = serde_json::to_string(cred)?;
    println!("{}", json);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test E1: emit produces correct ExecCredential JSON structure.
    #[test]
    fn test_e1_exec_credential_json_structure() {
        let cred = build("eyJ.abc".to_string(), 1_712_000_000);
        let json = serde_json::to_string(&cred).unwrap();

        assert!(
            json.contains(r#""apiVersion":"client.authentication.k8s.io/v1""#),
            "must have correct apiVersion: {json}"
        );
        assert!(
            json.contains(r#""kind":"ExecCredential""#),
            "must have kind=ExecCredential: {json}"
        );
        assert!(
            json.contains(r#""token":"eyJ.abc""#),
            "must include token: {json}"
        );
        assert!(
            json.contains("expirationTimestamp"),
            "must include expirationTimestamp: {json}"
        );
    }

    /// Test E2: expirationTimestamp = exp_unix - 30 seconds.
    #[test]
    fn test_e2_expiration_timestamp_is_exp_minus_30s() {
        // exp_unix = 1712000000 → adjusted = 1711999970
        let cred = build("tok".to_string(), 1_712_000_000);
        // 1712000000 - 30 = 1711999970 → 2024-04-01T19:32:50Z (UTC)
        assert_eq!(
            cred.status.expiration_timestamp, "2024-04-01T19:32:50Z",
            "expirationTimestamp must be exp_unix - 30s (UTC)"
        );
    }

    /// Test E3: output parses as valid JSON.
    #[test]
    fn test_e3_json_is_valid() {
        let cred = build("tok".to_string(), 1_712_000_000);
        let json = serde_json::to_string(&cred).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["apiVersion"], "client.authentication.k8s.io/v1");
        assert_eq!(parsed["kind"], "ExecCredential");
        assert_eq!(parsed["status"]["token"], "tok");
    }

    /// Test E4: status block has no clientCertificateData or clientKeyData.
    /// (bearer-only until DT-E mTLS upgrade)
    #[test]
    fn test_e4_no_cert_fields() {
        let cred = build("tok".to_string(), 1_712_000_000);
        let json = serde_json::to_string(&cred).unwrap();
        assert!(
            !json.contains("clientCertificateData"),
            "must not contain clientCertificateData: {json}"
        );
        assert!(
            !json.contains("clientKeyData"),
            "must not contain clientKeyData: {json}"
        );
    }

    /// expirationTimestamp uses UTC timezone (Z suffix).
    #[test]
    fn test_expiration_timestamp_utc() {
        let cred = build("tok".to_string(), 1_712_000_000);
        assert!(
            cred.status.expiration_timestamp.ends_with('Z'),
            "expirationTimestamp must be UTC (Z suffix): {}",
            cred.status.expiration_timestamp
        );
    }

    /// Saturation: exp_unix = i64::MIN does not panic.
    #[test]
    fn test_saturation_no_panic_on_min_unix() {
        let cred = build("tok".to_string(), i64::MIN);
        assert!(!cred.status.expiration_timestamp.is_empty());
    }
}
