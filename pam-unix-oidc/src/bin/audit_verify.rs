//! unix-oidc-audit-verify — HMAC chain verification for audit log files.
//!
//! Reads a log file line-by-line, parses each line as JSON, and verifies the
//! HMAC chain by recomputing HMAC-SHA256 over each event's verifiable payload
//! (all fields EXCEPT `prev_hash` and `chain_hash`) and comparing to the
//! recorded `chain_hash`.
//!
//! Exit codes:
//!   0 — chain valid (or no chain fields present with appropriate message)
//!   1 — chain broken (one or more breaks detected)
//!   2 — usage / argument error
//!
//! # OCSF compatibility
//!
//! The verifiable payload includes ALL event fields EXCEPT `prev_hash` and
//! `chain_hash`. This means OCSF fields (category_uid, class_uid, severity_id,
//! activity_id, type_uid, metadata) — added by Plan 27-04 enrichment — are
//! part of the verified payload. Modifying an OCSF field will break the chain.
//!
//! # Key format
//!
//! The key must be supplied as a UTF-8 string via `--key` or read from a file
//! via `--key-file`. It is treated as raw bytes — the same encoding used when
//! the key was originally set in `UNIX_OIDC_AUDIT_HMAC_KEY`.
//!
//! # Security
//!
//! The key is NEVER logged or included in error messages. If the key is wrong
//! every single event will appear as a chain break — the verifier cannot
//! distinguish a wrong key from a tampered log.

use clap::Parser;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process;

type HmacSha256 = Hmac<Sha256>;

// ── CLI ───────────────────────────────────────────────────────────────────────

/// Verify the HMAC tamper-evidence chain of a unix-oidc audit log.
#[derive(Parser, Debug)]
#[command(name = "unix-oidc-audit-verify")]
#[command(about = "Verify the HMAC chain of a unix-oidc audit log file")]
#[command(long_about = None)]
struct Cli {
    /// HMAC key as a UTF-8 string (same value as UNIX_OIDC_AUDIT_HMAC_KEY)
    #[arg(long, conflicts_with = "key_file")]
    key: Option<String>,

    /// Path to a file containing the HMAC key (newline is stripped)
    #[arg(long, conflicts_with = "key")]
    key_file: Option<PathBuf>,

    /// Audit log file to verify
    #[arg(long, short)]
    file: PathBuf,
}

// ── Verification logic ────────────────────────────────────────────────────────

/// Result of verifying one event line.
#[derive(Debug)]
enum LineResult {
    /// Event verified successfully; carries the chain_hash for the next link.
    Ok { chain_hash: String },
    /// Event had no chain fields — tamper-evidence was not enabled when logged.
    NoChainFields,
    /// HMAC mismatch: computed chain_hash does not match the recorded one.
    ChainBreak {
        event_type: Option<String>,
        recorded_chain_hash: String,
        computed_chain_hash: String,
        expected_prev_hash: String,
        actual_prev_hash: String,
    },
    /// Line could not be parsed as JSON.
    // The String is used in display output; allow(dead_code) is required because
    // clippy does not trace reads of tuple struct fields through println!.
    #[allow(dead_code)]
    ParseError(String),
}

/// Verify a single log line against the expected `prev_hash`.
fn verify_line(line: &str, key: &[u8], expected_prev: &str) -> LineResult {
    // Parse the line as a JSON object.
    let obj: serde_json::Map<String, serde_json::Value> = match serde_json::from_str(line) {
        Ok(serde_json::Value::Object(m)) => m,
        Ok(_) => return LineResult::ParseError("line is not a JSON object".to_string()),
        Err(e) => return LineResult::ParseError(e.to_string()),
    };

    // Extract chain fields.
    let prev_hash = match obj.get("prev_hash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return LineResult::NoChainFields,
    };
    let recorded_chain_hash = match obj.get("chain_hash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return LineResult::NoChainFields,
    };

    // Extract event type for diagnostic messages.
    let event_type = obj.get("event").and_then(|v| v.as_str()).map(String::from);

    // Reconstruct the verifiable payload: all fields EXCEPT prev_hash and chain_hash.
    // This must exactly reproduce what `compute_chain` serialised in audit.rs.
    let mut payload_obj = obj.clone();
    payload_obj.remove("prev_hash");
    payload_obj.remove("chain_hash");
    let payload_json = match serde_json::to_string(&serde_json::Value::Object(payload_obj)) {
        Ok(j) => j,
        Err(e) => return LineResult::ParseError(format!("Failed to re-serialize payload: {e}")),
    };

    // Recompute HMAC-SHA256("{prev_hash}:{payload_json}") — same formula as audit.rs.
    let input = format!("{prev_hash}:{payload_json}");
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return LineResult::ParseError("HMAC key has zero length".to_string());
    };
    mac.update(input.as_bytes());
    let computed = hex::encode(mac.finalize().into_bytes());

    // Check prev_hash chain linkage.
    if prev_hash != expected_prev {
        return LineResult::ChainBreak {
            event_type,
            recorded_chain_hash,
            computed_chain_hash: computed,
            expected_prev_hash: expected_prev.to_string(),
            actual_prev_hash: prev_hash,
        };
    }

    // Check HMAC integrity.
    if computed != recorded_chain_hash {
        return LineResult::ChainBreak {
            event_type,
            recorded_chain_hash,
            computed_chain_hash: computed,
            expected_prev_hash: expected_prev.to_string(),
            actual_prev_hash: prev_hash,
        };
    }

    LineResult::Ok {
        chain_hash: recorded_chain_hash,
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    // Load the HMAC key.
    let key = match load_key(&cli) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(2);
        }
    };

    // Open the log file.
    let file = match fs::File::open(&cli.file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening {:?}: {e}", cli.file);
            process::exit(2);
        }
    };

    println!("Verifying audit chain: {}", cli.file.display());

    let reader = io::BufReader::new(file);
    let result = run_verification(reader, &key);

    println!("Events processed: {}", result.processed);

    if result.no_chain_fields {
        println!(
            "Chain status: NOT ENABLED (no chain fields found — tamper-evidence was not enabled)"
        );
        process::exit(0);
    }

    if result.processed == 0 {
        println!("Chain status: NO EVENTS (file is empty or contains no valid JSON lines)");
        process::exit(0);
    }

    if result.breaks.is_empty() {
        println!("Chain status: VALID (no breaks detected)");
        process::exit(0);
    } else {
        for b in &result.breaks {
            println!("CHAIN BREAK at line {}:", b.line_number);
            if let Some(ref et) = b.event_type {
                println!("  Event: {et}");
            }
            println!("  Expected prev_hash:      {}", b.expected_prev_hash);
            println!("  Found prev_hash:         {}", b.actual_prev_hash);
            println!("  Recorded chain_hash:     {}", b.recorded_chain_hash);
            println!("  Recomputed chain_hash:   {}", b.computed_chain_hash);
            println!(
                "  The event at line {} or the event at line {} may have been tampered with.",
                b.line_number,
                b.line_number.saturating_sub(1)
            );
        }
        println!(
            "Chain status: INVALID ({} break(s) detected)",
            result.breaks.len()
        );
        process::exit(1);
    }
}

fn load_key(cli: &Cli) -> Result<Vec<u8>, String> {
    if let Some(ref k) = cli.key {
        return Ok(k.as_bytes().to_vec());
    }
    if let Some(ref path) = cli.key_file {
        let contents = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read key file {:?}: {e}", path))?;
        return Ok(contents.trim_end_matches('\n').as_bytes().to_vec());
    }
    Err("Provide --key <KEY> or --key-file <PATH>".to_string())
}

/// A detected chain break.
struct BreakRecord {
    line_number: usize,
    event_type: Option<String>,
    expected_prev_hash: String,
    actual_prev_hash: String,
    // These fields are read via println! in the display loop; clippy dead_code
    // analysis does not trace reads through field access on borrowed struct refs.
    #[allow(dead_code)]
    recorded_chain_hash: String,
    #[allow(dead_code)]
    computed_chain_hash: String,
}

/// Aggregated result from a full log verification pass.
struct VerificationResult {
    processed: usize,
    breaks: Vec<BreakRecord>,
    no_chain_fields: bool,
}

fn run_verification<R: BufRead>(reader: R, key: &[u8]) -> VerificationResult {
    let mut prev_hash = "genesis".to_string();
    let mut processed = 0usize;
    let mut breaks = Vec::new();
    let mut no_chain_fields = false;

    for (idx, line_result) in reader.lines().enumerate() {
        let line_number = idx + 1;
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match verify_line(trimmed, key, &prev_hash) {
            LineResult::Ok { chain_hash } => {
                processed += 1;
                prev_hash = chain_hash;
            }
            LineResult::NoChainFields => {
                // If any line has no chain fields, report the whole file as non-chained.
                no_chain_fields = true;
                processed += 1;
            }
            LineResult::ChainBreak {
                event_type,
                expected_prev_hash,
                actual_prev_hash,
                recorded_chain_hash,
                computed_chain_hash,
            } => {
                processed += 1;
                breaks.push(BreakRecord {
                    line_number,
                    event_type,
                    expected_prev_hash,
                    actual_prev_hash,
                    recorded_chain_hash,
                    computed_chain_hash,
                });
                // Advance prev_hash to the recorded value so we continue checking
                // subsequent events from the break point (detect multiple breaks).
                // Note: we can't know what the "correct" next prev_hash should be
                // after a break — we use what was recorded.
                prev_hash = match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Ok(v) => v
                        .get("chain_hash")
                        .and_then(|h| h.as_str())
                        .unwrap_or("genesis")
                        .to_string(),
                    Err(_) => "genesis".to_string(),
                };
            }
            LineResult::ParseError(ref msg) => {
                // Skip unparseable lines (e.g. non-JSON log lines intermixed with
                // audit JSON), but log to stderr so operators know they exist.
                eprintln!("Warning: line {line_number} is not valid JSON: {msg}");
            }
        }
    }

    VerificationResult {
        processed,
        breaks,
        no_chain_fields,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod audit_verify_tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::io::Cursor;

    type HmacSha256Inner = Hmac<Sha256>;

    const TEST_KEY: &[u8] = b"test-hmac-key-for-audit-verify-tests-32b";

    /// Build a chain of JSON lines simulating what audit.rs logs when HMAC is enabled.
    /// Each event includes all event fields + prev_hash + chain_hash.
    fn build_chained_log(events: &[serde_json::Value]) -> Vec<String> {
        let mut lines = Vec::new();
        let mut prev = "genesis".to_string();

        for event in events {
            // The event JSON is the "base" (enriched) JSON — prev_hash/chain_hash excluded.
            let event_json = serde_json::to_string(event).unwrap();

            // Replicate compute_chain logic exactly.
            let input = format!("{prev}:{event_json}");
            let mut mac = HmacSha256Inner::new_from_slice(TEST_KEY).unwrap();
            mac.update(input.as_bytes());
            let chain_hash = hex::encode(mac.finalize().into_bytes());

            // Build the final logged line: flatten event + add chain fields.
            let mut chained = event.as_object().unwrap().clone();
            chained.insert(
                "prev_hash".to_string(),
                serde_json::Value::String(prev.clone()),
            );
            chained.insert(
                "chain_hash".to_string(),
                serde_json::Value::String(chain_hash.clone()),
            );

            lines.push(serde_json::to_string(&serde_json::Value::Object(chained)).unwrap());
            prev = chain_hash;
        }
        lines
    }

    fn make_event(event_type: &str, user: &str) -> serde_json::Value {
        serde_json::json!({
            "event": event_type,
            "user": user,
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "testhost"
        })
    }

    /// Build a chained log that includes OCSF fields (simulating Plan 27-04 enrichment).
    fn make_ocsf_event(event_type: &str, user: &str) -> serde_json::Value {
        serde_json::json!({
            "event": event_type,
            "user": user,
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "testhost",
            "category_uid": 3,
            "class_uid": 3002,
            "severity_id": 1,
            "activity_id": 1,
            "type_uid": 300201,
            "metadata": { "version": "1.3.0" }
        })
    }

    // ── Test 1: Valid chain reports VALID ─────────────────────────────────────

    #[test]
    fn test_verify_valid_chain_reports_ok() {
        let events = vec![
            make_event("SSH_LOGIN_SUCCESS", "alice"),
            make_event("SESSION_CLOSED", "alice"),
            make_event("TOKEN_REVOKED", "alice"),
        ];
        let lines = build_chained_log(&events);
        let log_content = lines.join("\n") + "\n";

        let reader = Cursor::new(log_content);
        let result = run_verification(reader, TEST_KEY);

        assert_eq!(result.processed, 3, "all 3 events must be processed");
        assert!(result.breaks.is_empty(), "valid chain must have no breaks");
        assert!(
            !result.no_chain_fields,
            "chained log must not report no-chain-fields"
        );
    }

    // ── Test 2: Modified event reports a break ────────────────────────────────

    #[test]
    fn test_verify_modified_event_reports_break() {
        let events = vec![
            make_event("SSH_LOGIN_SUCCESS", "alice"),
            make_event("SESSION_CLOSED", "alice"),
        ];
        let mut lines = build_chained_log(&events);

        // Tamper with event 1 (line 0) — change the user field.
        lines[0] = lines[0].replace("\"alice\"", "\"mallory\"");

        let log_content = lines.join("\n") + "\n";
        let reader = Cursor::new(log_content);
        let result = run_verification(reader, TEST_KEY);

        assert_eq!(result.processed, 2);
        // The first event will fail because its HMAC doesn't match after tampering.
        assert!(
            !result.breaks.is_empty(),
            "tampered event must cause a break"
        );
    }

    // ── Test 3: Deleted event reports a break at the gap ─────────────────────

    #[test]
    fn test_verify_deleted_event_reports_break() {
        let events = vec![
            make_event("SSH_LOGIN_SUCCESS", "alice"),
            make_event("TOKEN_VALIDATION_FAILED", "alice"),
            make_event("SESSION_CLOSED", "alice"),
        ];
        let mut lines = build_chained_log(&events);

        // "Delete" the middle event (index 1).
        lines.remove(1);

        let log_content = lines.join("\n") + "\n";
        let reader = Cursor::new(log_content);
        let result = run_verification(reader, TEST_KEY);

        assert_eq!(result.processed, 2, "2 events remain after deletion");
        // Event 3 (now at index 1 after deletion) will have prev_hash == event2's
        // chain_hash, but the expected prev is event1's chain_hash — chain breaks.
        assert!(
            !result.breaks.is_empty(),
            "deleted event must cause a chain break"
        );
    }

    // ── Test 4 (negative): No chain fields → reports NOT ENABLED ─────────────

    #[test]
    fn test_verify_no_chain_fields_reports_not_enabled() {
        let log_content = r#"{"event":"SSH_LOGIN_SUCCESS","user":"alice","timestamp":"2026-01-01T00:00:00Z"}
{"event":"SESSION_CLOSED","user":"alice","timestamp":"2026-01-01T00:00:01Z"}
"#;
        let reader = Cursor::new(log_content);
        let result = run_verification(reader, TEST_KEY);

        assert!(
            result.no_chain_fields,
            "log without chain fields must set no_chain_fields=true"
        );
    }

    // ── Test 5: Empty file → no events ───────────────────────────────────────

    #[test]
    fn test_verify_empty_file_reports_no_events() {
        let reader = Cursor::new("");
        let result = run_verification(reader, TEST_KEY);

        assert_eq!(
            result.processed, 0,
            "empty file must yield 0 processed events"
        );
        assert!(result.breaks.is_empty(), "empty file must have no breaks");
    }

    // ── Test 6: OCSF fields in payload are verified ───────────────────────────

    #[test]
    fn test_verify_ocsf_fields_included_in_verifiable_payload() {
        let events = vec![make_ocsf_event("SSH_LOGIN_SUCCESS", "alice")];
        let lines = build_chained_log(&events);
        let log_content = lines.join("\n") + "\n";

        // Valid chain with OCSF fields → should pass.
        let reader = Cursor::new(log_content.clone());
        let result = run_verification(reader, TEST_KEY);
        assert!(
            result.breaks.is_empty(),
            "valid OCSF-enriched chain must verify cleanly"
        );

        // Tamper with an OCSF field (change severity_id) → chain must break.
        let tampered = log_content.replace("\"severity_id\":1", "\"severity_id\":5");
        let reader = Cursor::new(tampered);
        let result = run_verification(reader, TEST_KEY);
        assert!(
            !result.breaks.is_empty(),
            "modifying an OCSF field must break the chain"
        );
    }
}
