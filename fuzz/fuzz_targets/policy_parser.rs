//! Fuzz target for policy YAML parsing
//!
//! Tests the robustness of policy file parsing against malformed YAML.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse as UTF-8
    if let Ok(yaml_str) = std::str::from_utf8(data) {
        // Attempt to parse as YAML
        let _ = parse_policy_yaml(yaml_str);
    }
});

fn parse_policy_yaml(yaml: &str) -> Option<Policy> {
    // First, parse as generic YAML
    let value: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;

    // Extract policy fields
    let version = value.get("version")?.as_u64()?;

    let defaults = value.get("defaults").and_then(|d| {
        Some(PolicyDefaults {
            required_acr: d.get("required_acr").and_then(|v| v.as_str()).map(String::from),
            session_timeout: d.get("session_timeout").and_then(|v| v.as_str()).map(String::from),
            dpop_enabled: d.get("dpop").and_then(|d| d.get("enabled")).and_then(|v| v.as_bool()),
        })
    });

    Some(Policy { version, defaults })
}

#[derive(Debug)]
struct Policy {
    version: u64,
    defaults: Option<PolicyDefaults>,
}

#[derive(Debug)]
struct PolicyDefaults {
    required_acr: Option<String>,
    session_timeout: Option<String>,
    dpop_enabled: Option<bool>,
}
