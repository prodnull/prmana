use oauth_dpop::{DPoPClient, DPoPConfig, validate_proof, verify_binding};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;

#[derive(Serialize, Deserialize)]
struct ProofData {
    proof: String,
    thumbprint: String,
    method: String,
    target: String,
}

const METHOD: &str = "POST";
const TARGET: &str = "https://cross-test.example.com/token";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <generate|validate> [proof_file]", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "generate" => {
            let output_file = args.get(2).map(|s| s.as_str()).unwrap_or("rust_proof.json");
            generate(output_file);
        }
        "validate" => {
            if args.len() < 3 {
                eprintln!("Usage: {} validate <proof_file>", args[0]);
                std::process::exit(1);
            }
            validate(&args[2]);
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn generate(output_file: &str) {
    let client = DPoPClient::generate();
    let proof = client.create_proof(METHOD, TARGET, None).expect("Failed to create proof");

    let data = ProofData {
        proof,
        thumbprint: client.thumbprint().to_string(),
        method: METHOD.to_string(),
        target: TARGET.to_string(),
    };

    let json = serde_json::to_string_pretty(&data).expect("Failed to serialize");
    fs::write(output_file, json).expect("Failed to write file");
    println!("Generated proof: {}", output_file);
}

fn validate(input_file: &str) {
    let json = fs::read_to_string(input_file).expect("Failed to read file");
    let data: ProofData = serde_json::from_str(&json).expect("Failed to parse JSON");

    let config = DPoPConfig {
        max_proof_age_secs: 300, // 5 minutes for cross-language tests
        require_nonce: false,
        expected_nonce: None,
        expected_method: data.method.clone(),
        expected_target: data.target.clone(),
    };

    match validate_proof(&data.proof, &config) {
        Ok(thumbprint) => {
            match verify_binding(&thumbprint, &data.thumbprint) {
                Ok(()) => {
                    println!("PASS: {} validated successfully", input_file);
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("FAIL: Thumbprint mismatch: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("FAIL: Validation error: {}", e);
            std::process::exit(1);
        }
    }
}
