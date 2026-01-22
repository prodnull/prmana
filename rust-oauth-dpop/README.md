# rust-oauth-dpop

A Rust implementation of OAuth 2.0 DPoP (Demonstrating Proof of Possession) as defined in [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).

[![Crates.io](https://img.shields.io/crates/v/oauth-dpop.svg)](https://crates.io/crates/oauth-dpop)
[![Documentation](https://docs.rs/oauth-dpop/badge.svg)](https://docs.rs/oauth-dpop)
[![License](https://img.shields.io/crates/l/oauth-dpop.svg)](LICENSE)

## Overview

DPoP is a mechanism for sender-constraining OAuth 2.0 tokens by binding them to a cryptographic key held by the client. This prevents stolen tokens from being used by attackers who don't possess the private key.

## Features

- **Client-side proof generation** - Generate DPoP proofs for HTTP requests
- **Server-side validation** - Validate proofs with replay protection
- **RFC 9449 compliant** - Full compliance with the specification
- **Security hardened** - Constant-time comparisons, JTI replay protection, key validation

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
oauth-dpop = "0.1"
```

### Feature flags

- `client` (default) - Client-side proof generation
- `server` (default) - Server-side proof validation with replay protection

Use only what you need:

```toml
# Client-only (smaller dependency tree)
oauth-dpop = { version = "0.1", default-features = false, features = ["client"] }

# Server-only
oauth-dpop = { version = "0.1", default-features = false, features = ["server"] }
```

## Usage

### Client: Generate DPoP proofs

```rust
use oauth_dpop::{DPoPClient, DPoPError};

// Create a new client with a random P-256 keypair
let client = DPoPClient::generate();

// Get the key thumbprint (for token binding via cnf.jkt claim)
println!("Thumbprint: {}", client.thumbprint());

// Generate a proof for a token request
let proof = client.create_proof("POST", "https://auth.example.com/token", None)?;

// Generate a proof with a server-provided nonce
let proof = client.create_proof(
    "GET",
    "https://api.example.com/resource",
    Some("server-nonce-123")
)?;

// Include in HTTP request:
// DPoP: <proof>
```

### Server: Validate DPoP proofs

```rust
use oauth_dpop::{validate_proof, verify_binding, DPoPConfig, DPoPValidationError};

let config = DPoPConfig {
    max_proof_age_secs: 60,
    require_nonce: false,
    expected_nonce: None,
    expected_method: "POST".to_string(),
    expected_target: "https://auth.example.com/token".to_string(),
};

// Validate the proof and get the key thumbprint
match validate_proof(&dpop_header, &config) {
    Ok(thumbprint) => {
        // For token requests: bind the thumbprint to the issued token
        // For resource requests: verify binding matches token's cnf.jkt
        if let Err(e) = verify_binding(&thumbprint, &token_jkt) {
            return Err("Token not bound to this key");
        }
    }
    Err(DPoPValidationError::ReplayDetected) => {
        // Proof was already used - reject
    }
    Err(e) => {
        // Other validation failure
    }
}
```

## Security Features

### JTI Replay Protection

Each proof's unique identifier (jti) is cached to prevent replay attacks. The cache automatically expires entries based on proof age.

### Constant-Time Comparison

All cryptographic value comparisons (nonces, thumbprints) use constant-time operations to prevent timing attacks.

### Key Validation

P-256 coordinate lengths are validated to be exactly 32 bytes to prevent malformed key attacks.

### Proof Age Validation

Proofs are rejected if they're too old or from the future (with small clock skew allowance).

## Algorithm Support

Currently supports:
- **ES256** (ECDSA with P-256 and SHA-256) - recommended by RFC 9449

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
