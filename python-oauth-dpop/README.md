# python-oauth-dpop

A Python implementation of OAuth 2.0 DPoP (Demonstrating Proof of Possession) per [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).

## Overview

DPoP is a mechanism for sender-constraining OAuth 2.0 tokens by binding them to a cryptographic key held by the client. This prevents stolen tokens from being used by attackers who don't possess the private key.

## Installation

```bash
pip install oauth-dpop
```

## Usage

### Client: Generate DPoP proofs

```python
from oauth_dpop import DPoPClient

# Create a new client with a random P-256 keypair
client = DPoPClient.generate()

# Get the thumbprint for token binding
print(f"Thumbprint: {client.thumbprint}")

# Generate a proof for a token request
proof = client.create_proof("POST", "https://auth.example.com/token")

# Include in HTTP request header:
# DPoP: <proof>

# With server-provided nonce
proof_with_nonce = client.create_proof(
    "GET",
    "https://api.example.com/resource",
    nonce="server-nonce-123",
)

# With access token hash (for resource requests)
proof_with_ath = client.create_proof_with_ath(
    "GET",
    "https://api.example.com/resource",
    access_token="eyJhbGci...",
)
```

### Server: Validate DPoP proofs

```python
from oauth_dpop import DPoPConfig, DPoPValidationError, validate_proof, verify_binding

config = DPoPConfig(
    max_proof_age_secs=60,
    require_nonce=False,
    expected_method="POST",
    expected_target="https://auth.example.com/token",
)

try:
    thumbprint = validate_proof(dpop_header, config)

    # For token requests: bind thumbprint to issued token's cnf.jkt
    # For resource requests: verify binding
    verify_binding(thumbprint, token_jkt)

    print("DPoP proof valid!")

except DPoPValidationError as e:
    if e.code == "REPLAY_DETECTED":
        print("Replay attack detected")
    elif e.code == "PROOF_EXPIRED":
        print("Proof has expired")
    else:
        print(f"Validation failed: {e.message}")
```

## Security Features

- **JTI Replay Protection**: Each proof's unique identifier is cached to prevent replay attacks
- **Constant-Time Comparison**: Cryptographic values use constant-time comparison
- **Key Validation**: P-256 coordinate lengths are validated
- **Proof Age Validation**: Proofs are rejected if too old or from the future

## Algorithm Support

Currently supports:
- **ES256** (ECDSA with P-256 and SHA-256) - recommended by RFC 9449

## License

Licensed under either Apache License 2.0 or MIT license, at your option.
