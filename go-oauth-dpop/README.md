# go-oauth-dpop

A Go implementation of OAuth 2.0 DPoP (Demonstrating Proof of Possession) per [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).

## Overview

DPoP is a mechanism for sender-constraining OAuth 2.0 tokens by binding them to a cryptographic key held by the client. This prevents stolen tokens from being used by attackers who don't possess the private key.

## Installation

```bash
go get github.com/prodnull/unix-oidc/go-oauth-dpop
```

## Usage

### Client: Generate DPoP proofs

```go
package main

import (
    "fmt"
    "log"

    dpop "github.com/prodnull/unix-oidc/go-oauth-dpop"
)

func main() {
    // Create a new client with a random P-256 keypair
    client, err := dpop.NewClient()
    if err != nil {
        log.Fatal(err)
    }

    // Get the thumbprint for token binding
    fmt.Printf("Thumbprint: %s\n", client.Thumbprint())

    // Generate a proof for a token request
    proof, err := client.CreateProof("POST", "https://auth.example.com/token", nil)
    if err != nil {
        log.Fatal(err)
    }

    // Include in HTTP request header:
    // DPoP: <proof>
    fmt.Printf("DPoP: %s\n", proof)

    // With server-provided nonce
    nonce := "server-nonce-123"
    proofWithNonce, err := client.CreateProof("GET", "https://api.example.com/resource", &nonce)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("DPoP (with nonce): %s\n", proofWithNonce)
}
```

### Server: Validate DPoP proofs

```go
package main

import (
    "fmt"
    "log"

    dpop "github.com/prodnull/unix-oidc/go-oauth-dpop"
)

func main() {
    config := dpop.Config{
        MaxProofAgeSecs: 60,
        RequireNonce:    false,
        ExpectedMethod:  "POST",
        ExpectedTarget:  "https://auth.example.com/token",
    }

    dpopHeader := "..." // From request header

    thumbprint, err := dpop.ValidateProof(dpopHeader, config)
    if err != nil {
        switch err {
        case dpop.ErrReplayDetected:
            log.Println("Replay attack detected")
        case dpop.ErrProofExpired:
            log.Println("Proof has expired")
        default:
            log.Printf("Validation failed: %v\n", err)
        }
        return
    }

    // For token requests: bind thumbprint to issued token's cnf.jkt
    // For resource requests: verify binding
    tokenJkt := "..." // From token's cnf.jkt claim
    if err := dpop.VerifyBinding(thumbprint, tokenJkt); err != nil {
        log.Println("Token not bound to this key")
        return
    }

    fmt.Println("DPoP proof valid!")
}
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
