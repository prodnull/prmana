# java-oauth-dpop

A Java implementation of OAuth 2.0 DPoP (Demonstrating Proof of Possession) per [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).

## Overview

DPoP is a mechanism for sender-constraining OAuth 2.0 tokens by binding them to a cryptographic key held by the client. This prevents stolen tokens from being used by attackers who don't possess the private key.

## Requirements

- Java 11+ (targets Java 11, the lowest non-EOL LTS version)

## Installation

### Gradle

```kotlin
implementation("com.github.unixoidcproject:java-oauth-dpop:0.1.0")
```

### Maven

```xml
<dependency>
    <groupId>com.github.unixoidcproject</groupId>
    <artifactId>java-oauth-dpop</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

### Client: Generate DPoP proofs

```java
import com.github.unixoidcproject.oauthdpop.DPoPClient;

// Create a new client with a random P-256 keypair
DPoPClient client = DPoPClient.generate();

// Get the thumbprint for token binding
System.out.println("Thumbprint: " + client.getThumbprint());

// Generate a proof for a token request
String proof = client.createProof("POST", "https://auth.example.com/token", null);

// Include in HTTP request header:
// DPoP: <proof>

// With server-provided nonce
String proofWithNonce = client.createProof(
    "GET",
    "https://api.example.com/resource",
    "server-nonce-123"
);

// With access token hash (for resource requests)
String proofWithAth = client.createProofWithAth(
    "GET",
    "https://api.example.com/resource",
    null,
    "eyJhbGci..."
);
```

### Server: Validate DPoP proofs

```java
import com.github.unixoidcproject.oauthdpop.*;

DPoPConfig config = DPoPConfig.builder()
    .maxProofAgeSecs(60)
    .requireNonce(false)
    .expectedMethod("POST")
    .expectedTarget("https://auth.example.com/token")
    .build();

try {
    String thumbprint = DPoPValidator.validateProof(dpopHeader, config);

    // For token requests: bind thumbprint to issued token's cnf.jkt
    // For resource requests: verify binding
    DPoPValidator.verifyBinding(thumbprint, tokenJkt);

    System.out.println("DPoP proof valid!");

} catch (DPoPValidationException e) {
    switch (e.getCode()) {
        case DPoPValidationException.REPLAY_DETECTED:
            System.out.println("Replay attack detected");
            break;
        case DPoPValidationException.PROOF_EXPIRED:
            System.out.println("Proof has expired");
            break;
        default:
            System.out.println("Validation failed: " + e.getMessage());
    }
}
```

## Security Features

- **JTI Replay Protection**: Each proof's unique identifier is cached (using Eclipse Collections) to prevent replay attacks
- **Constant-Time Comparison**: Cryptographic values use `MessageDigest.isEqual()` for constant-time comparison
- **Key Validation**: P-256 coordinate lengths are validated to be exactly 32 bytes
- **Proof Age Validation**: Proofs are rejected if too old or from the future

## Algorithm Support

Currently supports:
- **ES256** (ECDSA with P-256 and SHA-256) - recommended by RFC 9449

## License

Licensed under either Apache License 2.0 or MIT license, at your option.
