# ADR-001: DPoP Proof-of-Possession for Token Binding

## Status

Accepted

## Context

OIDC access tokens are bearer tokens - anyone possessing the token can use it. This creates risks:

1. **Token theft**: Stolen tokens can be replayed from any machine
2. **Man-in-the-middle**: Intercepted tokens are immediately usable
3. **Credential forwarding**: Tokens obtained on one machine work everywhere

For SSH authentication, these risks are particularly severe:
- SSH sessions grant shell access to systems
- Lateral movement becomes trivial with stolen tokens
- Traditional SSH key binding provides stronger guarantees

We needed a mechanism to bind tokens to specific clients without requiring:
- PKI infrastructure (complex certificate management)
- Hardware tokens (cost and availability constraints)
- Modifications to identity providers (deployment complexity)

## Decision

We implemented **DPoP (Demonstrating Proof-of-Possession)** per RFC 9449.

### Key aspects:

1. **Client-generated key pairs**: Each unix-oidc-agent generates an ephemeral P-256 ECDSA key pair
2. **Proof binding**: Every token use requires a fresh DPoP proof signed by the private key
3. **Server validation**: The PAM module validates proofs match the token's `cnf` claim
4. **Replay protection**: JTI (JWT ID) tracking prevents proof reuse

### Implementation details:

```
Token Request:
  Client → IdP: Authorization + DPoP Proof (containing public key)
  IdP → Client: Access token with cnf: {jkt: thumbprint}

Token Use:
  Client → Server: Access token + DPoP Proof (fresh, signed)
  Server: Verify proof signature matches token's jkt claim
```

### Algorithm choice: ES256 (P-256 ECDSA)

- NIST-approved, widely supported
- 128-bit security level
- Fast signing/verification
- Compact signatures (64 bytes)

### Why not alternatives:

| Alternative | Why Not |
|------------|---------|
| mTLS | Requires PKI, cert management, IdP support |
| Token Binding (RFC 8471) | Browser-focused, limited IdP support |
| FIDO2/WebAuthn | Requires hardware, browser context |
| Custom MAC | Non-standard, interoperability issues |

## Consequences

### Positive

- **Reduced blast radius**: If credentials stolen, damage is time-limited and centrally revocable
- **Strong binding**: Tokens unusable without private key (but see Limitations below)
- **Standard protocol**: RFC 9449 compliance, IdP support growing
- **No PKI required**: Self-managed keys, no CA infrastructure
- **Replay resistant**: Fresh proof per request + JTI tracking
- **Transparent to users**: Key management handled by agent
- **Audit trail**: Token issuance logged at IdP, unlike SSH keys

### Negative

- **IdP dependency**: Requires IdP DPoP support (graceful fallback exists)
- **Computational cost**: ECDSA operations per authentication
- **Key storage**: Private keys must be protected on client
- **Complexity**: Additional validation layer in PAM module

### Mitigations

- Fallback to bearer tokens when IdP doesn't support DPoP
- Hardware acceleration for ECDSA where available
- Key storage in OS keychain with appropriate protections
- Well-tested validation code with comprehensive fuzzing

### Limitations (Honest Assessment)

**DPoP does not eliminate credential theft risks.** If an attacker can extract an SSH private key from memory, they can likely extract a DPoP signing key the same way.

What DPoP provides vs SSH keys:

| Scenario | SSH Key Stolen | DPoP Key + Token Stolen |
|----------|----------------|-------------------------|
| Usable indefinitely? | Yes | No - token expires (minutes) |
| Can mint new credentials? | Yes | No - requires IdP auth |
| Centralized revocation? | No - hunt authorized_keys | Yes - single IdP action |
| Audit trail? | Limited | Full (IdP logs) |

For high-security environments requiring protection against memory dump attacks, use hardware-backed key storage (TPM, Secure Enclave, HSM).

## References

- [RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
- [Implementation: rust-oauth-dpop crate](../../rust-oauth-dpop/)
- [Security Guide: DPoP section](../security-guide.md#dpop-proof-of-possession)
