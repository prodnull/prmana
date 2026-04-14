# ADR-007: Post-Quantum Hybrid DPoP Signatures (ML-DSA-65+ES256)

## Status

Accepted (experimental, behind `pqc` feature flag)

## Context

Cryptographically-relevant quantum computers (CRQCs) threaten the ECDSA signatures
used in our DPoP proofs. NIST published FIPS 204 (ML-DSA, formerly CRYSTALS-Dilithium)
as the primary post-quantum digital signature standard. The IETF is standardizing
composite PQC+traditional signatures in draft-ietf-jose-pq-composite-sigs-01.

### Why Hybrid, Not Pure ML-DSA-65

A hybrid approach (ML-DSA-65 + ES256) provides defense-in-depth:

1. **Cryptographic insurance** — If ML-DSA is broken by classical cryptanalysis before
   CRQCs arrive, the ES256 component remains secure. If CRQCs arrive, the ML-DSA
   component provides protection.
2. **Regulatory acceptance** — ANSSI (France), BSI (Germany), and CNSA 2.0 (US)
   recommend hybrid approaches during the transition period.
3. **IETF alignment** — draft-ietf-jose-pq-composite-sigs-01 defines `ML-DSA-65-ES256`
   as a named composite algorithm for JOSE. This is the standard path for JWS/JWT.
4. **Incremental deployment** — Hybrid allows gradual rollout; verifiers that don't
   support PQC reject the unknown algorithm cleanly (UnsupportedAlgorithm).

Pure ML-DSA was rejected because it provides no fallback if the algorithm is broken
classically, and no IETF composite draft exists for pure-ML-DSA in JOSE.

### Crate Selection: ml-dsa (RustCrypto) vs Alternatives

Three Rust crates implementing ML-DSA were evaluated (2026-03-12):

| Criterion | ml-dsa (RustCrypto) | libcrux-ml-dsa (Cryspen) | pqcrypto-mldsa |
|---|---|---|---|
| Version | 0.1.0-rc.7 | 0.0.7 | 0.1.2 |
| Pure Rust | Yes | Yes | No (C FFI via PQClean) |
| `signature::Signer` trait | **Yes** | No | No |
| Zeroize support | **Yes** (feature flag) | No | No |
| FIPS 204 final | Yes | Yes | Uncertain |
| Formal verification | None | Partial (HAX/F*) | None |
| External audit | None | None | None |
| Maintenance | Active (Mar 2026) | Active (Mar 2026) | Low; PQClean archiving Jul 2026 |
| License | Apache-2.0 OR MIT | Apache-2.0 | Apache-2.0 OR MIT |

**Decision: `ml-dsa` (RustCrypto)**

Rationale:
- **Ecosystem integration** — Our workspace uses `p256`, `sha2`, `signature` traits.
  `ml-dsa` implements the same `signature::Signer`/`Verifier` traits (v3.0.0-rc.10),
  enabling zero-adapter integration with the existing `DPoPSigner` trait hierarchy.
- **Memory protection** — `ml-dsa` supports `ZeroizeOnDrop` on `SigningKey` via the `zeroize`
  feature flag, aligning with our `ProtectedSigningKey` memory invariants (MEM-01/02/04/05).
  Note: `p256::ecdsa::SigningKey` implements `ZeroizeOnDrop` unconditionally in `ecdsa-0.16`
  (no feature flag needed).
- **No C in the security path** — `pqcrypto-mldsa` wraps C code from PQClean (entering
  archive status July 2026) and is outside `cargo audit` coverage. Non-starter.
- **libcrux formal verification is compelling but premature** — HAX/F* proofs for
  core arithmetic are the most rigorous work in this space, but the project lacks
  `signature` trait support, lacks zeroize, and is still finding spec bugs (March 2026
  commits). Worth watching for future promotion from experimental to production.
- **No crate in this space has been independently audited** — The `ml-dsa` README
  disclaimer is honest disclosure, not a unique deficiency. Same status as `p256`.

### Experimental Status

This feature is experimental because:
1. The `ml-dsa` crate is pre-1.0 (release candidate)
2. draft-ietf-jose-pq-composite-sigs-01 is not yet an RFC
3. No IdP currently supports composite DPoP tokens (agent-side only)
4. The composite signature format may change before standardization

### Promotion Criteria

Move from experimental (`pqc` feature flag) to default when:
1. `ml-dsa` reaches 1.0 stable and receives an independent security audit
2. The IETF composite signatures draft reaches RFC status
3. At least one major IdP (Entra, Okta, Keycloak) supports PQC token binding
4. The composite JWK thumbprint computation is standardized (currently per RFC 7638
   with our canonical extension)

## Decision

1. Implement hybrid ML-DSA-65+ES256 composite DPoP signatures behind `pqc` feature flag
2. Use `ml-dsa` 0.1.0-rc.7 (RustCrypto) with `zeroize` feature enabled on the agent side
   (PAM verifier does not hold signing keys, so `zeroize` is not needed there)
3. Follow draft-ietf-jose-pq-composite-sigs-01 for composite signature format
4. Agent-side signing only initially; PAM verification gated behind `#[cfg(feature = "pqc")]`
5. No hardware signer PQC support (YubiKey/TPM don't support ML-DSA yet)

## Consequences

### Positive
- Crypto-agility: infrastructure ready for PQ transition before it's urgent
- Defense-in-depth: hybrid provides insurance against both classical and quantum breaks
- Standards-aligned: follows IETF composite draft, not a custom format
- Zero impact on non-PQC users: entirely behind feature flag

### Negative
- Pre-release dependency: `ml-dsa` API may change between RC versions
- Larger signatures: 3373 bytes (ML-DSA-65: 3309 + ES256: 64) vs 64 bytes for ES256 alone
- Larger keys: ML-DSA-65 public key is 1952 bytes vs 65 bytes for P-256
- Draft dependency: composite format may change before RFC

### Risks
- If `ml-dsa` crate is abandoned, we must migrate to an alternative (libcrux is the fallback)
- If the IETF draft changes the composite format, we must update accordingly
- Users enabling `pqc` in production should understand the experimental status

## References

- FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- RFC 7638: JSON Web Key (JWK) Thumbprint
- draft-ietf-jose-pq-composite-sigs-01: Use of Post-Quantum Algorithms with JOSE
- CNSA 2.0: NSA Commercial National Security Algorithm Suite 2.0
- ANSSI: French cybersecurity agency PQC transition guidance
- BSI TR-02102-1: German federal office cryptographic algorithms recommendation
