# ADR-018: TPM 2.0 Key Attestation via TPM2_CC_Certify

## Status

Accepted

## Context

The unix-oidc agent can use TPM 2.0 hardware to generate non-exportable P-256 DPoP signing keys (ADR-014). However, the PAM module currently has no way to verify that a client's DPoP key is actually TPM-resident. A compromised client could claim to use a TPM but generate keys in software, undermining the non-exportability guarantee.

For enterprises that require hardware-bound keys (phishing-resistant hardware, ACR `urn:schemas.openid.net/acr/2016/07/phishing-resistant-hardware`), server-side verification of key provenance is essential.

### Options considered

1. **TPM2_CC_Quote (Platform attestation)** — Proves platform state via PCR values. Overkill for our use case: we need to prove a specific key is TPM-resident, not that the platform is in a known-good state. Also requires a PCR policy and reference values.

2. **TPM2_CC_Certify (Key certification)** — Proves that a specific key object was created by and is resident in a specific TPM. The TPM signs a `TPMS_ATTEST` structure containing the certified key's `Name` (a hash of its public area). Simple, targeted, and sufficient.

3. **FIDO2/WebAuthn attestation** — Not applicable; we're attesting SSH DPoP keys, not browser credentials.

4. **IdP-mediated attestation** — Have the IdP verify attestation during token issuance. Attractive long-term but requires IdP support that doesn't exist today. Can be layered on later.

### Why key certification

- It answers the exact question: "Is this DPoP signing key non-exportable and TPM-resident?"
- The `TPMS_ATTEST` structure contains the key's `Name` — a SHA-256 hash of the public area — which the PAM module can verify against the DPoP proof's JWK.
- No PCR policy, no platform state management, no IMA.
- The Attestation Key (AK) proves TPM identity via the EK certificate chain.

## Decision

### Attestation method

Use `TPM2_CC_Certify` to produce key attestation evidence:

1. **Attestation Key (AK)**: A transient P-256 key created under the Endorsement Hierarchy. The AK signs the `TPMS_ATTEST` structure. The AK's public key is included in the evidence so the verifier can check the signature.

2. **Certification flow**: `TPM2_CC_Certify(signingKey=DPoP_key, certifyingKey=AK)` produces:
   - `TPMS_ATTEST`: Contains `TPMS_CERTIFY_INFO` with the certified key's `Name` and `qualifiedName`.
   - Signature: ECDSA over the `TPMS_ATTEST` bytes, signed by the AK.

3. **Evidence structure**:
   ```json
   {
     "certify_info": "<base64url(TPMS_ATTEST)>",
     "signature": "<base64url(ECDSA signature)>",
     "ak_public": "<base64url(AK public area)>"
   }
   ```

### Transport mechanism

Attestation evidence is carried in the DPoP proof JWT header as an optional `attest` parameter:

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "attest": {
    "certify_info": "base64url...",
    "signature": "base64url...",
    "ak_public": "base64url..."
  }
}
```

**Why JWT header, not body claims?** The DPoP proof body (payload) is already specified by RFC 9449. Adding custom claims would conflict with the standard. JWT headers are extensible and this is precedented (e.g., `x5c` in the header).

**Why not a separate endpoint?** Attestation is tightly coupled to the DPoP proof — the evidence proves the key that *signed this specific proof*. A separate attestation endpoint would require correlation and introduce TOCTOU risk.

### PAM-side verification

When `IssuerConfig.attestation` is present:

1. Extract `attest` from the DPoP proof JWT header.
2. Verify the AK signature over `certify_info`.
3. Parse `TPMS_ATTEST` and extract the certified key's `Name`.
4. Compute the expected `Name` from the DPoP proof's `jwk` parameter.
5. Verify `Name` matches — this proves the JWK in the DPoP proof is the same key the TPM certified.

**Enforcement modes** (same as other configurable checks):
- `strict`: Attestation required. DPoP proofs without `attest` are rejected.
- `warn`: Log warning if attestation is missing, but allow (migration path).
- `disabled`: Skip attestation check entirely (default for backward compatibility).

### Scope limitations

- **Key attestation only** (this phase). Platform attestation (TPM2_CC_Quote with PCR values) is deferred.
- **EK certificate chain verification is not implemented** in this phase. The AK signature is verified, but proving the AK belongs to a genuine TPM (via the EK cert chain) requires a trust store of TPM manufacturer CA certificates. This is a Phase 38+ enhancement.
- **No nonce from server** in this phase. The `TPMS_ATTEST` has a `qualifyingData` field that could carry a server nonce for freshness. For now, the PAM module trusts the `iat` timestamp of the DPoP proof for freshness (already validated by DPoP verification).

## Consequences

### Positive

- Enterprises can enforce hardware-bound DPoP keys at the PAM level.
- The `ACR_PHRH` constant (`urn:schemas.openid.net/acr/2016/07/phishing-resistant-hardware`) can be meaningfully enforced based on actual hardware evidence, not just IdP-asserted ACR values.
- Token Exchange (37-01) is strengthened: an attested exchanger key proves the jump host's key is non-exportable.

### Negative

- Clients must have a TPM and must run the attestation flow — adds latency to the first proof.
- Attestation evidence increases DPoP proof size (~500 bytes additional).
- Testing requires swtpm or a real TPM.

### Future enhancements

- Server nonce in `qualifyingData` for attestation freshness.
- EK certificate chain verification against a TPM manufacturer CA trust store.
- Caching attestation evidence so it's not recomputed on every DPoP proof.
- IdP-mediated attestation where the IdP verifies attestation during token issuance.

## References

- TCG TPM2 Specification Part 3: Commands, SS18.2 (TPM2_CC_Certify)
- TCG Infrastructure Working Group, Credential Profiles (EK certificates)
- ADR-014: TPM 2.0 Object Attributes
- RFC 9449: DPoP (JWT header structure)
