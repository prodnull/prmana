# ADR-014: TPM 2.0 Object Attributes

## Status

Accepted

## Context

prmana uses TPM 2.0 for hardware-backed DPoP signing keys. The TPM key template
must select object attributes that enforce non-exportability while still allowing
unrestricted P-256 ECDSA signing for RFC 9449 DPoP proofs.

Alternatives considered included enabling decrypt capability, using policy-based admin
authorization, or omitting attributes such as `fixedTPM` or `sensitiveDataOrigin`.
Those variants either broadened key capability unnecessarily or weakened provenance
and non-exportability guarantees.

## Decision

TPM signing keys use these object attributes:

- `fixedTPM`
- `fixedParent`
- `sensitiveDataOrigin`
- `userWithAuth`
- `noDA`
- `sign_encrypt`

They do not use `decrypt` or `adminWithPolicy`.

## Consequences

### Positive

- `fixedTPM` and `fixedParent` support non-exportability expectations
- `sensitiveDataOrigin` ensures the TPM generated the private key internally
- `sign_encrypt` restricts the key to the required signing operation
- `noDA` avoids dictionary-attack lockout interfering with legitimate signing

### Negative

- The template is intentionally narrow and not reusable for decryption workloads
- Policy-based TPM authorization is deferred in favor of simpler user auth semantics
- Operational guidance is required to protect TPM hierarchy configuration
