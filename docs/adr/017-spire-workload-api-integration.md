# ADR-017: SpireSigner via tonic + Official Workload API Proto

## Status

Accepted

## Context

Phase 35-02 implements `SpireSigner`, a `DPoPSigner` backend that fetches JWT-SVIDs
from a local SPIRE agent. The SPIRE Workload API is a gRPC service over a Unix
domain socket — the agent must speak gRPC to acquire SVIDs.

Four options were evaluated for the gRPC client implementation:

| Option | Approach | New deps | Risk |
|--------|----------|----------|------|
| **A** | tonic + prost with official `workload.proto` stubs | ~30 transitive (feature-gated) | Low: tonic is widely used, well-understood |
| **B** | `spiffe` crate (Rust SPIFFE SDK) | ~30 + spiffe wrapper | Medium: no public security audit, extra trust hop |
| **C** | SPIRE experimental REST API via reqwest | 0 new | High: experimental, not universally available |
| **D** | Hand-rolled gRPC over h2 + prost only | ~5 | High: fragile, reinventing gRPC |

Cross-review by Codex and Gemini both recommended Option A.

Key factors:
- The Workload API is the SPIFFE standard interface (not experimental or optional)
- tonic is the de facto Rust gRPC library, actively maintained
- Feature-gating (`--features spire`) means non-SPIRE builds pay zero dependency cost
- The agent daemon already depends on tokio — tonic's async runtime is compatible
- Only the `FetchJWTSVID` unary RPC is needed (no streaming, no server-side)

The `spiffe` crate (Option B) shows good design (granular feature flags, OpenSSF badge)
but has no published security audit and is not the official SPIFFE project repo,
adding a supply-chain trust hop that Option A avoids.

## Decision

Use tonic 0.12 with hand-written prost stubs (checked in, no build-time protoc)
from the official SPIFFE Workload API specification. Feature-gated behind `spire`.

Implementation details:
- Protobuf stubs in `unix-oidc-agent/src/spire/workload_api.rs` (hand-written from spec)
- Reference proto in `unix-oidc-agent/src/spire/workload.proto` (not used at build time)
- `SpireSigner` in `unix-oidc-agent/src/crypto/spire_signer.rs`
- UDS connection via `tower::service_fn` + `tokio::net::UnixStream` + `hyper_util::rt::TokioIo`
- `workload.spiffe.io: true` metadata header on every gRPC call (spec requirement)
- JWT-SVID cached by (audience, expiry) with proactive refresh at 50% lifetime
- gRPC buffers are normal heap — never mlock'd (only ephemeral DPoP keys are mlock'd)
- No process isolation (Codex/Gemini agreed: a bridge binary without real UID/seccomp
  isolation just reshuffles complexity)

## Consequences

### Positive

- Standard interface: any SPIRE deployment works without custom configuration
- Minimal API surface: only `FetchJWTSVID` is implemented
- No build-time tooling: checked-in stubs avoid protoc dependency
- Feature isolation: `--features spire` keeps tonic out of default builds
- Consistent with existing signer pattern (YubiKey, TPM)

### Negative

- ~30 transitive dependencies when spire feature is enabled (tonic, hyper, h2, etc.)
- tonic minor version upgrades may require stub updates (low risk: proto is stable)
- `block_on` bridge between sync `DPoPSigner` trait and async gRPC requires care
  in nested-runtime contexts (tests must use separate threads)

### References

- SPIFFE Workload API spec: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md
- RFC 9449 (DPoP): https://www.rfc-editor.org/rfc/rfc9449
- ADR-015: SPIFFE trust via OIDC Discovery
- ADR-016: Ephemeral DPoP keys for SPIRE
