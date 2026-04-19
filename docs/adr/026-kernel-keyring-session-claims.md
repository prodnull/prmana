# ADR-026: Kernel Keyring Session-Claims Publication

## Status

Proposed

**Date:** 2026-04-19
**Related:** ADR-002 (PAM module / agent separation), ADR-013 (same-UID IPC trust model)
**Trigger:** external contribution PR #14 (`prodnull/prmana#14`)

## Context

### The cross-fork handoff problem

`pam-prmana` authenticates the user in `pam_sm_authenticate`. Downstream PAM modules in the same stack (audit correlators, nftables session gating, attestation-aware helpers) may run later in the transaction — after sshd's privsep `fork(2)` from auth-worker to session-worker — and need to see the freshly-validated token's claims.

Today that handoff uses `pam_putenv` to publish `PRMANA_SESSION_ID`, `PRMANA_TOKEN_JTI`, `PRMANA_TOKEN_EXP`, `PRMANA_ISSUER`. PAM env values are documented as fragile across the sshd privsep boundary: depending on PAM stack ordering and `sshd_config` `PermitUserEnvironment` state, they can be stripped or cleared by the session worker.

The Linux kernel keyring (`keyrings(7)`) is the natural durability class for same-session cross-fork metadata: inherited across `fork()`/`execve()` including setuid transitions, ACL-governed, kernel-managed lifetime, no filesystem dependency.

### The contributed capability

PR #14 adds `pam-prmana/src/keyring.rs` and a call site in `pam_sm_authenticate`. On successful authentication it publishes a versioned, printable-ASCII payload of selected token claims (`jti`, `exp`, `iss`, `sid`, `user`, `uid`, optional `acr`, `dpop`) into the Linux kernel session keyring as a `user`-type key, aligns the TTL to the token expiry, restricts the ACL to possessor-only, and exports the key's serial number as `PRMANA_KEY` in PAM env.

The original PR also exported `AUTHNFT_CORRELATION=prmana-<sid>` for a specific downstream (`pam_authnft`). This ADR declines that export.

### Adversarial review

The capability was threat-modeled adversarially by two independent AI reviewers (Codex and Gemini-3-pro) before acceptance. Both converged on the decision and the merge preconditions documented below. Severity disagreements were resolved by citation (`user-session-keyring(7)`, `KEYCTL_SETPERM(2const)`, `KEYCTL_LINK(2const)`).

## Options considered

### Option (1) — Accept the PR as-written

Merge the keyring publisher plus the `AUTHNFT_CORRELATION` export, subject to the technical preconditions.

**Rejected.** `AUTHNFT_CORRELATION` hardcodes a single downstream's correlation convention into an OSS crate. Any consumer can construct the same value from `sid`. Coupling `pam-prmana` to one specific integration is the wrong precedent.

### Option (2) — Adopt generic primitive, drop consumer-specific exports (selected)

Accept the kernel keyring publisher and the `PRMANA_KEY` env var as a consumer-agnostic post-auth primitive. Decline `AUTHNFT_CORRELATION`. Require five technical preconditions before merge (see §Invariants).

### Option (3) — Reject the capability entirely

Keep PAM env vars as the only cross-fork channel.

**Rejected.** The keyring is the correct durability class for same-session cross-fork metadata. Declining on principle would push downstream integrators into worse workarounds or into forking `pam-prmana`.

## Decision

Adopt Option (2). `pam-prmana` publishes authenticated session claims into the Linux kernel keyring as a generic, consumer-neutral primitive. `AUTHNFT_CORRELATION` is out of scope and MUST NOT ship as part of this primitive. The capability is Linux-only.

## Invariants

These are binding merge preconditions. None are optional.

1. **Keyring anchor integrity.** Publication MUST guarantee a distinct per-login session keyring. `KEY_SPEC_SESSION_KEYRING` alone is insufficient — on stacks without `pam_keyinit.so force revoke` it resolves to the shared `@us` user-session keyring (`user-session-keyring(7)`), widening the reader set to every concurrent login for the same UID. Prmana MUST either mint a fresh keyring via `keyctl(KEYCTL_JOIN_SESSION_KEYRING, NULL)` when `@us` is the target, or detect `@us` and refuse to publish (warn + continue, non-fatal). The current implementation chooses detect-and-refuse.

2. **Atomic ACL.** The publisher MUST use a process-keyring-anchored pattern: `add_key` into `KEY_SPEC_PROCESS_KEYRING` (exclusively possessed by the publishing process), apply `SETPERM` (POSSESSOR view/read/search, strip SETATTR) and `SET_TIMEOUT` there, then `KEYCTL_LINK` into the target session keyring. On any failure before LINK, `KEYCTL_REVOKE` so no partial state escapes into a multi-possessor keyring. An `add_key → SET_TIMEOUT → SETPERM` sequence directly into the session keyring is NOT acceptable: the key is mutable by any possessor until SETPERM lands.

3. **Versioned, escaped payload.** The payload is a wire protocol the moment a consumer exists. It MUST be prefixed `v=1;` for schema-version negotiation. `;`, `=`, `%`, `\0`, CR, and LF MUST be percent-encoded in every claim value before concatenation. Egress sanitisation is the publisher's responsibility; downstream consumer sanitisation is not a substitute. Pairs that would push the payload past the bounded size are skipped whole — never truncated mid-escape.

4. **Linux-only build.** `mod keyring;` and every call site MUST be gated with `#[cfg(target_os = "linux")]`. `cargo check -p pam-prmana --all-features` MUST succeed on non-Linux developer hosts.

5. **ABI commitment.** `PRMANA_KEY` env var and the `prmana_<sid>` payload schema become a stable contract on merge. Schema changes within `v=1` are append-only; incompatible changes require `v=2` and a deprecation window. Removal of the capability requires a semver major bump on `pam-prmana` and a documented replacement primitive.

## Non-goals

- This primitive is NOT a session secret or authentication factor under NIST SP 800-63B. The payload is metadata, not a credential.
- It does NOT make same-possession local processes private from one another. Shell descendants and post-sudo root remain possessors of the user's session keyring by design (`keyrings(7)` possession rules, `session-keyring(7)` inheritance across `execve`).
- It does NOT authorise consumer-specific payload fields or consumer-specific env var exports. Downstream integrators build their own correlation IDs from `sid`.
- It does NOT extend prmana's trust model against root or kernel-level attackers.
- It does NOT replace agent-side session state. The keyring is the lightweight cross-fork fast path for PAM consumers; the agent remains authoritative for DPoP signing and richer session metadata.

## Consequences

### Positive

- Eliminates the `pam_putenv`/sshd-privsep fragility for the metadata set a downstream PAM module typically needs.
- Establishes a consumer-neutral integration point. Future integrations (nftables session tags, audit correlators, SELinux/AppArmor context hints) do not require a prmana-side code change per consumer.
- Codified threat model (TB-8) makes the trust boundary explicit for integrators.

### Negative

- Adds a Linux-only `unsafe` surface to `pam-prmana` (three syscalls via `libc::syscall`). Surface is isolated to one module under `#[cfg(target_os = "linux")]` with `#![allow(unsafe_code)]` documented at module level.
- Commits to an ABI. Future payload evolution must observe the version contract.
- Process-keyring anchor + LINK pattern is marginally more syscalls per successful auth than a direct session-keyring write. Cost is microseconds; auth path is not latency-critical.

### Risks accepted and documented

- **R-KR-1 — Same-possession readers.** The user's shell, any fork descendant, and any setuid descendant (including `sudo`, `su`) can `KEYCTL_READ` the payload including the `dpop` thumbprint. The thumbprint is a public value per RFC 9449 §6; its presence enables local same-session correlation but does not break DPoP binding. Documented in TB-8 residual risks.
- **R-KR-2 — Non-fatal publish failure.** When publication fails (kernel denial, quota, `@us` detected, LSM policy), `PRMANA_KEY` is absent and consumers MUST fall through to the prior env-var-only path. Documented as part of the ABI.
- **R-KR-3 — Multiple keys per session tree.** Each successful `pam_sm_authenticate` publishes a new key keyed by its unique `sid`. Consumers MUST key off `sid` / the `prmana_<sid>` description and MUST NOT assume a singleton `prmana_*` key per session tree.

## Related

- ADR-002 — PAM module / agent separation (the architectural split that makes this primitive necessary).
- ADR-013 — Same-UID agent IPC trust model (referenced for contrast: that ADR governs agent IPC; this ADR governs PAM-internal session-claims handoff).
- TB-8 — Kernel-keyring session-claims publication (in `docs/threat-model.md`, added alongside this ADR).
- RFC 9449 (OAuth 2.0 DPoP) §6 — JWK thumbprint as public confirmation material.
- `keyrings(7)`, `session-keyring(7)`, `user-session-keyring(7)`, `pam_keyinit(8)`, `add_key(2)`, `KEYCTL_SETPERM(2const)`, `KEYCTL_SET_TIMEOUT(2const)`, `KEYCTL_LINK(2const)`, `KEYCTL_JOIN_SESSION_KEYRING(2const)`.
