# Security Audit Response — April 2026

**Audit Date:** 2026-04-08/09
**Reviewers:** Codex (source audit), Gemini (architectural review), Claude (implementation + cross-examination)
**Scope:** Full source review of pam-prmana and prmana-agent crates

---

## Executive Summary

A three-model adversarial security review identified 5 findings across the prmana codebase. Four findings were fixed in the same session; one was accepted as inherent to the design model with documented mitigations and a v3.1 hardening plan.

| # | Severity | Finding | Status | Commit |
|---|----------|---------|--------|--------|
| 1 | **High** | Introspection cache key collision | **Fixed** | `4f072e9` |
| 2 | Medium | Agent IPC same-UID broker authority | **Accepted** (SSH-agent model) | Documented |
| 3 | Medium | Socket hijacking in sudo/session PAM paths | **Fixed** | `4f072e9` |
| 4 | Low | Env-policy override bypasses validation | **Fixed** | `4f072e9` |
| 5 | Low | Session file permission TOCTOU race | **Fixed** | `4f072e9` |

Additionally, Phase 31 (Security Hardening Sweep) addressed 5 categories of proactive hardening:

| Sub-phase | Category | Commit |
|-----------|----------|--------|
| 31-01 | Session ID entropy: 64-bit → 128-bit | `6c5707f` |
| 31-02 | TokenClaims PII redaction + JWT SecretString wrapping | `6c5707f` |
| 31-03 | TOCTOU hardening: O_NOFOLLOW, fstat-on-fd, S_IFREG, UID check | `6c5707f` |
| 31-04 | TLS validation: compile-time gate on insecure paths, auth_header redaction | `6c5707f` |
| 31-05 | Webhook HMAC-SHA256 signing with timestamp-bound replay protection | `6c5707f` |

---

## Finding 1 (High): Introspection Cache Key Collision

**Reporter:** Codex
**File:** `pam-prmana/src/oidc/introspection.rs`
**Risk:** A revoked token from Issuer A could inherit a cached `active=true` result from Issuer B if they shared a JTI value or token prefix.

### Root Cause

`derive_cache_key()` used the bare JTI (or SHA-256 of first 32 token bytes) without issuer scoping. JTIs are only unique within a single issuer, not globally.

### Fix

Cache key now includes the introspection endpoint URL as scope:
- With JTI: `SHA-256(endpoint + ":" + jti)`
- Without JTI: `SHA-256(endpoint + ":" + full_token)` (full token, not first 32 bytes)

### Verification

3 new tests confirm cross-issuer isolation:
- `test_cache_key_same_jti_different_issuer_produces_different_keys`
- `test_cache_key_same_token_different_issuer_produces_different_keys`
- `test_cache_key_same_issuer_same_jti_is_stable`

---

## Finding 2 (Medium): Agent IPC Same-UID Broker Authority

**Reporter:** Codex
**File:** `prmana-agent/src/daemon/peer_cred.rs`, `socket.rs`
**Risk:** Any process running as the same UID can use the agent socket to request DPoP proofs, trigger token refresh, shut down the daemon, or wipe credentials.

### Assessment

This is the **SSH-agent trust model** — `ssh-agent` has the identical property. The mitigations are:
- Socket permissions 0600 (owner-only)
- Peer credential UID verification
- Core dumps disabled (`PR_SET_DUMPABLE=0` / `PT_DENY_ATTACH`)
- mlock on key material pages

### Why Not Fixed Now

PPID/TTY binding would break legitimate multi-session use cases (tmux, screen, nohup, detached jobs). IPC channel separation (admin vs crypto) is architecturally sound but requires significant refactoring.

### v3.1 Plan

Phase 34+ will implement:
1. **IPC channel separation:** Crypto operations (GetProof, Refresh) on one socket; Admin operations (Shutdown, SessionClosed) on a separate root-only socket.
2. **Optional per-session binding:** Configurable policy for environments that want to restrict proof issuance to the originating TTY/session.

### Operator Guidance

If your threat model includes malware under the authenticated user:
- Use hardware-bound keys (TPM/YubiKey) — the agent cannot export hardware-locked private keys
- Enable full-disk encryption to protect the socket file
- Consider SELinux/AppArmor confinement for the agent process

---

## Finding 3 (Medium): Socket Hijacking in Sudo/Session PAM Paths

**Reporter:** Codex
**File:** `pam-prmana/src/sudo.rs`, `pam-prmana/src/lib.rs`
**Risk:** In sudo and session-close PAM paths (running as root), the agent socket was resolved from user-controlled environment variables (`PRMANA_AGENT_SOCKET`, `XDG_RUNTIME_DIR`). An attacker could redirect root to a malicious socket.

### Fix

Socket path resolution now uses `uzers::get_current_uid()` to derive `/run/user/{uid}/prmana-agent.sock`. Environment variable override is restricted to `#[cfg(feature = "test-mode")]`.

### Residual Risk

If `/run/user/{uid}/` is writable by an attacker (misconfigured system), the socket could still be replaced. This is mitigated by systemd's `RuntimeDirectory` management which creates these directories with correct ownership.

---

## Finding 4 (Low): Env-Policy Override Bypasses Validation

**Reporter:** Codex
**File:** `pam-prmana/src/policy/config.rs`
**Risk:** `PRMANA_POLICY_YAML` environment variable could inject arbitrary policy, silently relaxing security enforcement (e.g., changing `strict` to `disabled`).

### Fix

`PRMANA_POLICY_YAML` inline config restricted to `#[cfg(feature = "test-mode")]`. Production policy must come from the file-based path which runs through `load_from()` validation.

### Codex Follow-Up (v2)

Codex noted that even in test-mode, the inline YAML path returns the config without running full `load_from()` validation. This is accepted for test builds but documented.

---

## Finding 5 (Low): Session File Permission TOCTOU Race

**Reporter:** Codex
**File:** `pam-prmana/src/session/mod.rs`
**Risk:** `File::create()` followed by `set_permissions(0o600)` has a brief window where the file exists with default umask permissions.

### Fix

Replaced with `OpenOptions::new().mode(0o600).open()` which sets permissions atomically at creation time via the kernel's `open(2)` mode argument.

### Pre-existing Mitigation

The session directory itself is 0700, so the race was only exploitable if the directory permissions were misconfigured.

---

## Phase 31: Proactive Security Hardening

### 31-01: 128-bit Session IDs

Upgraded from 64-bit to 128-bit CSPRNG randomness for session IDs, request IDs, and approval request IDs. Birthday bound improved from ~2^32 to ~2^64 per NIST SP 800-63B.

### 31-02: PII Redaction + JWT SecretString

- Custom `Debug` impl on `TokenClaims` redacts `sub` and `preferred_username`
- Custom `Debug` on `WebhookConfig` redacts `auth_header` and `hmac_secret`
- Raw JWT wrapped in `SecretString` at PAM entry point; exposed only at validation callsite

### 31-03: TOCTOU Hardening

- `secure_remove()`: `O_NOFOLLOW | O_NONBLOCK`, `fstat` on fd, `S_IFREG` + UID verification
- New error variants: `SymlinkRejected`, `NotRegularFile`, `OwnerMismatch`
- `FsAtomicStore`: explicit `chmod 0700` on newly-created directories

### 31-04: TLS Validation

- `with_insecure_tls()` method removed from production builds (`#[cfg(feature = "test-mode")]`)
- Audited all 8 `reqwest::Client::builder()` calls — none use `danger_accept_invalid_certs`

### 31-05: Webhook HMAC-SHA256 Signing

- `X-Unix-OIDC-Timestamp` + `X-Unix-OIDC-Signature` headers on outbound webhooks
- Signed payload: `"{timestamp}.{body}"` prevents replay and body substitution
- Shared secret stored as `SecretString`, redacted in Debug output

---

*This document should be updated when Finding 2 mitigations are implemented in v3.1.*
