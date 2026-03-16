# JTI Cache Architecture

This document explains the JTI (JWT ID) replay-protection cache used in unix-oidc, why the current per-process design is sufficient for the sshd fork model, and how the DPoP server-issued nonce protocol provides the primary replay defense for DPoP proofs.

**Target audiences:** Security auditors, contributors, enterprise operators evaluating distributed deployment.

---

## Table of Contents

1. [Background: What is JTI?](#1-background-what-is-jti)
2. [The Forked-sshd Process Model](#2-the-forked-sshd-process-model)
3. [Per-Process Cache Design](#3-per-process-cache-design)
4. [Why the Per-Process Cache is Sufficient](#4-why-the-per-process-cache-is-sufficient)
5. [DPoP Nonces: The Actual Replay Defense](#5-dpop-nonces-the-actual-replay-defense)
6. [Why Redis (Distributed Cache) is Out of Scope](#6-why-redis-distributed-cache-is-out-of-scope)
7. [Cache Sizing and DoS Protection](#7-cache-sizing-and-dos-protection)
8. [Security Properties Summary](#8-security-properties-summary)

---

## 1. Background: What is JTI?

The `jti` (JWT ID) claim is defined in RFC 7519 §4.1.7 as a unique identifier for a JWT. For DPoP proofs (RFC 9449 §11.1), the server must check that each DPoP proof's `jti` claim is unique within the proof's lifetime to prevent replay attacks — an attacker who intercepts a valid DPoP proof must not be able to reuse it.

The `jti` claim is optional in OIDC access tokens (RFC 7519 §4.1.7) but unix-oidc also records the access token JTI when present, configurable via `jti_enforcement = strict|warn|disabled` (CLAUDE.md §Security Check Decision Matrix).

---

## 2. The Forked-sshd Process Model

Understanding JTI cache design requires understanding how `sshd` works:

```
sshd (listening, port 22)
    │
    ├── fork() ──▶ sshd-child (handles Alice's connection)
    │                  │
    │                  └── pam_unix_oidc.so loaded in this process
    │                          JTI cache lives here (process-local)
    │
    └── fork() ──▶ sshd-child (handles Bob's connection)
                       │
                       └── pam_unix_oidc.so loaded in this process
                               Separate JTI cache (different process)
```

Key facts:

- Each SSH connection gets its **own sshd child process** (not a thread)
- PAM modules are loaded as `.so` files into the sshd child process
- There is **no shared memory** between sshd child processes
- Each child process runs to completion (auth → session → close) then exits
- The PAM module's global static `DPOP_JTI_CACHE` is process-local

---

## 3. Per-Process Cache Design

The JTI cache is implemented in `pam-unix-oidc/src/oidc/dpop.rs`:

```rust
/// Maximum entries in the DPoP JTI cache before forced cleanup/rejection
/// This prevents memory exhaustion attacks where an attacker submits many unique JTIs
const MAX_JTI_CACHE_ENTRIES: usize = 100_000;

/// Global DPoP JTI cache for replay protection (RFC 9449 Section 11.1)
static DPOP_JTI_CACHE: Lazy<DPoPJtiCache> = Lazy::new(DPoPJtiCache::new);
```

The cache stores `(jti, expiry_instant)` entries in a `HashMap` behind a `parking_lot::RwLock`. It:

- Records each new JTI with an expiry of `now + proof_lifetime`
- Rejects any proof whose JTI is already present and not yet expired
- Runs cleanup every 300 seconds to evict expired entries (`maybe_cleanup()` checks `duration_since(last_cleanup) > 300s`)
- Rejects new proofs when `len >= MAX_JTI_CACHE_ENTRIES` after cleanup

---

## 4. Why the Per-Process Cache is Sufficient

**The threat model for sshd:** An attacker intercepts a DPoP proof used during Alice's SSH authentication and attempts to replay it to gain Alice's access. The relevant question is: can the attacker replay the proof in a **different sshd process** before the proof expires?

**Why cross-process replay is not a viable attack:**

1. **DPoP proofs are bound to a specific `htu` (HTTP target URI).** In unix-oidc, the PAM module is not an HTTP server — DPoP proofs are validated against the PAM authentication context, not an HTTP URI. A proof from one SSH connection cannot satisfy the `htu` binding for a different SSH connection.

2. **DPoP proofs are bound to a specific `htm` (HTTP method).** The method field further constrains reuse.

3. **Access tokens have short lifetimes.** DPoP access tokens typically expire in 5–60 minutes. By the time an attacker could intercept and reuse a proof across processes, the token will have expired.

4. **The primary replay defense is the nonce protocol** (see Section 5). Server-issued nonces are single-use and process-scoped. A replayed DPoP proof will fail nonce validation even if the JTI has aged out of the cache.

5. **Authentication is a single atomic operation.** sshd forks, authenticates, and proceeds. The window for cross-process replay is the token lifetime, not the proof lifetime — and that window is protected by token expiration and nonce binding.

**Known limitation (F-02 in docs/standards-compliance-matrix.md §8):** In a hypothetical scenario where two sshd processes authenticate simultaneously using the same access token, the process-local JTI caches cannot coordinate. This is documented as gap F-02 (SP 800-53 IA-2(12) cross-instance replay window) and assessed as LOW practical risk given nonce binding and token expiration.

---

## 5. DPoP Nonces: The Actual Replay Defense

unix-oidc implements RFC 9449 §8 server-issued DPoP nonces as the primary replay-prevention mechanism. The two-round PAM keyboard-interactive conversation is implemented at `pam-unix-oidc/src/lib.rs` line 150 (§"DPoP nonce challenge/response"):

```
Round 1:
  Server → Client:  "DPOP_NONCE:<hex-nonce>"   (pam_prompt echo-off)
  Client → Server:  (empty response, nonce received)

Round 2:
  Server → Client:  "DPoP proof:"              (pam_prompt echo-off)
  Client → Server:  <DPoP proof with nonce bound into "nonce" claim>
```

The nonce is:

- Generated by `generate_dpop_nonce()` — cryptographically random (256-bit CSPRNG, 43-char base64url per RFC 9449 §8), stored in `global_nonce_cache()`
- **Single-use:** consumed from the cache on receipt; replaying the same nonce fails
- **Short-lived:** nonces expire after 60 seconds (default)
- **Process-scoped:** bound to the sshd child process handling this connection

This means: **even if an attacker intercepts and replays a DPoP proof immediately**, the nonce is already consumed. The JTI cache is a second line of defense (belt-and-suspenders), not the primary mechanism.

Implementation: `pam-unix-oidc/src/lib.rs` line 150 ("DPoP nonce challenge/response"), `pam-unix-oidc/src/security/nonce_cache.rs`.

---

## 6. Why Redis (Distributed Cache) is Out of Scope

A common audit question: "Why not use Redis or a shared cache for cross-process JTI deduplication?"

**Architectural reasons:**

1. **sshd forks, not threads.** There is no long-running unix-oidc process to maintain a Redis connection pool. Each auth attempt is a fresh process that would need to establish, use, and tear down a Redis connection — adding 5–50ms latency to every SSH login.

2. **The unix-oidc agent daemon cannot be the cache.** The agent daemon runs in user space (per-user), not as a system service visible to all sshd forks. PAM modules run as root in the sshd context, which cannot contact a per-user socket reliably.

3. **Nonce binding makes it unnecessary.** Because each DPoP proof contains a server-issued single-use nonce, an attacker cannot replay the proof against any server — local or remote. The JTI cache is defense-in-depth, not the primary defense.

4. **Operational complexity.** A Redis dependency would add infrastructure requirements that contradict the project's goal of being deployable with minimal dependencies. unix-oidc must work on air-gapped servers.

5. **The threat is bounded by token lifetime.** Cross-process replay requires the attacker to have an unexpired token and an unexpired (non-nonce-validated) DPoP proof. The nonce protocol closes this window entirely.

**Conclusion:** Distributed JTI caching is out of scope and will not be added to v3.0. Full security against cross-process replay is provided by the nonce protocol.

---

## 7. Cache Sizing and DoS Protection

The cache is bounded at `MAX_JTI_CACHE_ENTRIES = 100_000` entries. This prevents memory exhaustion attacks where an adversary submits proofs with many unique JTIs.

**Behavior at capacity (`pam-unix-oidc/src/oidc/dpop.rs`):**

1. Force cleanup: evict all expired entries (`entries.retain(|_, exp| *exp > now)`)
2. If still at capacity after cleanup: reject the proof (return `false` from `check_and_record`)
3. Log a `WARN` with current cache size via `tracing::warn!(cache_size = ..., "DPoP JTI cache at capacity, rejecting new proof")`

**Cleanup schedule:** Every 300 seconds (`maybe_cleanup()` checks `duration_since(last_cleanup) > 300s`).

**Memory estimate:** Each entry is `(String, Instant)` — approximately 40–80 bytes per entry depending on JTI length. At 100_000 entries: ~4–8 MB. This is within acceptable PAM module memory constraints.

---

## 8. Security Properties Summary

| Property | Mechanism | Standard |
|----------|-----------|----------|
| DPoP proof replay within same process | JTI cache + nonce consumption | RFC 9449 §11.1 |
| DPoP proof replay across processes | Server-issued nonce (single-use per connection) | RFC 9449 §8 |
| Access token replay | Token expiration + DPoP cnf.jkt binding | RFC 9449 §9.3 |
| Memory exhaustion via JTI flooding | MAX_JTI_CACHE_ENTRIES=100,000 with TTL cleanup | — |
| Cross-connection replay | Nonce scoped to process; htm/htu binding | RFC 9449 §4.2 |

**Known open gap (F-02):** Cross-instance JTI deduplication for scenarios without nonce binding. Risk is LOW due to token lifetime constraints and nonce protocol coverage. See `docs/standards-compliance-matrix.md §8 Known Gaps`.
