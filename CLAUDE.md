# CLAUDE.md - AI Assistant Guide for prmana

This document provides comprehensive context for AI assistants (Claude, Copilot, Cursor, etc.) working on the prmana project. It captures our philosophy, architecture decisions, security invariants, and the reasoning behind key design choices.

## Project Philosophy

### Security Should Not Be Annoying

The fundamental premise of prmana is that **security and usability are not opposing forces**. When security is annoying, people circumvent it. When it's an IT burden, organizations disable it. We believe:

- **Authentication should be invisible when possible** - Single sign-on means users authenticate once and work seamlessly
- **Step-up authentication should feel natural** - When elevated privileges are needed, the flow should be quick and intuitive
- **Configuration should have sensible defaults** - Secure out of the box, with knobs for enterprise customization
- **Failure modes should be clear** - When something goes wrong, the user should understand why and how to fix it

**Important clarification**: "Security shouldn't be annoying" does NOT mean "if security is annoying, disable it." It means **find a better UX**. The response to friction is always to improve the experience while maintaining security, never to remove the security check.

### Conservative Security, Pragmatic Usability

We follow the principle of **defense in depth with graceful degradation**:

1. **Default to the most secure option** that doesn't break legitimate use cases
2. **Warn before rejecting** when encountering edge cases (e.g., missing JTI claims)
3. **Make security configurable** for enterprises with different risk profiles (see issue #10)
4. **Never silently fail** - if a security check can't be performed, log it prominently

This means we might accept a token with a missing JTI claim (with a warning) rather than lock out a user whose IdP doesn't implement that optional field - but we make it configurable so strict environments can enforce it.

### The Problem We're Solving

Traditional Unix authentication has a fundamental disconnect with modern identity:

- **SSH keys get copied, shared, and never rotated** - That key on a developer's laptop from 2019? Still works.
- **When someone leaves, finding all their access is archaeology** - authorized_keys files scattered across servers
- **Enterprise MFA stops at the browser** - You need MFA for email but not for root access to production?
- **Compliance is painful** - "Show me who accessed what" requires parsing logs from dozens of sources

prmana bridges this gap by bringing OIDC (the same protocol behind "Sign in with Google/Microsoft/Okta") to Linux PAM, with DPoP token binding to prevent token theft.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User's Machine                               │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────────┐  │
│  │ SSH Client  │───▶│ oidc-ssh-agent   │───▶│ Identity Provider │  │
│  └─────────────┘    │ (token + DPoP)   │    │ (Okta/Azure/etc)  │  │
│                     └──────────────────┘    └───────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ SSH with token in env/keyboard-interactive
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Linux Server                                 │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────────┐  │
│  │   sshd      │───▶│  PAM Module      │───▶│ Token Validation  │  │
│  └─────────────┘    │ (pam_prmana)  │    │ + DPoP Verify     │  │
│                     └──────────────────┘    └───────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Location | License | Purpose |
|-----------|----------|---------|---------|
| `prmana-core` | `/prmana-core/` | Apache-2.0 | Shared OIDC discovery, JWKS types, common validation primitives |
| `pam-prmana` | `/pam-prmana/` | Apache-2.0 | Core PAM module (Rust) — depends on prmana-core |
| `prmana-agent` | `/prmana-agent/` | Apache-2.0 | Client-side agent daemon (token acquisition, DPoP, device flow) |
| DPoP Libraries | `/*-oauth-dpop/` | Apache-2.0 | Cross-language DPoP implementation |
| Enterprise crates | `/enterprise/crates/` | Proprietary | SCIM, kubectl, sudo step-up, CIBA, failover, token exchange, SPIFFE |

### Why DPoP (Demonstrating Proof of Possession)?

Standard OAuth tokens are bearer tokens - anyone who has them can use them. DPoP (RFC 9449) adds cryptographic binding:

1. Client generates an ephemeral key pair
2. Each request includes a proof signed with the private key
3. Server verifies the proof matches the token's thumbprint
4. **Even if an attacker intercepts the token, they can't use it** without the private key

This is the same protection used by banking APIs and is critical for SSH where tokens might traverse untrusted networks.

## OSS / Enterprise Boundary

The workspace is split into open-source and enterprise components with a strict dependency boundary.

### Open Source (Apache-2.0)

| Crate | Scope |
|-------|-------|
| `prmana-core` | OIDC discovery, JWKS fetching/caching, shared validation types |
| `pam-prmana` | PAM module: SSH login, DPoP validation, break-glass, local audit logging |
| `prmana-agent` | Agent daemon: device flow, auth code + PKCE, DPoP proof generation, credential storage |
| `*-oauth-dpop` | Cross-language DPoP libraries |

### Enterprise (Proprietary, `enterprise/` directory)

| Component | Location |
|-----------|----------|
| `prmana-scim` | `enterprise/crates/prmana-scim/` — SCIM user provisioning |
| `prmana-kubectl` | `enterprise/crates/prmana-kubectl/` — Kubernetes credential plugin |
| Sudo step-up | `enterprise/` — approval workflows, CIBA-based step-up |
| IdP failover | `enterprise/` — active-passive multi-IdP redundancy |
| Token exchange | `enterprise/` — RFC 8693 delegation |
| SPIFFE | `enterprise/` — SPIFFE/SPIRE integration |
| Fleet management | `enterprise/` — fleet-wide policy, SCIM entitlements |
| Enterprise docs/deploy/fixtures | `enterprise/docs/`, `enterprise/deploy/`, `enterprise/tests/` |

### Dependency Rule

```
OSS crates --> prmana-core    (allowed)
Enterprise --> prmana-core    (allowed)
OSS crates --> enterprise/    (NEVER — build must fail)
```

OSS crates must **never** depend on anything under `enterprise/`. This is a hard architectural invariant. Enterprise crates may depend on `prmana-core` for shared types.

### What moved out of OSS crates

The following modules were removed from OSS crates and relocated to `enterprise/`:

- **From `pam-prmana`**: `approval/`, `ciba/`, `evidence.rs`, `sudo.rs`
- **From `prmana-agent`**: `failover.rs`, `exchange.rs`, `spire/`, `attestation_pop.rs`, `spire_signer.rs`

### JWKS shared via prmana-core

OIDC discovery and JWKS types now live in `prmana-core`. Both `pam-prmana` and `prmana-agent` depend on `prmana-core` for these types. `pam-prmana/src/oidc/jwks.rs` is now a thin re-export shim over `prmana-core`.

## Security Invariants

These invariants MUST be maintained. Violating them is a security vulnerability.

### DPoP Validation (`pam-prmana/src/oidc/dpop.rs`)

1. **JWK thumbprint computation uses canonical values**
   ```rust
   // CORRECT: Hardcoded canonical values
   let canonical = format!(
       r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
       jwk.x, jwk.y
   );

   // WRONG: Using user-supplied kty/crv
   // An attacker could supply "kty":"oct" to change the thumbprint
   ```

2. **JTI (JWT ID) uniqueness for replay protection**
   - Each DPoP proof must have a unique `jti` claim
   - The JTI cache has a size limit (100k entries) to prevent DoS
   - Cache cleanup removes expired entries before rejecting new proofs

3. **Proof timing validation**
   - `iat` (issued at) must be recent (within clock skew tolerance)
   - `exp` (expiration) must be in the future
   - These prevent replay of old proofs

4. **HTTP method and URI binding**
   - DPoP proof is bound to specific `htm` (HTTP method) and `htu` (HTTP URI)
   - Prevents using a proof from one endpoint on another

5. **Algorithm enforcement is non-negotiable**
   - DPoP proofs MUST use ES256 (P-256 ECDSA) - never accept `alg: "none"` or symmetric algorithms
   - This prevents algorithm confusion attacks where an attacker tricks the verifier into using a weaker algorithm
   - ID tokens should be validated against the algorithm specified in JWKS, not the token header
   - Never allow user-controlled algorithm selection

### Token Validation (`pam-prmana/src/oidc/validation.rs`)

1. **Issuer validation** - Token must come from configured IdP
2. **Audience validation** - Token must be intended for this service
3. **Signature verification** - Using IdP's published JWKS
4. **Expiration check** - Token must not be expired
5. **DPoP binding** - If token has `cnf` claim, DPoP proof must match

### JWKS Caching Security

The JWKS (JSON Web Key Set) cache has security implications:

1. **Cache TTL should survive IdP transient failures** - If IdP is briefly unavailable, cached keys allow continued operation
2. **Key rollover support** - Old keys should remain valid during IdP key rotation (typically IdPs publish new keys before using them)
3. **TLS validation is mandatory** - JWKS endpoint must be fetched over HTTPS with proper certificate validation to the expected issuer
4. **Cache poisoning prevention** - Only cache keys from the configured issuer URL, never from token claims

### Security Check Decision Matrix

**HARD-FAIL (Never Optional)** - These checks can NEVER be skipped or made lenient:

| Check | Reason |
|-------|--------|
| Signature verification | Attacker can forge any token |
| Issuer validation | Attacker can use token from malicious IdP |
| Audience validation | Token meant for another service accepted |
| Expiration check | Stolen tokens valid forever |
| Algorithm enforcement | Algorithm confusion attacks |

**WARN-AND-ALLOW (Configurable per Issue #10)** - These can be lenient for compatibility:

| Check | Default | Reason for flexibility |
|-------|---------|----------------------|
| JTI presence | warn | Some IdPs don't implement this optional claim |
| ACR/AMR claims | warn | Not all IdPs support authentication context |
| DPoP binding | configurable | Legacy clients may not support DPoP |

**IMPORTANT**: When adding new security checks, explicitly decide which category they belong to and document the reasoning.

Also add to HARD-FAIL table:

| Key material zeroization on drop | Prevents key recovery from freed memory |

### kubectl Authentication Invariant (enterprise: `enterprise/crates/prmana-kubectl/`, Phase DT-A onwards)

**kubectl uses bearer tokens by design — do NOT claim DPoP protection.**

The Kubernetes exec credential API (`client.authentication.k8s.io/v1`) returns a bearer
token to kubectl. kubectl has no mechanism to inject per-request `DPoP` proof headers —
there is no callback between "received credential" and "sent HTTP request." Populating
`cnf.jkt` in a kubectl-issued token and claiming RFC 9449 protection would be security
theater: no party in the request path verifies proof-of-possession.

**Invariants for `prmana-kubectl` token issuance:**

1. **NO `cnf` claim** — kubectl tokens must never carry a `cnf.jkt` thumbprint. If you
   see `cnf` being populated in a `GetKubectlCredential` code path, it is a bug.

2. **Audience isolation (HARD-FAIL)** — kubectl tokens use audience
   `<cluster-id>.kube.prmana`. This audience MUST NOT be accepted by the SSH/PAM
   validator (`pam-prmana/src/oidc/validation.rs`). A stolen kubectl token must
   not allow SSH login. Enforce at every `aud` check point.

3. **Short TTL** — 10 minutes maximum. The short window is the primary replay mitigation
   in the absence of DPoP binding.

4. **`expirationTimestamp` = JWT `exp` minus 30 seconds** — forces kubectl to re-invoke
   the plugin before the token expires, preventing mid-request 401s.

**Evolution path:** Phase DT-E upgrades kubectl auth to ephemeral mTLS client
certificates (`clientCertificateData`/`clientKeyData` in ExecCredential). This provides
real cryptographic key binding via native Kubernetes x509 authentication — no proxy, no
custom authenticator, no security theater. Until DT-E ships, the honest marketing
language is: "short-lived, IdP-issued, audience-scoped tokens — no long-lived
kubeconfig credentials."

**Reference:** Opus adversarial review 2026-04-11; RFC 9449 §4.1, §4.3, §7.

### Memory Protection Invariants (`prmana-agent/src/crypto/protected_key.rs`, `src/storage/secure_delete.rs`)

These invariants apply to the client-side agent daemon, where DPoP private keys and OAuth tokens are held in memory and stored on disk.

#### In-memory protection

1. **SigningKey zeroed on drop via `ZeroizeOnDrop`**
   - `p256::ecdsa::SigningKey` implements `ZeroizeOnDrop` unconditionally in `ecdsa-0.16` — no feature flag required. Key material is volatile-written to zero when the struct is dropped.
   - Do NOT add a `zeroize` feature to `p256 = "0.13"` — the feature does not exist in that version.

2. **Key material pages locked via `mlock(2)`** (best-effort, MEM-04)
   - `ProtectedSigningKey` calls `libc::mlock()` over the entire `Box<Self>` allocation at construction. This prevents the OS from swapping the key page to disk.
   - Failures (EPERM in containers, ENOMEM) are logged at WARN and the daemon continues. Never fatal.
   - `mlock` does **not** protect against root or kernel-level access; it only prevents swap-based exposure.

3. **`ProtectedSigningKey` is Box-only** (MEM-05)
   - No public stack constructors exist (`new() -> Self` is intentionally absent). All constructors return `Box<Self>`. This prevents accidental stack copies of key material.
   - `from_key(SigningKey)` round-trips through `Zeroizing<Vec<u8>>` to avoid leaving a plain copy on the stack.

4. **`export_key()` returns `Zeroizing<Vec<u8>>`** (MEM-01)
   - Callers MUST NOT convert to `Vec<u8>`. The `Zeroizing` wrapper ensures the bytes are zeroed when the variable goes out of scope.
   - `Zeroizing<Vec<u8>>` implements `Deref<Target=[u8]>` so `&exported` coerces to `&[u8]` without a copy.

5. **OAuth tokens wrapped in `secrecy::SecretString`** (MEM-03)
   - `AgentState.access_token` is `Option<SecretString>`, not `Option<String>`. `Debug`/`Display` emits `[REDACTED]`; tokens never appear in logs regardless of log level.
   - The raw value is accessible only via `.expose_secret()`. All usages must be grep-auditable.
   - Two permitted audit boundaries: (a) sending to SSH client in `GetProof` handler, (b) writing to storage in `store(KEY_ACCESS_TOKEN, ...)`.

6. **Core dumps disabled at startup** (MEM-03)
   - `security::disable_core_dumps()` called before loading keys:
     - Linux: `prctl(PR_SET_DUMPABLE, 0)` — kernel refuses to produce core dump; `/proc/PID/mem` restricted.
     - macOS: `ptrace(PT_DENY_ATTACH, 0, NULL, 0)` — prevents debugger attach and core dump.
   - Best-effort: WARN on failure, never prevents daemon startup.

#### On-disk protection

7. **File deletion uses three-pass overwrite per NIST SP 800-88 Rev 1 SS2.4** (MEM-05)
   - Pass 1: random bytes + `sync_all()`. Pass 2: complement (XOR 0xFF) + `sync_all()`. Pass 3: new random bytes + `sync_all()`. Then `unlink`.
   - Originally inspired by DoD 5220.22-M (retired by DoD in 2006). Current implementation follows NIST SP 800-88 Rev 1 SS2.4 (Clear method) as the authoritative media sanitization guidance.
   - Overwrite failures are best-effort: log at WARN, still unlink.
   - See `prmana-agent/src/storage/secure_delete.rs`.

8. **CoW filesystem advisory** (MEM-06)
   - `detect_cow_filesystem()` checks `statfs(2)` for btrfs (`BTRFS_SUPER_MAGIC` on Linux) and APFS (`f_fstypename == "apfs"` on macOS).
   - WARN logged at `FileStorage::new()` (startup) and again before each `delete()` call if CoW is detected.
   - **Limitation**: On CoW filesystems, the three-pass overwrite may not modify the original data blocks. Full-disk encryption is the correct mitigation (NIST SP 800-88 Rev 1, §2.5).

9. **SSD/flash wear leveling advisory** (MEM-06)
   - `detect_rotational_device()` reads `/sys/block/{dev}/queue/rotational` on Linux.
   - WARN logged at startup if `rotational == 0` (SSD/flash).
   - **Limitation**: Wear-leveling firmware may redirect writes to spare blocks, leaving the original data intact. Full-disk encryption is the correct mitigation.

#### Summary of limitations

- `mlock` and `zeroize` do not protect against root/kernel-level access or live memory forensics.
- `zeroize` uses volatile writes to resist compiler optimization; it cannot guarantee zeroing in all compiler/architecture combinations, but the zeroize crate makes a best-effort guarantee.
- Swap protection is best-effort (`mlock` failures are not fatal).
- On CoW filesystems and SSDs, the three-pass overwrite is a signal of intent but not a guarantee. Full-disk encryption is the defense for those environments.

### Storage Backend Invariants (`prmana-agent/src/storage/router.rs`)

These invariants apply to the client-side agent daemon's credential persistence layer.

#### Backend selection

1. **Probe-based detection** — `StorageRouter::detect()` uses a full write → read → delete
   cycle (probe) to validate each backend. Constructor success alone is insufficient;
   some backends construct without error but fail on I/O (e.g., keyutils when the
   session keyring is not initialized, Secret Service when D-Bus is absent).

2. **Priority chain (Linux)**: Secret Service → keyutils user keyring → file fallback.
   **Priority chain (macOS)**: macOS Keychain → file fallback.

3. **Forced backend contract** — When `PRMANA_STORAGE_BACKEND` is set, probe only
   the requested backend and return `Err` on failure. Never fall through to the next
   backend. This ensures the operator's explicit choice is honored exactly.

4. **Probe key uniqueness** — Each probe uses a key with a PID + atomic counter suffix
   (`prmana-probe-{pid}-{seq}`). This prevents collision between parallel probes
   in tests or concurrent daemon starts.

#### Migration

5. **Atomic migration with rollback** — If any key write or read-back fails during
   migration, `rollback_migration()` deletes all keys already written to the destination
   before returning `Err`. Partial migrations must not be left behind.

6. **No file-to-file migration** — `maybe_migrate_from()` returns `NotApplicable`
   immediately when the destination is `BackendKind::File`. File-to-file migration
   is always a no-op.

7. **Source deletion is best-effort** — After a successful migration, source files are
   secure-deleted. Deletion failures are logged at `WARN` but do not abort the migration.
   The credential is already safe in the keyring.

8. **Migration trigger points** — Migration runs at daemon startup (`serve`) and at
   login. Both triggers are required: daemon startup handles long-running servers
   where users do not re-login; login handles the common upgrade path where a user
   installs a keyring after initial setup.

#### Fallback safety

9. **File fallback is always available** — `FileStorage::new()` must never fail silently.
   If even the file fallback fails, `detect()` returns `Err` and the daemon refuses
   to start rather than operating without credential storage.

10. **CoW/SSD advisory at startup** — On btrfs or APFS filesystems, and on SSD devices,
    the agent logs a `WARN` at startup. Operators on these configurations should use
    full-disk encryption (NIST SP 800-88 Rev 1, §2.5) as the primary protection for
    at-rest key material, and should prefer a keyring backend over file storage.

11. **Legacy key-name migration (prmana rename)** — `migrate_legacy_key_names()` runs at
    startup and login. It reads `unix-oidc-*` keys from the active backend, writes the
    same bytes under `prmana-*` names, and deletes the legacy keys only after the new-name
    write succeeds. Idempotent, safe to re-run. No credential values are logged.

See `docs/storage-architecture.md` for deployment guide and troubleshooting.

### IdP Failover Invariants (enterprise: `enterprise/crates/*/src/failover.rs`, ADR-020)

These invariants apply to the agent-side multi-IdP failover mechanism (Phase 41).

1. **Failover is availability-only**
   - Only connect timeout, TLS failure, DNS failure, and HTTP 5xx trigger failover
   - Policy errors (4xx), crypto failures, malformed responses from reachable endpoints NEVER trigger failover
   - This prevents failover from becoming a security bypass vector

2. **JWKS caches remain issuer-scoped across failover**
   - A JWKS key from issuer A must never validate tokens from issuer B
   - MIDP-07 invariant is preserved — failover does not merge or share caches

3. **In-flight requests never switch issuers mid-stream**
   - If a device flow poll or CIBA poll is in progress against primary and primary fails, that request fails
   - The next new request uses the failover target

4. **PAM does not perform failover**
   - PAM validates tokens against the token's own `iss` claim
   - Both issuers in a failover pair must be in PAM's `issuers` array
   - The agent owns all failover logic and OIDC endpoint selection

5. **Exhausted state fails closed**
   - When both primary and secondary are unavailable, authentication fails
   - `IDP_FAILOVER_EXHAUSTED` audit event (OCSF severity Critical) must trigger SIEM alerting

6. **Configuration validation at load time**
   - Same URL as both primary and secondary: rejected
   - Same URL as primary in multiple pairs: rejected
   - Both URLs must reference known issuers

### PAM Module Constraints

1. **No panics** - A panic in PAM can lock users out of their system
2. **Timeout handling** - Network calls must have timeouts
3. **Graceful degradation** - If OIDC fails, don't brick the system
4. **Audit logging** - All authentication attempts must be logged

### CRITICAL: Test Mode Security

> ⚠️ **NEVER ENABLE TEST MODE IN PRODUCTION** ⚠️

The `test-mode` feature flag and `PRMANA_TEST_MODE` environment variable **completely bypass signature verification**. This allows ANY attacker to forge tokens with arbitrary claims.

```rust
// This function exists for testing ONLY
// It skips ALL cryptographic verification
pub fn new_insecure_for_testing() -> Self { ... }
```

**Requirements:**
- Production binaries MUST be built without `--features test-mode`
- CI/CD pipelines SHOULD verify test features are not present in release builds
- Never recommend enabling test mode "for debugging" in production - use proper logging instead
- The environment variable check should use explicit string comparison (e.g., `== "1"` or `== "true"`), not just presence checking

## Coding Conventions

### Rust Idioms

```rust
// Use thiserror for error types
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Token expired at {0}")]
    TokenExpired(DateTime<Utc>),

    #[error("Invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer { expected: String, actual: String },
}

// Use tracing for structured logging
tracing::info!(
    username = %claims.preferred_username,
    issuer = %claims.iss,
    "Authentication successful"
);

// Prefer explicit error handling over unwrap/expect in production paths
let token = token_str.parse::<Token>()
    .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;
```

### Error Handling Philosophy

1. **In PAM paths**: Never panic, always return PAM error codes
2. **In CLI tools**: Can panic on truly unrecoverable errors (OOM, etc.)
3. **Log before returning errors**: The caller might not log details
4. **Include context**: "Failed to validate token" is useless; include why

### Security-Sensitive Code

When modifying security-sensitive code:

1. **Add comments explaining the security rationale**
2. **Reference relevant RFCs or CVEs** when applicable
3. **Consider timing attacks** for comparison operations
4. **Use constant-time comparison** for secrets

```rust
// Security: Use constant-time comparison to prevent timing attacks
use subtle::ConstantTimeEq;
if !expected_hash.ct_eq(&actual_hash).into() {
    return Err(ValidationError::InvalidSignature);
}
```

## Testing Requirements

### Test Matrix

| Platform | Status | Notes |
|----------|--------|-------|
| Ubuntu 22.04 | ✅ CI | Primary development target |
| Ubuntu 24.04 | ✅ CI | |
| RHEL 9 / Rocky 9 | 🧪 Community | SELinux considerations |
| Debian 12 | 🧪 Community | |
| Amazon Linux 2023 | 🧪 Community | |

| Provider | Status | Notes |
|----------|--------|-------|
| Keycloak | ✅ CI | Docker-based integration tests |
| Auth0 | ✅ CI | Requires secrets |
| Google Cloud Identity | ✅ CI | Requires secrets |
| Azure AD | 🧪 Community | Needs testing |
| Okta | 🧪 Community | Needs testing |

### Writing Tests

```rust
#[test]
fn test_dpop_proof_validation() {
    // Arrange: Set up test fixtures
    let proof = create_test_proof();
    let validator = DpopValidator::new();

    // Act: Perform the operation
    let result = validator.validate(&proof);

    // Assert: Check expectations
    assert!(result.is_ok());
}

#[test]
fn test_rejects_replayed_proof() {
    // Security test: Verify replay protection works
    let proof = create_test_proof();
    let validator = DpopValidator::new();

    // First use should succeed
    assert!(validator.validate(&proof).is_ok());

    // Second use should fail (replay)
    assert!(matches!(
        validator.validate(&proof),
        Err(DpopError::ReplayedProof)
    ));
}
```

### Security Testing

- **Fuzz testing**: `cargo fuzz` targets in `/fuzz/`
- **Dependency audit**: `cargo audit` in CI
- **SAST**: CodeQL analysis
- **Secret scanning**: Prevent credential leaks

## Deployment and Operations

### Break-Glass Access is MANDATORY

> ⚠️ **Never deploy OIDC authentication as the ONLY authentication path** ⚠️

Before deploying prmana to production servers:

1. **Configure a local break-glass account** - See `break_glass` in policy.yaml
2. **Test break-glass access works** when OIDC is disabled/unreachable
3. **Document credentials** in your organization's emergency procedures (secure vault, not wiki)
4. **Consider hardware tokens** (YubiKey) for break-glass authentication
5. **Regularly test break-glass** - Include in quarterly DR exercises

Getting locked out of servers because your IdP is down is a catastrophic, career-affecting failure mode. Plan for it.

### Operational Failure Modes

| Failure | Symptom | Resolution |
|---------|---------|------------|
| IdP unreachable | "Connection refused" or timeout errors | Check network, IdP status; break-glass if needed |
| JWKS endpoint error | "Failed to fetch JWKS" | IdP certificate issue or endpoint changed; check IdP config |
| Clock skew | "Token not yet valid" or "Token expired" (for fresh tokens) | Sync NTP; check server/client clocks |
| Certificate expiration | TLS errors to IdP | IdP needs to renew certs; temporary workaround via break-glass |
| User not provisioned | "User not found" after successful OIDC | Check SSSD/LDAP sync; verify username mapping |
| Rate limited | "Too many authentication attempts" | Wait for cooldown; check for brute force attacks |

### Log Locations and Troubleshooting

```bash
# PAM authentication logs (most Linux distros)
journalctl -u sshd -f
tail -f /var/log/auth.log      # Debian/Ubuntu
tail -f /var/log/secure        # RHEL/CentOS

# Check PAM module is loaded
grep pam_prmana /etc/pam.d/sshd

# Verify OIDC configuration
cat /etc/prmana/config.yaml

# Test IdP connectivity (from server)
curl -v https://your-idp.com/.well-known/openid-configuration

# Check for clock skew
date && curl -I https://your-idp.com 2>&1 | grep -i date
```

### Rollback Procedure

If the PAM module has issues, quickly revert:

```bash
# Option 1: Disable the PAM module (keeps it installed)
# Edit /etc/pam.d/sshd and comment out the pam_prmana line
sudo sed -i 's/^auth.*pam_prmana/#&/' /etc/pam.d/sshd

# Option 2: Uninstall completely
sudo rm /lib/security/pam_prmana.so  # or /lib64/security/
sudo rm /etc/pam.d/prmana  # if using include

# Option 3: Use break-glass account to access and fix
ssh breakglass@server  # Uses local password auth
```

**Pre-deployment checklist:**
- [ ] Break-glass account configured and tested
- [ ] Rollback procedure documented and accessible
- [ ] On-call team knows rollback steps
- [ ] Monitoring alerts for auth failures configured

### Error Message Verbosity

Security vs. debugging tradeoff for error messages:

**External-facing (returned to user/client):**
- Generic: "Authentication failed" - don't reveal why
- Never expose: internal paths, stack traces, IdP configuration details
- OK to include: request ID for correlation with logs

**Internal logs (server-side):**
- Verbose: Include full error details, token claims (excluding signatures), timing
- Structured logging: Use tracing spans for correlation
- Sensitive data: Never log full tokens, passwords, or private keys

```rust
// GOOD: Generic to user, detailed in logs
tracing::warn!(
    error = %e,
    username = %attempted_username,
    client_ip = %peer_addr,
    "Authentication failed"
);
return Err(AuthError::AuthenticationFailed);  // Generic

// BAD: Leaks information to attacker
return Err(AuthError::InvalidSignature(format!(
    "Expected key {} but got {}", expected_kid, actual_kid
)));
```

## Adding New OIDC Providers

### What's Needed

1. **Discovery endpoint** - Most providers support `/.well-known/openid-configuration`
2. **JWKS endpoint** - For token signature verification
3. **Supported claims** - `preferred_username`, `email`, `sub` at minimum
4. **DPoP support** - Check if provider supports RFC 9449 (optional but recommended)

### Integration Test Template

```rust
#[tokio::test]
#[ignore = "Requires NewProvider credentials"]
async fn test_newprovider_integration() {
    let config = ProviderConfig {
        issuer: "https://newprovider.com".into(),
        client_id: env::var("NEWPROVIDER_CLIENT_ID").unwrap(),
        // ...
    };

    // Test discovery
    let metadata = discover_metadata(&config.issuer).await.unwrap();
    assert!(metadata.token_endpoint.is_some());

    // Test token validation
    // ...
}
```

### Common Provider Quirks

| Provider | Quirk | Workaround |
|----------|-------|------------|
| Azure AD | `preferred_username` might be UPN not username | Username mapping config |
| Okta | Custom authorization server URLs | Configurable issuer |
| Google | Limited custom claims | Use `email` as identifier |
| Keycloak | Highly configurable but needs setup | Provide Docker Compose |

## Future Evolution

### OAuth/OIDC Landscape

The identity landscape is evolving. Be prepared for:

1. **IETF drafts becoming RFCs** - DPoP was draft, now RFC 9449
2. **New token binding mechanisms** - Watch for alternatives to DPoP
3. **Passkey/WebAuthn integration** - May complement OIDC flows
4. **Decentralized identity** - DIDs and verifiable credentials
5. **Post-quantum considerations** - Current EC curves may need replacement

### Configurable Security Modes (Issue #10)

We're moving toward configurable enforcement:

```toml
[security]
# strict: Reject anything suspicious
# warn: Log warnings but allow (current default)
# disabled: Skip check entirely (not recommended)
jti_enforcement = "warn"
dpop_required = "strict"
```

This allows enterprises to:
- Start permissive and tighten over time
- Accommodate IdPs with varying RFC compliance
- Meet different compliance requirements

### Planned Enhancements

**OSS:**
- [ ] Group-based access policies
- [ ] Session management (revocation)
- [ ] Centralized audit log shipping

**Enterprise (shipped):**
- [x] SCIM integration for user provisioning
- [x] Hardware key attestation
- [x] Token exchange (RFC 8693) for multi-hop SSH delegation

## Working with This Codebase

### Quick Start for Contributors

The workspace includes OSS crates at the root and enterprise crates under `enterprise/crates/`.

```bash
# Build OSS crates only
cargo build --workspace --exclude 'prmana-scim' --exclude 'prmana-kubectl'

# Build everything (OSS + enterprise)
cargo build --workspace

# Run tests (unit + integration where possible)
cargo test --workspace

# Run specific crate tests
cargo test -p prmana-core
cargo test -p pam-prmana

# Check for security issues
cargo audit
cargo clippy -- -D warnings

# Format code
cargo fmt --all
```

### Key Files to Understand

| File | Purpose | Security-Critical |
|------|---------|-------------------|
| `prmana-core/src/oidc/jwks.rs` | Shared JWKS fetching/caching types | ⚠️ Yes |
| `prmana-core/src/oidc/discovery.rs` | OIDC discovery metadata | ⚠️ Yes |
| `pam-prmana/src/lib.rs` | PAM entry points | ⚠️ Yes |
| `pam-prmana/src/oidc/dpop.rs` | DPoP validation | ⚠️ Yes |
| `pam-prmana/src/oidc/validation.rs` | Token validation | ⚠️ Yes |
| `pam-prmana/src/oidc/jwks.rs` | Re-export shim over prmana-core | Moderate |
| `pam-prmana/src/config.rs` | Configuration parsing | Moderate |
| `prmana-agent/src/main.rs` | Agent daemon entry point | Moderate |

### Common Tasks

**Adding a new configuration option:**
1. Add to `config.rs` with appropriate defaults
2. Update example configs in `examples/`
3. Document in README and man pages
4. Consider security implications

**Fixing a security issue:**
1. Create a private security advisory first (if applicable)
2. Write a test that demonstrates the vulnerability
3. Fix with minimal changes
4. Document the fix with CVE/advisory reference
5. Consider backporting to maintenance branches

**Updating dependencies:**
1. Run `cargo update` for patch updates
2. For major updates, check changelogs for breaking changes
3. Run full test suite
4. Check for new security advisories

### Dependency Evaluation Criteria

For a security-critical PAM module, new dependencies require scrutiny:

**Before adding a dependency, evaluate:**

| Criterion | Questions to Ask |
|-----------|-----------------|
| **Necessity** | Can we do this with std or existing deps? Is the complexity worth it? |
| **Maintenance** | Active maintainer? Recent commits? Responsive to issues? |
| **Security track record** | Past CVEs? How were they handled? Security policy? |
| **Supply chain** | Reputable author/org? Verified on crates.io? |
| **Transitive deps** | What does it pull in? Any known-bad dependencies? |
| **Size/complexity** | Is it minimal or kitchen-sink? More code = more attack surface |

**Trusted dependencies** (well-audited, critical path):
- `ring` / `rustls` - Cryptographic operations
- `jsonwebtoken` - JWT parsing and validation
- `tokio` - Async runtime
- `tracing` - Logging infrastructure

**Extra scrutiny required** (directly handles untrusted input):
- Any new JWT/JOSE library
- Any new HTTP client
- Any serialization library (serde is fine, others need review)

**Responding to dependency CVEs:**
1. Assess impact - does the vulnerability affect our usage?
2. Check if patched version exists
3. If no patch: evaluate workaround or temporary fork
4. Update ASAP, don't wait for scheduled dependency updates
5. Document the CVE response in commit message

## Philosophy Reminders

When making decisions, remember:

1. **Would this annoy a user trying to do their job?** - If yes, find a better way
2. **Would this create work for IT admins?** - If yes, automate it
3. **What's the most conservative option that still works?** - Default to that
4. **If this fails, how does the user recover?** - Make it obvious
5. **Would we be comfortable if this code was audited?** - Write for scrutiny

## Contact and Contribution

- **Issues**: GitHub Issues for bugs and features
- **Security**: See SECURITY.md for vulnerability reporting
- **Testing**: See `docs/community-testing-guide.md` for testing on various platforms

---

*This document is part of the prmana project and should evolve with the codebase. When making significant architectural changes, please update this guide.*
