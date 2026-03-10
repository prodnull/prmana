# Storage Architecture

This document covers the unix-oidc-agent storage subsystem: how the backend is
selected, how credentials are migrated between backends, and how to deploy and
troubleshoot on headless (no-GUI) servers.

## Overview

The agent stores four credential keys:

| Key | Contents |
|-----|----------|
| `unix-oidc-dpop-private` | P-256 DPoP private key (EC scalar, SEC1 DER-encoded) |
| `unix-oidc-access-token` | OAuth access token (JWT) |
| `unix-oidc-refresh-token` | OAuth refresh token |
| `unix-oidc-token-metadata` | OIDC config for refresh (issuer, client ID, expiry, etc.) |

All keys are stored with `0600` permissions (or the equivalent keyring ACL).
Key material is subject to the memory protection invariants described in CLAUDE.md
(mlock, zeroize-on-drop, secure delete).

## Backend Selection

`StorageRouter::detect()` selects the best available backend via a probe-based
detection chain. A **probe** is a full write → read → delete cycle using a
sentinel key. Constructor success alone is insufficient — some backends appear
to construct successfully but fail on I/O.

### Detection chain (priority order)

```
UNIX_OIDC_STORAGE_BACKEND set?
    Yes → probe only the requested backend; return Err on failure (no fallthrough)
    No  → auto-detection:

    1. Linux: Secret Service (D-Bus / libsecret)        ← preferred on Linux desktop
    2. Linux: keyutils user keyring (@u)                ← headless server default
    3. macOS: macOS Keychain Services                    ← preferred on macOS
    4. File storage (plaintext, 0600, secure-delete)     ← last resort
```

Diagram:

```
StorageRouter::detect()
        │
        ├─ UNIX_OIDC_STORAGE_BACKEND set? ──► probe forced backend
        │                                         success → use it
        │                                         failure → Err (no fallthrough)
        │
        └─ auto-detection
                │
                ├─[Linux] Secret Service probe ──► success → BackendKind::SecretService
                │         (D-Bus available?)        failure → warn + continue
                │
                ├─[Linux] keyutils probe ──────────► success → BackendKind::KeyutilsUser
                │         (@u keyring available?)    failure → warn + continue
                │
                ├─[macOS] macOS Keychain probe ─────► success → BackendKind::MacOsKeychain
                │                                     failure → warn + continue
                │
                └─ FileStorage::new() ──────────────► BackendKind::File (last resort)
```

### Environment variable override

Set `UNIX_OIDC_STORAGE_BACKEND` to one of:

| Value | Backend |
|-------|---------|
| `secret-service` | Secret Service over D-Bus (Linux only) |
| `keyutils` | Linux kernel keyutils `@u` (Linux only) |
| `macos-keychain` | macOS Keychain Services (macOS only) |
| `file` | Plain-file fallback |

If the forced backend fails its probe, `detect()` returns `Err` and the daemon
will not start. Use this for diagnosis, not for production pinning.

## Migration

### Why migration exists

Prior to the storage router, all credentials were stored in plain files under
`$XDG_DATA_HOME/unix-oidc-agent/` (or `~/.local/share/unix-oidc-agent/` if
`XDG_DATA_HOME` is unset). When a keyring backend becomes available (e.g., after
installing `gnome-keyring` on a previously headless system), the agent automatically
migrates credentials to the new backend on its first run.

### When migration runs

Migration is attempted at two points:

1. **Daemon startup** (`unix-oidc-agent serve`) — before loading any in-memory state.
2. **Login** (`unix-oidc-agent login`) — after a successful authentication, giving
   the upgraded backend an opportunity to absorb new credentials immediately.

### Migration semantics

`StorageRouter::maybe_migrate()` internally creates a `FileStorage` instance pointing
at the default data directory and then calls `maybe_migrate_from(&file_storage)`.

`maybe_migrate_from()`:

1. If the current backend **is** `File`, returns `NotApplicable` immediately — no
   file-to-file migration.
2. Collects whichever of the 4 credential keys exist in the file store.
3. If none exist, returns `NotApplicable`.
4. For each key:
   - Writes to the new backend.
   - Reads back and compares (verifies silent write failures).
   - On any mismatch or error, calls `rollback_migration()` — deletes all keys
     previously written to the new backend — and returns `Err`.
5. After all keys are verified, secure-deletes each from the file source. Deletion
   failures are best-effort: logged at `WARN`, do not abort the migration.
6. Updates `migration_status` to `Migrated(n)` where `n` is the key count.

### Migration status

`unix-oidc-agent status` shows the migration outcome:

| Status | Meaning |
|--------|---------|
| `migrated` | Credentials were copied from file storage to the current keyring |
| `not migrated` | Migration ran but found no credentials to move |
| `n/a` | Migration is not applicable (backend is file, or first run) |

## Headless Deployment Guide

### Recommended backend: keyutils

For headless servers (no D-Bus session bus), the `keyutils` user keyring (`@u`) is
the recommended backend. It is provided by the Linux kernel keyutils subsystem
(CONFIG_KEYS=y, present in all major distributions since kernel 2.6.10).

**Verify keyutils availability:**

```bash
keyctl show @u          # list current user keyring contents
keyctl list @s          # show session keyring (for comparison)
```

The agent probes keyutils automatically. If the probe succeeds, `unix-oidc-agent
status` will show `Storage: keyring (keyutils @u)`.

### Persistence across daemon restarts

The Linux kernel user keyring (`@u`) is **persistent** within a login session.
Credentials survive daemon restarts (stop and start `unix-oidc-agent serve`) without
requiring re-authentication — provided the user session remains active.

**Keyring lifetime and expiry:**

The kernel defines a timeout for persistent keyrings via:

```
/proc/sys/kernel/keys/persistent_keyring_expiry   # default: 259200 (72 hours)
```

This is the idle expiry for the *persistent* keyring (`@persistent`), not the user
keyring (`@u`). The user keyring (`@u`) lifetime is tied to the user session. On
systemd-based systems, `loginctl` session management governs when `@u` is destroyed.

For long-running server deployments, consider:
- Using PAM `pam_keyinit.so` to ensure the keyring is initialized at login.
- Token refresh via `unix-oidc-agent refresh` (or `Refresh` IPC request) before
  the access token expires.

### Container deployments

Containers sharing the host's user namespace inherit the host user keyring. Containers
with isolated user namespaces get their own keyring — credentials stored inside a
container will not persist when the container is restarted unless the keyring is
explicitly persisted (e.g., via a volume or secrets manager).

The probe chain handles containers naturally: if keyutils probes fail (e.g., in a
minimal container without the keyutils subsystem), the agent falls back to file
storage. Set `UNIX_OIDC_STORAGE_BACKEND=file` to bypass probing in environments
where keyutils is unavailable and avoid probe-failure log noise.

## Status Reporting

`unix-oidc-agent status` reports storage information in two modes:

**Daemon running:**

```
Status: Logged in
  User: alice
  DPoP thumbprint: <JWK thumbprint>
  Token expires in: 3599s
  Memory protection: mlock active: key pages memory-locked
  Storage: keyring (Secret Service)
  Migration: n/a
```

**Daemon not running (non-daemon path):**

```
Status: Agent not running
  Error: Connection refused
  Start the agent with: unix-oidc-agent serve
  Storage: keyring (keyutils @u)
  Migration: n/a
  DPoP keypair: stored
  Access token: stored
```

The `Storage` line reflects the backend detected at query time. The `Migration` line
reflects the most recent migration outcome from the daemon startup.

## Troubleshooting

### Secret Service probe fails

**Symptom:** `unix-oidc-agent serve` logs `Secret Service probe failed`.

**Cause:** No D-Bus session bus is running, or `gnome-keyring`/`kwallet` is not
started. Common on headless servers and SSH sessions without a display.

**Resolution:**
- Headless servers: expected — the agent falls back to keyutils automatically.
- Desktop sessions: start `gnome-keyring-daemon --start --daemonize` or ensure
  your display manager starts it automatically.
- To force keyutils on a desktop: `UNIX_OIDC_STORAGE_BACKEND=keyutils unix-oidc-agent serve`.

### D-Bus unavailable in SSH sessions

**Symptom:** Probe fails only via SSH, but works in a local terminal.

**Cause:** The D-Bus session bus is tied to the desktop session. SSH sessions do not
inherit `DBUS_SESSION_BUS_ADDRESS`.

**Resolution:** Expected fallback behavior. The agent will use keyutils or file
storage automatically.

### Migration not triggering

**Symptom:** `unix-oidc-agent status` shows `Storage: keyring (...)` but
`Migration: n/a`, even though file credentials exist.

**Possible causes:**
1. The file credentials are in a non-default location. Check `XDG_DATA_HOME`.
2. `FileStorage::new()` failed (e.g., home directory permissions). Check logs.
3. File credentials were already migrated in a previous run (files deleted after
   successful migration).

**Debug with:** `RUST_LOG=debug unix-oidc-agent serve --foreground 2>&1 | grep -i migrat`

### Keyutils probe fails

**Symptom:** `unix-oidc-agent serve` logs `keyutils probe failed`.

**Cause:** The kernel keyutils subsystem is not available or the user keyring is
not initialized.

**Resolution:**
1. Verify: `keyctl show @u` — if this fails, keyutils is unavailable.
2. In containers: run `keyctl new_session` or check if the host exposes keyutils
   to the container's user namespace.
3. Force file storage: `UNIX_OIDC_STORAGE_BACKEND=file`.

### Diagnostic: force a specific backend

```bash
# Test a specific backend without modifying configuration
UNIX_OIDC_STORAGE_BACKEND=keyutils unix-oidc-agent status
UNIX_OIDC_STORAGE_BACKEND=file unix-oidc-agent status
```

If the forced backend probe fails, the status command will error with a descriptive
message indicating which backend was probed and why it failed.

## Security Considerations

### File fallback

When no keyring is available, credentials are stored in plain files under
`$XDG_DATA_HOME/unix-oidc-agent/` with permissions `0600`. On deletion, the agent
applies a three-pass DoD 5220.22-M overwrite (random, complement, random) followed
by `unlink`.

**Limitations:**
- On **CoW filesystems** (btrfs, APFS): the overwrite may not modify the original
  data blocks. The agent logs a `WARN` at startup and before each deletion on CoW
  filesystems. Full-disk encryption is the correct mitigation (NIST SP 800-88
  Rev 1, §2.5).
- On **SSDs/flash storage**: wear-leveling firmware may redirect writes to spare
  blocks, leaving original data intact. The agent logs a `WARN` on SSDs. Again,
  full-disk encryption is the correct mitigation.
- The three-pass overwrite is a **signal of intent** and best-effort. Do not rely
  on it as the sole protection for sensitive material on non-rotating media.

### Keyring preference

The keyring is strongly preferred over file storage because:
- Key material is stored in kernel or daemon memory, not on disk.
- The keyring enforces per-user ACLs at the OS level.
- On Secret Service: credentials are encrypted by the keyring daemon.
- On keyutils: credentials are kernel-managed and not accessible to other users
  without CAP_SYS_ADMIN.

### Migration file deletion

After a successful migration from file to keyring, source files are secure-deleted
(three-pass overwrite + unlink). Deletion failures are logged at `WARN` but do not
abort the migration — the credential already exists in the keyring. On CoW/SSD
systems, the file overwrite limitations described above apply.

## Architecture Diagram

```
unix-oidc-agent serve / login
         │
         ▼
StorageRouter::detect()
         │
    ┌────┴────────────────────────────────┐
    │  UNIX_OIDC_STORAGE_BACKEND set?     │
    │  Yes → forced probe (no fallthrough)│
    │  No  → auto probe chain             │
    └────┬────────────────────────────────┘
         │
         ▼
    ┌──────────────────────────────────────────┐
    │  Probe chain (auto mode)                 │
    │                                          │
    │  [Linux]  Secret Service ──► OK? ─ yes ──┼──► BackendKind::SecretService
    │                             │ no         │
    │  [Linux]  keyutils       ──► OK? ─ yes ──┼──► BackendKind::KeyutilsUser
    │                             │ no         │
    │  [macOS]  macOS Keychain ──► OK? ─ yes ──┼──► BackendKind::MacOsKeychain
    │                             │ no         │
    │           FileStorage    ──► always OK ──┼──► BackendKind::File
    └──────────────────────────────────────────┘
         │
         ▼
    StorageRouter { kind, migration_status, backend }
         │
         ├── maybe_migrate()  ──► copies file creds to keyring (if applicable)
         │
         └── store/retrieve/delete  ──► delegated to selected backend
```
