# Hardware Key Setup Guide

This guide covers setting up hardware-backed DPoP signing keys with `prmana-agent`.

## Overview

`prmana-agent` supports three signer backends:

| Backend | Flag | Key storage | Platform |
|---------|------|-------------|----------|
| `software` (default) | `--signer software` | Encrypted on disk / in keyring | All |
| YubiKey PIV | `--signer yubikey:<slot>` | Non-exportable on YubiKey | Linux, macOS |
| TPM 2.0 | `--signer tpm` | Non-exportable in TPM | Linux |

Hardware signers store the DPoP private key directly on the device. **The key never leaves the hardware.** Even if your machine is compromised, the signing key cannot be extracted.

Hardware support is not included in the default build. Enable it with cargo feature flags:

```bash
# YubiKey support
cargo build --features yubikey

# TPM support (Linux only)
cargo build --features tpm

# Both
cargo build --features yubikey,tpm
```

---

## YubiKey PIV Setup

### Prerequisites

- YubiKey 5 series (or any PIV-capable YubiKey with EC key support)
- `pcscd` running (PC/SC smart card daemon)
- `libykcs11` installed (YubiKey PKCS#11 provider)

### Installation

**Ubuntu / Debian:**

```bash
sudo apt install pcscd libykcs11 yubico-piv-tool
sudo systemctl enable --now pcscd
```

**RHEL / Rocky / Fedora:**

```bash
sudo dnf install pcsc-lite ykpers yubico-piv-tool
sudo systemctl enable --now pcscd
```

**macOS:**

```bash
brew install yubico-piv-tool
# pcscd is provided by the OS as com.apple.ifdreader — no separate install needed.
```

### Supported PIV slots

| Slot | Recommended use | Notes |
|------|----------------|-------|
| `9a` | Authentication (recommended) | Default PIV authentication slot |
| `9c` | Digital Signature | Typically requires touch confirmation |
| `9d` | Key Management | Generally used for key agreement |
| `9e` | Card Authentication | No PIN required by default |

Use slot `9a` unless you have a specific reason to use another slot.

### Provisioning

Generate a P-256 key on the YubiKey:

```bash
prmana-agent provision --signer yubikey:9a
```

This calls `C_GenerateKeyPair` with `CKM_EC_KEY_PAIR_GEN` and P-256 curve OID `1.2.840.10045.3.1.7` (RFC 5480) via the PKCS#11 interface (PKCS#11 v2.40 §2.3.6).

If slot `9a` already contains a P-256 key, the existing key is adopted without regeneration. If the slot contains an incompatible key type, an error is returned with guidance.

Output on success:

```
Provisioning key on yubikey (slot 9a)...
Key provisioned successfully on yubikey (slot 9a).
DPoP thumbprint: abc123...
Run `prmana-agent login --signer yubikey:9a` to authenticate.
```

### Authentication

```bash
prmana-agent login --signer yubikey:9a --issuer https://your-idp.example.com
```

You will be prompted for the YubiKey PIV PIN on first use (or after the cache timeout expires).

### PIN management

| Default | Value | Notes |
|---------|-------|-------|
| PIV PIN | `123456` | Change immediately after first use |
| PUK | `12345678` | Unblocks PIN if locked |
| Management key | See YubiKey docs | Not needed for DPoP use |

**Change the default PIN immediately:**

```bash
ykman piv access change-pin
```

**PIN lockout and recovery:**

- After **3 incorrect PIN attempts**, the PIV application locks. Unblock with the PUK:

  ```bash
  ykman piv access unblock-pin
  ```

- After **3 incorrect PUK attempts**, the PIV application is **permanently locked**. Recovery requires a factory reset, which **destroys all PIV keys**:

  ```bash
  ykman piv reset
  ```

  After a factory reset, re-provision with `prmana-agent provision --signer yubikey:9a`.

**Touch confirmation (optional, high security):**

```bash
# Require physical touch for every signing operation
ykman piv keys set-touch-policy --slot 9a always
```

---

## TPM 2.0 Setup

### Prerequisites

- TPM 2.0 hardware (physical chip or virtual TPM / vTPM)
- `tpm2-abrmd` resource manager (recommended for multi-process access)
- `tpm2-tools` (optional, for diagnostics)

### Installation

**Ubuntu / Debian:**

```bash
sudo apt install tpm2-abrmd tpm2-tools
sudo systemctl enable --now tpm2-abrmd
```

**RHEL / Rocky / Fedora:**

```bash
sudo dnf install tpm2-abrmd tpm2-tools
sudo systemctl enable --now tpm2-abrmd
```

### Verify TPM availability

```bash
# Check TPM manufacturer info
tpm2_getcap properties-fixed

# Verify P-256 curve is available (required by prmana-agent)
tpm2_getcap ecc-curves | grep NIST_P256
```

### Provisioning

```bash
prmana-agent provision --signer tpm
```

This performs the following steps:

1. **P-256 capability probe** (`HW-05`): queries `TPM2_CC_GetCapability(ECC_CURVES)`. If `TPM_ECC_NIST_P256` is absent, provisioning fails with a clear error before any key operation.
2. Creates a non-exportable P-256 ECDSA signing key under the Owner hierarchy.
3. Persists the key at handle `0x81000001` (configurable; see Configuration below).

The persistent handle survives reboots. Re-provisioning is only needed if the handle is explicitly evicted.

### Authentication

```bash
prmana-agent login --signer tpm --issuer https://your-idp.example.com
```

### Cloud vTPM notes

| Cloud | vTPM availability | P-256 support | Notes |
|-------|-----------------|---------------|-------|
| AWS Nitro | Nitro instances with NitroTPM | Generally yes | Verify with `prmana-agent provision --signer tpm` |
| GCP Shielded VM | Enabled by default | Yes | |
| Azure Trusted Launch | `security.trustedLaunch.enabled: true` | Yes (FW >= 2022) | |

Always run `prmana-agent provision --signer tpm` on a new instance type before deploying. The command probes P-256 availability and fails fast if unsupported.

---

## Configuration

Hardware signer behavior is controlled by `~/.config/prmana/signer.yaml` (user-level) or `/etc/prmana/signer.yaml` (system-level). The user config takes precedence.

```yaml
yubikey:
  # Path to the PKCS#11 provider library.
  # Defaults:
  #   Linux: /usr/lib/libykcs11.so (or /usr/lib/x86_64-linux-gnu/libykcs11.so)
  #   macOS: /usr/local/lib/libykcs11.dylib
  pkcs11_library: /usr/lib/libykcs11.so

  # Seconds to cache the PIN after first entry. Default: 28800 (8 hours).
  # Set to 0 to disable caching and always prompt.
  pin_cache_timeout: 28800

tpm:
  # TCTI (TPM Command Transmission Interface) string.
  # Default: tabrmd (resource manager daemon, recommended for multi-process use).
  # Other values: device:/dev/tpm0 (direct kernel device), mssim (TPM simulator).
  tcti: tabrmd

  # TPM persistent key handle. Default: 0x81000001 (first user-space persistent handle).
  # Must be in the range 0x81000000–0x8100FFFF (Owner hierarchy persistent handles,
  # per TCG TPM 2.0 Part 2 §20.2.2).
  persistent_handle: 0x81000001

  # Seconds to cache the TPM PIN/passphrase after first entry. Default: 28800.
  pin_cache_timeout: 28800
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No YubiKey detected (is pcscd running?)` | `pcscd` not running | `sudo systemctl start pcscd` |
| `No P-256 key found in YubiKey PIV slot 9a` | Slot empty or incompatible key type | Run `prmana-agent provision --signer yubikey:9a` |
| `YubiKey PIN is locked` | 3 incorrect PIN attempts | `ykman piv access unblock-pin` (requires PUK) |
| `YubiKey PIN and PUK are both locked` | 3 incorrect PUK attempts after PIN lock | `ykman piv reset` (destroys all PIV keys) — then re-provision |
| `PCSC exclusive lock` / `CKR_TOKEN_NOT_PRESENT` | Another process holds the PCSC lock | Close `gpg-agent`, `ssh-agent` with PKCS#11, or any PCSC application |
| `Hardware signer 'yubikey:9a' unavailable` at daemon start | YubiKey unplugged | Insert YubiKey and run `prmana-agent login --signer yubikey:9a` |
| `YubiKey support not compiled in` | Built without `--features yubikey` | `cargo build --features yubikey` |
| `TPM not available` | `tpm2-abrmd` not running | `sudo systemctl start tpm2-abrmd` |
| `This TPM does not support P-256` | TPM lacks `TPM_ECC_NIST_P256` | Use software signer on this device |
| `TPM support not compiled in` | Built without `--features tpm` | `cargo build --features tpm` |
| `Hardware signer 'tpm' unavailable` at daemon start | TPM or abrmd unavailable | `sudo systemctl start tpm2-abrmd`, then re-login |
| `TPM support is only available on Linux` | macOS build with `--features tpm` | TPMs are Linux-only; use YubiKey or software on macOS |

### Checking PKCS#11 library path

If `prmana-agent` cannot find `libykcs11`:

```bash
# Ubuntu/Debian
dpkg -L libykcs11 | grep libykcs11

# RHEL/Fedora
rpm -ql ykpers | grep libykcs11

# macOS (homebrew)
find /usr/local/lib /opt/homebrew/lib -name "libykcs11*" 2>/dev/null
```

Set the correct path in `~/.config/prmana/signer.yaml`.

---

## Security Considerations

### Key non-exportability

Hardware keys are generated with `CKA_EXTRACTABLE = FALSE` (YubiKey PKCS#11) or as non-exportable objects (TPM Owner hierarchy). The DPoP private key material is never accessible to software. Even a root-level attacker on the host cannot extract it.

### No silent fallback

If a hardware signer is specified in token metadata but the device is unavailable at daemon startup, the agent logs an `ERROR` and starts without signing capability. Authentication will fail until the user re-inserts the device and re-runs `prmana-agent login --signer <spec>`. There is no silent fallback to a software key.

### PIN caching

The PIN is cached in memory using `secrecy::SecretString` (RFC 9449 §5 recommends protection of signing material). The cache expires after the configured timeout (default: 8 hours). The cache is cleared immediately if the device returns `CKR_PIN_INCORRECT`.

### TPM key binding

TPM P-256 keys are bound to the specific TPM chip by the TPM's endorsement hierarchy. Moving a machine image to a new host, or replacing the physical TPM, requires re-provisioning with `prmana-agent provision --signer tpm` and re-authenticating with `prmana-agent login --signer tpm`.

### DPoP proof binding (RFC 9449)

DPoP proofs are bound to the HTTP method (`htm`) and URI (`htu`) of the request. For SSH authentication, the method is `SSH` and the URI is the server hostname. Even if an attacker intercepts a proof, it cannot be replayed to a different server or method.

---

*References: RFC 9449 (DPoP), PKCS#11 v2.40, TCG TPM 2.0 Part 2*
