# Installing prmana on Debian / Ubuntu

Supported: Debian 12, Ubuntu 22.04, Ubuntu 24.04.

## Add the repository

```bash
# Install the signing key
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://prodnull.github.io/prmana/packages/gpg/prmana.gpg \
    | sudo tee /etc/apt/keyrings/prmana.gpg > /dev/null

# Add the sources.list entry (arch= is mandatory — prevents downloading wrong-arch index files)
echo "deb [arch=amd64,arm64 signed-by=/etc/apt/keyrings/prmana.gpg] \
https://prodnull.github.io/prmana/packages/apt stable main" \
    | sudo tee /etc/apt/sources.list.d/prmana.list

sudo apt update
```

## Install

```bash
sudo apt install prmana
```

This installs the `prmana-agent` daemon and the `pam_prmana.so` PAM module.

## Verify signing (optional but recommended)

Cross-check the key you downloaded against `keys.openpgp.org`:

```bash
gpg --keyserver keys.openpgp.org --recv-keys 4A2F0B8412F43809A09CB922CB7756F8AE011BAF
gpg --fingerprint prodnull@proton.me
# Expected fingerprint: 4A2F 0B84 12F4 3809 A09C  B922 CB77 56F8 AE01 1BAF
```

## Upgrade

```bash
sudo apt update
sudo apt upgrade prmana
```

User configuration under `/etc/prmana/` is preserved across upgrades.

## Troubleshooting

**`NO_PUBKEY` on apt update** — the key was not installed correctly. Re-run
the install step. If you see `The following signatures were invalid: NODATA`,
you likely saved the ASCII-armored form instead of the binary form — replace
`/etc/apt/keyrings/prmana.gpg` with the binary version from the URL above.

**`E: Failed to fetch ... 404 Not Found`** — the repo does not yet have this
architecture. Check that the `arch=` clause in sources.list.d matches what
the repo ships (currently `amd64,arm64`).

**`W: Conflicting distribution: ... was 'stable' but now is 'stable'`** — this
warning can appear after a `Release` file is regenerated with the same values.
It is harmless; running `apt update` a second time clears it.

## Notes on key format

Modern APT (Debian 11+, Ubuntu 22.04+) requires the signing key in binary
(dearmored) form at `/etc/apt/keyrings/`. The URL above serves the binary
form directly. If you use `curl | gpg --dearmor` instead, the result is
identical but requires `gpg` to be installed before the repo is added.
