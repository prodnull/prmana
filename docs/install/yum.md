# Installing prmana on Rocky Linux / Amazon Linux 2023 / Fedora

Supported: Rocky 9, Amazon Linux 2023, Fedora 39+.

## Add the repository

```bash
# Import the signing key
sudo rpm --import https://prodnull.github.io/unix-oidc/packages/gpg/prmana.gpg

# Write the repo file
sudo tee /etc/yum.repos.d/prmana.repo <<'EOF'
[prmana]
name=prmana
baseurl=https://prodnull.github.io/unix-oidc/packages/rpm/stable/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://prodnull.github.io/unix-oidc/packages/gpg/prmana.gpg
EOF
```

## Install

```bash
sudo dnf install prmana
```

This installs the `prmana-agent` daemon and the `pam_prmana.so` PAM module.

## Upgrade

```bash
sudo dnf upgrade prmana
```

User configuration under `/etc/prmana/` is preserved across upgrades.

## Verify signing (optional but recommended)

```bash
rpm -qa gpg-pubkey | xargs rpm -qi gpg-pubkey | grep -A2 prmana
# Look for: Key ID CB7756F8AE011BAF (last 16 hex digits of fingerprint)
# Full fingerprint: 4A2F 0B84 12F4 3809 A09C  B922 CB77 56F8 AE01 1BAF
```

## Troubleshooting

**`Error: GPG check FAILED`** — the key was not imported correctly. Re-run
the `rpm --import` step. Verify with:

```bash
rpm -qa gpg-pubkey | xargs rpm -qi gpg-pubkey | grep -A5 prmana
```

**`repomd.xml.asc` signature failure** — `repo_gpgcheck=1` verifies the
repository metadata signature. If this fails, the `repomd.xml.asc` file
may not have been published yet (e.g., first publish). Try:

```bash
sudo dnf makecache --refresh
```

**Amazon Linux 2023** — AL2023 uses `dnf` by default and the above commands
work without modification. `yum` is an alias for `dnf` on AL2023.

## Notes on `$basearch`

The `$basearch` variable in the `baseurl` is expanded by `dnf`/`yum` to
the local machine's base architecture (`x86_64` or `aarch64`). This is
standard DNF behavior — do not replace it with a literal string in the
repo file, or packages for the wrong architecture will not be found.
