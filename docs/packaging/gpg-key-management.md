# GPG Key Management — prmana Package Signing

**Audience:** prmana maintainers with access to the 1Password vault and GitHub
repository secrets.

---

## Active Key

| Field | Value |
|-------|-------|
| **Fingerprint** | `4A2F0B8412F43809A09CB922CB7756F8AE011BAF` |
| **Key ID (short)** | `CB7756F8AE011BAF` |
| **UID** | `prmana Package Signing <prodnull@proton.me>` |
| **Algorithm** | Ed25519 (EdDSA, Curve25519) |
| **Created** | 2026-04-11 |
| **Expiry** | None |
| **Passphrase** | None (required for unattended CI signing) |
| **Keyserver** | `keys.openpgp.org` |
| **1Password vault** | `prmana GPG signing key (v1.0.0)` |

---

## Key Generation

The key was generated on a trusted workstation using:

```bash
mkdir -p /tmp/prmana-gpg && cd /tmp/prmana-gpg
export GNUPGHOME=/tmp/prmana-gpg

gpg --batch --gen-key <<'EOF'
Key-Type: EDDSA
Key-Curve: Ed25519
Key-Usage: sign
Name-Real: prmana Package Signing
Name-Email: prodnull@proton.me
Expire-Date: 0
%no-protection
EOF

# Capture fingerprint
FINGERPRINT=$(gpg --with-colons --list-keys prodnull@proton.me \
    | awk -F: '/^fpr:/ { print $10; exit }')
echo "Fingerprint: $FINGERPRINT"
```

---

## Exported Key Material

Three files were exported and stored in 1Password:

```bash
# Armored public (for docs and keys.openpgp.org submission)
gpg --armor --export "$FINGERPRINT" > prmana-public.asc

# Binary public (for /etc/apt/keyrings/ — modern APT requires binary form)
gpg --export "$FINGERPRINT" > prmana-public.gpg

# Armored private (for GitHub Secrets — NEVER log or echo this)
gpg --armor --export-secret-keys "$FINGERPRINT" > prmana-private.asc
```

The public key files (`prmana-public.asc`, `prmana-public.gpg`) are committed
to the repository at `packaging/repo/` and published at:

- `https://prodnull.github.io/prmana/packages/gpg/prmana.gpg` (binary)
- `https://prodnull.github.io/prmana/packages/gpg/prmana.asc` (armored)

**The private key (`prmana-private.asc`) is NEVER committed to the repository.**

---

## 1Password Storage

Vault item: **prmana GPG signing key (v1.0.0)**

Attachments:
- `prmana-private.asc` — ASCII-armored private key
- `prmana-public.asc` — ASCII-armored public key
- `prmana-public.gpg` — Binary (dearmored) public key

Fields:
- `fingerprint` — `4A2F0B8412F43809A09CB922CB7756F8AE011BAF`
- `generated` — 2026-04-11
- `note` — "No passphrase. CI import via crazy-max/ghaction-import-gpg@v6. See docs/packaging/gpg-key-management.md."

---

## GitHub Secrets

| Secret Name | Value | Used by |
|-------------|-------|---------|
| `PRMANA_GPG_PRIVATE_KEY` | ASCII-armored private key block (including `-----BEGIN PGP PRIVATE KEY BLOCK-----` header and footer) | `publish-repo.yml` via `crazy-max/ghaction-import-gpg@v6` |
| `PRMANA_GPG_FINGERPRINT` | `4A2F0B8412F43809A09CB922CB7756F8AE011BAF` | `publish-repo.yml` (passed to `--local-user`) |

To view (masked) in the GitHub UI:
`https://github.com/prodnull/prmana/settings/secrets/actions`

---

## CI Import

The private key is imported in `publish-repo.yml` via the
`crazy-max/ghaction-import-gpg@v6` action:

```yaml
- name: Import GPG signing key
  id: import_gpg
  uses: crazy-max/ghaction-import-gpg@v6
  with:
    gpg_private_key: ${{ secrets.PRMANA_GPG_PRIVATE_KEY }}
```

This action:
- Imports the key into a temporary GPG keyring on the CI runner
- Does **not** echo the key material to logs
- Outputs `fingerprint`, `keyid`, `name`, `email` as step outputs
- The `fingerprint` output is used with `--local-user` in signing commands

The key has **no passphrase** because `crazy-max/ghaction-import-gpg` supports
passphrase via a separate `passphrase` input, but a passphrase-free key is
simpler for fully unattended signing.

---

## Signing Operations

**APT `InRelease` (clearsign):**

```bash
gpg --batch --yes --clearsign \
    --local-user "$FINGERPRINT" \
    --output InRelease \
    Release
```

**APT `Release.gpg` (detached signature):**

```bash
gpg --batch --yes --armor --detach-sign \
    --local-user "$FINGERPRINT" \
    --output Release.gpg \
    Release
```

**RPM package header signing:**

```bash
rpm --define "%_signature gpg" \
    --define "%_gpg_name ${FINGERPRINT}" \
    --addsign package.rpm
```

**RPM repomd.xml detached signature:**

```bash
gpg --batch --yes --armor --detach-sign \
    --local-user "$FINGERPRINT" \
    --output repodata/repomd.xml.asc \
    repodata/repomd.xml
```

---

## Keys.openpgp.org Publication

The public key is uploaded to `keys.openpgp.org`:

```bash
gpg --keyserver keys.openpgp.org --send-keys "$FINGERPRINT"
```

After upload, a verification email is sent to `prodnull@proton.me`. Until the
email is confirmed, the key is retrievable by fingerprint only, not by email UID.
After confirmation, it is searchable by `prodnull@proton.me`.

To verify from another machine:

```bash
gpg --keyserver keys.openpgp.org --recv-keys 4A2F0B8412F43809A09CB922CB7756F8AE011BAF
gpg --fingerprint prodnull@proton.me
```

---

## Secure Deletion After Generation

After exporting, delete the temporary GNUPGHOME:

```bash
cd /
# macOS (shred not available):
rm -Pv /tmp/prmana-gpg/private-keys-v1.d/*
rm -Pv /tmp/prmana-gpg/prmana-private.asc
rm -rf /tmp/prmana-gpg

# Linux:
shred -u /tmp/prmana-gpg/private-keys-v1.d/*
shred -u /tmp/prmana-gpg/prmana-private.asc
rm -rf /tmp/prmana-gpg
```

---

## Key Rotation

See `docs/packaging/rotation-procedure.md` for the full rotation runbook.
Rotation is required when the private key is lost, leaked, or compromised,
and should be considered annually as a matter of policy.
