# GPG Key Rotation Procedure — prmana Package Signing

**Audience:** prmana maintainers responding to a key compromise, loss, or
scheduled rotation event.

**Reference:** `docs/packaging/gpg-key-management.md` for the active key details
and CI import instructions.

---

## When to Rotate

| Trigger | Urgency | Notes |
|---------|---------|-------|
| Private key leaked or compromised | **Immediate** | Revoke old key within hours |
| Private key lost (no backup) | **Immediate** | No revocation possible — publish notice |
| Annual rotation policy | Scheduled | Plan downtime window |
| CI secret accidentally logged | **Immediate** | Treat as compromise |

---

## Rotation Procedure

### Step 1 — Generate new key

Follow the generation steps in `docs/packaging/gpg-key-management.md §Key Generation`
using a fresh `GNUPGHOME`. Record the new fingerprint.

### Step 2 — Store in 1Password

Create a new vault item: **prmana GPG signing key (v{N+1})** — do not overwrite
the old entry until the rotation is complete. Attach `prmana-private.asc`,
`prmana-public.asc`, `prmana-public.gpg`. Record the fingerprint and generation
date.

### Step 3 — Update GitHub Secrets

Navigate to `https://github.com/prodnull/prmana/settings/secrets/actions`:

- Update `PRMANA_GPG_PRIVATE_KEY` — paste the new armored private key block
- Update `PRMANA_GPG_FINGERPRINT` — paste the new fingerprint

**Test the new secret immediately:** trigger a `workflow_dispatch` run of
`publish-repo.yml` with any recent release tag. Verify the workflow completes
without GPG errors before proceeding.

### Step 4 — Publish new public key to keys.openpgp.org

```bash
gpg --keyserver keys.openpgp.org --send-keys "$NEW_FINGERPRINT"
```

Confirm the verification email at `prodnull@proton.me`.

### Step 5 — Update repository files

Replace the committed public key files in the repository:

```bash
gpg --armor --export "$NEW_FINGERPRINT" > packaging/repo/prmana-public.asc
gpg --export "$NEW_FINGERPRINT" > packaging/repo/prmana-public.gpg
```

Update the fingerprint in all documentation:
- `docs/install/apt.md` — `gpg --recv-keys` example
- `docs/install/yum.md` — verification note
- `docs/packaging/gpg-key-management.md` — active key table

Commit these changes with message:
`chore: rotate prmana GPG signing key to {NEW_FINGERPRINT_SHORT}`

### Step 6 — Re-sign all current packages

After the new key is in GitHub Secrets and the commit above is merged to main,
trigger a `workflow_dispatch` run of `publish-repo.yml` for every currently
published release tag.

This re-generates `InRelease`, `Release.gpg`, `repomd.xml.asc`, and RPM
package headers with the new key. The old signatures are replaced.

```bash
# List current release tags (adjust as needed)
gh release list --repo prodnull/prmana --limit 10

# Trigger republish for each
for TAG in v1.0.0 v1.0.1; do
  gh workflow run publish-repo.yml \
    --repo prodnull/prmana \
    --field release_tag="$TAG"
done
```

### Step 7 — Revoke the old key (if not lost)

```bash
# Generate a revocation certificate
export GNUPGHOME=/tmp/prmana-revoke
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"

# Import old private key from 1Password
gpg --import /path/to/old-prmana-private.asc

# Generate and immediately apply the revocation
gpg --gen-revoke "$OLD_FINGERPRINT" | gpg --import

# Upload the revocation to the keyserver
gpg --keyserver keys.openpgp.org --send-keys "$OLD_FINGERPRINT"

# Clean up
shred -u "$GNUPGHOME"/private-keys-v1.d/* && rm -rf "$GNUPGHOME"
```

If the private key is lost (no backup), skip the revocation step. Document
this in the 1Password vault item for the old key.

### Step 8 — Announce and document

1. Create a GitHub release note for the next release mentioning the key rotation
2. Add a NEWS entry to `CHANGELOG.md`
3. Update the 1Password vault item for the old key:
   - Add field `revoked` = rotation date
   - Add field `replaced_by` = new fingerprint
   - Retain the item for audit trail (do not delete)

---

## User Re-Trust Flow

After a key rotation, users with the old key installed must replace it.

**Debian/Ubuntu users:**

```bash
# Remove the old key
sudo rm /etc/apt/keyrings/prmana.gpg

# Install the new key
curl -fsSL https://prodnull.github.io/prmana/packages/gpg/prmana.gpg \
    | sudo tee /etc/apt/keyrings/prmana.gpg > /dev/null

sudo apt update
```

**Rocky/Amazon Linux users:**

```bash
# Remove the old key (find the key ID first)
rpm -qa gpg-pubkey | xargs rpm -qi gpg-pubkey | grep -B2 prmana
# Note the package name, e.g.: gpg-pubkey-ae011baf-67f87e82

sudo rpm -e gpg-pubkey-ae011baf-67f87e82

# Import the new key
sudo rpm --import https://prodnull.github.io/prmana/packages/gpg/prmana.gpg

sudo dnf makecache --refresh
```

---

## Why There Is No Automatic Key Revocation in APT

The `/etc/apt/keyrings/` model (Debian policy since Bullseye) stores keys as
individual files per repository, not in the shared legacy APT keyring
(`/etc/apt/trusted.gpg`). This provides stronger isolation — a compromised
key for one repo cannot affect another — but it means key revocations are
NOT automatically propagated to user machines.

Users must manually replace the file in `/etc/apt/keyrings/`. This is an
accepted UX cost for the stronger isolation model. The rotation procedure
above documents the exact commands needed.

The same limitation applies to RPM: `rpm --import` adds the key to the RPM
database, and removal requires `rpm -e gpg-pubkey-{keyid}`. There is no
automatic revocation propagation.

**Mitigation:** Publish the rotation prominently (release notes, CHANGELOG,
security advisory if compromise) so users know to update.
