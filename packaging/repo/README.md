# packaging/repo — APT and YUM repository tooling

This directory contains configuration and public key material for the prmana
signed package repository, hosted on GitHub Pages at
`https://prodnull.github.io/prmana/packages/`.

## Repository layout (on gh-pages)

```
packages/
  apt/           # APT flat repo (Packages, Packages.gz, Release, InRelease, Release.gpg)
  rpm/
    stable/
      x86_64/    # RPM repo (repodata/, *.rpm)
      aarch64/   # RPM repo (repodata/, *.rpm)
  gpg/
    prmana.gpg   # Binary (dearmored) public key — use for /etc/apt/keyrings/
    prmana.asc   # Armored public key — cross-reference copy
```

## Contents of this directory

| File | Purpose |
|------|---------|
| `apt-ftparchive.conf` | Release metadata for `apt-ftparchive release` (Origin, Label, Suite, Codename, Architectures, Components) |
| `prmana-public.gpg` | Binary (dearmored) Ed25519 public signing key — committed as the canonical copy for CI |
| `prmana-public.asc` | Armored public key — for human cross-verification and keys.openpgp.org |
| `README.md` | This file |

## publish-repo.yml workflow overview

The `.github/workflows/publish-repo.yml` workflow runs on `release: published`
and on `workflow_dispatch` (for manual republish without a new release).

**Steps:**
1. Download `.deb` and `.rpm` artifacts from the GitHub release
2. Import the GPG private key from `PRMANA_GPG_PRIVATE_KEY` secret via
   `crazy-max/ghaction-import-gpg@v6`
3. Run `apt-ftparchive packages` + `apt-ftparchive release` to generate
   `Packages`, `Packages.gz`, and `Release`
4. GPG-sign `Release` → `InRelease` (clearsign) and `Release.gpg` (detached)
5. Run `createrepo_c` to generate RPM `repodata/`
6. GPG-sign each RPM header via `rpm --addsign`
7. GPG-sign `repodata/repomd.xml` → `repomd.xml.asc`
8. Push everything to `gh-pages` under `packages/` via
   `peaceiris/actions-gh-pages@v4` with `keep_files: true`

## Local test procedure

The repo toolchain (`apt-ftparchive`, `createrepo_c`) is Debian/RHEL-native
and not available on macOS without significant effort. For local testing,
use a Debian container:

```bash
docker run --rm -it -v "$PWD:/repo" -w /repo debian:12-slim bash
apt-get update && apt-get install -y apt-utils createrepo-c gnupg2

# Stage some .deb files
mkdir -p stage/apt
cp /path/to/your.deb stage/apt/

# Generate APT metadata
cd stage/apt
apt-ftparchive packages . > Packages
gzip -kf Packages
apt-ftparchive -c /repo/packaging/repo/apt-ftparchive.conf release . > Release
```

## Manual workflow_dispatch republish

To republish a release without cutting a new tag (e.g., to add a missing
architecture or fix a signing error):

1. Go to **Actions → publish-repo → Run workflow**
2. Enter the release tag (e.g., `v1.0.0`)
3. Click **Run workflow**

The `keep_files: true` flag in the peaceiris action ensures that packages
from prior releases are preserved alongside the newly published ones.

## GPG key management

See `docs/packaging/gpg-key-management.md` for:
- Key fingerprint and generation procedure
- 1Password vault location
- GitHub Secrets names
- CI import details

See `docs/packaging/rotation-procedure.md` for the key rotation runbook.
