# prmana Package Build Toolchain

This directory contains the [nfpm](https://nfpm.goreleaser.com/) configuration and
maintainer scripts for building installable `.deb` and `.rpm` packages for prmana.

## Package Structure (Decision B — locked)

| Package | Contents | Why co-packaged |
|---|---|---|
| `prmana` | `pam_prmana.so` PAM module + `prmana-agent` daemon + systemd units + config template | PAM module and agent are tightly coupled; version mismatches cause auth failures. Install one package to get a fully working deployment. |
| `prmana-scim` | `prmana-scim` SCIM provisioning server | Separate because not all deployments need SCIM provisioning. |
| `prmana-tools` | `prmana-kubectl` Kubernetes exec credential plugin | **Gated on DT-A-04** — see §prmana-tools gate below. |

There is intentionally no `prmana-agent`, `prmana-pam`, or `prmana-common` package.

## Tool Versions

| Tool | Version | Purpose |
|---|---|---|
| nfpm | **2.46.0** (pinned) | Produces both `.deb` and `.rpm` from one YAML config. |
| shellcheck | any recent | Validates maintainer scripts. |
| lintian | any (Debian runner) | Lints `.deb` packages. |
| rpmlint | any (RHEL runner) | Lints `.rpm` packages. |

## Architecture Mapping

nfpm uses different architecture names for deb and rpm:

| Physical arch | deb `arch` | rpm `arch` | Rust target |
|---|---|---|---|
| x86-64 | `amd64` | `x86_64` | `x86_64-unknown-linux-gnu` |
| ARM 64 | `arm64` | `aarch64` | `aarch64-unknown-linux-gnu` |

In the nfpm YAML files, `arch: "${GOARCH}"` is a placeholder that must be substituted
before invoking nfpm. Set `GOARCH` to the appropriate value per the table above.

## Building Locally

### Prerequisites

```bash
# macOS
brew install nfpm goreleaser/tap/nfpm

# Ubuntu/Debian
NFPM_VERSION=2.46.0
curl -sfL "https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz" \
    | sudo tar xz -C /usr/local/bin nfpm
nfpm --version  # must show 2.46.0
```

You must also have a Rust release build available:

```bash
# Linux x86_64
cargo build --release --locked --target x86_64-unknown-linux-gnu
export RUST_TARGET=x86_64-unknown-linux-gnu
```

### Build .deb packages (amd64)

```bash
export RUST_TARGET=x86_64-unknown-linux-gnu
export GOARCH=amd64
export DEB_PAM_MULTIARCH=x86_64-linux-gnu
mkdir -p dist/packages

# Main package (co-installs pam_prmana.so + prmana-agent + systemd units)
envsubst < packaging/nfpm/prmana.yaml > /tmp/prmana-expanded.yaml
nfpm pkg --packager deb --config /tmp/prmana-expanded.yaml \
    --target dist/packages/prmana_1.0.0_amd64.deb

# SCIM server
GOARCH=amd64 nfpm pkg --packager deb --config packaging/nfpm/prmana-scim.yaml \
    --target dist/packages/prmana-scim_1.0.0_amd64.deb
```

### Build .rpm packages (x86_64)

```bash
export RUST_TARGET=x86_64-unknown-linux-gnu
export GOARCH=x86_64  # RPM arch naming differs from deb

nfpm pkg --packager rpm --config packaging/nfpm/prmana.yaml \
    --target dist/packages/prmana-1.0.0-1.x86_64.rpm
nfpm pkg --packager rpm --config packaging/nfpm/prmana-scim.yaml \
    --target dist/packages/prmana-scim-1.0.0-1.x86_64.rpm
```

### Build arm64

Repeat the above with:
- `RUST_TARGET=aarch64-unknown-linux-gnu`
- `GOARCH=arm64` (deb) or `GOARCH=aarch64` (rpm)
- `DEB_PAM_MULTIARCH=aarch64-linux-gnu`

## Deb Multi-arch PAM Symlink

Debian systems use architecture-qualified library paths:

- amd64: `/lib/x86_64-linux-gnu/security/pam_prmana.so`
- arm64: `/lib/aarch64-linux-gnu/security/pam_prmana.so`

The `prmana.yaml` nfpm config uses `${DEB_PAM_MULTIARCH}` as a template variable
in the symlink `dst`. The build script sets `DEB_PAM_MULTIARCH` to the correct value
and runs `envsubst < packaging/nfpm/prmana.yaml > /tmp/prmana-expanded.yaml` before
calling `nfpm pkg`.

The `.so` is installed at `/usr/lib/security/pam_prmana.so` (primary path) with a
symlink at the arch-qualified path. Both paths are checked by the `postinst` self-check.

## Linting

### deb

```bash
sudo apt-get install -y lintian
lintian --profile debian --pedantic dist/packages/prmana_1.0.0_amd64.deb
lintian --profile debian --pedantic dist/packages/prmana-scim_1.0.0_amd64.deb
```

Known suppressions are in `packaging/nfpm/lintian-overrides/`. Each suppression has
a comment explaining why it is acceptable.

### rpm

```bash
sudo apt-get install -y rpmlint   # or dnf install rpmlint on RHEL
rpmlint dist/packages/*.rpm
```

## prmana-tools Gate (DT-A-04)

`packaging/nfpm/prmana-tools.yaml` references `target/${RUST_TARGET}/release/prmana-kubectl`,
which does not exist until **DT-A-04** ships the `prmana-kubectl` crate.

Attempting to build `prmana-tools.deb` before DT-A-04 completes will produce a clear
nfpm error:

```
FATA[0000] could not add file to package: source file
  target/x86_64-unknown-linux-gnu/release/prmana-kubectl: no such file or directory
```

This is expected. The CI `release.yml` package job skips `prmana-tools` when
`prmana-kubectl` is absent:

```bash
if [ -x "target/${RUST_TARGET}/release/prmana-kubectl" ]; then
    build packaging/nfpm/prmana-tools.yaml prmana-tools
else
    echo "skip prmana-tools: prmana-kubectl not built (DT-A-04 not yet shipped)"
fi
```

## systemd-analyze Security Score

The `prmana-agent.service` unit targets a `systemd-analyze security` score of ≤ 2.0
(Green). The hardening directives applied are documented inline in
`contrib/systemd/prmana-agent.service`.

To check the score on a Debian 12 system with systemd:

```bash
systemctl daemon-reload
systemd-analyze security prmana-agent
```

## System vs. Per-User Deployment

The package installs a **system service** (`User=prmana`, `WantedBy=multi-user.target`).
This is appropriate for servers where prmana-agent must be available before any user
logs in (e.g., SSH servers, sudo hosts).

For developer laptop deployments, prmana-agent can alternatively be run as a **user
service** using the socket at `$XDG_RUNTIME_DIR/prmana-agent.sock`. This mode does
not use the system package — install the binary directly and use the user unit from
`contrib/systemd/` as a template.

See `docs/installation.md` for full deployment guidance.
