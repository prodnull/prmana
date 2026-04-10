# Marketplace image references for each supported distro×arch combination.
#
# Publishers verified against `az vm image list --publisher <X> --output table`:
#   - Canonical    — official Ubuntu images
#   - Debian       — official Debian images
#   - resf         — Rocky Enterprise Software Foundation (official Rocky Linux)
#   - tunnelbiz    — Fedora community publisher on Azure Marketplace
#
# IMPORTANT: Some marketplace images require accepting publisher terms before first use:
#   az vm image terms accept --publisher <publisher> --offer <offer> --plan <sku>
# See README.md §Marketplace Terms for per-distro commands.
#
# Unsupported combinations:
#   - fedora-40 + arm64: No official Azure Marketplace image published by Fedora/tunnelbiz.
#     Operators who need Fedora arm64 must pre-upload a custom image and set vm_size_arm64.
#   - amazon-linux-2023 (any arch): AWS-only distribution, not available on Azure.

locals {
  # Map of distro-arch key → marketplace image reference attributes.
  # Each entry is consumed by the azurerm_linux_virtual_machine source_image_reference block.
  image_map = {
    "ubuntu-22.04-amd64" = {
      publisher = "Canonical"
      offer     = "0001-com-ubuntu-server-jammy"
      sku       = "22_04-lts-gen2"
      version   = "latest"
    }
    "ubuntu-22.04-arm64" = {
      publisher = "Canonical"
      offer     = "0001-com-ubuntu-server-jammy"
      sku       = "22_04-lts-arm64"
      version   = "latest"
    }
    "ubuntu-24.04-amd64" = {
      publisher = "Canonical"
      offer     = "ubuntu-24_04-lts"
      sku       = "server"
      version   = "latest"
    }
    "ubuntu-24.04-arm64" = {
      publisher = "Canonical"
      offer     = "ubuntu-24_04-lts"
      sku       = "server-arm64"
      version   = "latest"
    }
    "debian-12-amd64" = {
      publisher = "Debian"
      offer     = "debian-12"
      sku       = "12-gen2"
      version   = "latest"
    }
    "debian-12-arm64" = {
      publisher = "Debian"
      offer     = "debian-12"
      sku       = "12-arm64"
      version   = "latest"
    }
    "rocky-9-amd64" = {
      publisher = "resf"
      offer     = "rockylinux-x86_64"
      sku       = "9-base"
      version   = "latest"
    }
    "rocky-9-arm64" = {
      publisher = "resf"
      offer     = "rockylinux-aarch64"
      sku       = "9-base"
      version   = "latest"
    }
    "fedora-40-amd64" = {
      publisher = "tunnelbiz"
      offer     = "fedora"
      sku       = "fedora-40"
      version   = "latest"
    }
    # fedora-40-arm64 is intentionally absent — no official Marketplace image.
    # Precondition in main.tf rejects this combination with a clear error.
  }

  # Derived key for this invocation's distro+arch combination.
  image_key = "${var.distro}-${var.arch}"

  # The resolved marketplace image reference for this run.
  # Preconditions below guard against unsupported combinations before this lookup.
  image_reference = local.image_map[local.image_key]

  # Admin username per distro — cloud provider convention.
  ssh_user_map = {
    "debian-12"    = "admin"
    "ubuntu-22.04" = "ubuntu"
    "ubuntu-24.04" = "ubuntu"
    "rocky-9"      = "rocky"
    "fedora-40"    = "fedora"
  }

  ssh_user = local.ssh_user_map[var.distro]
}
