# Preconditions for unsupported distro×arch combinations.
# These must fail at plan time with a clear error rather than at apply time with
# a cryptic "key not found in map" error.

locals {
  # Validate that the requested distro×arch combination has a marketplace image.
  # Fedora arm64 has no official Azure Marketplace image.
  _assert_image_exists = (
    var.arch == "arm64" && var.distro == "fedora-40"
    ? tobool("ERROR: fedora-40 + arm64 is not supported on Azure Marketplace. No official Fedora arm64 image is published. Use amd64 for Fedora, or pre-upload a custom image and modify image.tf.")
    : true
  )
}

# ─── Resource Group ─────────────────────────────────────────────────────────
# All fleet resources are scoped to a per-run resource group.
# `terraform destroy` or `az group delete` removes everything atomically.

resource "azurerm_resource_group" "fleet" {
  name     = "rg-prmana-ci-${var.github_run_id}"
  location = var.azure_location

  tags = {
    Project   = "prmana-ci"
    GitHubRun = var.github_run_id
    Distro    = var.distro
    Arch      = var.arch
  }
}

# ─── Compute: Spot VMs ───────────────────────────────────────────────────────
# Spot priority with Delete eviction policy: when Azure reclaims a Spot VM it is
# fully destroyed (no Deallocate state), preventing ghost resources from accruing
# cost while in stopped-deallocated state.
#
# Threat mitigations applied here:
#   T-DT0-02-03 disable_password_authentication = true (SSH keys only)
#   T-DT0-02-07 SystemAssigned identity, no RBAC roles granted by this module
#   T-DT0-02-08 All resources tagged with Project and GitHubRun

resource "azurerm_linux_virtual_machine" "nodes" {
  count               = var.vm_count
  name                = "prmana-ci-${var.github_run_id}-${count.index}"
  resource_group_name = azurerm_resource_group.fleet.name
  location            = azurerm_resource_group.fleet.location

  # VM size: arm64 uses Ampere Altra (D*ps_v5 family); amd64 uses B-series Spot-eligible.
  size = var.arch == "arm64" ? var.vm_size_arm64 : var.vm_size_amd64

  # Spot priority: Delete eviction ensures evicted VMs are fully destroyed,
  # not left in deallocated state (which still incurs disk storage costs).
  # max_bid_price = -1 accepts up to the pay-as-you-go on-demand price.
  priority        = "Spot"
  eviction_policy = "Delete"
  max_bid_price   = -1

  admin_username = local.ssh_user

  # T-DT0-02-03: Password authentication disabled; SSH keys only.
  disable_password_authentication = true

  admin_ssh_key {
    username   = local.ssh_user
    public_key = var.ssh_public_key
  }

  # Marketplace image resolved from image.tf locals map.
  source_image_reference {
    publisher = local.image_reference.publisher
    offer     = local.image_reference.offer
    sku       = local.image_reference.sku
    version   = local.image_reference.version
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  network_interface_ids = [azurerm_network_interface.nodes[count.index].id]

  # Cloud-init: installs the shutdown watchdog and writes CI metadata.
  # base64encode wraps the rendered YAML template for the custom_data field.
  custom_data = base64encode(templatefile("${path.module}/cloud-init.yaml.tftpl", {
    max_instance_minutes = var.max_instance_minutes
    github_run_id        = var.github_run_id
    distro               = var.distro
    arch                 = var.arch
  }))

  # T-DT0-02-07: SystemAssigned managed identity — no RBAC roles granted here.
  # Downstream phases (DT-A) grant minimum permissions as needed.
  identity {
    type = "SystemAssigned"
  }

  tags = {
    Project   = "prmana-ci"
    GitHubRun = var.github_run_id
    Distro    = var.distro
    Arch      = var.arch
    Name      = "prmana-ci-${var.github_run_id}-${count.index}"
  }

  depends_on = [local._assert_image_exists]
}
