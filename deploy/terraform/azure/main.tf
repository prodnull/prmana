# unix-oidc Azure Terraform Module
# https://github.com/prodnull/unix-oidc
#
# This module creates an Azure VM with unix-oidc installed and configured.
# It can create a new Resource Group and VNet or use existing ones.

terraform {
  required_version = ">= 1.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

# =============================================================================
# Data Sources
# =============================================================================

# Lookup existing resource group if provided
data "azurerm_resource_group" "existing" {
  count = var.resource_group_name != "" ? 1 : 0
  name  = var.resource_group_name
}

# Lookup existing VNet if provided
data "azurerm_virtual_network" "existing" {
  count               = var.vnet_name != "" ? 1 : 0
  name                = var.vnet_name
  resource_group_name = local.resource_group_name
}

# Lookup existing subnet if provided
data "azurerm_subnet" "existing" {
  count                = var.subnet_name != "" && var.vnet_name != "" ? 1 : 0
  name                 = var.subnet_name
  virtual_network_name = var.vnet_name
  resource_group_name  = local.resource_group_name
}

# =============================================================================
# Local Values
# =============================================================================

locals {
  # Resource group selection
  create_resource_group = var.resource_group_name == ""
  resource_group_name = local.create_resource_group ? azurerm_resource_group.main[0].name : var.resource_group_name
  resource_group_location = local.create_resource_group ? azurerm_resource_group.main[0].location : data.azurerm_resource_group.existing[0].location

  # VNet selection
  create_vnet = var.vnet_name == ""
  vnet_name   = local.create_vnet ? azurerm_virtual_network.main[0].name : var.vnet_name

  # Subnet selection
  create_subnet = var.subnet_name == "" || var.vnet_name == ""
  subnet_id = local.create_subnet ? azurerm_subnet.main[0].id : data.azurerm_subnet.existing[0].id

  # Common tags
  common_tags = merge(
    {
      "Project"     = "unix-oidc"
      "Environment" = var.environment
      "ManagedBy"   = "terraform"
    },
    var.tags
  )

  # Custom script extension for installing unix-oidc
  install_script = <<-EOF
    #!/bin/bash
    set -euo pipefail

    # Log to both console and file
    exec > >(tee /var/log/unix-oidc-install.log) 2>&1
    echo "Starting unix-oidc installation at $(date)"

    # Wait for cloud-init to complete
    cloud-init status --wait || true

    # Update packages
    apt-get update -y
    apt-get install -y curl jq

    # Download and run installer
    curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh -o /tmp/install.sh
    chmod +x /tmp/install.sh

    # Run installer with provided configuration
    /tmp/install.sh \
      --issuer "${var.oidc_issuer}" \
      --client-id "${var.oidc_client_id}" \
      ${var.install_agent ? "" : "--no-agent"} \
      --yes

    # Configure DPoP if enabled
    if [ "${var.enable_dpop}" = "true" ]; then
      if [ -f /etc/unix-oidc/config.env ]; then
        echo "" >> /etc/unix-oidc/config.env
        echo "# DPoP token binding enabled" >> /etc/unix-oidc/config.env
        echo "OIDC_DPOP_REQUIRED=true" >> /etc/unix-oidc/config.env
      fi
    fi

    # Apply PAM configuration for sshd
    if [ -f /etc/unix-oidc/pam.d-sshd.recommended ]; then
      cp /etc/pam.d/sshd /etc/pam.d/sshd.backup.$(date +%Y%m%d%H%M%S)
      cp /etc/unix-oidc/pam.d-sshd.recommended /etc/pam.d/sshd
      echo "PAM configuration applied for sshd"
    fi

    # Restart SSH to pick up PAM changes
    systemctl restart sshd

    echo "unix-oidc installation completed at $(date)"
    EOF
}

# =============================================================================
# Resource Group (conditional)
# =============================================================================

resource "azurerm_resource_group" "main" {
  count = local.create_resource_group ? 1 : 0

  name     = "${var.vm_name}-rg"
  location = var.location

  tags = local.common_tags
}

# =============================================================================
# Virtual Network Resources (conditional)
# =============================================================================

resource "azurerm_virtual_network" "main" {
  count = local.create_vnet ? 1 : 0

  name                = "${var.vm_name}-vnet"
  address_space       = [var.vnet_address_space]
  location            = local.resource_group_location
  resource_group_name = local.resource_group_name

  tags = local.common_tags
}

resource "azurerm_subnet" "main" {
  count = local.create_subnet ? 1 : 0

  name                 = "${var.vm_name}-subnet"
  resource_group_name  = local.resource_group_name
  virtual_network_name = local.vnet_name
  address_prefixes     = [var.subnet_address_prefix]
}

# =============================================================================
# Network Security Group
# =============================================================================

resource "azurerm_network_security_group" "unix_oidc" {
  name                = "${var.vm_name}-nsg"
  location            = local.resource_group_location
  resource_group_name = local.resource_group_name

  # Allow SSH from specified CIDRs
  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = var.allowed_ssh_cidrs
    destination_address_prefix = "*"
  }

  # Allow all outbound traffic (required for OIDC provider communication)
  security_rule {
    name                       = "AllowAllOutbound"
    priority                   = 1000
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.common_tags
}

# =============================================================================
# Public IP
# =============================================================================

resource "azurerm_public_ip" "unix_oidc" {
  count = var.create_public_ip ? 1 : 0

  name                = "${var.vm_name}-pip"
  location            = local.resource_group_location
  resource_group_name = local.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = local.common_tags
}

# =============================================================================
# Network Interface
# =============================================================================

resource "azurerm_network_interface" "unix_oidc" {
  name                = "${var.vm_name}-nic"
  location            = local.resource_group_location
  resource_group_name = local.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = local.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = var.create_public_ip ? azurerm_public_ip.unix_oidc[0].id : null
  }

  tags = local.common_tags
}

# Associate NSG with NIC
resource "azurerm_network_interface_security_group_association" "unix_oidc" {
  network_interface_id      = azurerm_network_interface.unix_oidc.id
  network_security_group_id = azurerm_network_security_group.unix_oidc.id
}

# =============================================================================
# Virtual Machine
# =============================================================================

resource "azurerm_linux_virtual_machine" "unix_oidc" {
  name                = var.vm_name
  resource_group_name = local.resource_group_name
  location            = local.resource_group_location
  size                = var.vm_size
  admin_username      = var.admin_username

  network_interface_ids = [
    azurerm_network_interface.unix_oidc.id
  ]

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = var.os_disk_type
    disk_size_gb         = var.os_disk_size_gb
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # Disable password authentication
  disable_password_authentication = true

  # Enable boot diagnostics with managed storage
  boot_diagnostics {
    storage_account_uri = null # Use managed storage account
  }

  tags = local.common_tags

  # Ensure network resources are ready
  depends_on = [
    azurerm_network_interface_security_group_association.unix_oidc,
    azurerm_subnet.main
  ]
}

# =============================================================================
# Custom Script Extension for unix-oidc Installation
# =============================================================================

resource "azurerm_virtual_machine_extension" "unix_oidc_install" {
  name                 = "unix-oidc-install"
  virtual_machine_id   = azurerm_linux_virtual_machine.unix_oidc.id
  publisher            = "Microsoft.Azure.Extensions"
  type                 = "CustomScript"
  type_handler_version = "2.1"

  settings = jsonencode({
    script = base64encode(local.install_script)
  })

  tags = local.common_tags

  depends_on = [azurerm_linux_virtual_machine.unix_oidc]
}
