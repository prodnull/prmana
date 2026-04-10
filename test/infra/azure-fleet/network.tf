# ─── Virtual Network ─────────────────────────────────────────────────────────

resource "azurerm_virtual_network" "fleet" {
  name                = "vnet-prmana-ci-${var.github_run_id}"
  resource_group_name = azurerm_resource_group.fleet.name
  location            = azurerm_resource_group.fleet.location
  address_space       = ["10.99.0.0/16"]

  tags = {
    Project   = "prmana-ci"
    GitHubRun = var.github_run_id
  }
}

resource "azurerm_subnet" "fleet" {
  name                 = "snet-prmana-ci"
  resource_group_name  = azurerm_resource_group.fleet.name
  virtual_network_name = azurerm_virtual_network.fleet.name
  address_prefixes     = ["10.99.1.0/24"]
}

# ─── Network Security Group ──────────────────────────────────────────────────
# T-DT0-02-04: SSH access gated by allowed_ssh_cidr (default 0.0.0.0/0 for CI).
# Acceptable risk: ephemeral test VMs with a maximum 30-minute TTL.
# Future hardening: restrict to GitHub Actions IP ranges via Meta API.

resource "azurerm_network_security_group" "fleet" {
  name                = "nsg-prmana-ci-${var.github_run_id}"
  resource_group_name = azurerm_resource_group.fleet.name
  location            = azurerm_resource_group.fleet.location

  security_rule {
    name                       = "ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.allowed_ssh_cidr
    destination_address_prefix = "*"
  }

  tags = {
    Project   = "prmana-ci"
    GitHubRun = var.github_run_id
  }
}

resource "azurerm_subnet_network_security_group_association" "fleet" {
  subnet_id                 = azurerm_subnet.fleet.id
  network_security_group_id = azurerm_network_security_group.fleet.id
}

# ─── Public IPs ──────────────────────────────────────────────────────────────
# Standard SKU static IPs. zones omitted: Spot VMs are not reliably zone-pinned
# in all Azure regions, and zone conflicts cause plan failures.

resource "azurerm_public_ip" "nodes" {
  count               = var.vm_count
  name                = "pip-prmana-ci-${var.github_run_id}-${count.index}"
  resource_group_name = azurerm_resource_group.fleet.name
  location            = azurerm_resource_group.fleet.location
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    Project   = "prmana-ci"
    GitHubRun = var.github_run_id
  }
}

# ─── Network Interfaces ───────────────────────────────────────────────────────

resource "azurerm_network_interface" "nodes" {
  count               = var.vm_count
  name                = "nic-prmana-ci-${var.github_run_id}-${count.index}"
  resource_group_name = azurerm_resource_group.fleet.name
  location            = azurerm_resource_group.fleet.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.fleet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.nodes[count.index].id
  }

  tags = {
    Project   = "prmana-ci"
    GitHubRun = var.github_run_id
  }
}
