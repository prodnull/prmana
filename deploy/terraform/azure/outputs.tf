# unix-oidc Azure Terraform Module - Outputs
# https://github.com/prodnull/unix-oidc

# =============================================================================
# VM Outputs
# =============================================================================

output "vm_id" {
  description = "Azure VM resource ID"
  value       = azurerm_linux_virtual_machine.unix_oidc.id
}

output "vm_name" {
  description = "Name of the VM"
  value       = azurerm_linux_virtual_machine.unix_oidc.name
}

output "vm_private_ip" {
  description = "Private IP address of the VM"
  value       = azurerm_network_interface.unix_oidc.private_ip_address
}

output "vm_public_ip" {
  description = "Public IP address of the VM (if created)"
  value       = var.create_public_ip ? azurerm_public_ip.unix_oidc[0].ip_address : null
}

# =============================================================================
# SSH Connection
# =============================================================================

output "ssh_command" {
  description = "SSH command to connect to the VM"
  value = var.create_public_ip ? "ssh ${var.admin_username}@${azurerm_public_ip.unix_oidc[0].ip_address}" : "ssh ${var.admin_username}@${azurerm_network_interface.unix_oidc.private_ip_address}"
}

output "ssh_host" {
  description = "SSH host for connection"
  value       = var.create_public_ip ? azurerm_public_ip.unix_oidc[0].ip_address : azurerm_network_interface.unix_oidc.private_ip_address
}

output "admin_username" {
  description = "Admin username for SSH"
  value       = var.admin_username
}

# =============================================================================
# Network Outputs
# =============================================================================

output "resource_group_name" {
  description = "Resource group name where resources are deployed"
  value       = local.resource_group_name
}

output "vnet_name" {
  description = "Virtual network name"
  value       = local.vnet_name
}

output "vnet_id" {
  description = "Virtual network ID"
  value       = local.create_vnet ? azurerm_virtual_network.main[0].id : data.azurerm_virtual_network.existing[0].id
}

output "subnet_id" {
  description = "Subnet ID where the VM is deployed"
  value       = local.subnet_id
}

output "network_interface_id" {
  description = "Network interface ID attached to the VM"
  value       = azurerm_network_interface.unix_oidc.id
}

output "network_security_group_id" {
  description = "Network security group ID"
  value       = azurerm_network_security_group.unix_oidc.id
}

output "public_ip_id" {
  description = "Public IP resource ID (if created)"
  value       = var.create_public_ip ? azurerm_public_ip.unix_oidc[0].id : null
}

# =============================================================================
# Configuration Outputs
# =============================================================================

output "oidc_issuer" {
  description = "Configured OIDC issuer URL"
  value       = var.oidc_issuer
}

output "oidc_client_id" {
  description = "Configured OIDC client ID"
  value       = var.oidc_client_id
}

output "location" {
  description = "Azure region where resources are deployed"
  value       = local.resource_group_location
}

# =============================================================================
# Created Resources Summary
# =============================================================================

output "created_resource_group" {
  description = "Whether a new resource group was created"
  value       = local.create_resource_group
}

output "created_vnet" {
  description = "Whether a new virtual network was created"
  value       = local.create_vnet
}

output "created_public_ip" {
  description = "Whether a public IP was created"
  value       = var.create_public_ip
}
