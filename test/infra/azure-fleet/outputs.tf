# Output contract mirrors aws-fleet for cloud-agnostic orchestration in fleet-test.yml.
# The orchestration workflow treats both modules identically via these output names.

output "vm_names" {
  description = "Names of the provisioned VMs."
  value       = azurerm_linux_virtual_machine.nodes[*].name
}

output "public_ips" {
  description = "Public IPv4 addresses of the provisioned VMs."
  value       = azurerm_public_ip.nodes[*].ip_address
}

output "private_ips" {
  description = "Private IPv4 addresses of the provisioned VMs (within the fleet VNet)."
  value       = azurerm_network_interface.nodes[*].private_ip_address
}

output "ssh_user" {
  description = "Admin username to use for SSH connections. Derived from the distro (ubuntu, rocky, admin, etc.)."
  value       = local.ssh_user
}

output "resource_group_name" {
  description = "Name of the per-run Azure resource group. Deleting this RG removes all fleet resources."
  value       = azurerm_resource_group.fleet.name
}

output "fleet_tag" {
  description = "Tag value used to identify all resources in this fleet run (prmana-ci-<github_run_id>)."
  value       = "prmana-ci-${var.github_run_id}"
}

output "region" {
  description = "Azure region where the fleet was provisioned."
  value       = var.azure_location
}
