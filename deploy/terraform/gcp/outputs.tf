# unix-oidc GCP Terraform Module - Outputs
# https://github.com/prodnull/unix-oidc

# =============================================================================
# Instance Outputs
# =============================================================================

output "instance_id" {
  description = "GCE instance ID"
  value       = google_compute_instance.unix_oidc.instance_id
}

output "instance_name" {
  description = "GCE instance name"
  value       = google_compute_instance.unix_oidc.name
}

output "instance_self_link" {
  description = "GCE instance self link"
  value       = google_compute_instance.unix_oidc.self_link
}

output "instance_private_ip" {
  description = "Private IP address of the instance"
  value       = google_compute_instance.unix_oidc.network_interface[0].network_ip
}

output "instance_public_ip" {
  description = "Public IP address of the instance (if assigned)"
  value       = var.assign_public_ip ? google_compute_instance.unix_oidc.network_interface[0].access_config[0].nat_ip : null
}

# =============================================================================
# SSH Connection
# =============================================================================

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = var.assign_public_ip ? "ssh ${var.ssh_user}@${google_compute_instance.unix_oidc.network_interface[0].access_config[0].nat_ip}" : "ssh ${var.ssh_user}@${google_compute_instance.unix_oidc.network_interface[0].network_ip}"
}

output "ssh_host" {
  description = "SSH host for connection"
  value       = var.assign_public_ip ? google_compute_instance.unix_oidc.network_interface[0].access_config[0].nat_ip : google_compute_instance.unix_oidc.network_interface[0].network_ip
}

output "gcloud_ssh_command" {
  description = "gcloud SSH command to connect to the instance"
  value       = "gcloud compute ssh ${var.ssh_user}@${google_compute_instance.unix_oidc.name} --zone=${var.zone} --project=${var.project_id}"
}

# =============================================================================
# Network Outputs
# =============================================================================

output "network" {
  description = "VPC network used by the instance"
  value       = local.network
}

output "subnetwork" {
  description = "Subnetwork used by the instance"
  value       = local.subnetwork
}

output "zone" {
  description = "Zone where the instance is deployed"
  value       = google_compute_instance.unix_oidc.zone
}

output "firewall_ssh_name" {
  description = "Name of the SSH firewall rule"
  value       = google_compute_firewall.allow_ssh.name
}

output "firewall_egress_name" {
  description = "Name of the egress firewall rule"
  value       = google_compute_firewall.allow_egress.name
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

output "machine_type" {
  description = "Machine type used for the instance"
  value       = google_compute_instance.unix_oidc.machine_type
}

output "image" {
  description = "Boot disk image used"
  value       = "projects/${var.image_project}/global/images/family/${var.image_family}"
}

# =============================================================================
# Status Outputs
# =============================================================================

output "instance_status" {
  description = "Current status of the instance"
  value       = google_compute_instance.unix_oidc.current_status
}

# =============================================================================
# Created Resources Summary
# =============================================================================

output "created_network" {
  description = "Whether a new VPC network was created"
  value       = local.create_network
}

output "created_static_ip" {
  description = "Whether a static external IP was created"
  value       = var.create_static_ip
}

output "static_ip_address" {
  description = "Static external IP address (if created)"
  value       = var.create_static_ip ? google_compute_address.static_ip[0].address : null
}
