# prmana-instance module outputs

output "install_complete" {
  description = "Indicates that prmana installation is complete"
  value       = true
  depends_on  = [null_resource.prmana_validate]
}

output "config_path" {
  description = "Path to the prmana configuration file"
  value       = "/etc/prmana/config.env"
}

output "pam_module_paths" {
  description = "Possible paths to the PAM module (depends on OS)"
  value = [
    "/lib/security/pam_prmana.so",
    "/lib64/security/pam_prmana.so"
  ]
}

output "agent_path" {
  description = "Path to the prmana-agent binary (if installed)"
  value       = var.install_agent ? "/usr/local/bin/prmana-agent" : null
}

output "oidc_issuer" {
  description = "Configured OIDC issuer URL"
  value       = var.oidc_issuer
}

output "oidc_client_id" {
  description = "Configured OIDC client ID"
  value       = var.oidc_client_id
}

output "dpop_enabled" {
  description = "Whether DPoP token binding is enabled"
  value       = var.enable_dpop
}

output "instance_host" {
  description = "Host address of the configured instance"
  value       = var.connection.host
}
