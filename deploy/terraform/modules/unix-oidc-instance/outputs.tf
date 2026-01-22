# unix-oidc-instance module outputs

output "install_complete" {
  description = "Indicates that unix-oidc installation is complete"
  value       = true
  depends_on  = [null_resource.unix_oidc_validate]
}

output "config_path" {
  description = "Path to the unix-oidc configuration file"
  value       = "/etc/unix-oidc/config.env"
}

output "pam_module_paths" {
  description = "Possible paths to the PAM module (depends on OS)"
  value = [
    "/lib/security/pam_unix_oidc.so",
    "/lib64/security/pam_unix_oidc.so"
  ]
}

output "agent_path" {
  description = "Path to the unix-oidc-agent binary (if installed)"
  value       = var.install_agent ? "/usr/local/bin/unix-oidc-agent" : null
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
