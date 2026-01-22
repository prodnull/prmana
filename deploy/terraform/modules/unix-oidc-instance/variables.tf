# unix-oidc-instance module variables
# Shared Terraform module for installing unix-oidc on cloud instances

variable "oidc_issuer" {
  description = "OIDC Issuer URL"
  type        = string
}

variable "oidc_client_id" {
  description = "OIDC Client ID"
  type        = string
  default     = "unix-oidc"
}

variable "install_agent" {
  description = "Whether to install the unix-oidc-agent"
  type        = bool
  default     = true
}

variable "enable_dpop" {
  description = "Enable DPoP token binding"
  type        = bool
  default     = false
}

variable "connection" {
  description = "SSH connection details for the target instance"
  type = object({
    type        = string
    host        = string
    user        = string
    private_key = string
  })
  sensitive = true
}

variable "unix_oidc_version" {
  description = "Version of unix-oidc to install"
  type        = string
  default     = "latest"
}

variable "required_acr" {
  description = "Required ACR level for authentication (optional)"
  type        = string
  default     = ""
}

variable "max_auth_age" {
  description = "Maximum authentication age in seconds (optional)"
  type        = number
  default     = 0
}

variable "installer_url" {
  description = "URL to the unix-oidc installer script"
  type        = string
  default     = "https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh"
}
