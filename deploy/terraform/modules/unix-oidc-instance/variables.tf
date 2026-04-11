# prmana-instance module variables
# Shared Terraform module for installing prmana on cloud instances

variable "oidc_issuer" {
  description = "OIDC Issuer URL"
  type        = string
}

variable "oidc_client_id" {
  description = "OIDC Client ID"
  type        = string
  default     = "prmana"
}

variable "install_agent" {
  description = "Whether to install the prmana-agent"
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

variable "prmana_version" {
  description = "Version of prmana to install"
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
  description = "URL to the prmana installer script"
  type        = string
  default     = "https://raw.githubusercontent.com/prodnull/prmana/main/deploy/installer/install.sh"
}
