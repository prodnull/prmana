# unix-oidc Azure Terraform Module - Variables
# https://github.com/prodnull/unix-oidc

# =============================================================================
# Required Variables
# =============================================================================

variable "oidc_issuer" {
  description = "OIDC issuer URL (e.g., https://login.example.com/realms/myorg)"
  type        = string

  validation {
    condition     = can(regex("^https://", var.oidc_issuer))
    error_message = "OIDC issuer must be an HTTPS URL."
  }
}

variable "admin_username" {
  description = "Admin username for the VM"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9_-]{0,31}$", var.admin_username))
    error_message = "Admin username must start with a lowercase letter and contain only lowercase letters, numbers, underscores, and hyphens (max 32 chars)."
  }
}

variable "admin_ssh_public_key" {
  description = "SSH public key for admin user authentication"
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^ssh-", var.admin_ssh_public_key))
    error_message = "SSH public key must start with 'ssh-' (e.g., ssh-rsa, ssh-ed25519)."
  }
}

# =============================================================================
# Optional Variables - OIDC Configuration
# =============================================================================

variable "oidc_client_id" {
  description = "OIDC client ID for unix-oidc"
  type        = string
  default     = "unix-oidc"
}

variable "install_agent" {
  description = "Whether to install the unix-oidc-agent"
  type        = bool
  default     = true
}

variable "enable_dpop" {
  description = "Enable DPoP token binding (recommended for production)"
  type        = bool
  default     = true
}

# =============================================================================
# Optional Variables - Resource Group
# =============================================================================

variable "resource_group_name" {
  description = "Name of existing resource group. If not provided, creates a new one"
  type        = string
  default     = ""
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastus"
}

# =============================================================================
# Optional Variables - VM Configuration
# =============================================================================

variable "vm_size" {
  description = "Azure VM size"
  type        = string
  default     = "Standard_B1s"
}

variable "vm_name" {
  description = "Name for the VM and related resources"
  type        = string
  default     = "unix-oidc-server"

  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}[a-zA-Z0-9]$|^[a-zA-Z0-9]$", var.vm_name))
    error_message = "VM name must be 1-64 characters, start and end with alphanumeric, and contain only alphanumerics and hyphens."
  }
}

variable "os_disk_size_gb" {
  description = "Size of the OS disk in GB"
  type        = number
  default     = 30
}

variable "os_disk_type" {
  description = "Type of the OS disk (Standard_LRS, StandardSSD_LRS, Premium_LRS)"
  type        = string
  default     = "StandardSSD_LRS"

  validation {
    condition     = contains(["Standard_LRS", "StandardSSD_LRS", "Premium_LRS"], var.os_disk_type)
    error_message = "OS disk type must be one of: Standard_LRS, StandardSSD_LRS, Premium_LRS."
  }
}

# =============================================================================
# Optional Variables - Network Configuration
# =============================================================================

variable "vnet_name" {
  description = "Name of existing VNet. If not provided, creates a new one"
  type        = string
  default     = ""
}

variable "subnet_name" {
  description = "Name of existing subnet. Required if vnet_name is provided"
  type        = string
  default     = ""
}

variable "vnet_address_space" {
  description = "Address space for new VNet (only used if vnet_name is not provided)"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_address_prefix" {
  description = "Address prefix for new subnet (only used if creating new VNet)"
  type        = string
  default     = "10.0.1.0/24"
}

variable "create_public_ip" {
  description = "Whether to create a public IP for the VM"
  type        = bool
  default     = true
}

# =============================================================================
# Optional Variables - Security Configuration
# =============================================================================

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH to the VM. SECURITY: Must be explicitly specified - no default to prevent accidental exposure."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.allowed_ssh_cidrs) > 0
    error_message = "allowed_ssh_cidrs must be explicitly specified. Using an empty default prevents accidental exposure to 0.0.0.0/0. Specify your trusted CIDR ranges (e.g., [\"10.0.0.0/8\"] or your office IP)."
  }
}

# =============================================================================
# Optional Variables - Tags
# =============================================================================

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
}
