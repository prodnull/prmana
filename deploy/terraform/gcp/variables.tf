# unix-oidc GCP Terraform Module - Variables
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

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "ssh_user" {
  description = "SSH username for instance access"
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key for instance access (e.g., ssh-rsa AAAA... user@host)"
  type        = string

  validation {
    condition     = can(regex("^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp)", var.ssh_public_key))
    error_message = "SSH public key must be a valid public key format (ssh-rsa, ssh-ed25519, or ecdsa)."
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
# Optional Variables - Location Configuration
# =============================================================================

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

# =============================================================================
# Optional Variables - Instance Configuration
# =============================================================================

variable "machine_type" {
  description = "GCE machine type"
  type        = string
  default     = "e2-micro"
}

variable "image_family" {
  description = "OS image family"
  type        = string
  default     = "ubuntu-2204-lts"
}

variable "image_project" {
  description = "OS image project"
  type        = string
  default     = "ubuntu-os-cloud"
}

variable "instance_name" {
  description = "Name for the GCE instance"
  type        = string
  default     = "unix-oidc-server"
}

variable "boot_disk_size" {
  description = "Boot disk size in GB"
  type        = number
  default     = 20
}

variable "boot_disk_type" {
  description = "Boot disk type (pd-standard, pd-ssd, pd-balanced)"
  type        = string
  default     = "pd-balanced"
}

variable "preemptible" {
  description = "Whether the instance is preemptible (spot VM)"
  type        = bool
  default     = false
}

# =============================================================================
# Optional Variables - Network Configuration
# =============================================================================

variable "network" {
  description = "VPC network self_link or name. If not provided, creates a new network"
  type        = string
  default     = ""
}

variable "subnetwork" {
  description = "Subnetwork self_link or name. If not provided, creates a new subnetwork"
  type        = string
  default     = ""
}

variable "subnet_cidr" {
  description = "CIDR block for new subnet (only used if network is not provided)"
  type        = string
  default     = "10.0.1.0/24"
}

variable "assign_public_ip" {
  description = "Whether to assign a public IP to the instance"
  type        = bool
  default     = true
}

variable "create_static_ip" {
  description = "Whether to create a static external IP"
  type        = bool
  default     = false
}

# =============================================================================
# Optional Variables - Security Configuration
# =============================================================================

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH to the instance. SECURITY: Must be explicitly specified - no default to prevent accidental exposure."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.allowed_ssh_cidrs) > 0
    error_message = "allowed_ssh_cidrs must be explicitly specified. Using an empty default prevents accidental exposure to 0.0.0.0/0. Specify your trusted CIDR ranges (e.g., [\"10.0.0.0/8\"] or your office IP)."
  }
}

variable "service_account_email" {
  description = "Service account email for the instance. If empty, uses default compute service account"
  type        = string
  default     = ""
}

variable "service_account_scopes" {
  description = "OAuth scopes for the instance service account"
  type        = list(string)
  default     = ["https://www.googleapis.com/auth/cloud-platform"]
}

# =============================================================================
# Optional Variables - Labels
# =============================================================================

variable "labels" {
  description = "Additional labels to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
}
