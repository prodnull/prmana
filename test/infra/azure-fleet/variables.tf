variable "distro" {
  type        = string
  description = "Linux distribution. One of: debian-12, ubuntu-22.04, ubuntu-24.04, rocky-9, fedora-40. Note: amazon-linux-2023 is not available on Azure Marketplace."

  validation {
    condition     = contains(["debian-12", "ubuntu-22.04", "ubuntu-24.04", "rocky-9", "fedora-40"], var.distro)
    error_message = "distro must be one of: debian-12, ubuntu-22.04, ubuntu-24.04, rocky-9, fedora-40. Amazon Linux 2023 is AWS-only and not supported on Azure."
  }
}

variable "arch" {
  type        = string
  description = "CPU architecture: amd64 or arm64."

  validation {
    condition     = contains(["amd64", "arm64"], var.arch)
    error_message = "arch must be 'amd64' or 'arm64'."
  }
}

variable "vm_count" {
  type        = number
  description = "Number of VMs to provision. Must be between 1 and 10."

  validation {
    condition     = var.vm_count >= 1 && var.vm_count <= 10
    error_message = "vm_count must be between 1 and 10."
  }
}

variable "max_instance_minutes" {
  type        = number
  default     = 30
  description = "Maximum runtime for each VM in minutes. The cloud-init watchdog will call `shutdown -h +N` to ensure VMs halt at this deadline."
}

variable "budget_limit_usd" {
  type        = number
  default     = 5
  description = "Azure Consumption Budget cap in USD for the per-run resource group. An alert fires at 80% of this threshold."
}

variable "github_run_id" {
  type        = string
  description = "GitHub Actions run ID, used to name resources uniquely (e.g., rg-prmana-ci-<run_id>)."
}

variable "azure_location" {
  type        = string
  default     = "westus2"
  description = "Azure region for all resources. Must have Spot VM quota for the selected VM sizes."
}

variable "vm_size_amd64" {
  type        = string
  default     = "Standard_B2s"
  description = "Azure VM size for amd64 nodes. Must be Spot-eligible in var.azure_location."
}

variable "vm_size_arm64" {
  type        = string
  default     = "Standard_D2ps_v5"
  description = "Azure VM size for arm64 nodes. Standard_D2ps_v5 uses Ampere Altra (arm64) and is Spot-eligible."
}

variable "ssh_public_key" {
  type        = string
  description = "SSH public key to install on each VM. Injected from a GitHub secret or generated in the workflow."
  sensitive   = true
}

variable "allowed_ssh_cidr" {
  type        = string
  default     = "0.0.0.0/0"
  description = "CIDR block allowed inbound SSH (port 22/tcp) on the fleet NSG. Default allows all; tighten to GitHub Actions IP ranges in production. Acceptable for ephemeral test VMs with max 30 min TTL."
}
