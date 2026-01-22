# unix-oidc AWS Terraform Module - Variables
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

variable "key_name" {
  description = "Name of the SSH key pair in AWS for instance access"
  type        = string
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
# Optional Variables - Instance Configuration
# =============================================================================

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "ami_id" {
  description = "AMI ID for the instance. If not specified, auto-detects Ubuntu 22.04 LTS"
  type        = string
  default     = ""
}

variable "instance_name" {
  description = "Name tag for the EC2 instance"
  type        = string
  default     = "unix-oidc-server"
}

variable "root_volume_size" {
  description = "Size of the root EBS volume in GB"
  type        = number
  default     = 20
}

variable "root_volume_type" {
  description = "Type of the root EBS volume"
  type        = string
  default     = "gp3"
}

# =============================================================================
# Optional Variables - Network Configuration
# =============================================================================

variable "vpc_id" {
  description = "VPC ID to deploy into. If not provided, creates a new VPC"
  type        = string
  default     = ""
}

variable "subnet_id" {
  description = "Subnet ID to deploy into. If not provided, uses first public subnet"
  type        = string
  default     = ""
}

variable "create_vpc" {
  description = "Whether to create a new VPC. Ignored if vpc_id is provided"
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "CIDR block for new VPC (only used if create_vpc is true)"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (only used if create_vpc is true)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "availability_zones" {
  description = "Availability zones for subnets. If empty, auto-selects"
  type        = list(string)
  default     = []
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

variable "associate_public_ip" {
  description = "Whether to associate a public IP address"
  type        = bool
  default     = true
}

variable "create_eip" {
  description = "Whether to create an Elastic IP for the instance"
  type        = bool
  default     = false
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
