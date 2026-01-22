# unix-oidc AWS Simple Example
#
# This example demonstrates the minimal configuration needed to deploy
# unix-oidc on an EC2 instance with a new VPC.
#
# Usage:
#   terraform init
#   terraform plan -var="oidc_issuer=https://your-idp.example.com" -var="key_name=your-key"
#   terraform apply -var="oidc_issuer=https://your-idp.example.com" -var="key_name=your-key"

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region
}

# =============================================================================
# Variables
# =============================================================================

variable "aws_region" {
  description = "AWS region to deploy to"
  type        = string
  default     = "us-west-2"
}

variable "oidc_issuer" {
  description = "OIDC issuer URL (e.g., https://login.example.com/realms/myorg)"
  type        = string
}

variable "key_name" {
  description = "Name of the SSH key pair in AWS"
  type        = string
}

variable "my_ip" {
  description = "Your IP address for SSH access (CIDR format, e.g., 1.2.3.4/32)"
  type        = string
  default     = "0.0.0.0/0" # Warning: allows SSH from anywhere
}

# =============================================================================
# Module
# =============================================================================

# Basic usage - creates a new VPC
module "unix_oidc" {
  source = "../../"

  # Required
  oidc_issuer = var.oidc_issuer
  key_name    = var.key_name

  # Optional - restrict SSH access
  allowed_ssh_cidrs = [var.my_ip]

  # Tags
  environment = "demo"
  tags = {
    Example = "simple"
  }
}

# =============================================================================
# Example with Existing VPC (commented out)
# =============================================================================

# Uncomment and modify to use an existing VPC:
#
# module "unix_oidc_existing_vpc" {
#   source = "../../"
#
#   oidc_issuer = var.oidc_issuer
#   key_name    = var.key_name
#
#   # Use existing VPC and subnet
#   vpc_id    = "vpc-12345678"
#   subnet_id = "subnet-12345678"
#
#   allowed_ssh_cidrs = [var.my_ip]
# }

# =============================================================================
# Outputs
# =============================================================================

output "instance_id" {
  description = "EC2 instance ID"
  value       = module.unix_oidc.instance_id
}

output "public_ip" {
  description = "Public IP address of the instance"
  value       = module.unix_oidc.instance_public_ip
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = module.unix_oidc.ssh_command
}

output "oidc_issuer" {
  description = "Configured OIDC issuer"
  value       = module.unix_oidc.oidc_issuer
}

# =============================================================================
# Next Steps
# =============================================================================

output "next_steps" {
  description = "Instructions for connecting"
  value       = <<-EOF

    unix-oidc has been deployed!

    Next steps:
    1. Wait 2-3 minutes for the instance to initialize
    2. Get an OIDC token from your IdP
    3. Connect using:

       # With unix-oidc-agent (recommended)
       export OIDC_TOKEN=$(unix-oidc-agent get-token)
       ssh -o "SetEnv OIDC_TOKEN=$OIDC_TOKEN" ubuntu@${module.unix_oidc.instance_public_ip}

       # Or with SSH key (for initial verification)
       ssh -i ~/.ssh/${var.key_name}.pem ubuntu@${module.unix_oidc.instance_public_ip}

    4. Verify installation:
       sudo cat /var/log/unix-oidc-install.log

    Documentation: https://github.com/prodnull/unix-oidc

  EOF
}
