# unix-oidc AWS Terraform Module - Outputs
# https://github.com/prodnull/unix-oidc

# =============================================================================
# Instance Outputs
# =============================================================================

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.unix_oidc.id
}

output "instance_arn" {
  description = "EC2 instance ARN"
  value       = aws_instance.unix_oidc.arn
}

output "instance_private_ip" {
  description = "Private IP address of the instance"
  value       = aws_instance.unix_oidc.private_ip
}

output "instance_public_ip" {
  description = "Public IP address of the instance (if assigned)"
  value       = var.create_eip ? aws_eip.unix_oidc[0].public_ip : aws_instance.unix_oidc.public_ip
}

output "instance_public_dns" {
  description = "Public DNS name of the instance"
  value       = aws_instance.unix_oidc.public_dns
}

# =============================================================================
# SSH Connection
# =============================================================================

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = "ssh -i ~/.ssh/${var.key_name}.pem ubuntu@${var.create_eip ? aws_eip.unix_oidc[0].public_ip : coalesce(aws_instance.unix_oidc.public_ip, aws_instance.unix_oidc.private_ip)}"
}

output "ssh_host" {
  description = "SSH host for connection"
  value       = var.create_eip ? aws_eip.unix_oidc[0].public_ip : coalesce(aws_instance.unix_oidc.public_ip, aws_instance.unix_oidc.private_ip)
}

# =============================================================================
# Network Outputs
# =============================================================================

output "vpc_id" {
  description = "VPC ID where the instance is deployed"
  value       = local.vpc_id
}

output "subnet_id" {
  description = "Subnet ID where the instance is deployed"
  value       = local.subnet_id
}

output "security_group_id" {
  description = "Security group ID attached to the instance"
  value       = aws_security_group.unix_oidc.id
}

output "availability_zone" {
  description = "Availability zone of the instance"
  value       = aws_instance.unix_oidc.availability_zone
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

output "ami_id" {
  description = "AMI ID used for the instance"
  value       = local.ami_id
}

# =============================================================================
# Status Outputs
# =============================================================================

output "instance_state" {
  description = "Current state of the instance"
  value       = aws_instance.unix_oidc.instance_state
}

# =============================================================================
# Created Resources Summary
# =============================================================================

output "created_vpc" {
  description = "Whether a new VPC was created"
  value       = var.create_vpc && !local.use_existing_vpc
}

output "created_eip" {
  description = "Whether an Elastic IP was created"
  value       = var.create_eip
}
