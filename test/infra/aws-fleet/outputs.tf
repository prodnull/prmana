output "instance_ids" {
  description = "List of EC2 instance IDs for the fleet. Use these with aws ec2 wait or SSM for orchestration."
  value       = aws_instance.fleet[*].id
}

output "public_ips" {
  description = "List of public IP addresses assigned to fleet instances. Order matches instance_ids."
  value       = aws_instance.fleet[*].public_ip
}

output "private_ips" {
  description = "List of private IP addresses for fleet instances. Order matches instance_ids."
  value       = aws_instance.fleet[*].private_ip
}

output "ssh_user" {
  description = "Default SSH user for this distro. Callers use this to construct SSH commands without hardcoding per-distro usernames."
  value       = local.ssh_user
}

output "fleet_tag" {
  description = "Value of the GitHubRun tag applied to all fleet resources. Use for cost attribution and cleanup verification."
  value       = "prmana-ci-${var.github_run_id}"
}

output "region" {
  description = "AWS region where the fleet was deployed. Passed through for use in downstream commands."
  value       = var.aws_region
}

output "ami_id" {
  description = "Resolved AMI ID used for this fleet. Useful for audit and reproducing a run."
  value       = local.ami_id
}

output "security_group_id" {
  description = "Security group ID created for this fleet run. Useful for debugging inbound access issues."
  value       = aws_security_group.fleet.id
}

output "key_pair_name" {
  description = "Name of the ephemeral EC2 key pair created for this fleet run. Used by log collection SSH steps."
  value       = aws_key_pair.fleet.key_name
}
