# unix-oidc AWS Terraform Module
# https://github.com/prodnull/unix-oidc
#
# This module creates an EC2 instance with unix-oidc installed and configured.
# It can create a new VPC or use an existing one.

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

# =============================================================================
# Data Sources
# =============================================================================

# Get current region
data "aws_region" "current" {}

# Get available AZs
data "aws_availability_zones" "available" {
  state = "available"
}

# Auto-detect Ubuntu 22.04 LTS AMI if not specified
data "aws_ami" "ubuntu" {
  count       = var.ami_id == "" ? 1 : 0
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Lookup existing VPC if provided
data "aws_vpc" "existing" {
  count = var.vpc_id != "" ? 1 : 0
  id    = var.vpc_id
}

# Lookup existing subnet if provided
data "aws_subnet" "existing" {
  count = var.subnet_id != "" ? 1 : 0
  id    = var.subnet_id
}

# =============================================================================
# Local Values
# =============================================================================

locals {
  # AMI selection
  ami_id = var.ami_id != "" ? var.ami_id : data.aws_ami.ubuntu[0].id

  # VPC selection
  use_existing_vpc = var.vpc_id != ""
  vpc_id           = local.use_existing_vpc ? var.vpc_id : (var.create_vpc ? aws_vpc.main[0].id : "")

  # Subnet selection
  use_existing_subnet = var.subnet_id != ""
  subnet_id = local.use_existing_subnet ? var.subnet_id : (
    var.create_vpc ? aws_subnet.public[0].id : ""
  )

  # Availability zones
  azs = length(var.availability_zones) > 0 ? var.availability_zones : slice(data.aws_availability_zones.available.names, 0, min(2, length(data.aws_availability_zones.available.names)))

  # Common tags
  common_tags = merge(
    {
      "Project"     = "unix-oidc"
      "Environment" = var.environment
      "ManagedBy"   = "terraform"
    },
    var.tags
  )

  # User data script for installing unix-oidc
  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail

    # Log to both console and file
    exec > >(tee /var/log/unix-oidc-install.log) 2>&1
    echo "Starting unix-oidc installation at $(date)"

    # Wait for cloud-init to complete
    cloud-init status --wait || true

    # Update packages
    apt-get update -y
    apt-get install -y curl jq

    # Download and run installer
    curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh -o /tmp/install.sh
    chmod +x /tmp/install.sh

    # Run installer with provided configuration
    /tmp/install.sh \
      --issuer "${var.oidc_issuer}" \
      --client-id "${var.oidc_client_id}" \
      ${var.install_agent ? "" : "--no-agent"} \
      --yes

    # Configure DPoP if enabled
    if [ "${var.enable_dpop}" = "true" ]; then
      if [ -f /etc/unix-oidc/config.env ]; then
        echo "" >> /etc/unix-oidc/config.env
        echo "# DPoP token binding enabled" >> /etc/unix-oidc/config.env
        echo "OIDC_DPOP_REQUIRED=true" >> /etc/unix-oidc/config.env
      fi
    fi

    # Apply PAM configuration for sshd
    # This copies the recommended config - adjust for your security requirements
    if [ -f /etc/unix-oidc/pam.d-sshd.recommended ]; then
      cp /etc/pam.d/sshd /etc/pam.d/sshd.backup.$(date +%Y%m%d%H%M%S)
      cp /etc/unix-oidc/pam.d-sshd.recommended /etc/pam.d/sshd
      echo "PAM configuration applied for sshd"
    fi

    # Restart SSH to pick up PAM changes
    systemctl restart sshd

    echo "unix-oidc installation completed at $(date)"
    EOF
}

# =============================================================================
# VPC Resources (conditional)
# =============================================================================

resource "aws_vpc" "main" {
  count = var.create_vpc && !local.use_existing_vpc ? 1 : 0

  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "${var.instance_name}-vpc"
  })
}

resource "aws_internet_gateway" "main" {
  count = var.create_vpc && !local.use_existing_vpc ? 1 : 0

  vpc_id = aws_vpc.main[0].id

  tags = merge(local.common_tags, {
    Name = "${var.instance_name}-igw"
  })
}

resource "aws_subnet" "public" {
  count = var.create_vpc && !local.use_existing_vpc ? length(local.azs) : 0

  vpc_id                  = aws_vpc.main[0].id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${var.instance_name}-public-${count.index + 1}"
    Type = "public"
  })
}

resource "aws_route_table" "public" {
  count = var.create_vpc && !local.use_existing_vpc ? 1 : 0

  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }

  tags = merge(local.common_tags, {
    Name = "${var.instance_name}-public-rt"
  })
}

resource "aws_route_table_association" "public" {
  count = var.create_vpc && !local.use_existing_vpc ? length(local.azs) : 0

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

# =============================================================================
# Security Group
# =============================================================================

resource "aws_security_group" "unix_oidc" {
  name        = "${var.instance_name}-sg"
  description = "Security group for unix-oidc instance"
  vpc_id      = local.vpc_id

  # Allow SSH from specified CIDRs
  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidrs
  }

  # Allow all outbound traffic (required for OIDC provider communication)
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.instance_name}-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# EC2 Instance
# =============================================================================

resource "aws_instance" "unix_oidc" {
  ami                         = local.ami_id
  instance_type               = var.instance_type
  key_name                    = var.key_name
  subnet_id                   = local.subnet_id
  vpc_security_group_ids      = [aws_security_group.unix_oidc.id]
  associate_public_ip_address = var.associate_public_ip

  user_data                   = local.user_data
  user_data_replace_on_change = true

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = var.root_volume_type
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  tags = merge(local.common_tags, {
    Name = var.instance_name
  })

  # Ensure VPC and subnets are ready before creating instance
  depends_on = [
    aws_route_table_association.public,
    aws_internet_gateway.main
  ]
}

# =============================================================================
# Elastic IP (optional)
# =============================================================================

resource "aws_eip" "unix_oidc" {
  count = var.create_eip ? 1 : 0

  instance = aws_instance.unix_oidc.id
  domain   = "vpc"

  tags = merge(local.common_tags, {
    Name = "${var.instance_name}-eip"
  })

  depends_on = [aws_internet_gateway.main]
}
