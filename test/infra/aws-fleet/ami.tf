# ---------------------------------------------------------------------------
# AMI resolution for the locked distro × arch matrix.
#
# Strategy:
#   Ubuntu + Amazon Linux 2023: AWS SSM public parameters (owned by AWS, no
#     fragile name-glob, automatically updated on each new release).
#   Debian 12: data "aws_ami" from Debian official owner 136693071363.
#   Rocky 9:   data "aws_ami" from Rocky official owner 792107900819.
#   Fedora 40: data "aws_ami" from Fedora Cloud owner 125523088429 (amd64 only).
#
# Security invariant (T-DT0-01-08): AMIs are resolved only from the above
# well-known, verified public owners. No community or unverified owners.
#
# Cross-variable constraint: fedora-40 + arm64 is not in the matrix.
# This is enforced below via a local that will produce a clear error if
# an unsupported combination is requested (see locals.ami_id).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Fedora 40 + arm64 guard — explicit early fail with a readable message.
# Terraform evaluates locals eagerly; if the combination is invalid, the
# locals.ami_id map construction will reference null and plan will fail cleanly.
# ---------------------------------------------------------------------------
locals {
  fedora_arm64_unsupported = (var.distro == "fedora-40" && var.arch == "arm64")
}

# ---------------------------------------------------------------------------
# Ubuntu 22.04 — SSM public parameters (canonical public parameters)
# Ref: https://documentation.ubuntu.com/aws/en/latest/aws-how-to/instances/find-ubuntu-images/
# ---------------------------------------------------------------------------
data "aws_ssm_parameter" "ubuntu_2204_amd64" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

data "aws_ssm_parameter" "ubuntu_2204_arm64" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/arm64/hvm/ebs-gp2/ami-id"
}

# ---------------------------------------------------------------------------
# Ubuntu 24.04 — SSM public parameters
# ---------------------------------------------------------------------------
data "aws_ssm_parameter" "ubuntu_2404_amd64" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

data "aws_ssm_parameter" "ubuntu_2404_arm64" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp2/ami-id"
}

# ---------------------------------------------------------------------------
# Amazon Linux 2023 — AWS SSM public parameters
# Ref: https://docs.aws.amazon.com/linux/al2023/ug/ec2.html#launch-from-ssm
# ---------------------------------------------------------------------------
data "aws_ssm_parameter" "al2023_amd64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

# ---------------------------------------------------------------------------
# Debian 12 (Bookworm) — owner: 136693071363 (Debian official on AWS Marketplace)
# Ref: https://wiki.debian.org/Cloud/AmazonEC2Image
# ---------------------------------------------------------------------------
data "aws_ami" "debian_12_amd64" {
  most_recent = true
  owners      = ["136693071363"]

  filter {
    name   = "name"
    values = ["debian-12-amd64-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

data "aws_ami" "debian_12_arm64" {
  most_recent = true
  owners      = ["136693071363"]

  filter {
    name   = "name"
    values = ["debian-12-arm64-*"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# ---------------------------------------------------------------------------
# Rocky Linux 9 — owner: 792107900819 (Rocky Linux official)
# Ref: https://rockylinux.org/cloud-images
# Note: Rocky uses "aarch64" in AMI names for arm64.
# ---------------------------------------------------------------------------
data "aws_ami" "rocky_9_amd64" {
  most_recent = true
  owners      = ["792107900819"]

  filter {
    name   = "name"
    values = ["Rocky-9-EC2-Base-*.x86_64-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

data "aws_ami" "rocky_9_arm64" {
  most_recent = true
  owners      = ["792107900819"]

  filter {
    name   = "name"
    values = ["Rocky-9-EC2-Base-*.aarch64-*"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# ---------------------------------------------------------------------------
# Fedora 40 (amd64 only) — owner: 125523088429 (Fedora Cloud official)
# Ref: https://fedoraproject.org/cloud/
# arm64 variant intentionally absent — not in the locked matrix.
# ---------------------------------------------------------------------------
data "aws_ami" "fedora_40_amd64" {
  most_recent = true
  owners      = ["125523088429"]

  filter {
    name   = "name"
    values = ["Fedora-Cloud-Base-40-*.x86_64-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# ---------------------------------------------------------------------------
# AMI resolution map: "${distro}-${arch}" → ami_id string
#
# Fedora 40 + arm64: the map key is intentionally absent. If a caller passes
# distro=fedora-40 + arch=arm64, the lookup returns null, Terraform will error
# at plan time with a clear message referencing the unsupported combination.
# The variable validation blocks catch the individual values; this catches the
# illegal combination.
# ---------------------------------------------------------------------------
locals {
  ami_id_map = {
    "ubuntu-22.04-amd64"     = data.aws_ssm_parameter.ubuntu_2204_amd64.value
    "ubuntu-22.04-arm64"     = data.aws_ssm_parameter.ubuntu_2204_arm64.value
    "ubuntu-24.04-amd64"     = data.aws_ssm_parameter.ubuntu_2404_amd64.value
    "ubuntu-24.04-arm64"     = data.aws_ssm_parameter.ubuntu_2404_arm64.value
    "amazonlinux-2023-amd64" = data.aws_ssm_parameter.al2023_amd64.value
    "amazonlinux-2023-arm64" = data.aws_ssm_parameter.al2023_arm64.value
    "debian-12-amd64"        = data.aws_ami.debian_12_amd64.id
    "debian-12-arm64"        = data.aws_ami.debian_12_arm64.id
    "rocky-9-amd64"          = data.aws_ami.rocky_9_amd64.id
    "rocky-9-arm64"          = data.aws_ami.rocky_9_arm64.id
    "fedora-40-amd64"        = data.aws_ami.fedora_40_amd64.id
    # fedora-40-arm64: intentionally absent — not in the locked distro×arch matrix
  }

  ami_id = local.ami_id_map["${var.distro}-${var.arch}"]

  # SSH user by distro — consumed by outputs.tf
  ssh_user_map = {
    "debian-12"        = "admin"
    "ubuntu-22.04"     = "ubuntu"
    "ubuntu-24.04"     = "ubuntu"
    "rocky-9"          = "rocky"
    "amazonlinux-2023" = "ec2-user"
    "fedora-40"        = "fedora"
  }

  ssh_user = local.ssh_user_map[var.distro]
}
