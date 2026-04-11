# ---------------------------------------------------------------------------
# AMI resolution for the locked distro × arch matrix.
#
# Strategy: all distros use data "aws_ami" with verified public owner IDs.
# No SSM parameter lookups — avoids requiring ssm:GetParameter IAM permission
# on the CI role; ec2:DescribeImages is sufficient and already granted.
#
# Verified owner IDs (T-DT0-01-08 security invariant):
#   Ubuntu:          099720109477  (Canonical Ltd. official)
#   Amazon Linux:    amazon         (AWS first-party, resolves to AWS account)
#   Debian 12:       136693071363  (Debian official on AWS Marketplace)
#   Rocky Linux 9:   792107900819  (Rocky Linux official)
#   Fedora 40:       125523088429  (Fedora Cloud official)
#
# Cross-variable constraint: fedora-40 + arm64 is not in the matrix.
# Enforced via variable validation block in variables.tf.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Fedora 40 + arm64 guard — explicit local for readable plan-time errors.
# ---------------------------------------------------------------------------
locals {
  fedora_arm64_unsupported = (var.distro == "fedora-40" && var.arch == "arm64")
}

# ---------------------------------------------------------------------------
# Ubuntu 22.04 — Canonical official (owner: 099720109477)
# Name pattern matches Canonical's stable HVM/EBS naming scheme.
# ---------------------------------------------------------------------------
data "aws_ami" "ubuntu_2204_amd64" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
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

data "aws_ami" "ubuntu_2204_arm64" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-arm64-server-*"]
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
# Ubuntu 24.04 — Canonical official (owner: 099720109477)
# 24.04 uses hvm-ssd-gp3 in the path (GP3 root volumes are the new default).
# ---------------------------------------------------------------------------
data "aws_ami" "ubuntu_2404_amd64" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
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

data "aws_ami" "ubuntu_2404_arm64" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*"]
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
# Amazon Linux 2023 — AWS first-party (owner: amazon)
# ---------------------------------------------------------------------------
data "aws_ami" "al2023_amd64" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
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

data "aws_ami" "al2023_arm64" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-arm64"]
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
    "ubuntu-22.04-amd64"     = data.aws_ami.ubuntu_2204_amd64.id
    "ubuntu-22.04-arm64"     = data.aws_ami.ubuntu_2204_arm64.id
    "ubuntu-24.04-amd64"     = data.aws_ami.ubuntu_2404_amd64.id
    "ubuntu-24.04-arm64"     = data.aws_ami.ubuntu_2404_arm64.id
    "amazonlinux-2023-amd64" = data.aws_ami.al2023_amd64.id
    "amazonlinux-2023-arm64" = data.aws_ami.al2023_arm64.id
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
