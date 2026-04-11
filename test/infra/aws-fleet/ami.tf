# ---------------------------------------------------------------------------
# AMI resolution for the locked distro × arch matrix.
#
# Strategy: each data source uses count = 1 only when it matches the selected
# distro × arch combination. This means only one data source is ever evaluated
# per apply, avoiding failures from AMIs not available in the target region or
# from distros not yet selected for a run.
#
# Verified owner IDs (T-DT0-01-08 security invariant):
#   Ubuntu:          099720109477  (Canonical Ltd. official)
#   Amazon Linux:    amazon         (AWS first-party)
#   Debian 12:       136693071363  (Debian official on AWS Marketplace)
#   Rocky Linux 9:   792107900819  (Rocky Linux official)
#   Fedora 40:       125523088429  (Fedora Cloud official)
#
# Cross-variable constraint: fedora-40 + arm64 is not in the matrix.
# Enforced via variable validation block in variables.tf.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Ubuntu 22.04 — Canonical official (owner: 099720109477)
# ---------------------------------------------------------------------------
data "aws_ami" "ubuntu_2204_amd64" {
  count       = var.distro == "ubuntu-22.04" && var.arch == "amd64" ? 1 : 0
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
  count       = var.distro == "ubuntu-22.04" && var.arch == "arm64" ? 1 : 0
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
# ---------------------------------------------------------------------------
data "aws_ami" "ubuntu_2404_amd64" {
  count       = var.distro == "ubuntu-24.04" && var.arch == "amd64" ? 1 : 0
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
  count       = var.distro == "ubuntu-24.04" && var.arch == "arm64" ? 1 : 0
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
  count       = var.distro == "amazonlinux-2023" && var.arch == "amd64" ? 1 : 0
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
  count       = var.distro == "amazonlinux-2023" && var.arch == "arm64" ? 1 : 0
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
  count       = var.distro == "debian-12" && var.arch == "amd64" ? 1 : 0
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
  count       = var.distro == "debian-12" && var.arch == "arm64" ? 1 : 0
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
# Note: Rocky uses "aarch64" in AMI names, "arm64" as the architecture filter.
# ---------------------------------------------------------------------------
data "aws_ami" "rocky_9_amd64" {
  count       = var.distro == "rocky-9" && var.arch == "amd64" ? 1 : 0
  most_recent = true
  owners      = ["792107900819"]

  filter {
    name   = "name"
    values = ["Rocky-9-EC2-Base-*.x86_64"]
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
  count       = var.distro == "rocky-9" && var.arch == "arm64" ? 1 : 0
  most_recent = true
  owners      = ["792107900819"]

  filter {
    name   = "name"
    values = ["Rocky-9-EC2-Base-*.aarch64"]
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
  count       = var.distro == "fedora-40" && var.arch == "amd64" ? 1 : 0
  most_recent = true
  owners      = ["125523088429"]

  filter {
    name   = "name"
    values = ["Fedora-Cloud-Base-40-*.x86_64"]
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
# AMI ID resolution — selects the single data source that was instantiated.
# Only one of the data sources above has count=1; all others are count=0.
# ---------------------------------------------------------------------------
locals {
  ami_id = (
    var.distro == "ubuntu-22.04" && var.arch == "amd64" ? data.aws_ami.ubuntu_2204_amd64[0].id :
    var.distro == "ubuntu-22.04" && var.arch == "arm64" ? data.aws_ami.ubuntu_2204_arm64[0].id :
    var.distro == "ubuntu-24.04" && var.arch == "amd64" ? data.aws_ami.ubuntu_2404_amd64[0].id :
    var.distro == "ubuntu-24.04" && var.arch == "arm64" ? data.aws_ami.ubuntu_2404_arm64[0].id :
    var.distro == "amazonlinux-2023" && var.arch == "amd64" ? data.aws_ami.al2023_amd64[0].id :
    var.distro == "amazonlinux-2023" && var.arch == "arm64" ? data.aws_ami.al2023_arm64[0].id :
    var.distro == "debian-12" && var.arch == "amd64" ? data.aws_ami.debian_12_amd64[0].id :
    var.distro == "debian-12" && var.arch == "arm64" ? data.aws_ami.debian_12_arm64[0].id :
    var.distro == "rocky-9" && var.arch == "amd64" ? data.aws_ami.rocky_9_amd64[0].id :
    var.distro == "rocky-9" && var.arch == "arm64" ? data.aws_ami.rocky_9_arm64[0].id :
    var.distro == "fedora-40" && var.arch == "amd64" ? data.aws_ami.fedora_40_amd64[0].id :
    null # fedora-40 + arm64: caught by variable validation in variables.tf
  )

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
