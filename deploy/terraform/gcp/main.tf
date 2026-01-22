# unix-oidc GCP Terraform Module
# https://github.com/prodnull/unix-oidc
#
# This module creates a GCE instance with unix-oidc installed and configured.
# It can create a new VPC or use an existing one.

terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
  }
}

# =============================================================================
# Local Values
# =============================================================================

locals {
  # Network selection
  create_network = var.network == ""
  network        = local.create_network ? google_compute_network.main[0].self_link : var.network
  subnetwork     = var.subnetwork != "" ? var.subnetwork : (local.create_network ? google_compute_subnetwork.main[0].self_link : "")

  # Common labels
  common_labels = merge(
    {
      "project"     = "unix-oidc"
      "environment" = var.environment
      "managed-by"  = "terraform"
    },
    var.labels
  )

  # User data script for installing unix-oidc
  startup_script = <<-EOF
    #!/bin/bash
    set -euo pipefail

    # Log to both console and file
    exec > >(tee /var/log/unix-oidc-install.log) 2>&1
    echo "Starting unix-oidc installation at $(date)"

    # Wait for cloud-init to complete (if applicable)
    if command -v cloud-init >/dev/null 2>&1; then
      cloud-init status --wait || true
    fi

    # Detect package manager and install prerequisites
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y curl jq
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y curl jq
    elif command -v yum >/dev/null 2>&1; then
      yum install -y curl jq
    fi

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
    systemctl restart sshd || systemctl restart ssh

    echo "unix-oidc installation completed at $(date)"
    EOF
}

# =============================================================================
# VPC Network (conditional)
# =============================================================================

resource "google_compute_network" "main" {
  count = local.create_network ? 1 : 0

  name                    = "${var.instance_name}-network"
  project                 = var.project_id
  auto_create_subnetworks = false
  description             = "VPC network for unix-oidc instance"
}

resource "google_compute_subnetwork" "main" {
  count = local.create_network ? 1 : 0

  name          = "${var.instance_name}-subnet"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.main[0].self_link
  ip_cidr_range = var.subnet_cidr

  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# =============================================================================
# Firewall Rules
# =============================================================================

resource "google_compute_firewall" "allow_ssh" {
  name        = "${var.instance_name}-allow-ssh"
  project     = var.project_id
  network     = local.network
  description = "Allow SSH access to unix-oidc instance"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.allowed_ssh_cidrs
  target_tags   = ["unix-oidc"]

  priority = 1000
}

resource "google_compute_firewall" "allow_egress" {
  name        = "${var.instance_name}-allow-egress"
  project     = var.project_id
  network     = local.network
  description = "Allow outbound traffic for OIDC provider communication"
  direction   = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["443", "80"]
  }

  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["unix-oidc"]

  priority = 1000
}

# =============================================================================
# GCE Instance
# =============================================================================

resource "google_compute_instance" "unix_oidc" {
  name         = var.instance_name
  project      = var.project_id
  zone         = var.zone
  machine_type = var.machine_type

  tags = ["unix-oidc"]

  labels = local.common_labels

  boot_disk {
    initialize_params {
      image = "projects/${var.image_project}/global/images/family/${var.image_family}"
      size  = var.boot_disk_size
      type  = var.boot_disk_type
    }
  }

  network_interface {
    network    = local.network
    subnetwork = local.subnetwork

    dynamic "access_config" {
      for_each = var.assign_public_ip ? [1] : []
      content {
        // Ephemeral public IP
      }
    }
  }

  metadata = {
    startup-script = local.startup_script
    ssh-keys       = "${var.ssh_user}:${var.ssh_public_key}"
  }

  service_account {
    email  = var.service_account_email
    scopes = var.service_account_scopes
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    preemptible         = var.preemptible
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  allow_stopping_for_update = true

  depends_on = [
    google_compute_subnetwork.main,
    google_compute_firewall.allow_ssh,
    google_compute_firewall.allow_egress
  ]
}

# =============================================================================
# Static External IP (optional)
# =============================================================================

resource "google_compute_address" "static_ip" {
  count = var.create_static_ip ? 1 : 0

  name         = "${var.instance_name}-ip"
  project      = var.project_id
  region       = var.region
  address_type = "EXTERNAL"
  description  = "Static external IP for unix-oidc instance"
}
