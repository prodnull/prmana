# ---------------------------------------------------------------------------
# Fleet compute resources — see Task 2 of DT-0-01-PLAN.md for full implementation.
# This stub satisfies terraform validate for the module scaffold (Task 1).
# The full implementation (spot instances, IMDSv2, shutdown watchdog) is added
# in Task 2.
# ---------------------------------------------------------------------------

provider "aws" {
  region = var.aws_region

  # Default tags applied to every resource in this module (T-DT0-01-06).
  # Ensures the budget cost filter on Project=prmana-ci catches all resources
  # even if a resource-level tags block is accidentally omitted.
  default_tags {
    tags = {
      Project   = "prmana-ci"
      ManagedBy = "terraform"
    }
  }
}

# ---------------------------------------------------------------------------
# Spot fleet: one aws_instance per count index.
# Using per-instance spot requests (not aws_spot_fleet_request) so that
# outputs are flat lists and teardown is unambiguous.
# ---------------------------------------------------------------------------
resource "aws_instance" "fleet" {
  count = var.instance_count

  ami           = local.ami_id
  instance_type = var.arch == "arm64" ? var.instance_type_arm64 : var.instance_type_amd64

  # Spot market configuration (T-DT0-01-05: runaway fleet mitigation layer 2)
  instance_market_options {
    market_type = "spot"
    spot_options {
      spot_instance_type             = "one-time"
      instance_interruption_behavior = "terminate"
    }
  }

  # Note: instance_initiated_shutdown_behavior is intentionally absent.
  # AWS does not support modifying this attribute on spot instances via
  # ModifyInstanceAttribute (UnsupportedOperation). Spot instances default
  # to "terminate" on shutdown, which is the behaviour we want. The user-data
  # watchdog (shutdown -h +N) combined with spot_options.instance_interruption_behavior
  # = "terminate" provides the required auto-destroy guarantee.

  # IMDSv2 enforcement (T-DT0-01-03: SSRF-based credential theft mitigation)
  metadata_options {
    http_tokens            = "required"
    http_endpoint          = "enabled"
    instance_metadata_tags = "enabled"
  }

  # Reuse the existing CI instance profile (see README.md for prerequisites).
  # This profile is already scoped to test-only actions in the legacy workflows.
  # T-DT0-01-07: over-scoping of this profile is a pre-existing issue, not
  # introduced by this module.
  iam_instance_profile = "prmana-ci-instance-profile"

  key_name               = aws_key_pair.fleet.key_name
  vpc_security_group_ids = [aws_security_group.fleet.id]

  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    max_instance_minutes = var.max_instance_minutes
    github_run_id        = var.github_run_id
    distro               = var.distro
    arch                 = var.arch
  })

  tags = {
    Name          = "prmana-ci-${var.github_run_id}-${count.index}"
    GitHubRun     = var.github_run_id
    Distro        = var.distro
    Arch          = var.arch
    AutoTerminate = "true"
  }
}
