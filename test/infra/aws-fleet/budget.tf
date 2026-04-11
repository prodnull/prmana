# ---------------------------------------------------------------------------
# AWS Budget — per-run cost cap (T-DT0-01-05: runaway fleet mitigation layer 3)
#
# Scope: costs tagged Project=prmana-ci. This catches every resource created
# by this module because the provider default_tags block in main.tf applies
# Project=prmana-ci to all resources unconditionally.
#
# The budget is a backstop. Primary controls are:
#   1. instance_count <= 10 (Terraform variable validation)
#   2. shutdown -h +N watchdog in user-data (instance-level)
#   3. This budget alarm (AWS account-level)
#
# Time unit is MONTHLY (required by the AWS Budgets API). Enforcement per-run
# is provided by the fleet-test workflow's always()-destroy step. The budget
# catches cases where workflow teardown fails and instances keep running.
# ---------------------------------------------------------------------------

resource "aws_budgets_budget" "fleet_run" {
  name         = "prmana-ci-${var.github_run_id}"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Tag-scoped cost filter: only track costs from prmana-ci resources.
  # The "user:" prefix is required by the AWS Cost Allocation Tags format.
  # Tags must be activated for cost allocation in the AWS Billing console
  # before this filter is effective (pre-existing requirement, not new).
  cost_filter {
    name   = "TagKeyValue"
    values = ["user:Project$prmana-ci"]
  }

  # Notification at 80% of the budget cap — only created when an SNS topic
  # ARN is provided. AWS Budgets requires at least one subscriber per
  # notification; omitting the block entirely is valid and leaves the budget
  # visible in Cost Explorer without sending alerts.
  dynamic "notification" {
    for_each = var.sns_budget_topic_arn != "" ? [1] : []
    content {
      comparison_operator       = "GREATER_THAN"
      threshold                 = 80
      threshold_type            = "PERCENTAGE"
      notification_type         = "ACTUAL"
      subscriber_sns_topic_arns = [var.sns_budget_topic_arn]
    }
  }

  tags = {
    GitHubRun = var.github_run_id
  }
}
