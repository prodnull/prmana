# Per-run Azure Consumption Budget — a cost-guardrail backstop.
#
# Cost enforcement layers (T-DT0-02-05):
#   1. vm_count <= 10 validation in variables.tf
#   2. cloud-init `shutdown -h +<minutes>` watchdog in each VM
#   3. eviction_policy = Delete: Spot reclaim fully destroys VMs
#   4. This budget: alerts at 80% of cap; workflow teardown is primary enforcement
#
# The budget is scoped to the per-run resource group so it only tracks costs
# for this specific CI run (T-DT0-02-06 isolation).

resource "azurerm_consumption_budget_resource_group" "fleet" {
  name              = "budget-prmana-ci-${var.github_run_id}"
  resource_group_id = azurerm_resource_group.fleet.id

  amount     = var.budget_limit_usd
  time_grain = "Monthly"

  time_period {
    # Budget window starts at the first of the current month.
    # formatdate produces e.g. "2026-04-01T00:00:00Z".
    start_date = formatdate("YYYY-MM-01'T'00:00:00'Z'", timestamp())
  }

  notification {
    threshold      = 80
    operator       = "GreaterThan"
    threshold_type = "Actual"
    contact_emails = []
  }
}
