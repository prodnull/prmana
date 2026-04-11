# test/infra/aws-fleet — prmana-ci Spot Fleet Module

Reusable Terraform module that provisions N spot EC2 instances for fleet-based
integration testing. Consumed by `.github/workflows/fleet-test.yml` (plan DT-0-04).

## Purpose

Provides a parameterized "give me N clean Linux nodes of distro X on arch Y"
primitive for the DT-A, DT-B, and DT-C test phases. Solves the provisioning
problem once; downstream phases assert against the nodes.

**Non-goals (explicit):** This module does NOT install prmana packages, does NOT
configure PAM, does NOT run cargo or any test assertions. That is DT-A's job.
This module is pure infrastructure.

---

## Supported Distro × Arch Matrix

| Distro             | amd64 | arm64 | Default SSH User |
|--------------------|-------|-------|-----------------|
| `debian-12`        | yes   | yes   | `admin`         |
| `ubuntu-22.04`     | yes   | yes   | `ubuntu`        |
| `ubuntu-24.04`     | yes   | yes   | `ubuntu`        |
| `rocky-9`          | yes   | yes   | `rocky`         |
| `amazonlinux-2023` | yes   | yes   | `ec2-user`      |
| `fedora-40`        | yes   | no    | `fedora`        |

`fedora-40` + `arm64` is explicitly excluded from the matrix and will produce a
Terraform plan-time error if requested.

AMI sources (verified, supply-chain-safe per T-DT0-01-08):
- Ubuntu: AWS SSM public parameters (`/aws/service/canonical/ubuntu/server/...`)
- Amazon Linux 2023: AWS SSM public parameters (`/aws/service/ami-amazon-linux-latest/...`)
- Debian 12: owner `136693071363` (Debian official on AWS Marketplace)
- Rocky 9: owner `792107900819` (Rocky Linux official)
- Fedora 40: owner `125523088429` (Fedora Cloud official)

---

## Prerequisites

Before running this module you need:

1. **AWS OIDC federation** configured for your GitHub repository. The existing
   `secrets.AWS_ROLE_ARN` in the repository is already set up for this. Do not
   create a new federation role — reuse the existing one.

2. **IAM role supplemental policy** — the `unix-oidc-ci-github-actions` role
   needs the following additions beyond its base permissions (the Terraform AWS
   provider makes many read-back calls after resource creation that the existing
   CLI-based workflows do not trigger):

   ```json
   {
     "Statement": [
       {
         "Sid": "PrmanaFleetEC2Reads",
         "Effect": "Allow",
         "Action": "ec2:Describe*",
         "Resource": "*"
       },
       {
         "Sid": "PrmanaFleetEC2Writes",
         "Effect": "Allow",
         "Action": [
           "ec2:ImportKeyPair", "ec2:DeleteKeyPair",
           "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
           "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress",
           "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress",
           "ec2:RunInstances", "ec2:TerminateInstances",
           "ec2:CreateTags", "ec2:ModifyInstanceAttribute"
         ],
         "Resource": "*"
       },
       {
         "Sid": "PrmanaFleetBudgets",
         "Effect": "Allow",
         "Action": [
           "budgets:CreateBudget", "budgets:ModifyBudget", "budgets:DeleteBudget",
           "budgets:DescribeBudgets", "budgets:ViewBudget",
           "budgets:TagResource", "budgets:ListTagsForResource"
         ],
         "Resource": "arn:aws:budgets::<ACCOUNT_ID>:budget/prmana-ci-*"
       },
       {
         "Sid": "PrmanaFleetPassRole",
         "Effect": "Allow",
         "Action": "iam:PassRole",
         "Resource": "arn:aws:iam::<ACCOUNT_ID>:instance-profile/unix-oidc-ci-instance-profile"
       }
     ]
   }
   ```

   Apply with: `aws iam put-role-policy --role-name unix-oidc-ci-github-actions --policy-name prmana-fleet-supplemental --policy-document file://policy.json`

3. **IAM instance profile** named `unix-oidc-ci-instance-profile` (or override
   `iam_instance_profile` in `main.tf`). This profile is already created in the
   account for the legacy arm64 CI workflows.

3. **Default VPC** must exist in `var.aws_region` (us-west-2 by default). This
   module does not create a VPC. If the default VPC was deleted, restore it with:
   `aws ec2 create-default-vpc --region us-west-2`

4. **Cost Allocation Tags** `Project` and `GitHubRun` activated in AWS Billing
   console for the budget cost filter to be effective. Tags must be activated
   before spending appears in filtered budget views.

---

## Usage

### Minimal example (fleet-test.yml pattern)

```hcl
module "fleet" {
  source = "./test/infra/aws-fleet"

  distro         = "ubuntu-22.04"
  arch           = "amd64"
  instance_count = 5
  github_run_id  = var.github_run_id   # from workflow env
  ssh_public_key = tls_private_key.ephemeral.public_key_openssh
}
```

### Manual invocation (developer testing)

```bash
cd test/infra/aws-fleet

terraform init \
  -backend-config="bucket=prmana-ci-tfstate" \
  -backend-config="key=runs/${GITHUB_RUN_ID}/terraform.tfstate" \
  -backend-config="region=us-west-2" \
  -backend-config="dynamodb_table=prmana-ci-tflock"

SSH_KEY=$(ssh-keygen -t ed25519 -C "prmana-ci" -f /tmp/fleet-key -N "" && cat /tmp/fleet-key.pub)

terraform apply \
  -var="distro=ubuntu-22.04" \
  -var="arch=amd64" \
  -var="instance_count=5" \
  -var="github_run_id=${GITHUB_RUN_ID}" \
  -var="ssh_public_key=${SSH_KEY}" \
  -var="max_instance_minutes=30" \
  -auto-approve

# After testing:
terraform destroy -auto-approve
```

---

## Variables

| Name                  | Type   | Default     | Description |
|-----------------------|--------|-------------|-------------|
| `distro`              | string | (required)  | Linux distro. See supported matrix above. |
| `arch`                | string | (required)  | `amd64` or `arm64`. |
| `instance_count`      | number | (required)  | Number of spot instances. Must be 1–10. |
| `github_run_id`       | string | (required)  | GitHub Actions run ID for tagging and attribution. |
| `ssh_public_key`      | string | (required)  | Public key material for the ephemeral keypair. |
| `max_instance_minutes`| number | `30`        | Hard shutdown watchdog in minutes. Range: 5–120. |
| `budget_limit_usd`    | number | `5`         | Per-run AWS Budget cap in USD. |
| `aws_region`          | string | `us-west-2` | AWS region. Must match your federation role's region. |
| `instance_type_amd64` | string | `t3a.small` | EC2 instance type for x86_64. |
| `instance_type_arm64` | string | `t4g.small` | EC2 instance type for Graviton (arm64). |
| `sns_budget_topic_arn`| string | `""`        | Optional SNS topic for budget alerts. Budget is created either way. |
| `allowed_ssh_cidr`    | string | `0.0.0.0/0` | Inbound SSH CIDR. **CI-only default** — restrict in production. |

---

## Outputs

| Name               | Description |
|--------------------|-------------|
| `instance_ids`     | List of EC2 instance IDs. |
| `public_ips`       | List of public IP addresses (same order as `instance_ids`). |
| `private_ips`      | List of private IP addresses. |
| `ssh_user`         | Default SSH user for the selected distro. |
| `fleet_tag`        | Value of the `GitHubRun` tag: `prmana-ci-{github_run_id}`. |
| `region`           | AWS region where the fleet was deployed. |
| `ami_id`           | Resolved AMI ID used for this run (for audit). |
| `security_group_id`| Security group created for this fleet run. |
| `key_pair_name`    | EC2 key pair name created for this fleet run. |

---

## Cost Model

- `t3a.small` spot in us-west-2: ~$0.005–0.01/hr
- `t4g.small` spot in us-west-2: ~$0.005–0.01/hr
- Full matrix run (6 distros × ~2 arches × 5 nodes × 15 min): ~$0.50
- Budget default ($5) provides ~10× headroom over a typical full-matrix run

---

## Shutdown Watchdog (Defense in Depth)

Three independent layers prevent runaway fleets:

**Layer 1 — Terraform validation:** `instance_count` is capped at 10 by a
`validation` block. An invalid value fails at `terraform plan` time before any
API call is made.

**Layer 2 — Instance-level watchdog (this module):** The user-data script runs
`shutdown -h +N` where N is `var.max_instance_minutes` (default: 30). Combined
with `instance_initiated_shutdown_behavior = "terminate"` in the `aws_instance`
resource, the instance is fully destroyed when the timer fires. This is
independent of the workflow; it fires even if the CI runner crashes or the
`terraform destroy` step is skipped.

**Layer 3 — AWS Budget alarm:** `budget.tf` creates a monthly budget scoped
to `Project=prmana-ci` with a 80%-of-cap SNS notification. If layers 1 and 2
both fail and instances accumulate, the budget alarm fires. This is the backstop.

The workflow-level `if: always()` destroy step is an additional safety net but
is NOT counted as a formal layer — it depends on the GitHub Actions runner
remaining healthy, which the above layers do not.

---

## Security Notes

- **IMDSv2 enforced:** All instances require `http_tokens = "required"`. This
  prevents SSRF-based instance credential theft (T-DT0-01-03).
- **Ephemeral keypair:** One keypair per run, named `prmana-ci-{run_id}`. The
  private key is generated in the workflow and never stored. The keypair is
  destroyed with the fleet.
- **Run-scoped security group:** One SG per run, named
  `prmana-ci-fleet-{run_id}`. Destroyed with the fleet. No shared SGs between
  runs.
- **AMI supply chain:** Only verified public owners are used. No community AMIs
  or name-glob-only searches (T-DT0-01-08).
- **Branding note:** The IAM instance profile `unix-oidc-ci-instance-profile`
  retains legacy naming. A future cleanup task can rename it to
  `prmana-ci-instance-profile` once all legacy workflows are migrated.
