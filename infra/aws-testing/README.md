# AWS Testing Infrastructure

Secure, cost-controlled infrastructure for testing prmana on Amazon Linux and RHEL.

## Security Model

| Control | Implementation |
|---------|----------------|
| No stored credentials | OIDC federation - GitHub proves identity to AWS |
| Repository restriction | IAM trust policy only allows `prodnull/prmana` |
| Manual trigger only | `workflow_dispatch` - no automatic runs |
| Approval required | GitHub Environment protection rules |
| Instance type limits | IAM policy restricts to t3.micro/small |
| Spot instances only | IAM policy blocks on-demand |
| Auto-cleanup | Instances terminated even on failure |
| Budget alerts | Email at 80% and 100% of $2/month |
| Session timeout | 45 minutes max |
| No SSH access | SSM only - no ports open |

## Cost Estimate

### Infrastructure (Idle/Standing Costs)

| Resource | Monthly Cost | Notes |
|----------|--------------|-------|
| S3 bucket (state) | ~$0.00 | Few KB of state files |
| DynamoDB (locks) | ~$0.00 | PAY_PER_REQUEST, minimal usage |
| IAM resources | $0.00 | IAM is free |
| Security Group | $0.00 | Free |
| Budget alerts | $0.00 | First 2 budgets free per account |
| **Total idle cost** | **~$0.00/month** | No cost when not running tests |

### Per-Test Costs

| Instance Type | Spot Price* | 30-min Test |
|---------------|-------------|-------------|
| t3.micro | ~$0.003/hr | ~$0.0015 |
| t3.small | ~$0.006/hr | ~$0.003 |

*Spot prices vary by region and demand. us-west-2 typical rates shown.

### Monthly Estimates

| Scenario | Cost |
|----------|------|
| Single platform test (t3.small) | ~$0.003 |
| All platforms (3× t3.small) | ~$0.01 |
| 10 full test runs/month | ~$0.10 |
| 50 full test runs/month | ~$0.50 |
| **Monthly budget cap** | **$2.00** |
| Tests before budget alert (80%) | ~160 |

## Setup Instructions

### Prerequisites

- AWS CLI configured with admin access
- Terraform >= 1.0
- GitHub repository admin access

### 1. Set Up Terraform State Backend (Recommended)

For secure, shared state storage with locking:

```bash
cd infra/aws-testing

# Create S3 bucket and DynamoDB table for state
./bootstrap.sh

# Copy the example backend config
cp backend.tf.example backend.tf

# Edit backend.tf - replace ACCOUNT_ID with your AWS account ID
# (The bootstrap script outputs the exact configuration to use)
```

This provides:
- **Encryption at rest** (AES-256)
- **Versioning** (recover from mistakes)
- **State locking** (prevents concurrent modifications)
- **Access restricted** to your AWS account only

**Skip this step** if you want local state (not recommended for shared use).

### 2. Deploy Infrastructure

```bash
cd infra/aws-testing

# Initialize Terraform (with backend if configured)
terraform init

# Review the plan
terraform plan \
  -var="github_repo=prodnull/prmana" \
  -var="budget_email=your@email.com"

# Apply (creates all AWS resources)
terraform apply \
  -var="github_repo=prodnull/prmana" \
  -var="budget_email=your@email.com"
```

### 3. Configure GitHub

1. **Add Repository Secret** (Settings → Secrets and variables → Actions):
   - `AWS_ROLE_ARN`: The IAM role ARN (from Terraform output)

2. **Create Protected Environment** (Settings → Environments → New environment):
   - Name: `aws-testing`
   - Enable "Required reviewers"
   - Add yourself as the only reviewer
   - This ensures **only you** can approve test runs

### 4. Run a Test

1. Go to: **Actions** → **AWS Platform Tests**
2. Click **Run workflow**
3. Select platform and instance type
4. Click **Run workflow**
5. **Approve the deployment** when prompted

## Trigger Methods

### Manual (Recommended)
```
GitHub → Actions → AWS Platform Tests → Run workflow
```

### GitHub CLI
```bash
gh workflow run aws-platform-tests.yml \
  -f platform=amazon-linux-2023 \
  -f instance_type=t3.small
```

### API
```bash
curl -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/prodnull/prmana/actions/workflows/aws-platform-tests.yml/dispatches \
  -d '{"ref":"main","inputs":{"platform":"amazon-linux-2023","instance_type":"t3.small"}}'
```

## Troubleshooting

### "Access Denied" when assuming role
- Verify the GitHub Actions workflow has `id-token: write` permission
- Check the IAM trust policy allows your repository

### Instance launch fails
- Check AWS service quotas for spot instances
- Verify the security group and VPC exist
- Check CloudTrail for detailed errors

### SSM command times out
- Instance may not have SSM agent (older AMIs)
- Check instance has internet access for package downloads

### Budget exceeded
- Spot prices can spike during high demand
- Consider using `t3.micro` for routine tests

## Cleanup

To remove all AWS resources:

```bash
terraform destroy \
  -var="github_repo=prodnull/prmana" \
  -var="budget_email=your@email.com"
```

**Note**: This won't delete the GitHub OIDC provider if other workflows use it.

## Files

| File | Purpose |
|------|---------|
| `main.tf` | All AWS infrastructure (IAM, EC2, Budget) |
| `bootstrap.sh` | Creates S3 bucket and DynamoDB for state storage |
| `backend.tf.example` | Template for Terraform backend configuration |
| `../../.github/workflows/aws-platform-tests.yml` | GitHub Actions workflow |

## Security Audit

Run these commands to verify the setup is secure:

```bash
# Check IAM role trust policy
aws iam get-role --role-name prmana-ci-github-actions \
  --query 'Role.AssumeRolePolicyDocument'

# Check IAM permissions
aws iam get-role-policy --role-name prmana-ci-github-actions \
  --policy-name prmana-ci-permissions

# List any running instances (should be empty)
aws ec2 describe-instances \
  --filters "Name=tag:Project     = "prmana-ci" \
  --query 'Reservations[].Instances[].{ID:InstanceId,State:State.Name}'

# Check budget status
aws budgets describe-budget \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --budget-name prmana-ci-budget
```
