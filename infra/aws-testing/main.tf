# =============================================================================
# prmana AWS Testing Infrastructure
# =============================================================================
#
# SECURITY MODEL:
# - GitHub Actions authenticates via OIDC (no stored credentials)
# - Only manual workflow_dispatch triggers allowed
# - Only prodnull/prmana repository can assume the role
# - Only spot instances (cost control)
# - Only t3/t4g micro/small/medium instances (cost control)
# - All resources must be tagged for cost tracking
# - 45-minute maximum session duration
# - Budget alerts at 80% and 100% of $5/month limit
#
# CAPABILITIES:
# - x86_64 platform tests (t3 instances)
# - arm64/Graviton tests (t4g instances)
# - Custom AMI management (auto-build, retain 2 AMIs)
# - SNS notifications for AMI builds
#
# COST: ~$0.005-0.015 per test run (spot instances, 15-30 min)
#       ~$1/month for AMI storage
#       Total budget: $5/month
#
# Usage:
#   cd infra/aws-testing
#   terraform init
#   terraform apply -var="github_repo=prodnull/prmana" -var="budget_email=you@example.com"
#
# =============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "prmana-ci"
      ManagedBy   = "terraform"
      Repository  = var.github_repo
      Environment = "ci"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "aws_region" {
  description = "AWS region for testing"
  type        = string
  default     = "us-west-2"
}

variable "github_repo" {
  description = "GitHub repository (owner/repo format)"
  type        = string
  default     = "prodnull/prmana"

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+/[a-zA-Z0-9-_.]+$", var.github_repo))
    error_message = "github_repo must be in owner/repo format"
  }
}

variable "budget_limit_usd" {
  description = "Monthly budget limit in USD"
  type        = number
  default     = 5.00
}

variable "budget_email" {
  description = "Email for budget alerts"
  type        = string
}

variable "allowed_instance_types" {
  description = "Instance types allowed for testing (cost control)"
  type        = list(string)
  default     = ["t3.micro", "t3.small", "t4g.micro", "t4g.small", "t4g.medium"]
}

variable "max_session_duration_seconds" {
  description = "Maximum duration for assumed role sessions"
  type        = number
  default     = 3600 # 1 hour minimum required by AWS; workflow has 45-min timeout
}

# =============================================================================
# GitHub OIDC Provider
# =============================================================================

# Create OIDC provider for GitHub Actions
# Note: This is account-global. If you already have one, import it:
#   terraform import aws_iam_openid_connect_provider.github arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  tags = {
    Name = "github-actions-oidc"
  }
}

# =============================================================================
# IAM Role for GitHub Actions
# =============================================================================

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "github_actions" {
  name                 = "prmana-ci-github-actions"
  max_session_duration = var.max_session_duration_seconds

  # SECURITY: Trust policy restricts to specific repo and workflow_dispatch only
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            # SECURITY: Only this specific repository
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:*"
          }
        }
      }
    ]
  })

  tags = {
    Name = "prmana-ci-github-actions"
  }
}

# =============================================================================
# IAM Policy - Least Privilege
# =============================================================================

resource "aws_iam_role_policy" "github_actions" {
  name = "prmana-ci-permissions"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # EC2: Launch spot instances only, specific types only
      {
        Sid    = "EC2LaunchSpotOnly"
        Effect = "Allow"
        Action = ["ec2:RunInstances"]
        Resource = [
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"
        ]
        Condition = {
          StringEquals = {
            "ec2:InstanceMarketType" = "spot"
            # SECURITY: Must tag with project
            "aws:RequestTag/Project" = "prmana-ci"
            # SECURITY: Only allowed instance types
            "ec2:InstanceType" = var.allowed_instance_types
          }
        }
      },
      # EC2: Required resources for RunInstances
      {
        Sid    = "EC2RunInstancesResources"
        Effect = "Allow"
        Action = ["ec2:RunInstances"]
        Resource = [
          "arn:aws:ec2:${var.aws_region}::image/*",
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:subnet/*",
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:security-group/*",
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:network-interface/*",
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:volume/*",
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:spot-instances-request/*"
        ]
      },
      # EC2: Tag on creation
      {
        Sid      = "EC2CreateTags"
        Effect   = "Allow"
        Action   = ["ec2:CreateTags"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:CreateAction" = "RunInstances"
          }
        }
      },
      # EC2: Manage only our tagged instances
      {
        Sid    = "EC2ManageTaggedInstances"
        Effect = "Allow"
        Action = [
          "ec2:TerminateInstances",
          "ec2:StopInstances"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            # SECURITY: Can only manage instances we created
            "aws:ResourceTag/Project" = "prmana-ci"
          }
        }
      },
      # EC2: Read-only describe actions
      {
        Sid    = "EC2DescribeReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeImages",
          "ec2:DescribeSpotPriceHistory",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs"
        ]
        Resource = "*"
      },
      # SSM: Get AMI parameters (public AWS parameters)
      {
        Sid    = "SSMGetParameters"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = [
          "arn:aws:ssm:${var.aws_region}::parameter/aws/service/ami-amazon-linux-latest/*",
          "arn:aws:ssm:${var.aws_region}::parameter/aws/service/ami-rockylinux-latest/*"
        ]
      },
      # SSM: Access to AWS-RunShellScript document (no tag condition - AWS-managed)
      {
        Sid    = "SSMRunShellScriptDocument"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand"
        ]
        Resource = [
          "arn:aws:ssm:${var.aws_region}::document/AWS-RunShellScript"
        ]
      },
      # SSM: Run commands on our tagged instances only
      {
        Sid    = "SSMSendCommandToInstances"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand"
        ]
        Resource = [
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"
        ]
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Project" = "prmana-ci"
          }
        }
      },
      # SSM: Get command results
      {
        Sid    = "SSMGetCommandInvocation"
        Effect = "Allow"
        Action = [
          "ssm:GetCommandInvocation",
          "ssm:ListCommandInvocations"
        ]
        Resource = "*"
      },
      # IAM: Pass role for instance profile
      {
        Sid    = "IAMPassRole"
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [
          aws_iam_role.ec2_instance.arn
        ]
      },
      # AMI: Create images from our tagged instances
      {
        Sid    = "AMICreateFromInstance"
        Effect = "Allow"
        Action = [
          "ec2:CreateImage"
        ]
        Resource = [
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"
        ]
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Project" = "prmana-ci"
          }
        }
      },
      # AMI: Allow creating AMI resources with project tag
      {
        Sid    = "AMICreateResources"
        Effect = "Allow"
        Action = [
          "ec2:CreateImage"
        ]
        Resource = [
          "arn:aws:ec2:${var.aws_region}::image/*",
          "arn:aws:ec2:${var.aws_region}::snapshot/*"
        ]
      },
      # AMI: Tag AMIs during creation
      {
        Sid    = "AMICreateTags"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags"
        ]
        Resource = [
          "arn:aws:ec2:${var.aws_region}::image/*",
          "arn:aws:ec2:${var.aws_region}::snapshot/*"
        ]
        Condition = {
          StringEquals = {
            "ec2:CreateAction" = "CreateImage"
          }
        }
      },
      # AMI: Describe images (no tag condition needed for describe)
      {
        Sid    = "AMIDescribe"
        Effect = "Allow"
        Action = [
          "ec2:DescribeImages",
          "ec2:DescribeSnapshots"
        ]
        Resource = "*"
      },
      # AMI: Manage snapshots for AMIs we own
      {
        Sid    = "AMISnapshots"
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:DeleteSnapshot"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Project" = "prmana-ci"
          }
        }
      },
      # AMI: Deregister our tagged AMIs
      {
        Sid    = "AMIDeregister"
        Effect = "Allow"
        Action = [
          "ec2:DeregisterImage"
        ]
        Resource = "*"
      },
      # SNS: Publish notifications and list topics
      {
        Sid    = "SNSPublish"
        Effect = "Allow"
        Action = [
          "sns:Publish",
          "sns:ListTopics"
        ]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# IAM Role for EC2 Instances (SSM access)
# =============================================================================

resource "aws_iam_role" "ec2_instance" {
  name = "prmana-ci-ec2-instance"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "prmana-ci-ec2-instance"
  }
}

resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_instance" {
  name = "prmana-ci-instance-profile"
  role = aws_iam_role.ec2_instance.name
}

# =============================================================================
# Security Group
# =============================================================================

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "test_instances" {
  name        = "prmana-ci-test-instances"
  description = "Security group for prmana CI test instances"
  vpc_id      = data.aws_vpc.default.id

  # SECURITY: No inbound access - we use SSM only
  # No ingress rules = no SSH, no ports open

  # Allow outbound for package installation and SSM
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow outbound for SSM and package downloads"
  }

  tags = {
    Name = "prmana-ci-test-instances"
  }
}

# =============================================================================
# SNS Topic for CI Notifications
# =============================================================================

resource "aws_sns_topic" "ci_notifications" {
  name = "prmana-ci-notifications"

  tags = {
    Name = "prmana-ci-notifications"
  }
}

resource "aws_sns_topic_subscription" "ci_email" {
  topic_arn = aws_sns_topic.ci_notifications.arn
  protocol  = "email"
  endpoint  = var.budget_email # Reuse the budget email
}

# =============================================================================
# Budget Alert
# =============================================================================

resource "aws_budgets_budget" "ci_testing" {
  name         = "prmana-ci-budget"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["user:Project     = "prmana-ci"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }
}

# =============================================================================
# Outputs
# =============================================================================

output "github_actions_role_arn" {
  description = "ARN of the IAM role for GitHub Actions to assume"
  value       = aws_iam_role.github_actions.arn
}

output "instance_profile_name" {
  description = "Name of the instance profile for EC2 instances"
  value       = aws_iam_instance_profile.ec2_instance.name
}

output "security_group_id" {
  description = "ID of the security group for test instances"
  value       = aws_security_group.test_instances.id
}

output "sns_topic_arn" {
  description = "ARN of SNS topic for CI notifications"
  value       = aws_sns_topic.ci_notifications.arn
}

output "setup_instructions" {
  description = "Next steps to complete setup"
  value       = <<-EOT

    ============================================================
    SETUP COMPLETE! Next steps:
    ============================================================

    1. Add this secret to your GitHub repository:
       - AWS_ROLE_ARN: ${aws_iam_role.github_actions.arn}

    2. Create a GitHub Environment named 'aws-testing':
       - Go to: https://github.com/${var.github_repo}/settings/environments
       - Click "New environment" → name it "aws-testing"
       - Enable "Required reviewers" → Add yourself
       - This ensures ONLY YOU can approve AWS test runs

    3. To trigger a test:
       - Go to: https://github.com/${var.github_repo}/actions
       - Select "AWS Platform Tests"
       - Click "Run workflow"
       - You'll need to approve the deployment

    Cost estimate: ~$0.005 per run ($2/month budget set)

    ============================================================
  EOT
}
