terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # No backend block: the caller (fleet-test.yml, plan DT-0-04) wires S3+DynamoDB
  # remote state per github_run_id so that concurrent runs never share state.
}
