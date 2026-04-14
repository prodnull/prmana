#!/bin/bash
# =============================================================================
# Bootstrap script for Terraform state backend
# =============================================================================
#
# This creates the S3 bucket and DynamoDB table needed to store Terraform state
# securely. Run this ONCE before running terraform init.
#
# Security features:
# - S3 bucket encryption (AES-256)
# - S3 versioning (recover from mistakes)
# - S3 public access blocked
# - DynamoDB for state locking (prevents concurrent modifications)
# - Bucket policy restricts access to your account only
#
# Usage:
#   ./bootstrap.sh
#
# =============================================================================

set -euo pipefail

# Configuration
BUCKET_PREFIX="prmana-terraform-state"
DYNAMODB_TABLE="prmana-terraform-locks"
REGION="${AWS_REGION:-us-west-2}"

# Get account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="${BUCKET_PREFIX}-${ACCOUNT_ID}"

echo "============================================================"
echo "Bootstrapping Terraform State Backend"
echo "============================================================"
echo "Account:  ${ACCOUNT_ID}"
echo "Region:   ${REGION}"
echo "Bucket:   ${BUCKET_NAME}"
echo "Table:    ${DYNAMODB_TABLE}"
echo "============================================================"
echo ""

# Check if bucket already exists
if aws s3api head-bucket --bucket "${BUCKET_NAME}" 2>/dev/null; then
    echo "✓ S3 bucket already exists: ${BUCKET_NAME}"
else
    echo "Creating S3 bucket: ${BUCKET_NAME}..."

    # Create bucket (different command for us-east-1)
    if [ "${REGION}" = "us-east-1" ]; then
        aws s3api create-bucket \
            --bucket "${BUCKET_NAME}" \
            --region "${REGION}"
    else
        aws s3api create-bucket \
            --bucket "${BUCKET_NAME}" \
            --region "${REGION}" \
            --create-bucket-configuration LocationConstraint="${REGION}"
    fi

    echo "✓ Bucket created"
fi

# Enable versioning
echo "Enabling versioning..."
aws s3api put-bucket-versioning \
    --bucket "${BUCKET_NAME}" \
    --versioning-configuration Status=Enabled
echo "✓ Versioning enabled"

# Enable encryption
echo "Enabling encryption..."
aws s3api put-bucket-encryption \
    --bucket "${BUCKET_NAME}" \
    --server-side-encryption-configuration '{
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            },
            "BucketKeyEnabled": true
        }]
    }'
echo "✓ Encryption enabled"

# Block public access
echo "Blocking public access..."
aws s3api put-public-access-block \
    --bucket "${BUCKET_NAME}" \
    --public-access-block-configuration '{
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }'
echo "✓ Public access blocked"

# Add bucket policy (restrict to account)
echo "Adding bucket policy..."
aws s3api put-bucket-policy \
    --bucket "${BUCKET_NAME}" \
    --policy "{
        \"Version\": \"2012-10-17\",
        \"Statement\": [
            {
                \"Sid\": \"DenyInsecureTransport\",
                \"Effect\": \"Deny\",
                \"Principal\": \"*\",
                \"Action\": \"s3:*\",
                \"Resource\": [
                    \"arn:aws:s3:::${BUCKET_NAME}\",
                    \"arn:aws:s3:::${BUCKET_NAME}/*\"
                ],
                \"Condition\": {
                    \"Bool\": {
                        \"aws:SecureTransport\": \"false\"
                    }
                }
            },
            {
                \"Sid\": \"RestrictToAccount\",
                \"Effect\": \"Deny\",
                \"Principal\": \"*\",
                \"Action\": \"s3:*\",
                \"Resource\": [
                    \"arn:aws:s3:::${BUCKET_NAME}\",
                    \"arn:aws:s3:::${BUCKET_NAME}/*\"
                ],
                \"Condition\": {
                    \"StringNotEquals\": {
                        \"aws:PrincipalAccount\": \"${ACCOUNT_ID}\"
                    }
                }
            }
        ]
    }"
echo "✓ Bucket policy applied"

# Create DynamoDB table for locking
echo "Creating DynamoDB table for state locking..."
if aws dynamodb describe-table --table-name "${DYNAMODB_TABLE}" --region "${REGION}" 2>/dev/null; then
    echo "✓ DynamoDB table already exists: ${DYNAMODB_TABLE}"
else
    aws dynamodb create-table \
        --table-name "${DYNAMODB_TABLE}" \
        --attribute-definitions AttributeName=LockID,AttributeType=S \
        --key-schema AttributeName=LockID,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST \
        --region "${REGION}" \
        --tags Key=Project     = "prmana-ci Key=ManagedBy,Value=bootstrap

    echo "Waiting for table to be active..."
    aws dynamodb wait table-exists --table-name "${DYNAMODB_TABLE}" --region "${REGION}"
    echo "✓ DynamoDB table created"
fi

echo ""
echo "============================================================"
echo "Bootstrap Complete!"
echo "============================================================"
echo ""
echo "Add this backend configuration to your Terraform:"
echo ""
echo "terraform {"
echo "  backend \"s3\" {"
echo "    bucket         = \"${BUCKET_NAME}\""
echo "    key            = \"prmana-ci/terraform.tfstate\""
echo "    region         = \"${REGION}\""
echo "    encrypt        = true"
echo "    dynamodb_table = \"${DYNAMODB_TABLE}\""
echo "  }"
echo "}"
echo ""
echo "Then run: terraform init"
echo "============================================================"
