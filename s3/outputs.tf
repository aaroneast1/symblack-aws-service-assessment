# Output values for S3 bucket and IAM user

# Bucket outputs
output "bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.main.id
}

output "bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.main.arn
}

output "bucket_region" {
  description = "Region of the S3 bucket"
  value       = aws_s3_bucket.main.region
}

output "bucket_domain_name" {
  description = "Domain name of the S3 bucket"
  value       = aws_s3_bucket.main.bucket_domain_name
}

# IAM outputs
output "iam_user_name" {
  description = "Name of the IAM user"
  value       = aws_iam_user.s3_user.name
}

output "iam_user_arn" {
  description = "ARN of the IAM user"
  value       = aws_iam_user.s3_user.arn
}

output "iam_policy_arn" {
  description = "ARN of the IAM policy"
  value       = aws_iam_policy.s3_access.arn
}

# Access key outputs (sensitive)
output "access_key_id" {
  description = "Access key ID for the IAM user"
  value       = aws_iam_access_key.s3_user.id
  sensitive   = false
}

output "secret_access_key" {
  description = "Secret access key for the IAM user (only shown once)"
  value       = aws_iam_access_key.s3_user.secret
  sensitive   = true
}

# Helpful commands
output "aws_cli_configure_command" {
  description = "Command to configure AWS CLI with these credentials"
  value       = "aws configure --profile ${var.iam_user_name}"
}

output "aws_cli_test_command" {
  description = "Command to test S3 access"
  value       = "aws s3 ls s3://${aws_s3_bucket.main.id} --profile ${var.iam_user_name}"
}

output "console_url" {
  description = "URL to view the bucket in AWS Console"
  value       = "https://s3.console.aws.amazon.com/s3/buckets/${aws_s3_bucket.main.id}?region=${var.aws_region}"
}
