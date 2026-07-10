# Output values for the storage S3 bucket and its scoped IAM user.

output "aws_account_id" {
  description = "AWS account ID resources were created in"
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "AWS region resources were created in"
  value       = var.aws_region
}

output "bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.storage.id
}

output "bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.storage.arn
}

output "bucket_region" {
  description = "Region of the S3 bucket"
  value       = aws_s3_bucket.storage.region
}

output "bucket_domain_name" {
  description = "Domain name of the S3 bucket"
  value       = aws_s3_bucket.storage.bucket_domain_name
}

output "iam_user_name" {
  description = "Name of the IAM user"
  value       = aws_iam_user.storage_user.name
}

output "iam_user_arn" {
  description = "ARN of the IAM user"
  value       = aws_iam_user.storage_user.arn
}

output "iam_policy_arn" {
  description = "ARN of the IAM policy"
  value       = aws_iam_policy.storage_access.arn
}

output "access_key_id" {
  description = "Access key ID for the IAM user"
  value       = aws_iam_access_key.storage_user.id
}

output "secret_access_key" {
  description = "Secret access key for the IAM user (only shown once)"
  value       = aws_iam_access_key.storage_user.secret
  sensitive   = true
}

output "console_url" {
  description = "URL to view the bucket in AWS Console"
  value       = "https://s3.console.aws.amazon.com/s3/buckets/${aws_s3_bucket.storage.id}?region=${var.aws_region}"
}
