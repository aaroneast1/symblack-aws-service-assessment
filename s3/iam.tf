# IAM User and Policy for S3 bucket access

# Get current AWS account ID
data "aws_caller_identity" "current" {}

# IAM User
resource "aws_iam_user" "s3_user" {
  name = var.iam_user_name
  path = "/"

  tags = merge(var.tags, {
    Description = "IAM user for S3 bucket access"
  })
}

# IAM Policy for S3 read/write/delete access
resource "aws_iam_policy" "s3_access" {
  name        = "${var.iam_user_name}-s3-access"
  description = "Policy granting read/write/delete access to ${local.bucket_name}"
  path        = "/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = "arn:aws:s3:::${local.bucket_name}"
      },
      {
        Sid    = "ObjectReadWriteDelete"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetObjectVersion",
          "s3:DeleteObjectVersion"
        ]
        Resource = "arn:aws:s3:::${local.bucket_name}/*"
      }
    ]
  })

  tags = var.tags
}

# Attach policy to user
resource "aws_iam_user_policy_attachment" "s3_access" {
  user       = aws_iam_user.s3_user.name
  policy_arn = aws_iam_policy.s3_access.arn
}

# Access key for programmatic access
resource "aws_iam_access_key" "s3_user" {
  user = aws_iam_user.s3_user.name

  lifecycle {
    create_before_destroy = true
  }
}
