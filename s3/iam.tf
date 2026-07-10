# IAM user for read/write access to the storage bucket.
# Explicitly denied from creating any new bucket or deleting any bucket.

resource "aws_iam_user" "storage_user" {
  name = var.iam_user_name
  path = "/"

  tags = merge(var.tags, {
    Description = "IAM user for storage bucket read/write access"
  })
}

resource "aws_iam_policy" "storage_access" {
  name        = "${var.iam_user_name}-s3-access"
  description = "Read/write on ${local.bucket_name} objects; explicit deny on bucket create/delete."
  path        = "/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListStorageBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = "arn:aws:s3:::${local.bucket_name}"
      },
      {
        Sid    = "ObjectReadWrite"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::${local.bucket_name}/*"
      },
      {
        Sid      = "DenyBucketLifecycle"
        Effect   = "Deny"
        Action   = [
          "s3:CreateBucket",
          "s3:DeleteBucket"
        ]
        Resource = "*"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_user_policy_attachment" "storage_access" {
  user       = aws_iam_user.storage_user.name
  policy_arn = aws_iam_policy.storage_access.arn
}

resource "aws_iam_access_key" "storage_user" {
  user = aws_iam_user.storage_user.name

  lifecycle {
    create_before_destroy = true
  }
}
