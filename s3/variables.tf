# Input variables for S3 bucket and IAM user module

variable "aws_region" {
  description = "AWS region for the S3 bucket"
  type        = string
  default     = "eu-west-2"
}

variable "org_name" {
  description = "Organisation name used to construct the bucket name: {org_name}.s3.symmetryblack.com"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.org_name)) || can(regex("^[a-z0-9]$", var.org_name))
    error_message = "org_name must be lowercase alphanumeric characters and hyphens only, cannot start or end with a hyphen."
  }
}

variable "iam_user_name" {
  description = "Name of the IAM user to create"
  type        = string
  default     = "symblacks3"
}

variable "enable_versioning" {
  description = "Enable versioning on the S3 bucket"
  type        = bool
  default     = true
}

variable "enable_encryption" {
  description = "Enable server-side encryption on the S3 bucket"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}
