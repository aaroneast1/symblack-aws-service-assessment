# Terraform configuration for S3 bucket and IAM user
# This module creates an S3 bucket and IAM user with read/write/delete permissions

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Purpose     = "SymblackS3Storage"
      ManagedBy   = "Terraform"
      GeneratedBy = "SymmetryBlack"
    }
  }
}
