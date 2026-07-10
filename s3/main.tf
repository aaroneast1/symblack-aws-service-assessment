# Terraform configuration for the storage S3 bucket and its scoped IAM user.

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

data "aws_caller_identity" "current" {}
