#!/usr/bin/env python3
"""
AWS Service Assessment Tool
Analyzes AWS service usage and generates read-only IAM policies for security assessments.
"""

import subprocess
import json
import os
import sys
import argparse
from datetime import datetime, timedelta
from pathlib import Path


def run_aws_cli(command: list, profile: str) -> dict:
    """Execute AWS CLI command and return JSON output."""
    cmd = ["aws"] + command + ["--profile", profile, "--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if result.stdout.strip():
            return json.loads(result.stdout)
        return {}
    except subprocess.CalledProcessError as e:
        print(f"❌ AWS CLI Error: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ JSON Parse Error: {e}", file=sys.stderr)
        sys.exit(1)


def get_account_info(profile: str) -> dict:
    """Get AWS account ID and region."""
    print("🔍 Detecting AWS account information...")

    identity = run_aws_cli(["sts", "get-caller-identity"], profile)

    # Get region from AWS CLI config
    try:
        region_result = subprocess.run(
            ["aws", "configure", "get", "region", "--profile", profile],
            capture_output=True,
            text=True,
            check=True
        )
        region = region_result.stdout.strip() or "us-east-1"
    except subprocess.CalledProcessError:
        region = "us-east-1"

    account_id = identity.get("Account", "")
    user_arn = identity.get("Arn", "")

    print(f"  ✓ Account ID: {account_id}")
    print(f"  ✓ Region: {region}")
    print(f"  ✓ User: {user_arn}")

    return {
        "account_id": account_id,
        "region": region,
        "user_arn": user_arn
    }


def get_services_from_cost_explorer(profile: str) -> list:
    """Query Cost Explorer for 12-month service usage."""
    print("📊 Querying Cost Explorer for service usage (last 12 months)...")

    # Use first day of current month to avoid partial month issues
    end_date = datetime.now().replace(day=1).strftime("%Y-%m-%d")
    # Go back 12 full months
    start_date = (datetime.now().replace(day=1) - timedelta(days=365)).strftime("%Y-%m-%d")

    print(f"  ℹ️  Date range: {start_date} to {end_date}")

    result = run_aws_cli([
        "ce", "get-cost-and-usage",
        "--time-period", f"Start={start_date},End={end_date}",
        "--granularity", "MONTHLY",
        "--metrics", "UnblendedCost",
        "--group-by", "Type=DIMENSION,Key=SERVICE"
    ], profile)

    # Items to exclude - these are not AWS services
    non_service_items = {
        "tax",  # Tax charges
        "support",  # Support charges (different from AWS Support service)
        "refund",  # Refunds
        "credit",  # Credits
    }

    services = set()
    filtered_items = []

    for period in result.get("ResultsByTime", []):
        for group in period.get("Groups", []):
            if group.get("Keys"):
                service = group["Keys"][0]
                service_lower = service.lower()

                # Filter out non-service items
                if service_lower in non_service_items:
                    filtered_items.append(service)
                    continue

                # Filter out items that are just "Tax" or similar
                if service_lower == "tax" or service_lower.startswith("tax "):
                    filtered_items.append(service)
                    continue

                # Include ALL services that appear in Cost Explorer, regardless of cost
                # (services may have $0.00 cost if using free tier or credits)
                services.add(service)

    services_list = sorted(list(services))
    print(f"  ✓ Found {len(services_list)} AWS services with usage")

    if filtered_items:
        unique_filtered = set(filtered_items)
        print(f"  ℹ️  Filtered out non-services: {', '.join(sorted(unique_filtered))}")

    return services_list


def get_aws_service_mappings(profile: str) -> dict:
    """
    Retrieve AWS service mappings from Service Quotas API.
    Returns dict mapping service names to IAM service codes.

    Requires: servicequotas:ListServices permission
    """
    print("  ℹ️  Loading AWS service mappings from Service Quotas API...")

    result = run_aws_cli(["service-quotas", "list-services"], profile)

    service_patterns = {}
    for service in result.get("Services", []):
        service_code = service.get("ServiceCode", "")
        service_name = service.get("ServiceName", "")

        if service_code and service_name:
            # Store both exact name and normalized version
            service_patterns[service_name.lower()] = service_code

    print(f"  ✓ Loaded {len(service_patterns)} AWS service mappings")
    return service_patterns


def extract_iam_prefix(service_name: str, service_patterns: dict = None) -> str:
    """
    Dynamically extract IAM service prefix from AWS Cost Explorer service name.

    Examples:
        "Amazon Elastic Compute Cloud - Compute" -> "ec2"
        "AWS Lambda" -> "lambda"
        "Amazon Simple Storage Service" -> "s3"
        "Amazon Relational Database Service" -> "rds"
    """
    if service_patterns is None:
        service_patterns = {}

    # Normalize service name for matching
    normalized = service_name.lower().strip()

    # Special case mappings for common ambiguous names (check BEFORE removing suffixes)
    special_cases = {
        "amazon elastic compute cloud": "ec2",
        "elastic compute cloud": "ec2",
        "ec2 - other": "ec2",
        "amazon virtual private cloud": "ec2",  # VPC is part of EC2 service
        "virtual private cloud": "ec2",
        "amazon elastic load balancing": "elasticloadbalancing",
        "elastic load balancing": "elasticloadbalancing",
        "amazon elastic container service for kubernetes": "eks",
        "elastic container service for kubernetes": "eks",
    }

    for special_name, special_prefix in special_cases.items():
        if special_name in normalized:
            return special_prefix

    # Remove common suffixes that don't affect the service prefix
    suffixes_to_remove = [
        " - compute",
        " - data transfer",
        " - requests",
        " - storage",
        " - other",
        " (direct connect)",
    ]

    for suffix in suffixes_to_remove:
        if normalized.endswith(suffix):
            normalized = normalized[:-len(suffix)].strip()

    # Try exact match
    if normalized in service_patterns:
        return service_patterns[normalized]

    # Try partial matches (Service Quotas name in Cost Explorer name)
    # Sort by length (longer matches first) to prioritize more specific matches
    for pattern, prefix in sorted(service_patterns.items(), key=lambda x: len(x[0]), reverse=True):
        if pattern in normalized:
            return prefix

    # Try reverse partial matches (Cost Explorer keywords in Service Quotas name)
    # Extract significant keywords from Cost Explorer service name
    keywords = []
    temp = normalized.replace("aws", "").replace("amazon", "").strip()
    for word in temp.split():
        if len(word) > 2 and word not in ["the", "for", "and", "service"]:
            keywords.append(word)

    # Try matching keywords against Service Quotas names
    # Prioritize longer keywords first (more specific)
    for keyword in sorted(keywords, key=len, reverse=True):
        # First pass: look for whole word matches
        for pattern, prefix in service_patterns.items():
            pattern_words = pattern.split()
            if keyword in pattern_words:
                return prefix

        # Second pass: look for substring matches
        for pattern, prefix in service_patterns.items():
            if keyword in pattern:
                return prefix

    # Fallback: Try to extract acronym or first word
    # "AWS DataSync" -> "datasync"
    # "Amazon Macie" -> "macie"
    words = normalized.replace("aws", "").replace("amazon", "").strip().split()
    if words:
        # Use first significant word as fallback
        fallback = words[0].replace("-", "").replace("_", "")
        return fallback

    # Ultimate fallback: use lowercase version of service name
    return normalized.replace(" ", "").replace("-", "")[:20]


def generate_iam_policy(services: list, account_id: str, region: str, profile: str) -> dict:
    """Generate IAM policy JSON with read-only + security assessment permissions."""
    print("🗺️  Dynamically mapping services to IAM permissions...")

    # Load AWS service mappings from Service Quotas API
    service_patterns = get_aws_service_mappings(profile)

    statements = []
    service_mappings = {}
    prefix_to_services = {}  # Track which services map to each prefix

    # Dynamically generate IAM permissions for each discovered service
    for service in services:
        iam_prefix = extract_iam_prefix(service, service_patterns)

        # Track the mapping for reporting
        service_mappings[service] = iam_prefix

        # Group services by IAM prefix to avoid duplicates
        if iam_prefix not in prefix_to_services:
            prefix_to_services[iam_prefix] = []
        prefix_to_services[iam_prefix].append(service)

    # Create one statement per unique IAM prefix
    for iam_prefix, service_list in sorted(prefix_to_services.items()):
        # Generate unique SID from IAM prefix
        sid = f"{iam_prefix.replace('-', '').replace('_', '').title()}ReadOnly"

        statements.append({
            "Sid": sid,
            "Effect": "Allow",
            "Action": [
                f"{iam_prefix}:Describe*",
                f"{iam_prefix}:Get*",
                f"{iam_prefix}:List*"
            ],
            "Resource": "*"
        })

    # Add Cost Explorer permissions (required to enumerate services)
    statements.append({
        "Sid": "CostExplorerReadOnly",
        "Effect": "Allow",
        "Action": [
            "ce:Describe*",
            "ce:Get*",
            "ce:List*"
        ],
        "Resource": "*"
    })

    # Add core security assessment permissions (always included)
    statements.append({
        "Sid": "SecurityAssessmentCore",
        "Effect": "Allow",
        "Action": [
            "iam:Get*",
            "iam:List*",
            "iam:GenerateCredentialReport",
            "iam:GetCredentialReport",
            "access-analyzer:List*",
            "access-analyzer:Get*",
            "config:Describe*",
            "config:Get*",
            "config:List*",
            "securityhub:Get*",
            "securityhub:List*",
            "securityhub:Describe*",
            "trustedadvisor:Describe*",
            "guardduty:Get*",
            "guardduty:List*",
            "cloudtrail:Get*",
            "cloudtrail:List*",
            "cloudtrail:Lookup*",
            "organizations:Describe*",
            "organizations:List*"
        ],
        "Resource": "*"
    })

    # Calculate statistics
    unique_prefixes = len(prefix_to_services)
    total_services = len(services)

    print(f"  ✓ Mapped {total_services} services to {unique_prefixes} unique IAM prefixes")
    print(f"  ✓ Generated {len(statements)} policy statements")

    # Show some example mappings for user verification
    if service_mappings:
        print(f"  ℹ️  Sample of mappings:")
        for service, prefix in list(service_mappings.items())[:3]:
            print(f"     • {service} -> {prefix}:*")

        # Show if any services were consolidated
        consolidated = [f"{prefix} ({len(svcs)} services)"
                       for prefix, svcs in prefix_to_services.items() if len(svcs) > 1]
        if consolidated:
            print(f"  ℹ️  Consolidated prefixes: {', '.join(consolidated[:3])}")

    return {
        "Version": "2012-10-17",
        "Statement": statements
    }


def generate_terraform_policy_module(output_dir: Path, account_id: str, region: str, policy: dict):
    """Generate Terraform files for policy module."""
    policy_dir = output_dir / "policy"
    policy_dir.mkdir(parents=True, exist_ok=True)

    # policy.tf
    policy_tf = '''# IAM Policy for Security Assessment - Read-Only Permissions
resource "aws_iam_policy" "security_assessment" {
  name        = var.policy_name
  description = var.policy_description
  policy      = jsonencode(var.policy_document)

  tags = {
    Purpose     = "SecurityAssessment"
    GeneratedBy = "SymmetryBlack"
    GeneratedAt = var.generation_timestamp
  }
}
'''

    # attachment.tf
    attachment_tf = '''# Attach policy to existing IAM user
resource "aws_iam_user_policy_attachment" "attach_to_user" {
  user       = var.iam_user
  policy_arn = aws_iam_policy.security_assessment.arn
}

# Create access key for existing IAM user
resource "aws_iam_access_key" "user_key" {
  count = var.create_access_key ? 1 : 0
  user  = var.iam_user

  lifecycle {
    create_before_destroy = true
  }
}
'''

    # variables.tf
    variables_tf = f'''variable "aws_account_id" {{
  description = "AWS Account ID"
  type        = string
}}

variable "aws_region" {{
  description = "AWS Region"
  type        = string
}}

variable "policy_name" {{
  description = "Name of the IAM policy"
  type        = string
}}

variable "policy_description" {{
  description = "Description of the IAM policy"
  type        = string
}}

variable "iam_user" {{
  description = "IAM username to attach this policy to (e.g., 'security-auditor'). REQUIRED."
  type        = string
}}

variable "policy_document" {{
  description = "IAM policy document"
  type        = any
}}

variable "generation_timestamp" {{
  description = "Timestamp when this policy was generated"
  type        = string
}}

variable "create_access_key" {{
  description = "Whether to create an access key for the IAM user"
  type        = bool
  default     = true
}}

variable "access_key_expiration_date" {{
  description = "Expiration date for the access key (1 year from generation)"
  type        = string
}}
'''

    # outputs.tf
    outputs_tf = '''output "policy_arn" {
  description = "ARN of the created IAM policy"
  value       = aws_iam_policy.security_assessment.arn
}

output "policy_id" {
  description = "ID of the created IAM policy"
  value       = aws_iam_policy.security_assessment.id
}

output "policy_name" {
  description = "Name of the created IAM policy"
  value       = aws_iam_policy.security_assessment.name
}

output "attached_user" {
  description = "IAM user this policy is attached to"
  value       = var.iam_user
}

output "access_key_id" {
  description = "Access key ID (only if created)"
  value       = length(aws_iam_access_key.user_key) > 0 ? aws_iam_access_key.user_key[0].id : "N/A - create_access_key is false"
  sensitive   = false
}

output "access_key_secret" {
  description = "Access key secret (only if created) - SENSITIVE"
  value       = length(aws_iam_access_key.user_key) > 0 ? aws_iam_access_key.user_key[0].secret : "N/A - create_access_key is false"
  sensitive   = true
}

output "access_key_expiration" {
  description = "Access key expiration date"
  value       = var.access_key_expiration_date
}

output "credentials_warning" {
  description = "Important security warning about access keys"
  value       = length(aws_iam_access_key.user_key) > 0 ? "⚠️  SAVE THESE CREDENTIALS NOW! The secret key will not be shown again. Store securely and rotate before expiration." : "N/A"
}
'''

    # terraform.tfvars
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    expiration_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d")
    tfvars = f'''# Auto-detected from your AWS account
aws_account_id = "{account_id}"
aws_region     = "{region}"

# Policy configuration
policy_name        = "SymmetryBlackAssessmentReadOnlyPolicy"
policy_description = "Read-only access for security assessment - Generated {timestamp}"
generation_timestamp = "{timestamp}"

# ⚠️ REQUIRED: Specify the IAM username to attach this policy to
# Example: iam_user = "security-auditor"
iam_user = "REPLACE_WITH_YOUR_USERNAME"

# Access Key Configuration (for IAM users only)
create_access_key = true  # Set to false to skip access key creation
access_key_expiration_date = "{expiration_date}"  # 1 year from generation

# IAM Policy Document (auto-generated from discovered services)
policy_document = {json.dumps(policy, indent=2)}
'''

    # README.md
    readme = f'''# IAM Policy Deployment

This folder contains Terraform configuration to create and attach an IAM policy for security assessment.

## What This Does

- Creates an IAM policy with read-only permissions for discovered AWS services
- Automatically attaches the policy to the IAM user you specify
- **Creates access key + secret key for IAM users (valid 1 year)**
- Includes security assessment permissions (IAM, Config, Security Hub, etc.)

## Usage

### 1. Edit Configuration

Edit `terraform.tfvars` and specify the IAM username:

```hcl
iam_user = "security-auditor"  # Your IAM username (not the full ARN) - REQUIRED
create_access_key = true       # Set to false if you don't want access keys
```

### 2. Deploy

```bash
terraform init
terraform apply
```

### 3. Retrieve Access Keys

**⚠️ IMPORTANT: Save these credentials immediately! The secret key cannot be retrieved later.**

```bash
# Get access key ID
terraform output access_key_id

# Get secret access key (sensitive - will prompt for confirmation)
terraform output access_key_secret

# Get expiration date
terraform output access_key_expiration
```

**Configure AWS CLI with these credentials:**
```bash
aws configure --profile symmetry-black-assessment
# Paste Access Key ID and Secret Access Key when prompted
```

### 4. Verify

After deployment, verify the policy is attached:

```bash
# Check attached policies
aws iam list-attached-user-policies --user-name security-auditor

# Test with the new credentials
aws sts get-caller-identity --profile symmetry-black-assessment
```

## Generated On

- **Date**: {timestamp}
- **Account**: {account_id}
- **Region**: {region}

## Security Best Practices

1. **Rotate Access Keys**: Keys expire on {expiration_date}. Rotate before this date.
2. **Secure Storage**: Store credentials in a password manager or AWS Secrets Manager
3. **Least Privilege**: These are read-only permissions for security assessment only
4. **Audit Usage**: Regularly review CloudTrail logs for key usage

## Clean Up

To remove the policy and access keys:

```bash
terraform destroy
```

**⚠️ Warning**: This will:
- Delete the access keys (credentials will stop working)
- Detach and delete the policy
- Remove all associated resources
'''

    # Write all files
    (policy_dir / "policy.tf").write_text(policy_tf)
    (policy_dir / "attachment.tf").write_text(attachment_tf)
    (policy_dir / "variables.tf").write_text(variables_tf)
    (policy_dir / "outputs.tf").write_text(outputs_tf)
    (policy_dir / "terraform.tfvars").write_text(tfvars)
    (policy_dir / "README.md").write_text(readme)


def generate_terraform_role_module(output_dir: Path, account_id: str, region: str, policy: dict):
    """Generate Terraform files for role module."""
    role_dir = output_dir / "role"
    role_dir.mkdir(parents=True, exist_ok=True)

    # policy.tf
    policy_tf = '''# IAM Policy for Security Assessment - Read-Only Permissions
resource "aws_iam_policy" "security_assessment" {
  name        = var.policy_name
  description = var.policy_description
  policy      = jsonencode(var.policy_document)

  tags = {
    Purpose     = "SecurityAssessment"
    GeneratedBy = "SymmetryBlack"
    GeneratedAt = var.generation_timestamp
  }
}
'''

    # role.tf
    role_tf = '''# IAM Role with Security Assessment Policy
resource "aws_iam_role" "security_assessment" {
  name               = var.role_name
  description        = var.role_description
  assume_role_policy = data.aws_iam_policy_document.trust_policy.json

  tags = {
    Purpose     = "SecurityAssessment"
    GeneratedBy = "SymmetryBlack"
    GeneratedAt = var.generation_timestamp
  }
}

# Trust policy for the role
data "aws_iam_policy_document" "trust_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:user/${var.iam_user}"]
    }
  }
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "attach_policy" {
  role       = aws_iam_role.security_assessment.name
  policy_arn = aws_iam_policy.security_assessment.arn
}
'''

    # variables.tf
    variables_tf = '''variable "aws_account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "aws_region" {
  description = "AWS Region"
  type        = string
}

variable "role_name" {
  description = "Name of the IAM role"
  type        = string
}

variable "role_description" {
  description = "Description of the IAM role"
  type        = string
}

variable "policy_name" {
  description = "Name of the IAM policy"
  type        = string
}

variable "policy_description" {
  description = "Description of the IAM policy"
  type        = string
}

variable "iam_user" {
  description = "IAM username that can assume this role (e.g., 'security-auditor'). REQUIRED."
  type        = string
}


variable "policy_document" {
  description = "IAM policy document"
  type        = any
}

variable "generation_timestamp" {
  description = "Timestamp when this policy was generated"
  type        = string
}
'''

    # outputs.tf
    outputs_tf = '''output "role_arn" {
  description = "ARN of the created IAM role"
  value       = aws_iam_role.security_assessment.arn
}

output "role_name" {
  description = "Name of the created IAM role"
  value       = aws_iam_role.security_assessment.name
}

output "policy_arn" {
  description = "ARN of the created IAM policy"
  value       = aws_iam_policy.security_assessment.arn
}

output "assume_role_command" {
  description = "AWS CLI command to assume this role"
  value       = "aws sts assume-role --role-arn ${aws_iam_role.security_assessment.arn} --role-session-name security-assessment-session"
}

output "temporary_credentials_instructions" {
  description = "Instructions to get temporary credentials"
  value       = <<-EOT
    Step 1: Assume the role
    aws sts assume-role --role-arn ${aws_iam_role.security_assessment.arn} --role-session-name security-assessment-session

    Step 2: Export the credentials (copy-paste the output values)
    export AWS_ACCESS_KEY_ID="<AccessKeyId from above>"
    export AWS_SECRET_ACCESS_KEY="<SecretAccessKey from above>"
    export AWS_SESSION_TOKEN="<SessionToken from above>"

    Step 3: Verify credentials
    aws sts get-caller-identity

    Note: Temporary credentials expire after 1 hour by default (max 12 hours with --duration-seconds)
  EOT
}

output "assume_role_with_duration" {
  description = "Assume role command with custom duration (max 12 hours = 43200 seconds)"
  value       = "aws sts assume-role --role-arn ${aws_iam_role.security_assessment.arn} --role-session-name security-assessment-session --duration-seconds 43200"
}
'''

    # terraform.tfvars
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    tfvars = f'''# Auto-detected from your AWS account
aws_account_id = "{account_id}"
aws_region     = "{region}"

# Role configuration
role_name        = "SymmetryBlackAssessmentRole"
role_description = "Security assessment role with read-only permissions - Generated {timestamp}"
policy_name      = "SymmetryBlackAssessmentReadOnlyPolicy"
policy_description = "Read-only access for security assessment"
generation_timestamp = "{timestamp}"

# ⚠️ REQUIRED: Specify the IAM username that can assume this role
# Example: iam_user = "security-auditor"
iam_user = "REPLACE_WITH_YOUR_USERNAME"

# IAM Policy Document (auto-generated from discovered services)
policy_document = {json.dumps(policy, indent=2)}
'''

    # README.md
    readme = f'''# IAM Role Deployment

This folder contains Terraform configuration to create an IAM role for security assessment.

## What This Does

- Creates an IAM role with read-only permissions for discovered AWS services
- Creates an IAM policy and attaches it to the role
- Configures trust policy so specified principals can assume the role
- Supports IAM users, SAML federation (Entra ID), and cross-account access

## Usage

### 1. Edit Configuration

Edit `terraform.tfvars` and specify the IAM username:

```hcl
iam_user = "security-auditor"  # Your IAM username (not the full ARN) - REQUIRED
```

### 2. Deploy

```bash
terraform init
terraform apply
```

### 3. Get Temporary Credentials

**View complete instructions:**
```bash
terraform output temporary_credentials_instructions
```

**Quick start - Assume the role (1 hour credentials):**
```bash
# Assume the role
terraform output -raw assume_role_command | bash

# Or manually:
aws sts assume-role \\
  --role-arn <role-arn-from-output> \\
  --role-session-name security-assessment-session

# Copy the output and export credentials
export AWS_ACCESS_KEY_ID="<AccessKeyId>"
export AWS_SECRET_ACCESS_KEY="<SecretAccessKey>"
export AWS_SESSION_TOKEN="<SessionToken>"

# Verify
aws sts get-caller-identity
```

**For longer sessions (up to 12 hours):**
```bash
terraform output -raw assume_role_with_duration | bash
```

### 4. Use Credentials with AWS CLI Profile

**Option 1: Environment variables (above)**

**Option 2: Create a temporary profile**
```bash
# Manually configure after assuming role
aws configure --profile symmetry-black-temp
# Then paste the temporary credentials
```

## Credential Lifecycle

- **Default Duration**: 1 hour
- **Maximum Duration**: 12 hours (use `--duration-seconds 43200`)
- **Renewal**: Re-run assume-role command when credentials expire
- **No Long-term Keys**: Temporary credentials auto-expire (more secure than access keys)

## Generated On

- **Date**: {timestamp}
- **Account**: {account_id}
- **Region**: {region}

## Clean Up

To remove the role and policy:

```bash
terraform destroy
```

**Note**: This will delete the role. Any active sessions will continue until credentials expire.
'''

    # Write all files
    (role_dir / "policy.tf").write_text(policy_tf)
    (role_dir / "role.tf").write_text(role_tf)
    (role_dir / "variables.tf").write_text(variables_tf)
    (role_dir / "outputs.tf").write_text(outputs_tf)
    (role_dir / "terraform.tfvars").write_text(tfvars)
    (role_dir / "README.md").write_text(readme)


def save_detected_services(output_dir: Path, services: list):
    """Save list of detected services to JSON file."""
    services_file = output_dir / "detected_services.json"

    data = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "service_count": len(services),
        "services": services
    }

    with open(services_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"  ✓ Saved service list to {services_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AWS Service Assessment Tool - Generate read-only IAM policies for security audits",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 assess.py --profile my-profile
  python3 assess.py --profile prod --output-dir ./custom-output
        """
    )
    parser.add_argument(
        "--profile",
        required=True,
        help="AWS CLI profile name to use"
    )
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Output directory for Terraform files (default: ./output)"
    )

    args = parser.parse_args()

    print("=" * 70)
    print("AWS Service Assessment Tool")
    print("=" * 70)

    # Get account information
    account_info = get_account_info(args.profile)

    # Query Cost Explorer for services
    services = get_services_from_cost_explorer(args.profile)

    if not services:
        print("⚠️  No services found with usage in the last 12 months.")
        print("    Make sure Cost Explorer is enabled and you have service usage.")
        sys.exit(1)

    # Generate IAM policy (dynamic mapping using AWS Service Quotas API)
    policy = generate_iam_policy(
        services,
        account_info["account_id"],
        account_info["region"],
        args.profile
    )

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("📝 Generating Terraform configurations...")

    # Generate Terraform modules
    generate_terraform_policy_module(
        output_dir,
        account_info["account_id"],
        account_info["region"],
        policy
    )
    print("  ✓ Created policy module: output/policy/")

    generate_terraform_role_module(
        output_dir,
        account_info["account_id"],
        account_info["region"],
        policy
    )
    print("  ✓ Created role module: output/role/")

    # Save detected services list
    save_detected_services(output_dir, services)

    print("\n" + "=" * 70)
    print("✅ Success! Terraform configurations generated.")
    print("=" * 70)
    print("\nNext steps:")
    print("\n  Option A - Attach policy to IAM user:")
    print(f"    cd {output_dir}/policy")
    print("    # Edit terraform.tfvars (set target_principal_arn)")
    print("    terraform init")
    print("    terraform apply")
    print("\n  Option B - Create assumable role:")
    print(f"    cd {output_dir}/role")
    print("    # Edit terraform.tfvars (set trusted_principals)")
    print("    terraform init")
    print("    terraform apply")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
