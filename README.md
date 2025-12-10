# AWS Service Assessment Tool

Automatically assess AWS service usage and generate read-only IAM policies for security audits.

## Overview

This tool analyzes your AWS account to:
1. Discover all services used in the last 12 months (via Cost Explorer)
2. Map services to read-only IAM permissions
3. Generate ready-to-deploy Terraform configurations
4. Create either an IAM policy attachment OR an assumable IAM role


## Prerequisites

### System Requirements
- **Python 3.9+**
- **AWS CLI v2**
- **Terraform 1.0+**

### AWS Requirements

#### 1. Admin Profile (for running the assessment)
You need an AWS profile with the following permissions to run `assess.py`:
- `ce:GetCostAndUsage` (Cost Explorer access)
- `sts:GetCallerIdentity` (account information)
- `servicequotas:ListServices` (service mapping)

Ensure user has these privileges and if not add this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ce:GetCostAndUsage",
        "sts:GetCallerIdentity",
        "servicequotas:ListServices"
      ],
      "Resource": "*"
    }
  ]
}
```

#### 2. IAM User (for security assessment)
You must **create an IAM user** before deploying the generated Terraform. This user will receive the read-only permissions.

**Create the IAM user:**
```bash
aws iam create-user --user-name security-auditor --profile YOUR_ADMIN_PROFILE
```

**Important:** The IAM user should start with **NO permissions** (the Terraform will add them).

## Quick Start

### Setup (One-time)

#### macOS

```bash
# Install prerequisites
brew install python3 awscli terraform

# Clone repository
git clone https://github.com/yourusername/symblack-aws-service-assessment.git
cd symblack-aws-service-assessment

# Install Python dependencies (none required, uses stdlib only)
pip3 install -r requirements.txt

# Configure AWS CLI
aws configure --profile my-profile
```

#### Windows

```powershell
# Install Chocolatey (if not already installed)
# Visit https://chocolatey.org/install

# Install prerequisites
choco install python awscli terraform

# Clone repository
git clone https://github.com/yourusername/symblack-aws-service-assessment.git
cd symblack-aws-service-assessment

# Install Python dependencies (none required, uses stdlib only)
pip install -r requirements.txt

# Configure AWS CLI
aws configure --profile my-profile
```

### Usage

#### 1. Run Assessment

```bash
# Basic usage
python3 assess.py --profile my-profile

# Custom output directory
python3 assess.py --profile my-profile --output-dir ./custom-output
```

#### 2. Deploy - Choose Your Scenario

**Option A: Attach Policy to IAM User (Recommended - Simpler)**

This creates access keys for direct use.

```bash
cd output/policy

# Edit terraform.tfvars
# Set: iam_user = "security-auditor"
vim terraform.tfvars

# Deploy
terraform init
terraform apply

# Get access keys
terraform output access_key_id
terraform output -raw access_key_secret

# Configure AWS CLI profile
aws configure --profile security-auditor
# Paste the access key ID and secret when prompted
```

**Option B: Create Assumable Role (Advanced - Temporary Credentials)**

This requires the IAM user to have `sts:AssumeRole` permission.

```bash
cd output/role

# Edit terraform.tfvars
# Set: iam_user = "security-auditor"
vim terraform.tfvars

# Deploy
terraform init
terraform apply
```

**Important:** For Option B, the IAM user must have permission to assume roles. Attach this policy to the user:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::YOUR_ACCOUNT_ID:role/SymmetryBlackAssessmentRole"
    }
  ]
}
```

Then assume the role:
```bash
# Using the user's access keys (from policy module)
aws sts assume-role \
  --role-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/SymmetryBlackAssessmentRole \
  --role-session-name assessment \
  --profile security-auditor

# Export the temporary credentials from the output
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
```

## What Gets Generated

```
output/
├── policy/                       # IAM Policy + Attachment Module
│   ├── policy.tf                 # IAM policy resource
│   ├── attachment.tf             # Auto-attach to user/role
│   ├── variables.tf              # Input variables
│   ├── outputs.tf                # Policy ARN, attachment status
│   ├── terraform.tfvars          # Pre-filled with your account info
│   └── README.md                 # Deployment instructions
│
├── role/                         # IAM Role Module
│   ├── policy.tf                 # IAM policy resource
│   ├── role.tf                   # IAM role + trust policy
│   ├── variables.tf              # Input variables
│   ├── outputs.tf                # Role ARN, assume command
│   ├── terraform.tfvars          # Pre-filled with your account info
│   └── README.md                 # Deployment instructions
│
└── detected_services.json        # List of discovered services
```

## Supported Use Cases

### 1. Security Auditor with Access Keys (Recommended)
Create a dedicated user for security assessments with long-lived access keys:

```bash
# Step 1: Create IAM user (one-time)
aws iam create-user --user-name security-auditor --profile YOUR_ADMIN_PROFILE

# Step 2: Run assessment
python3 assess.py --profile YOUR_ADMIN_PROFILE

# Step 3: Deploy policy module
cd output/policy
# Edit terraform.tfvars: iam_user = "security-auditor"
terraform init
terraform apply

# Step 4: Configure AWS CLI with generated keys
terraform output access_key_id
terraform output -raw access_key_secret
aws configure --profile security-auditor

# Step 5: Test access
aws ec2 describe-security-groups --profile security-auditor
```

### 2. Security Auditor with Role Assumption (Temporary Credentials)
Use your existing admin credentials to assume a role for temporary assessment credentials:

```bash
# Step 1: Run assessment
python3 assess.py --profile YOUR_ADMIN_PROFILE

# Step 2: Deploy role module
cd output/role
# Edit terraform.tfvars: iam_user = "YOUR_ADMIN_USERNAME"
# (This is the user that will be allowed to assume the role)
terraform init && terraform apply

# Step 3: Assume role to get temporary credentials (1 hour default)
aws sts assume-role \
  --role-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/SymmetryBlackAssessmentRole \
  --role-session-name assessment \
  --profile YOUR_ADMIN_PROFILE

# Step 4: Export temporary credentials from the output
export AWS_ACCESS_KEY_ID="<AccessKeyId from output>"
export AWS_SECRET_ACCESS_KEY="<SecretAccessKey from output>"
export AWS_SESSION_TOKEN="<SessionToken from output>"

# Step 5: Test access (using temporary credentials via env vars)
aws ec2 describe-security-groups
```

**Note:** Your admin user must have `sts:AssumeRole` permission for this role. If you get an access denied error, add this policy to your admin user:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::YOUR_ACCOUNT_ID:role/SymmetryBlackAssessmentRole"
  }]
}
```

## Permissions Included

The generated policy includes:

- **Read-only access** to all discovered services (Describe*, Get*, List* actions)
- **Security assessment permissions**:
  - IAM: Credential reports, user/role enumeration
  - Access Analyzer: Findings and analyzers
  - Config: Compliance and configuration rules
  - Security Hub: Security findings
  - GuardDuty: Threat detection findings
  - CloudTrail: Audit logs
  - Trusted Advisor: Best practice checks

## How It Works

### Dynamic Service Mapping

1. **Cost Explorer Discovery**: Queries billing data for service names (e.g., "Amazon Elastic Compute Cloud - Compute")
2. **Read-Only Permissions**: Generates `Describe*`, `Get*`, and `List*` actions for each service

## Security Considerations

- **Read-Only Focus**: All permissions are read-only (Describe, Get, List)
- **Least Privilege**: Only grants access to services actually used in your account
- **No Secrets Access**: Does not include `secretsmanager:GetSecretValue` or similar
- **Audit Trail**: All IAM policy changes are logged in CloudTrail
- **Defensive Security**: Designed for security assessments, not offensive operations

## Project Structure

```
symblack-aws-service-assessment/
├── assess.py                  # Main Python script (dynamic IAM mapping)
├── requirements.txt           # Python dependencies (none)
├── README.md                  # This file
├── CLAUDE.md                  # AI assistant guidance
├── LICENSE                    # GPL-3.0 license
└── .gitignore                 # Git ignore rules
```

## Test your policy is working

```shell
aws ec2 describe-security-groups --profile MY-PROFILE \
    --filters "Name=ip-permission.from-port,Values=22" \
              "Name=ip-permission.to-port,Values=22" \
              "Name=ip-permission.cidr,Values=0.0.0.0/0" \
    --query 'SecurityGroups[*].[GroupId,GroupName,VpcId]' \
    --output json | jq .
```

```powershell
aws ec2 describe-security-groups --profile MY-PROFILE --filters "Name=ip-permission.from-port,Values=22" "Name=ip-permission.to-port,Values=22" "Name=ip-permission.cidr,Values=0.0.0.0/0" --query 'SecurityGroups[*].[GroupId,GroupName,VpcId]' --output json
```

## Audience

Developed for security professionals to implement least-privilege access based on actual AWS usage patterns.

## License

GPL-3.0 - See [LICENSE](LICENSE) file for details.
