# S3 Bucket and IAM User Module

This Terraform module creates:
- A private S3 bucket named `{org_name}.s3.symmetryblack.com`
- An IAM user (`symblacks3`) with read/write/delete permissions to the bucket
- Access keys for programmatic access

## What This Does

- Creates an S3 bucket with a standardised naming convention
- Blocks all public access (private bucket)
- Enables server-side encryption (AES256)
- Enables versioning for data protection
- Creates an IAM user with scoped permissions to only this bucket
- Generates access keys for programmatic access

## Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform >= 1.0.0
- Permissions to create S3 buckets and IAM resources

## Usage

### 1. Configure Variables

Copy the example variables file:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and set your organisation name:

```hcl
org_name = "your-org-name"  # Results in bucket: your-org-name.s3.symmetryblack.com
```

### 2. Deploy

```bash
# Initialise Terraform
terraform init

# Preview changes
terraform plan

# Apply changes
terraform apply
```

### 3. Retrieve Credentials

After deployment, retrieve the access credentials:

```bash
# View all outputs (secret key will be hidden)
terraform output

# Get the access key ID
terraform output -raw access_key_id

# Get the secret access key (sensitive values require -raw flag)
terraform output -raw secret_access_key
```

### 4. Configure AWS CLI Profile

```bash
# Configure a new profile with the credentials
aws configure --profile symblacks3

# When prompted, enter:
#   AWS Access Key ID: (from terraform output -raw access_key_id)
#   AWS Secret Access Key: (from terraform output -raw secret_access_key)
#   Default region name: eu-west-2
#   Default output format: json
```

### 5. Test S3 Access

Test the bucket permissions by creating, reading, and deleting an object:

```bash
# Set your bucket name (replace with your org_name)
BUCKET="your-org-name.s3.symmetryblack.com"
PROFILE="symblacks3"

# CREATE: Upload a test file
echo "Hello from SymmetryBlack" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://$BUCKET/test.txt --profile $PROFILE

# LIST: Verify the file exists
aws s3 ls s3://$BUCKET/ --profile $PROFILE

# READ: Download the file
aws s3 cp s3://$BUCKET/test.txt /tmp/test-downloaded.txt --profile $PROFILE
cat /tmp/test-downloaded.txt

# DELETE: Remove the file
aws s3 rm s3://$BUCKET/test.txt --profile $PROFILE

# Verify deletion
aws s3 ls s3://$BUCKET/ --profile $PROFILE
```

All commands should succeed if the IAM permissions are configured correctly.

## Variables

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `org_name` | Organisation name for bucket naming | `string` | - | Yes |
| `aws_region` | AWS region | `string` | `eu-west-2` | No |
| `iam_user_name` | IAM user name | `string` | `symblacks3` | No |
| `enable_versioning` | Enable bucket versioning | `bool` | `true` | No |
| `enable_encryption` | Enable encryption | `bool` | `true` | No |
| `tags` | Additional tags | `map(string)` | `{}` | No |

## Outputs

| Name | Description |
|------|-------------|
| `bucket_name` | Name of the S3 bucket |
| `bucket_arn` | ARN of the S3 bucket |
| `bucket_region` | Region of the S3 bucket |
| `iam_user_name` | Name of the IAM user |
| `iam_user_arn` | ARN of the IAM user |
| `access_key_id` | Access key ID |
| `secret_access_key` | Secret access key (sensitive) |
| `console_url` | AWS Console URL for the bucket |

## IAM Permissions Granted

The IAM user has the following permissions on the bucket:

**Bucket-level:**
- `s3:ListBucket`
- `s3:GetBucketLocation`

**Object-level:**
- `s3:GetObject`
- `s3:PutObject`
- `s3:DeleteObject`
- `s3:GetObjectVersion`
- `s3:DeleteObjectVersion`

## Security Features

- **Private by default**: All public access is blocked
- **Encryption**: Server-side encryption with AES256
- **Versioning**: Enabled by default for data protection
- **Scoped permissions**: IAM user can only access this specific bucket
- **No public ACLs**: Bucket owner enforced

## Clean Up

To remove all resources:

```bash
# Empty the bucket first (required before deletion)
aws s3 rm s3://your-org-name.s3.symmetryblack.com --recursive --profile symblacks3

# Destroy Terraform resources
terraform destroy
```

## Troubleshooting

### Bucket name already exists
S3 bucket names are globally unique. If the bucket name is taken, choose a different `org_name`.

### Access denied errors
Ensure your AWS credentials have permissions to create S3 buckets and IAM resources.

### Cannot delete bucket
The bucket must be empty before deletion. Use `aws s3 rm --recursive` to empty it first.
