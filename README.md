# AWS Service Assessment Tool

Assess AWS service usage and generate a least-privilege, read-only IAM policy for security audits. Optionally provision private S3 buckets to store audit artefacts.

## What This Does

1. Discovers every AWS service used in your account over the last 12 months (via Cost Explorer).
2. Maps each service to its read-only IAM actions (`Describe*`, `Get*`, `List*`).
3. Generates Terraform that provisions a `security-auditor` identity with those permissions — see [Choose an Option](#choose-an-option) below.
4. (Optional) Provisions two hardened S3 buckets, each with a dedicated scoped IAM user.

**Prerequisites (either option):** Python 3.9+, AWS CLI v2, Terraform 1.0+, and an admin AWS profile that can create IAM and (if you use the optional S3 step) S3 resources.

## Choose an Option

Both options give `security-auditor` the same read-only access to your account. They differ in **how the credentials are issued and how long they live** — pick one and follow only that section below.

### Option A — Static access keys

Terraform attaches the generated read-only policy directly to the `security-auditor` IAM user and (optionally) issues a long-lived access key ID + secret. The same pair remains valid until you rotate or delete it.

- **Best for**: short one-off audits, or automation where a key-rotation policy is already in place.
- **Trade-off**: if the key leaks, exposure persists until you notice and rotate.

Follow **[Option A — Static Access Keys](#option-a--static-access-keys)** below.

### Option B — Assumed role, per-use access keys

Terraform creates a read-only IAM role that `security-auditor` is allowed to assume. Each time you use the auditor, `aws sts assume-role` returns a fresh set of temporary credentials that expire (1 hour by default, up to 12 hours configurable).

- **Best for**: longer engagements, multi-auditor teams, or environments that prohibit long-lived keys.
- **Trade-off**: one extra `assume-role` step per session; expired credentials must be refreshed.

Follow **[Option B — Assumed Role, Per-Use Access Keys](#option-b--assumed-role-per-use-access-keys)** below.

---

## Option A — Static Access Keys

Long-lived key/secret pair attached directly to a `security-auditor` IAM user.

### Step 1 — Install prerequisites

macOS: `brew install python3 awscli terraform`
Windows (PowerShell): `choco install python awscli terraform`

Then:
```bash
git clone https://github.com/yourusername/symblack-aws-service-assessment.git
cd symblack-aws-service-assessment
pip3 install -r requirements.txt
```

### Step 2 — Configure your admin AWS profile

```bash
aws configure --profile my-admin-profile
aws sts get-caller-identity --profile my-admin-profile
```

Attach this inline policy to the admin user if it isn't already there:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ce:GetCostAndUsage",
      "sts:GetCallerIdentity",
      "servicequotas:ListServices"
    ],
    "Resource": "*"
  }]
}
```

### Step 3 — Create the security-auditor IAM user

```bash
aws iam create-user --user-name security-auditor --profile my-admin-profile
```

### Step 4 — Run the assessment

```bash
python3 assess.py --profile my-admin-profile
```

Generates `output/policy/` (the Terraform module for this option) and `output/detected_services.json`.

### Step 5 — Attach the policy and issue keys

```bash
cd output/policy
# Edit terraform.tfvars:
#   iam_user          = "security-auditor"
#   create_access_key = true    # false to keep the user's existing static keys
terraform init
AWS_PROFILE=my-admin-profile terraform apply
```

Retrieve the keys (when `create_access_key = true`):
```bash
terraform output access_key_id
terraform output -raw access_key_secret
```

Wire them into a profile:
```bash
aws configure --profile security-auditor
```

### Step 6 — Smoke-test the auditor

This should succeed (finds any SSH-open-to-world security groups):
```bash
aws ec2 describe-security-groups --profile security-auditor \
    --filters "Name=ip-permission.from-port,Values=22" \
              "Name=ip-permission.to-port,Values=22" \
              "Name=ip-permission.cidr,Values=0.0.0.0/0" \
    --query 'SecurityGroups[*].[GroupId,GroupName,VpcId]' \
    --output json | jq .
```

### Step 7 (Optional) — Provision the S3 storage bucket

The Terraform in `s3/` creates one hardened bucket, `{org_name}.storage.symmetryblack.com`, and a scoped IAM user `symblack-storage`:

- **Bucket**: public access blocked, AES256 SSE, versioning, bucket-owner-enforced ownership.
- **User `symblack-storage`**: read/write on objects only — no `s3:DeleteObject`; explicit `Deny` on `s3:CreateBucket` and `s3:DeleteBucket`.

```bash
cd s3
cp terraform.tfvars.example terraform.tfvars
# Edit: org_name = "your-org-name"   (lowercase alphanumerics + hyphens)
terraform init
AWS_PROFILE=my-admin-profile terraform apply
```

Retrieve the user's keys and configure a profile:
```bash
terraform output -raw access_key_id
terraform output -raw secret_access_key
aws configure --profile symblack-storage
```

Verify the denies actually fire — all three below **must return `AccessDenied`**:
```bash
STORAGE="your-org-name.storage.symmetryblack.com"
aws s3 rm s3://$STORAGE/nothing.txt   --profile symblack-storage   # no s3:DeleteObject
aws s3 mb s3://some-new-bucket-abcxyz --profile symblack-storage   # deny s3:CreateBucket
aws s3 rb s3://$STORAGE               --profile symblack-storage   # deny s3:DeleteBucket
```

### Step 8 — Clean up

```bash
# S3 (if Step 7 was run) — empty the bucket first, then destroy
cd s3
aws s3 rm s3://your-org-name.storage.symmetryblack.com --recursive --profile my-admin-profile
AWS_PROFILE=my-admin-profile terraform destroy

# Assessment policy
cd ../output/policy
AWS_PROFILE=my-admin-profile terraform destroy

# Auditor user (when the audit is finished)
aws iam delete-user --user-name security-auditor --profile my-admin-profile
```

---

## Option B — Assumed Role, Per-Use Access Keys

Short-lived, per-session access keys (1-hour default) obtained by having `security-auditor` assume a dedicated role each time it's used.

### Step 1 — Install prerequisites

macOS: `brew install python3 awscli terraform`
Windows (PowerShell): `choco install python awscli terraform`

Then:
```bash
git clone https://github.com/yourusername/symblack-aws-service-assessment.git
cd symblack-aws-service-assessment
pip3 install -r requirements.txt
```

### Step 2 — Configure your admin AWS profile

```bash
aws configure --profile my-admin-profile
aws sts get-caller-identity --profile my-admin-profile
```

Attach this inline policy to the admin user if it isn't already there:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ce:GetCostAndUsage",
      "sts:GetCallerIdentity",
      "servicequotas:ListServices"
    ],
    "Resource": "*"
  }]
}
```

### Step 3 — Create the security-auditor IAM user

Create the user and issue it a static access key — this key is used only to authenticate the `sts:AssumeRole` call in Step 7.

```bash
aws iam create-user --user-name security-auditor --profile my-admin-profile
aws iam create-access-key --user-name security-auditor --profile my-admin-profile
```

Save the returned `AccessKeyId` and `SecretAccessKey`; you'll wire them into a profile in Step 6.

### Step 4 — Run the assessment

```bash
python3 assess.py --profile my-admin-profile
```

Generates `output/role/` (the Terraform module for this option) and `output/detected_services.json`.

### Step 5 — Create the role

```bash
cd output/role
# Edit terraform.tfvars: iam_user = "security-auditor"
terraform init
AWS_PROFILE=my-admin-profile terraform apply
```

Terraform outputs the role ARN — expect `arn:aws:iam::YOUR_ACCOUNT_ID:role/SymmetryBlackAssessmentRole`.

### Step 6 — Grant sts:AssumeRole to the auditor

Attach this policy to `security-auditor` (using the admin profile):
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

Configure a profile with the static credentials from Step 3:
```bash
aws configure --profile security-auditor
```

### Step 7 — Assume the role

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/SymmetryBlackAssessmentRole \
  --role-session-name assessment \
  --profile security-auditor
```

Export the temporary credentials from the output:
```bash
export AWS_ACCESS_KEY_ID="<AccessKeyId>"
export AWS_SECRET_ACCESS_KEY="<SecretAccessKey>"
export AWS_SESSION_TOKEN="<SessionToken>"
```

Repeat this step whenever the credentials expire.

### Step 8 — Smoke-test the auditor

Using the exported temporary credentials (no `--profile`):
```bash
aws ec2 describe-security-groups \
    --filters "Name=ip-permission.from-port,Values=22" \
              "Name=ip-permission.to-port,Values=22" \
              "Name=ip-permission.cidr,Values=0.0.0.0/0" \
    --query 'SecurityGroups[*].[GroupId,GroupName,VpcId]' \
    --output json | jq .
```

Should succeed (finds any SSH-open-to-world security groups).

### Step 9 (Optional) — Provision the S3 storage bucket

The Terraform in `s3/` creates one hardened bucket, `{org_name}.storage.symmetryblack.com`, and a scoped IAM user `symblack-storage`:

- **Bucket**: public access blocked, AES256 SSE, versioning, bucket-owner-enforced ownership.
- **User `symblack-storage`**: read/write on objects only — no `s3:DeleteObject`; explicit `Deny` on `s3:CreateBucket` and `s3:DeleteBucket`.

```bash
cd s3
cp terraform.tfvars.example terraform.tfvars
# Edit: org_name = "your-org-name"   (lowercase alphanumerics + hyphens)
terraform init
AWS_PROFILE=my-admin-profile terraform apply
```

Retrieve the user's keys and configure a profile:
```bash
terraform output -raw access_key_id
terraform output -raw secret_access_key
aws configure --profile symblack-storage
```

Verify the denies actually fire — all three below **must return `AccessDenied`**:
```bash
STORAGE="your-org-name.storage.symmetryblack.com"
aws s3 rm s3://$STORAGE/nothing.txt   --profile symblack-storage   # no s3:DeleteObject
aws s3 mb s3://some-new-bucket-abcxyz --profile symblack-storage   # deny s3:CreateBucket
aws s3 rb s3://$STORAGE               --profile symblack-storage   # deny s3:DeleteBucket
```

### Step 10 — Clean up

```bash
# S3 (if Step 9 was run) — empty the bucket first, then destroy
cd s3
aws s3 rm s3://your-org-name.storage.symmetryblack.com --recursive --profile my-admin-profile
AWS_PROFILE=my-admin-profile terraform destroy

# Assessment role
cd ../output/role
AWS_PROFILE=my-admin-profile terraform destroy

# Auditor user (when the audit is finished)
aws iam delete-user --user-name security-auditor --profile my-admin-profile
```

---

## Reference

### Assessment policy contents

- Read-only (`Describe*`, `Get*`, `List*`) for every discovered service.
- Security-audit permissions across IAM, Access Analyzer, Config, Security Hub, GuardDuty, CloudTrail, Trusted Advisor, Organizations.
- **Does not** grant `secretsmanager:GetSecretValue` or `secretsmanager:BatchGetSecretValue` — secret-value reads are explicitly excluded.

### S3 storage module — permissions

**`symblack-storage`** on `{org_name}.storage.symmetryblack.com`
- Bucket: `s3:ListBucket`, `s3:GetBucketLocation`
- Objects: `s3:GetObject`, `s3:GetObjectVersion`, `s3:PutObject`
- Explicit deny on `*`: `s3:CreateBucket`, `s3:DeleteBucket`

### S3 storage module — variables

| Name | Default | Notes |
|------|---------|-------|
| `org_name` | — | Required. Lowercase alphanumerics + hyphens. |
| `aws_region` | `eu-west-2` | |
| `iam_user_name` | `symblack-storage` | IAM user for bucket access. |
| `enable_versioning` | `true` | |
| `enable_encryption` | `true` | AES256. |
| `tags` | `{}` | |

Outputs (via `terraform output`): `aws_account_id`, `aws_region`, `bucket_name`, `bucket_arn`, `bucket_region`, `bucket_domain_name`, `iam_user_name`, `iam_user_arn`, `iam_policy_arn`, `access_key_id`, `secret_access_key` (sensitive), `console_url`.

### Troubleshooting

**`AccessDeniedException … explicit deny in an identity-based policy`**
An explicit `Deny` matches the request; an `Allow` won't override it. Locate the offending statement from a truly-admin session:
```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::YOUR_ACCOUNT_ID:user/YOUR_USER \
  --action-names ce:GetCostAndUsage \
  --resource-arns '*'
```
`MatchedStatements` names the policy and statement ID. Common culprits: inline user policies, group policies, permissions boundary, or the AWS-managed `AWSCompromisedKeyQuarantineV2` (auto-attached when AWS detects an exposed access key — rotate the leaked key and detach the policy).

**S3 bucket name already exists** — bucket names are globally unique. Change `org_name`.

**`terraform destroy` won't remove an S3 bucket** — buckets must be empty first. Run `aws s3 rm s3://<bucket> --recursive` before retrying.

### Project structure

```
symblack-aws-service-assessment/
├── assess.py               # Assessment script
├── requirements.txt        # stdlib-only
├── README.md
├── s3/                     # Optional S3 bucket module
│   ├── main.tf, variables.tf, outputs.tf
│   ├── bucket.tf, iam.tf
│   └── terraform.tfvars.example
├── output/                 # Generated by assess.py — contains policy/ and role/ modules
├── LICENSE
└── .gitignore
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
