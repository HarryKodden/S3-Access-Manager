# S3 Access Manager - User Guide

## Overview

The S3 Access Manager provides secure, policy-based access to Ceph S3 storage through OIDC authentication. Users can create their own S3 credentials for offline use while administrators manage policies and group assignments.

## Table of Contents

- [User Workflow](#user-workflow)
- [Administrator Workflow](#administrator-workflow)
- [AWS CLI Configuration](#aws-cli-configuration)
- [Policy Examples](#policy-examples)
- [Troubleshooting](#troubleshooting)

---

## User Workflow

### 1. Login via OIDC

1. Navigate to `http://localhost:9000/tenant/{tenant-name}/` (or your gateway URL with tenant prefix)
2. Click **Sign In**
3. Authenticate with your OIDC provider
4. Your groups are automatically extracted from the OIDC token

**Required:** Your OIDC token must include a `Groups` claim matching SCIM-provisioned groups.

**Note:** For single-tenant deployments, you can also access `http://localhost:9000` directly.

### 2. Create S3 Credentials

Once logged in:

1. Navigate to **Credentials** tab
2. Click **+ New Credential**
3. Enter a name (e.g., `my-s3-access`)
4. Select your groups (groups determine your S3 permissions)
5. Click **Create**
6. **Important:** Copy your **Access Key** and **Secret Key** immediately - the secret is only shown once!

Example:
```
Access Key ID: Q4PMB2BKCHM9ZDBJ9TEP
Secret Key: DnFRKwv3gMMu4swvGVuY3Vmt35YKpz5ol7ZAWMiS
```

### 3. Configure AWS CLI

#### Option A: Using `aws configure`

```bash
aws configure --profile myprofile
```

Enter when prompted:
```
AWS Access Key ID: <your-access-key>
AWS Secret Access Key: <your-secret-key>
Default region name: us-east-1
Default output format: json
```

Then edit `~/.aws/config` and add the endpoint:

```ini
[profile myprofile]
region = us-east-1
endpoint_url = https://object-acc.data.surf.nl
s3 =
  signature_version = s3v4
  addressing_style = path
```

#### Option B: Manual Configuration

Create `~/.aws/credentials`:

```ini
[myprofile]
aws_access_key_id = Q4PMB2BKCHM9ZDBJ9TEP
aws_secret_access_key = DnFRKwv3gMMu4swvGVuY3Vmt35YKpz5ol7ZAWMiS
```

Create `~/.aws/config`:

```ini
[profile myprofile]
region = us-east-1
endpoint_url = https://object-acc.data.surf.nl
s3 =
  signature_version = s3v4
  addressing_style = path
```

### 4. Use AWS CLI for S3 Operations

**✅ Allowed Operations (S3 only):**

```bash
# List all buckets
aws --profile myprofile s3 ls

# Create a bucket
aws --profile myprofile s3 mb s3://mybucket

# Upload a file
aws --profile myprofile s3 cp myfile.txt s3://mybucket/

# List bucket contents
aws --profile myprofile s3 ls s3://mybucket

# Download a file
aws --profile myprofile s3 cp s3://mybucket/myfile.txt ./downloaded.txt

# Delete a file
aws --profile myprofile s3 rm s3://mybucket/myfile.txt

# Sync a directory
aws --profile myprofile s3 sync ./mydir s3://mybucket/backup/

# Remove a bucket (must be empty)
aws --profile myprofile s3 rb s3://mybucket
```

**Using S3 API directly:**

```bash
# Low-level S3 commands
aws --profile myprofile s3api list-buckets
aws --profile myprofile s3api get-object --bucket mybucket --key myfile output.txt
aws --profile myprofile s3api put-object --bucket mybucket --key myfile --body input.txt
```

**❌ Prohibited Operations (IAM - Will Fail):**

These commands will return authorization errors:

```bash
# These will fail with "User is not authorized"
aws --profile myprofile iam list-users
aws --profile myprofile iam create-user --user-name newuser
aws --profile myprofile iam create-group --group-name newgroup
aws --profile myprofile iam attach-group-policy --group-name mygroup --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
```

**Why?** Your credentials are restricted to S3-only operations for security. IAM operations can only be performed by administrators through the gateway's web UI.

---

## Administrator Workflow

### 1. Login as Admin

- Your email must be configured as `ADMIN` in the `.env` file
- Example: `ADMIN=harry.kodden@surf.nl`

### 2. Manage Policies

#### View Policies

1. Navigate to **Policies** tab
2. Review administrator-created policies

#### Create New Policy

1. Click **+ New Policy**
2. Enter policy name (e.g., `bucket-manager`)
3. Enter JSON policy document:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3BucketManagement",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:ListAllMyBuckets",
        "s3:ListBucket",
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::*",
        "arn:aws:s3:::*/*"
      ]
    }
  ]
}
```

4. Click **Create**

**Important:** The gateway validates that policies only contain S3 actions. Attempting to include IAM, EC2, or other service actions will be rejected:

```json
{
  "Action": ["iam:ListUsers"]  // ❌ ERROR: Only S3 actions allowed
}
```

#### Update Policy

1. Click **Edit** on existing policy
2. Modify JSON document
3. Click **Save**

#### Delete Policy

1. Click **Delete** on policy
2. Confirm deletion
3. **Warning:** Deleting a policy removes it from all groups

### 3. Manage Group Policies

#### View Groups

1. Navigate to **Groups** tab
2. View SCIM-provisioned groups:
   - `admin-group`
   - `developer-group`
   - (others provisioned via SCIM)

**Note:** Only SCIM-provisioned groups are shown. Groups are created externally via SCIM API, not through the gateway UI.

#### Attach Policy to Group

1. Select a group
2. Click **Attach Policy**
3. Select policy from dropdown
4. Click **Attach**

This grants all members of that group the permissions in the policy.

#### Detach Policy from Group

1. Select a group with attached policy
2. Click **Detach Policy**
3. Confirm detachment

### 4. SCIM Integration

Groups and users are provisioned via the SCIM API:

```bash
# SCIM API runs on port 8000
# Groups stored in: /data/Groups/
# Users stored in: /data/Users/

# Example: SCIM creates group file
/data/Groups/admin-group.json
/data/Groups/developer-group.json
```

**SCIM Group Format:**
```json
{
  "id": "admin-group",
  "displayName": "Administrators",
  "members": [
    {"value": "harry.kodden@surf.nl"}
  ]
}
```

---

## AWS CLI Configuration

### Endpoint Configuration

**Production:** Point directly to Ceph backend
```bash
endpoint_url = https://object-acc.data.surf.nl
```

**Development:** For testing with local gateway
```bash
endpoint_url = http://localhost:9000
```

### Common Issues

**Issue:** `SSL certificate problem`
```bash
# Solution: Use --no-verify-ssl for testing only
aws --profile myprofile --no-verify-ssl s3 ls
```

**Issue:** `SignatureDoesNotMatch`
```bash
# Solution: Check credentials and signature version
# Ensure s3.signature_version = s3v4 in ~/.aws/config
```

**Issue:** `InvalidAccessKeyId`
```bash
# Solution: Credential may be deleted or expired
# Create new credential via gateway UI
```

---

## Policy Examples

### Example 1: Read-Only Access

Users can list and download, but not upload or delete:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ReadOnlyAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "s3:GetBucketLocation",
        "s3:ListAllMyBuckets"
      ],
      "Resource": [
        "arn:aws:s3:::*",
        "arn:aws:s3:::*/*"
      ]
    }
  ]
}
```

**Allows:**
- `aws s3 ls`
- `aws s3 ls s3://mybucket`
- `aws s3 cp s3://mybucket/file.txt ./local.txt`

**Denies:**
- `aws s3 cp ./local.txt s3://mybucket/file.txt`
- `aws s3 rm s3://mybucket/file.txt`

### Example 2: Bucket-Specific Access

Users can only access specific buckets:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SpecificBucketAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-project-bucket",
        "arn:aws:s3:::my-project-bucket/*"
      ]
    },
    {
      "Sid": "ListAllBuckets",
      "Effect": "Allow",
      "Action": ["s3:ListAllMyBuckets"],
      "Resource": "*"
    }
  ]
}
```

**Allows:**
- Access to `my-project-bucket` only
- Can see all bucket names in listings

**Denies:**
- Access to other buckets

### Example 3: Read-Write Without Delete

Users can read and write, but not delete:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ReadWriteNoDelete",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket",
        "s3:ListAllMyBuckets",
        "s3:CreateBucket"
      ],
      "Resource": [
        "arn:aws:s3:::*",
        "arn:aws:s3:::*/*"
      ]
    }
  ]
}
```

**Allows:**
- Upload files
- Create buckets
- Download files

**Denies:**
- `aws s3 rm` (delete objects)
- `aws s3 rb` (delete buckets)

### Example 4: Full S3 Admin Access

Users have complete S3 control:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3AdminFullAccess",
      "Effect": "Allow",
      "Action": ["s3:*"],
      "Resource": [
        "arn:aws:s3:::*",
        "arn:aws:s3:::*/*"
      ]
    }
  ]
}
```

**Allows:**
- All S3 operations
- Create/delete buckets
- Upload/download/delete objects
- Manage bucket policies, versioning, etc.

**Still Denies:**
- IAM operations (always denied)

---

## Troubleshooting

### Login Issues

**Problem:** "Invalid token" after OIDC login

**Solutions:**
1. Check OIDC configuration in `.env`:
   ```bash
   OIDC_ISSUER=https://your-provider.com
   OIDC_CLIENT_ID=your-client-id
   OIDC_CLIENT_SECRET=your-secret
   ```
2. Verify your OIDC token includes `Groups` claim
3. Check gateway logs: `docker-compose logs gateway`

### Credential Issues

**Problem:** Credentials not working with AWS CLI

**Solutions:**
1. Verify credentials are active in gateway UI
2. Check endpoint URL in `~/.aws/config`
3. Test with: `aws --profile myprofile s3 ls --debug`
4. Ensure profile name matches in credentials and config

### Permission Issues

**Problem:** "Access Denied" when accessing S3

**Solutions:**
1. Check your group memberships in gateway UI
2. Verify policies attached to your groups
3. Confirm policy allows the specific action (e.g., `s3:GetObject`)
4. Check resource restrictions in policy

**Problem:** IAM commands fail

**Solution:** This is expected! User credentials only have S3 access. IAM operations are restricted.

### Policy Issues

**Problem:** Cannot create policy with IAM actions

**Solution:** This is intentional. Gateway only allows S3-only policies. Remove any non-S3 actions:
```json
// ❌ Wrong
"Action": ["iam:ListUsers", "s3:GetObject"]

// ✅ Correct
"Action": ["s3:GetObject"]
```

### SCIM Issues

**Problem:** Groups not appearing in gateway

**Solutions:**
1. Check SCIM server is running: `docker-compose ps scim`
2. Verify group files exist: `ls data/Groups/`
3. Check group JSON format matches SCIM schema
4. Restart gateway: `docker-compose restart gateway`

---

## Advanced Usage

### Using Multiple Credentials

Create multiple credentials for different purposes:

```bash
# Production access
aws configure --profile prod-readonly
# Use production endpoint

# Development access
aws configure --profile dev-full-access
# Use development endpoint

# Switch between profiles
aws --profile prod-readonly s3 ls
aws --profile dev-full-access s3 mb s3://test-bucket
```

### Credential Rotation

1. Create new credential in gateway UI
2. Update AWS CLI configuration with new keys
3. Test new credential works
4. Delete old credential from gateway UI

**Best Practice:** Rotate credentials every 90 days.

### Monitoring Usage

Administrators can monitor:
- Credential creation/deletion in gateway logs
- S3 access patterns in Ceph logs
- Failed authentication attempts

```bash
# View gateway logs
docker-compose logs -f gateway

# Check for errors
docker-compose logs gateway | grep ERROR
```

---

## Security Best Practices

1. **Never commit credentials to version control**
   - Use `.gitignore` for `.env` files
   - Store secrets in password managers

2. **Use least-privilege policies**
   - Grant minimum permissions needed
   - Use bucket-specific policies when possible

3. **Rotate credentials regularly**
   - Create new credentials every 90 days
   - Delete unused credentials

4. **Monitor access**
   - Review gateway logs regularly
   - Check for unauthorized access attempts

5. **Keep software updated**
   - Update gateway container: `docker-compose pull gateway`
   - Monitor security advisories

---

## Getting Help

- **Documentation:** See [docs/](../docs/) directory
- **API Reference:** [API.md](API.md)
- **OIDC Setup:** [OIDC_AUTHENTICATION.md](OIDC_AUTHENTICATION.md)
- **Policy Guide:** [POLICIES.md](POLICIES.md)
- **Issues:** https://github.com/HarryKodden/S3-Access-Manager/issues
