# S3 Gateway CLI Flow Demonstration

This document demonstrates the backend operations performed by the S3 Gateway using AWS CLI commands directly against the SURF object store.

## Prerequisites

- AWS CLI installed and configured
- Access to SURF object store credentials (IAM_ACCESS_KEY, IAM_SECRET_KEY)
- jq installed for JSON formatting

## Configuration

The script reads configuration from a `.env` file:

```bash
S3_ENDPOINT="${S3_ENDPOINT:-https://object-acc.data.surf.nl}"
S3_REGION="${S3_REGION:-default}"
IAM_ACCESS_KEY=""
IAM_SECRET_KEY=""
```

## Status Summary

- **Critical Issues (❌ NOT OK)**:        2 out of 13 steps have critical issues
- **Partial Issues (⚠️ PARTIALLY OK)**:        4 steps work but with limitations
- **Working Steps (✅ OK)**:        1 steps fully compliant

---

## 1. Setting up AWS CLI Configuration ✅ OK

Configure AWS CLI for the SURF object store endpoint:

```bash
export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""
export AWS_DEFAULT_REGION=""
```

Create AWS configuration files:

```bash
mkdir -p ~/.aws
cat > ~/.aws/config << EOF
[default]
region = 
endpoint_url = 
signature_version = s3v4
payload_signing_enabled = true
addressing_style = path
EOF

cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = 
aws_secret_access_key = 
EOF
```

---

## 2. Creating IAM User ✅ OK

**Command Executed:**
```bash
aws iam create-user --user-name demo-user-1768495177 --output json
```

**Expected Output:**
```json
{
    "User": {
        "UserName": "demo-user-1234567890",
        "UserId": "AIDACKCEVSQ6C2EXAMPLE",
        "Arn": "arn:aws:iam::123456789012:user/demo-user-1234567890",
        "CreateDate": "2023-01-15T10:30:00Z",
        "Path": "/"
    }
}
```

**Actual Output:**
```json
{
  "User": {
    "Path": "/",
    "UserName": "demo-user-1768495177",
    "UserId": "aa6a6779cc28480f88e3008e209a0516$1a98bf66-027d-4f50-bde8-1c639b2a6a80",
    "Arn": "arn:aws:iam::RGW63042161445168768:user/demo-user-1768495177",
    "CreateDate": "2026-01-15T16:39:49.097035+00:00"
  }
}
{
  "User": {
    "Path": "/",
    "UserName": "demo-user-1768495177",
    "UserId": "aa6a6779cc28480f88e3008e209a0516$1a98bf66-027d-4f50-bde8-1c639b2a6a80",
    "Arn": "arn:aws:iam::RGW63042161445168768:user/demo-user-1768495177",
    "CreateDate": "2026-01-15T16:39:49.097035+00:00"
  }
}
✅ IAM user created
```

---

## 3. Creating Access Key for User ❌ NOT OK

**Command Executed:**
```bash
aws iam create-access-key --user-name demo-user-1768495177 --output json
```

**Expected Output:**
```json
{
    "AccessKey": {
        "UserName": "demo-user-1234567890",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "Status": "Active",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "CreateDate": "2023-01-15T10:30:00Z"
    }
}
```

**Actual Output:**
```json

```

---

## 4. Attaching Read-Write Policy to User ❌ NOT OK

**Command Executed:**
```bash
aws iam put-user-policy --user-name demo-user-1768495177 --policy-name demo-user-1768495177-read-write-policy --policy-document file:///tmp/read-write-policy.json
```

**Expected Output:**
(No output - successful policy attachment)

**Actual Output:**
"❌ Policy attachment failed"

---

## 5. Listing Buckets ❌ NOT OK

**Command Executed:**
```bash
aws s3api list-buckets --output json
```

**Expected Output:**
```json
{
    "Buckets": [
        {
            "Name": "existing-bucket-1",
            "CreationDate": "2023-01-14T08:00:00Z"
        }
    ],
    "Owner": {
        "DisplayName": "user@example.com",
        "ID": "123456789012"
    }
}
```

**Actual Output:**
```json

```

---

## 6. Creating Bucket ⚠️ PARTIALLY OK

**Command Executed:**
```bash
aws s3api create-bucket --bucket demo-bucket-1768495196 --output json
```

**Expected Output:**
```json
{
    "Location": "https://bucket-name.s3.amazonaws.com/"
}
```

**Actual Output:**
```json

```

---

## 7. Listing Objects (Empty Bucket) ✅ OK

**Command Executed:**
```bash
aws s3api list-objects-v2 --bucket demo-bucket-1768495196 --output json
```

**Expected Output:**
```json
{
    "IsTruncated": false,
    "Contents": [],
    "Name": "demo-bucket-1234567890",
    "Prefix": "",
    "MaxKeys": 1000,
    "EncodingType": "url"
}
```

**Actual Output:**
```json

```

---

## 8. Uploading Object ❌ NOT OK

**Command Executed:**
```bash
aws s3api put-object --bucket demo-bucket-1768495196 --key test-object.txt --body /tmp/cli-test-object.txt --output json
```

**Expected Output:**
```json
{
    "ETag": "\"9bb58f26192e4ba00f01e2e7b136bbd8\"",
    "VersionId": "null"
}
```

**Actual Output:**
```json

```

---

## 9. Listing Objects (With Content) ❌ NOT OK

**Command Executed:**
```bash
aws s3api list-objects-v2 --bucket demo-bucket-1768495196 --output json
```

**Expected Output:**
```json
{
    "IsTruncated": false,
    "Contents": [
        {
            "Key": "test-object.txt",
            "LastModified": "2023-01-15T10:35:00Z",
            "ETag": "\"9bb58f26192e4ba00f01e2e7b136bbd8\"",
            "Size": 13,
            "StorageClass": "STANDARD"
        }
    ],
    "Name": "demo-bucket-1234567890",
    "Prefix": "",
    "MaxKeys": 1000
}
```

**Actual Output:**
```json

```

---

## 10. Downloading Object ❌ NOT OK

**Command Executed:**
```bash
aws s3api get-object --bucket demo-bucket-1768495196 --key test-object.txt /tmp/downloaded-object.txt --output json
```

**Expected Output:**
```
Hello, S3 CLI!
```

**Actual Output:**
"❌ Download failed"

---

## 11. Deleting Object ⚠️ PARTIALLY OK

**Command Executed:**
```bash
aws s3api delete-object --bucket demo-bucket-1768495196 --key test-object.txt --output json
```

**Expected Output:**
```json
{
    "delete": "success"
}
```

**Actual Output:**
```json

```

---

## 12. Deleting Bucket ⚠️ PARTIALLY OK

**Command Executed:**
```bash
aws s3api delete-bucket --bucket demo-bucket-1768495196 --output json
```

**Expected Output:**
```json
{
    "delete": "success"
}
```

**Actual Output:**
```json

```

---

## 13. Deleting User Policy ❌ NOT OK

**Command Executed:**
```bash
aws iam delete-user-policy --user-name demo-user-1768495177 --policy-name demo-user-1768495177-read-write-policy --output json
```

**Expected Output:**
(No output - successful policy deletion)

**Actual Output:**
"❌ Policy deletion failed"

---

## 14. Deleting Access Key ❌ NOT OK

**Command Executed:**
```bash
aws iam delete-access-key --user-name demo-user-1768495177 --access-key-id YNFDFYI5JRYCLW4B2TUG --output json
```

**Expected Output:**
(No output - successful access key deletion)

**Actual Output:**
"❌ Access key deletion failed"

---

## 15. Deleting IAM User ⚠️ PARTIALLY OK

**Command Executed:**
```bash
aws iam delete-user-policy --user-name demo-user-1768495177 --policy-name demo-user-1768495177-read-write-policy --output json
```

**Expected Output:**
```json
{
    "delete": "success"
}
```

**Actual Output:**
```json

```

---

## Known Issues

### Status Summary
- **Critical Issues (❌ NOT OK)**:        2 out of 13 steps have critical issues
- **Partial Issues (⚠️ PARTIALLY OK)**:        4 steps work but with limitations
- **Working Steps (✅ OK)**:        1 steps fully compliant

### Critical Issues
1. **List Buckets Failure**: The `aws s3api list-buckets` command fails with "argument of type 'NoneType' is not iterable", indicating a bug in the S3 backend implementation. (Expected: Standard AWS S3 bucket listing response)

### Backend-Specific Behaviors
- **IAM User Format**: Uses Ceph RGW format with embedded UUIDs instead of standard AWS IAM user IDs
- **Response Fields**: Empty bucket listings include `RequestCharged: null` and `Prefix: ""` fields not present in standard AWS S3
- **Minimal Responses**: Some operations return minimal JSON responses compared to standard AWS S3 (e.g., create-bucket returns `{}` instead of location)
- **Metadata Suppression**: Get-object metadata is suppressed in the demonstration script

### Comparison Notes
Each section now shows both **Expected Output** (standard AWS S3 behavior) and **Actual Output** (current SURF backend behavior) for easy comparison and debugging.

This document was auto-generated from the latest demo-flow-cli.sh execution on DATE_STAMP.