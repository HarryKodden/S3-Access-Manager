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
IAM_ACCESS_KEY="${IAM_ACCESS_KEY}"
IAM_SECRET_KEY="${IAM_SECRET_KEY}"
```

## Status Summary

- **Critical Issues (❌ NOT OK)**: $CRITICAL_COUNT out of 13 steps have critical issues
- **Partial Issues (⚠️ PARTIALLY OK)**: $PARTIAL_COUNT steps work but with limitations
- **Working Steps (✅ OK)**: $OK_COUNT steps fully compliant

---

## 1. Setting up AWS CLI Configuration $CREATE_USER_STATUS

Configure AWS CLI for the SURF object store endpoint:

```bash
export AWS_ACCESS_KEY_ID="$IAM_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$IAM_SECRET_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"
```

Create AWS configuration files:

```bash
mkdir -p ~/.aws
cat > ~/.aws/config << EOF
[default]
region = $S3_REGION
endpoint_url = $S3_ENDPOINT
signature_version = s3v4
payload_signing_enabled = true
addressing_style = path
EOF

cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = $IAM_ACCESS_KEY
aws_secret_access_key = $IAM_SECRET_KEY
EOF
```

---

## 2. Creating IAM User $CREATE_USER_STATUS

**Command Executed:**
```bash
$CREATE_USER_COMMAND
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
$CREATE_USER_JSON
```

---

## 3. Creating Access Key for User $CREATE_ACCESS_KEY_STATUS

**Command Executed:**
```bash
$CREATE_ACCESS_KEY_COMMAND
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
$CREATE_ACCESS_KEY_JSON
```

---

## 4. Attaching Read-Write Policy to User $PUT_USER_POLICY_STATUS

**Command Executed:**
```bash
$PUT_USER_POLICY_COMMAND
```

**Expected Output:**
(No output - successful policy attachment)

**Actual Output:**
$PUT_USER_POLICY_JSON

---

## 5. Listing Buckets $LIST_BUCKETS_STATUS

**Command Executed:**
```bash
$LIST_BUCKETS_COMMAND
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
$LIST_BUCKETS_JSON
```

---

## 6. Creating Bucket $CREATE_BUCKET_STATUS

**Command Executed:**
```bash
$CREATE_BUCKET_COMMAND
```

**Expected Output:**
```json
{
    "Location": "https://bucket-name.s3.amazonaws.com/"
}
```

**Actual Output:**
```json
$CREATE_BUCKET_JSON
```

---

## 7. Listing Objects (Empty Bucket) $LIST_OBJECTS_EMPTY_STATUS

**Command Executed:**
```bash
$LIST_OBJECTS_EMPTY_COMMAND
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
$LIST_OBJECTS_EMPTY_JSON
```

---

## 8. Uploading Object $PUT_OBJECT_STATUS

**Command Executed:**
```bash
$PUT_OBJECT_COMMAND
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
$PUT_OBJECT_JSON
```

---

## 9. Listing Objects (With Content) $LIST_OBJECTS_WITH_CONTENT_STATUS

**Command Executed:**
```bash
$LIST_OBJECTS_WITH_CONTENT_COMMAND
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
$LIST_OBJECTS_WITH_CONTENT_JSON
```

---

## 10. Downloading Object $GET_OBJECT_STATUS

**Command Executed:**
```bash
$GET_OBJECT_COMMAND
```

**Expected Output:**
```
Hello, S3 CLI!
```

**Actual Output:**
$GET_OBJECT_JSON

---

## 11. Deleting Object $DELETE_OBJECT_STATUS

**Command Executed:**
```bash
$DELETE_OBJECT_COMMAND
```

**Expected Output:**
```json
{
    "delete": "success"
}
```

**Actual Output:**
```json
$DELETE_OBJECT_JSON
```

---

## 12. Deleting Bucket $DELETE_BUCKET_STATUS

**Command Executed:**
```bash
$DELETE_BUCKET_COMMAND
```

**Expected Output:**
```json
{
    "delete": "success"
}
```

**Actual Output:**
```json
$DELETE_BUCKET_JSON
```

---

## 13. Deleting User Policy $DELETE_USER_POLICY_STATUS

**Command Executed:**
```bash
$DELETE_USER_POLICY_COMMAND
```

**Expected Output:**
(No output - successful policy deletion)

**Actual Output:**
$DELETE_USER_POLICY_JSON

---

## 14. Deleting Access Key $DELETE_ACCESS_KEY_STATUS

**Command Executed:**
```bash
$DELETE_ACCESS_KEY_COMMAND
```

**Expected Output:**
(No output - successful access key deletion)

**Actual Output:**
$DELETE_ACCESS_KEY_JSON

---

## 15. Deleting IAM User $DELETE_USER_STATUS

**Command Executed:**
```bash
$DELETE_USER_COMMAND
```

**Expected Output:**
```json
{
    "delete": "success"
}
```

**Actual Output:**
```json
$DELETE_USER_JSON
```

---

## Known Issues

### Status Summary
- **Critical Issues (❌ NOT OK)**: $CRITICAL_COUNT out of 13 steps have critical issues
- **Partial Issues (⚠️ PARTIALLY OK)**: $PARTIAL_COUNT steps work but with limitations
- **Working Steps (✅ OK)**: $OK_COUNT steps fully compliant

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