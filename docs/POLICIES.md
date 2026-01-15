# S3 Gateway - Policy Guide

## Overview

Policies in S3 Gateway control access to S3 resources based on user roles from OIDC claims.

## Policy Structure

Policies follow the AWS IAM policy format:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "StatementId",
      "Effect": "Allow|Deny",
      "Action": ["s3:Action"],
      "Resource": ["arn:aws:s3:::bucket/key"]
    }
  ]
}
```

## Policy Elements

### Version

Always use `"2012-10-17"` for compatibility.

### Statement

Array of policy statements. Each statement contains:

#### Sid (Optional)

A unique identifier for the statement.

```json
"Sid": "AllowReadAccess"
```

#### Effect

Either `"Allow"` or `"Deny"`. Explicit deny always overrides allow.

```json
"Effect": "Allow"
```

#### Action

S3 actions to allow or deny. Can be a string or array:

```json
"Action": "s3:GetObject"
```

or

```json
"Action": ["s3:GetObject", "s3:PutObject"]
```

Supported wildcards:

```json
"Action": "s3:*"  // All S3 actions
```

#### Resource

S3 resources (buckets and objects). Supports wildcards:

```json
"Resource": "arn:aws:s3:::my-bucket/*"
```

Multiple resources:

```json
"Resource": [
  "arn:aws:s3:::my-bucket",
  "arn:aws:s3:::my-bucket/*"
]
```

## Supported S3 Actions

### Object Operations

- `s3:GetObject` - Download objects
- `s3:PutObject` - Upload objects
- `s3:DeleteObject` - Delete objects
- `s3:ListBucket` - List bucket contents

### Wildcards

- `s3:*` - All S3 operations
- `s3:Get*` - All Get operations
- `s3:Put*` - All Put operations

## Resource Patterns

### Bucket Level

```json
"Resource": "arn:aws:s3:::my-bucket"
```

### All Objects in Bucket

```json
"Resource": "arn:aws:s3:::my-bucket/*"
```

### Prefix (Folder) Access

```json
"Resource": "arn:aws:s3:::my-bucket/users/john/*"
```

### Multiple Prefixes

```json
"Resource": [
  "arn:aws:s3:::my-bucket/dev/*",
  "arn:aws:s3:::my-bucket/staging/*"
]
```

### Wildcard Patterns

```json
"Resource": "arn:aws:s3:::my-bucket/*/data/*"
```

## Policy Examples

### Full Admin Access

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

### Read-Only Access

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }
  ]
}
```

### Per-User Folder Access

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::my-bucket/users/${aws:username}/*"
    }
  ]
}
```

### Environment-Based Access

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DevFullAccess",
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my-bucket/dev/*"
    },
    {
      "Sid": "StagingReadOnly",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/staging/*"
    },
    {
      "Sid": "ProdDeny",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my-bucket/prod/*"
    }
  ]
}
```

### Multi-Bucket Access

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": [
        "arn:aws:s3:::data-bucket/*",
        "arn:aws:s3:::reports-bucket/*",
        "arn:aws:s3:::archives-bucket/*"
      ]
    }
  ]
}
```

## Policy Evaluation

### Order of Evaluation

1. **Explicit Deny**: Always wins
2. **Explicit Allow**: Grants access
3. **Default Deny**: No match = deny (if `default_deny: true`)

### Example

User has roles: `["developer", "viewer"]`

Policy `developer.json`:
```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my-bucket/dev/*"
    }
  ]
}
```

Policy `viewer.json`:
```json
{
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

Result: User can read/write but **not delete** (deny overrides allow)

## OIDC Role Mapping

### Policy File Naming

Policy files must match role names from OIDC claims:

- OIDC Role: `admin` → Policy File: `policies/admin.json`
- OIDC Role: `developer` → Policy File: `policies/developer.json`
- OIDC Role: `data-scientist` → Policy File: `policies/data-scientist.json`

### Roles Claim Configuration

In `config.yaml`:

```yaml
oidc:
  roles_claim: "Roles"  # JWT claim containing roles
```

Example JWT token:
```json
{
  "sub": "user123",
  "email": "user@example.com",
  "Roles": ["developer", "viewer"]
}
```

Gateway loads policies: `developer.json` and `viewer.json`

## Policy Management

### Version Control

Store policies in Git:

```bash
git add policies/*.json
git commit -m "Update developer policy"
git push
```

### Policy Updates

Policies are automatically reloaded based on `cache_ttl`:

```yaml
policies:
  cache_enabled: true
  cache_ttl: 300s  # Reload every 5 minutes
```

Or manually restart the service:

```bash
docker-compose restart s3-gateway
```

### Testing Policies

Test policy evaluation:

```bash
# Get a JWT token
TOKEN="eyJhbGc..."

# Test access
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:9000/my-bucket/dev/test.txt
```

Check logs for policy evaluation:

```bash
docker-compose logs s3-gateway | grep "policy evaluation"
```

## Best Practices

### 1. Principle of Least Privilege

Grant minimal permissions needed:

```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],  // Only read
      "Resource": ["arn:aws:s3:::my-bucket/public/*"]  // Only public folder
    }
  ]
}
```

### 2. Use Explicit Deny for Restrictions

Prevent access to sensitive data:

```json
{
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my-bucket/secrets/*"
    }
  ]
}
```

### 3. Organize by Environment

```
policies/
├── prod-admin.json
├── prod-readonly.json
├── dev-developer.json
└── staging-tester.json
```

### 4. Use Descriptive Sids

```json
{
  "Sid": "AllowReadUserDocuments",
  "Effect": "Allow",
  ...
}
```

### 5. Test in Staging First

Always test policy changes in a non-production environment.

## Troubleshooting

### Access Denied

Check logs for policy evaluation:

```bash
docker-compose logs s3-gateway | grep "Access denied"
```

Common issues:
- Role name doesn't match policy file
- Policy syntax error
- Resource ARN mismatch

### Policy Not Loading

Verify:
1. Policy file is valid JSON
2. File is in `policies/` directory
3. File has `.json` extension
4. File name matches role name

### Debug Mode

Enable detailed policy evaluation logging:

```yaml
logging:
  level: "debug"
```
