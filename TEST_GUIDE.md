# E2E Test Guide

## Overview

The `test-e2e-workflow.sh` script validates the complete S3 Access Manager workflow:

1. **OIDC Authentication** - User logs in via test OIDC provider
2. **Credential Creation** - User creates S3 credentials via Gateway API
3. **Backend IAM Sync** - Gateway creates IAM user in Ceph backend
4. **Direct S3 Access** - User accesses Ceph S3 directly (not through gateway)
5. **IAM Operations Blocked** - Verifies credentials are S3-only

## Architecture Note

**Important:** Users access the S3 backend DIRECTLY with their credentials, not through the gateway proxy. This prevents the gateway from being a single point of failure. The gateway is only used for:
- Authentication (OIDC)
- Credential management (creating IAM users)
- Web UI

## Prerequisites

1. **Services Running:**
   ```bash
   docker compose up -d
   ```

2. **Clean Up Old Access Keys** (if you've run tests before):
   ```bash
   docker compose exec -T gateway aws iam list-access-keys --user-name testuser@example.com | \
     jq -r '.AccessKeyMetadata[]?.AccessKeyId' | while read key; do \
     docker compose exec -T gateway aws iam delete-access-key --user-name testuser@example.com --access-key-id "$key"; \
   done
   ```

3. **Required Tools:**
   - curl
   - jq
   - aws CLI

## Running the Test

```bash
./test-e2e-workflow.sh
```

## Expected Results

### Full Success (with accessible S3 backend):
```
Total Tests: 9
Passed: 9
Failed: 0

✓ All tests passed!
```

### Partial Success (S3 backend not accessible):
```
Total Tests: 9
Passed: 5
Failed: 0

Note: S3 backend tests were skipped
(Backend endpoint not accessible from this environment)

✓ All tests passed!
```

This is **expected** when the production Ceph endpoint (`https://object-acc.data.surf.nl`) is not reachable from your test environment. The test still validates:
- ✅ OIDC authentication
- ✅ Credential creation
- ✅ Backend IAM user creation
- ✅ IAM operations correctly denied

## Troubleshooting

### "user already has maximum access keys"

AWS/Ceph limits users to 2 access keys. Clean up old keys:

```bash
# List existing keys
docker compose exec -T gateway aws iam list-access-keys --user-name testuser@example.com

# Delete them
docker compose exec -T gateway aws iam list-access-keys --user-name testuser@example.com | \
  jq -r '.AccessKeyMetadata[]?.AccessKeyId' | while read key; do \
  docker compose exec -T gateway aws iam delete-access-key --user-name testuser@example.com --access-key-id "$key"; \
done
```

### S3 Operations Fail

If you see S3 operation failures, check:

1. **Is the backend accessible?**
   ```bash
   curl -I https://object-acc.data.surf.nl
   ```

2. **Are the credentials valid?**
   ```bash
   # Get credentials from test
   ACCESS_KEY="your-key"
   SECRET_KEY="your-secret"
   
   AWS_ACCESS_KEY_ID=$ACCESS_KEY AWS_SECRET_ACCESS_KEY=$SECRET_KEY \
   aws --endpoint-url https://object-acc.data.surf.nl s3 ls
   ```

3. **Test with local MinIO instead:**
   ```bash
   # Update test script to use local MinIO
   AWS_ENDPOINT="http://localhost:9001"
   ```

## Test Script Details

The script performs these operations:

1. **OIDC Auth** - Gets access token from test OIDC provider
2. **Create Credential** - POST to `/settings/credentials`
3. **Configure AWS CLI** - Adds credentials to `~/.aws/`
4. **S3 Operations** - List buckets, create bucket, upload/download files
5. **IAM Operations** - Verifies IAM commands are denied (security check)
6. **Cleanup** - Deletes test credential and AWS CLI profile

## Manual Testing

Test individual components:

```bash
# 1. Get OIDC token
TOKEN=$(curl -s "http://localhost:8888/test-token/testuser@example.com?groups=developer-group" | jq -r '.access_token')

# 2. Create credential
CREDS=$(curl -s -X POST "http://localhost:9000/settings/credentials" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"manual-test","groups":["developer-group"]}')

echo "$CREDS" | jq '.'

# 3. Extract keys
ACCESS_KEY=$(echo "$CREDS" | jq -r '.credential.AccessKey')
SECRET_KEY=$(echo "$CREDS" | jq -r '.credential.SecretKey')

# 4. Test S3 access
AWS_ACCESS_KEY_ID=$ACCESS_KEY AWS_SECRET_ACCESS_KEY=$SECRET_KEY \
aws --endpoint-url https://object-acc.data.surf.nl s3 ls

# 5. Cleanup
curl -s -X DELETE "http://localhost:9000/settings/credentials/$ACCESS_KEY" \
  -H "Authorization: Bearer $TOKEN"
```

## CI/CD Integration

Add to GitHub Actions:

```yaml
- name: Run E2E Tests
  run: |
    docker compose up -d
    docker compose exec -T gateway aws iam list-access-keys --user-name testuser@example.com | \
      jq -r '.AccessKeyMetadata[]?.AccessKeyId' | while read key; do \
      docker compose exec -T gateway aws iam delete-access-key --user-name testuser@example.com --access-key-id "$key" || true; \
    done
    ./test-e2e-workflow.sh
```
