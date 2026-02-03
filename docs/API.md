# API Reference

## Authentication

All API requests (except `/health`, `/metrics`, `/oidc-config`) require OIDC authentication.

```http
Authorization: Bearer <access_token>
```

## Public Endpoints

### Health Check
```http
GET /health
```
Returns: `{"status": "healthy", "version": "1.0.0"}`

### OIDC Configuration
```http
GET /oidc-config
```
Returns OIDC provider configuration for frontend

### Metrics
```http
GET /metrics
```
Returns Prometheus metrics (request duration, count, size)

## S3 Proxy Endpoints

All S3 operations at root level: `/{bucket}/{key...}` (also supports legacy `/s3/{bucket}/{key...}` prefix)

The gateway proxies S3 requests to the backend for both Web UI and AWS CLI:
- **Web UI**: Uses OIDC token + X-S3-Credential-AccessKey header
- **AWS CLI**: Uses AWS4-HMAC-SHA256 signature authentication

### Get Object
```http
GET /{bucket}/{key}

# Web UI:
Authorization: Bearer <oidc_token>
X-S3-Credential-AccessKey: <selected_credential>

# AWS CLI:
Authorization: AWS4-HMAC-SHA256 Credential=...
```

### Put Object
```http
PUT /{bucket}/{key}
Content-Type: application/octet-stream

# Web UI:
Authorization: Bearer <oidc_token>
X-S3-Credential-AccessKey: <selected_credential>

# AWS CLI:
Authorization: AWS4-HMAC-SHA256 Credential=...
```

### Delete Object
```http
DELETE /{bucket}/{key}

# Web UI:
Authorization: Bearer <oidc_token>
X-S3-Credential-AccessKey: <selected_credential>

# AWS CLI:
Authorization: AWS4-HMAC-SHA256 Credential=...
```

### List Bucket
```http
GET /{bucket}?prefix=path/&delimiter=/

# Web UI:
Authorization: Bearer <oidc_token>
X-S3-Credential-AccessKey: <selected_credential>

# AWS CLI:
Authorization: AWS4-HMAC-SHA256 Credential=...
```
```bash
# Web UI example
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-S3-Credential-AccessKey: $ACCESS_KEY" \
     http://localhost:9000/my-bucket/files/document.pdf \
     -o document.pdf

# AWS CLI example (gateway proxies to S3 backend)
aws s3 cp s3://my-bucket/files/document.pdf document.pdf \
    --endpoint-url http://localhost:9000
```
## Credential Management Endpoints

### List Credentials
```http
GET /settings/credentials
```

### Create Credential
```http
POST /settings/credentials
Content-Type: application/json

{
  "name": "My App",
  "description": "Production credentials",
  "policies": ["read-only", "developer"]
}
```

### Get Credential
```http
GET /settings/credentials/{accessKey}
```
Returns full credential including secret key (if authorized)

### Delete Credential
```http
DELETE /settings/credentials/{accessKey}
```

## Policy Management Endpoints

### List Policies
```http
GET /settings/policies
```

### Get Policy
```http
GET /settings/policies/{name}
```

### Create Policy (Admin only)
```http
POST /settings/policies
Content-Type: application/json

{
  "name": "my-policy",
  "document": { /* IAM policy JSON */ }
}
```

### Update Policy (Admin only)
```http
PUT /settings/policies/{name}
Content-Type: application/json

{
  "document": { /* IAM policy JSON */ }
}
```

### Delete Policy (Admin only)
```http
DELETE /settings/policies/{name}
```

## Bucket Management Endpoints

### List Buckets
```http
GET /settings/buckets
```

### Create Bucket
```http
POST /settings/buckets
Content-Type: application/json

{
  "name": "my-new-bucket"
}
```

### Delete Bucket
```http
DELETE /settings/buckets/{name}
```

## Error Responses

- **401 Unauthorized**: Missing/invalid token
- **403 Forbidden**: Access denied by policy
- **404 Not Found**: Resource not found
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error

## Rate Limiting

- **10 requests/second per IP** (burst of 20)
- Implemented via Go middleware
- No rate limit headers (simple token bucket)

## Example Usage

### cURL (Web UI)
```bash
TOKEN="your_oidc_access_token"
CRED_KEY="your_credential_access_key"

# List objects in bucket
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-S3-Credential-AccessKey: $CRED_KEY" \
     http://localhost:9000/my-bucket

# Upload file
curl -X PUT \
     -H "Authorization: Bearer $TOKEN" \
     -H "X-S3-Credential-AccessKey: $CRED_KEY" \
     --data-binary @file.txt \
     http://localhost:9000/my-bucket/file.txt

# Download file
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-S3-Credential-AccessKey: $CRED_KEY" \
     http://localhost:9000/my-bucket/file.txt -o file.txt
```

### AWS CLI (via Gateway)
```bash
# Configure AWS CLI with credentials created via gateway
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"

# Point AWS CLI to gateway (gateway proxies to S3 backend)
# List buckets
aws s3 ls --endpoint-url http://localhost:9000

# Upload file
aws s3 cp file.txt s3://my-bucket/file.txt --endpoint-url http://localhost:9000

# Download file
aws s3 cp s3://my-bucket/file.txt file.txt --endpoint-url http://localhost:9000
```

### Python (Web UI)
```python
import requests

headers = {
    "Authorization": f"Bearer {oidc_token}",
    "X-S3-Credential-AccessKey": credential_access_key
}
base_url = "http://localhost:9000"

# List objects
r = requests.get(f"{base_url}/bucket", headers=headers)
print(r.json())

# Upload
with open("file.txt", "rb") as f:
    requests.put(f"{base_url}/bucket/file.txt", headers=headers, data=f)
```

### Python with boto3 (via Gateway)
```python
import boto3

# Create S3 client pointing to gateway (gateway proxies to S3 backend)
s3 = boto3.client(
    's3',
    endpoint_url='http://localhost:9000',
    aws_access_key_id='your_access_key',
    aws_secret_access_key='your_secret_key',
    region_name='us-east-1'
)

# List buckets
buckets = s3.list_buckets()
print(buckets)

# Upload file
s3.upload_file('file.txt', 'bucket', 'file.txt')

# Download file
s3.download_file('bucket', 'file.txt', 'downloaded.txt')
```