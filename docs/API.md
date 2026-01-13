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

All S3 operations via `/s3/{bucket}/{key...}` prefix.

### Get Object
```http
GET /s3/{bucket}/{key}
```

### Put Object
```http
PUT /s3/{bucket}/{key}
Content-Type: application/octet-stream
```

### Delete Object
```http
DELETE /s3/{bucket}/{key}
```

### List Bucket
```http
GET /s3/{bucket}?prefix=path/&delimiter=/
```
```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/s3/my-bucket/files/document.pdf \
     -o document.pdf
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

### cURL
```bash
TOKEN="your_access_token"

# List buckets
curl -H "Authorization: Bearer $TOKEN" http://localhost/s3/my-bucket

# Upload file
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  --data-binary @file.txt http://localhost/s3/my-bucket/file.txt

# Download file
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost/s3/my-bucket/file.txt -o file.txt
```

### Python
```python
import requests

headers = {"Authorization": f"Bearer {token}"}
base_url = "http://localhost"

# List objects
r = requests.get(f"{base_url}/s3/bucket", headers=headers)
print(r.json())

# Upload
with open("file.txt", "rb") as f:
    requests.put(f"{base_url}/s3/bucket/file.txt", headers=headers, data=f)
```