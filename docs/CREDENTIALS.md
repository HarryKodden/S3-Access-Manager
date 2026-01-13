# Credentials Management

The S3 Gateway provides a credential management system that allows authenticated users to create and manage their own S3 access credentials. These credentials can be used with standard S3 clients (AWS CLI, SDKs, etc.) to access S3 buckets through the gateway.

## Features

- **Self-Service**: Users can create and manage their own credentials
- **Policy Inheritance**: Credentials can only have policies that the user already possesses
- **Secure Generation**: AWS-style access keys and secret keys
- **Access Control**: Users can only manage their own credentials
- **Audit Trail**: Creation and last-used timestamps
- **Multiple Credentials**: Create different credentials for different applications

## API Endpoints

All endpoints require OIDC authentication via Bearer token.

### List Credentials

```http
GET /settings/credentials
Authorization: Bearer <your-jwt-token>
```

Response:
```json
{
  "credentials": [
    {
      "id": "cred_abc123",
      "name": "My Application",
      "access_key": "AKIA1234567890ABCDEF",
      "policies": ["developer", "read-only"],
      "created_at": "2026-01-08T10:00:00Z",
      "last_used_at": "2026-01-08T11:30:00Z",
      "description": "Credentials for my app"
    }
  ],
  "count": 1
}
```

### Create Credential

```http
POST /settings/credentials
Authorization: Bearer <your-jwt-token>
Content-Type: application/json

{
  "name": "My Application",
  "description": "Credentials for production deployment",
  "policies": ["developer"]
}
```

**Important**: The `policies` array can only contain policy names that are already assigned to your user via OIDC claims. The gateway will validate this and reject any policies you don't have access to.

Response:
```json
{
  "credential": {
    "id": "cred_xyz789",
    "name": "My Application",
    "access_key": "AKIA1234567890ABCDEF",
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "policies": ["developer"],
    "created_at": "2026-01-08T12:00:00Z",
    "description": "Credentials for production deployment"
  },
  "message": "Credential created successfully. Save the secret key securely - it will not be shown again."
}
```

⚠️ **Warning**: The `secret_key` is only returned once during creation. Save it securely!

### Get Credential

```http
GET /settings/credentials/:id
Authorization: Bearer <your-jwt-token>
```

Response:
```json
{
  "credential": {
    "id": "cred_xyz789",
    "name": "My Application",
    "access_key": "AKIA1234567890ABCDEF",
    "policies": ["developer"],
    "created_at": "2026-01-08T12:00:00Z",
    "last_used_at": "2026-01-08T13:00:00Z",
    "description": "Credentials for production deployment"
  }
}
```

Note: The secret key is never returned in GET requests.

### Delete Credential

```http
DELETE /settings/credentials/:id
Authorization: Bearer <your-jwt-token>
```

Response:
```json
{
  "message": "Credential deleted successfully"
}
```

## Usage Examples

### Creating a Credential with cURL

```bash
# Get your JWT token from your OIDC provider first
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Create a new credential
curl -X POST http://localhost/settings/credentials \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production App",
    "description": "Credentials for prod deployment",
    "policies": ["developer", "read-only"]
  }'
```

### Using Generated Credentials with AWS CLI

Once you've created credentials, you can use them with the AWS CLI:

```bash
# Configure AWS CLI
aws configure --profile s3-gateway
# Enter the access key and secret key from the creation response
# Set region to match your S3 backend region
# Set output format (json/text/table)

# Use with AWS CLI
aws s3 ls s3://my-bucket/ \
  --profile s3-gateway \
  --endpoint-url http://localhost

aws s3 cp myfile.txt s3://my-bucket/path/to/file.txt \
  --profile s3-gateway \
  --endpoint-url http://localhost
```

### Using Generated Credentials with Python boto3

```python
import boto3

# Create S3 client with your credentials
s3 = boto3.client(
    's3',
    endpoint_url='http://localhost',
    aws_access_key_id='AKIA1234567890ABCDEF',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region_name='us-east-1'
)

# List objects
response = s3.list_objects_v2(Bucket='my-bucket')
for obj in response.get('Contents', []):
    print(obj['Key'])

# Upload file
s3.upload_file('local-file.txt', 'my-bucket', 'remote-file.txt')
```

### Using Generated Credentials with Node.js

```javascript
const AWS = require('aws-sdk');

const s3 = new AWS.S3({
  endpoint: 'http://localhost',
  accessKeyId: 'AKIA1234567890ABCDEF',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  region: 'us-east-1',
  s3ForcePathStyle: true
});

// List objects
s3.listObjectsV2({ Bucket: 'my-bucket' }, (err, data) => {
  if (err) console.error(err);
  else console.log(data.Contents);
});

// Upload file
const fs = require('fs');
const fileStream = fs.createReadStream('file.txt');

s3.upload({
  Bucket: 'my-bucket',
  Key: 'file.txt',
  Body: fileStream
}, (err, data) => {
  if (err) console.error(err);
  else console.log('Uploaded:', data.Location);
});
```

## Policy Restrictions

The credentials you create can only have policies that are assigned to you via your OIDC claims. For example:

- If your OIDC token has `Roles: ["developer", "read-only"]`
- You can create credentials with `["developer"]`, `["read-only"]`, or `["developer", "read-only"]`
- You CANNOT create credentials with `["admin"]` or any other role you don't have

This ensures that generated credentials can never have more permissions than the user who created them.

## Security Best Practices

1. **Rotate Credentials Regularly**: Delete old credentials and create new ones periodically
2. **Use Least Privilege**: Only assign the minimum policies needed for each credential
3. **Separate Credentials per Application**: Create different credentials for different apps
4. **Monitor Usage**: Check the `last_used_at` timestamp to identify unused credentials
5. **Revoke Immediately**: Delete credentials as soon as they're no longer needed
6. **Secure Storage**: Store secret keys in secure vaults (e.g., HashiCorp Vault, AWS Secrets Manager)

## Credential Format

The gateway generates AWS-compatible credentials:

- **Access Key**: Format `AKIA` + 16 random characters (20 chars total)
- **Secret Key**: 40-character base64-encoded random string
- **Credential ID**: Format `cred_` + unique identifier

These credentials are compatible with standard AWS S3 SDKs and tools.

## Troubleshooting

### "Invalid policy" error when creating credentials

This means you're trying to assign a policy that's not in your OIDC roles. Check your JWT token to see which roles you have:

```bash
# Decode your JWT to see roles (use jwt.io or jq)
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .Roles
```

### Credentials not working with S3 client

Make sure you're:
1. Using the correct endpoint URL (your gateway's URL)
2. Using the exact access key and secret key from creation
3. Setting `s3ForcePathStyle: true` if using a custom endpoint
4. The policies attached to your credentials allow the operation you're trying

### "Credential not found" when deleting

You can only delete your own credentials. Make sure:
1. The credential ID is correct
2. You're authenticated as the user who created the credential
3. The credential wasn't already deleted
