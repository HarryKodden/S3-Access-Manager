# Secure Configuration Guide

This guide explains how to configure the S3 Gateway securely using environment variables for sensitive credentials.

## Overview

The S3 Gateway uses a **two-tier configuration approach**:

1. **config.yaml** - Non-sensitive settings (server, logging, policies)
2. **Environment Variables** - Sensitive credentials (passwords, API keys, secrets)

Environment variables **always take precedence** over values in config.yaml, allowing you to keep sensitive data out of configuration files.

## Quick Start

### 1. Create Your Configuration Files

```bash
# Copy the example files
cp config.example.yaml config.yaml
cp .env.example .env
```

### 2. Edit config.yaml (Non-Sensitive Settings)

Keep non-sensitive configuration in `config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 9000
  read_timeout: 30s
  write_timeout: 30s

policies:
  directory: "./policies"
  default_deny: true
  cache_enabled: true

logging:
  level: "info"
  format: "json"
```

### 3. Edit .env (Sensitive Credentials)

Add your sensitive credentials to `.env`:

```bash
# OIDC Authentication
OIDC_ISSUER=https://your-oidc-provider.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-actual-secret-here

# S3 Backend
S3_ENDPOINT=https://s3.amazonaws.com
S3_REGION=us-east-1
S3_ACCESS_KEY=your-aws-access-key
S3_SECRET_KEY=your-aws-secret-key
```

### 4. Secure Your .env File

```bash
# Restrict file permissions (Linux/Mac)
chmod 600 .env

# Ensure .env is in .gitignore
grep ".env" .gitignore
```

## Environment Variables Reference

### OIDC Authentication

| Variable | Description | Required |
|----------|-------------|----------|
| `OIDC_ISSUER` | OIDC provider URL | Yes |
| `OIDC_CLIENT_ID` | OAuth client ID | Yes |
| `OIDC_CLIENT_SECRET` | OAuth client secret | Yes |
| `OIDC_SCOPES` | OIDC scopes to request | No (default: "openid profile email eduPersonEntitlement") |
| `OIDC_ROLES_CLAIM` | JWT claim for roles | No (default: "groups") |
| `OIDC_USER_CLAIM` | JWT claim for user ID | No (default: "sub") |
| `OIDC_EMAIL_CLAIM` | JWT claim for email | No (default: "email") |
| `OIDC_SESSION_CACHE_TTL` | Session cache TTL | No (default: "15m") |

### S3 Backend

| Variable | Description | Required | Alternative |
|----------|-------------|----------|-------------|
| `S3_ENDPOINT` | S3 API endpoint | No | - |
| `S3_REGION` | AWS region | Yes | `AWS_REGION` |
| `S3_FORCE_PATH_STYLE` | Force path-style URLs | No | - |

### SCIM Integration

| Variable | Description | Required |
|----------|-------------|----------|
| `SCIM_API_KEY` | API key for SCIM server authentication | No |

### SRAM Integration

| Variable | Description | Required |
|----------|-------------|----------|
| `SRAM_API_URL` | SRAM API base URL | No |
| `SRAM_API_KEY` | SRAM API key for authentication | No |
| `SRAM_ENABLED` | Enable/disable SRAM integration | No (default: false) |

### Global Configuration

| Variable | Description | Required |
|----------|-------------|----------|
| `GLOBAL_ADMINS` | Comma-separated list of global admin email addresses | No |

## Deployment Scenarios

### Development (Local)

Use `.env` file for local development:

```bash
# Create .env with your credentials
cp .env.example .env
vim .env

# Run the gateway (automatically loads .env)
./s3-gateway
```

### Production (Docker)

Pass environment variables via Docker:

```bash
docker run -d \
  -e OIDC_ISSUER=https://auth.example.com \
  -e OIDC_CLIENT_ID=my-client \
  -e OIDC_CLIENT_SECRET=my-secret \
  -e S3_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE \
  -e S3_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  -e S3_REGION=us-east-1 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -p 9000:9000 \
  s3-gateway:latest
```

Or use Docker Compose with an environment file:

```yaml
# docker-compose.yml
services:
  s3-gateway:
    image: s3-gateway:latest
    env_file:
      - .env.production
    volumes:
      - ./config.yaml:/app/config.yaml
    ports:
      - "9000:9000"
```

### Production (Kubernetes)

Use Kubernetes Secrets:

```bash
# Create secret from .env file
kubectl create secret generic s3-gateway-secrets --from-env-file=.env

# Or create secret from literal values
kubectl create secret generic s3-gateway-secrets \
  --from-literal=OIDC_CLIENT_SECRET=your-secret \
  --from-literal=S3_SECRET_KEY=your-aws-secret
```

Then reference in your deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: s3-gateway
spec:
  template:
    spec:
      containers:
      - name: s3-gateway
        image: s3-gateway:latest
        envFrom:
        - secretRef:
            name: s3-gateway-secrets
        - configMapRef:
            name: s3-gateway-config
```

### Production (Systemd Service)

Use systemd environment files:

```bash
# /etc/s3-gateway/.env (secure location)
OIDC_CLIENT_SECRET=your-secret
S3_SECRET_KEY=your-aws-secret
```

```ini
# /etc/systemd/system/s3-gateway.service
[Service]
EnvironmentFile=/etc/s3-gateway/.env
ExecStart=/usr/local/bin/s3-gateway
```

### Cloud Platforms

#### AWS ECS/Fargate
Use AWS Secrets Manager or Parameter Store:

```json
{
  "secrets": [
    {
      "name": "OIDC_CLIENT_SECRET",
      "valueFrom": "arn:aws:secretsmanager:region:account:secret:s3-gateway/oidc"
    },
    {
      "name": "S3_SECRET_KEY",
      "valueFrom": "arn:aws:secretsmanager:region:account:secret:s3-gateway/s3"
    }
  ]
}
```

#### Azure Container Instances
Use Azure Key Vault:

```bash
az container create \
  --name s3-gateway \
  --image s3-gateway:latest \
  --secrets-volume-mount-path /secrets \
  --secrets oidc-secret=keyvault-secret-uri
```

#### Google Cloud Run
Use Secret Manager:

```bash
gcloud run deploy s3-gateway \
  --image gcr.io/project/s3-gateway \
  --set-secrets OIDC_CLIENT_SECRET=oidc-secret:latest \
  --set-secrets S3_SECRET_KEY=s3-secret:latest
```

## Security Best Practices

### 1. Never Commit Secrets
```bash
# Ensure these patterns are in .gitignore
*.env
.env*
config.yaml  # if it contains secrets
```

### 2. Use Least Privilege
- Create dedicated IAM users/roles with minimal permissions
- Use separate credentials for development and production
- Rotate credentials regularly

### 3. Secure File Permissions
```bash
# Restrict access to credential files
chmod 600 .env
chmod 600 config.yaml
chown app-user:app-group .env
```

### 4. Use Secrets Management
For production, use dedicated secrets management:
- **AWS**: Secrets Manager, Parameter Store
- **Azure**: Key Vault
- **GCP**: Secret Manager
- **HashiCorp**: Vault
- **Kubernetes**: Sealed Secrets, External Secrets Operator

### 5. Audit and Monitor
- Enable audit logging in config.yaml
- Monitor access to secrets
- Set up alerts for unauthorized access

## Troubleshooting

### Environment Variables Not Loading

Check that:
1. `.env` file exists in the working directory
2. Variable names are correct (case-sensitive)
3. No quotes around values unless needed
4. File has proper line endings (LF, not CRLF)

```bash
# Verify .env file
cat .env

# Test if variables are loaded
env | grep S3_
env | grep OIDC_
```

### Configuration Precedence Issues

Remember the order of precedence:
1. **Environment variables** (highest priority)
2. **config.yaml** values
3. **Default values** (lowest priority)

To debug:
```bash
# Check what values are being used
./s3-gateway --config config.yaml --verbose
```

### Permission Denied Errors

```bash
# Fix .env file permissions
chmod 600 .env

# Verify ownership
ls -la .env
```

## Migration from Plain Text Config

If you currently have credentials in config.yaml:

1. **Backup** your current config:
   ```bash
   cp config.yaml config.yaml.backup
   ```

2. **Extract** sensitive values to .env:
   ```bash
   # Create .env with your actual credentials
   cat > .env << EOF
   OIDC_CLIENT_SECRET=$(yq '.oidc.client_secret' config.yaml)
   S3_ACCESS_KEY=$(yq '.s3.access_key' config.yaml)
   S3_SECRET_KEY=$(yq '.s3.secret_key' config.yaml)
   EOF
   ```

3. **Remove** sensitive values from config.yaml:
   ```bash
   yq -i '.oidc.client_secret = ""' config.yaml
   yq -i '.s3.access_key = ""' config.yaml
   yq -i '.s3.secret_key = ""' config.yaml
   ```

4. **Test** the configuration:
   ```bash
   ./s3-gateway --config config.yaml
   ```

5. **Secure** the .env file:
   ```bash
   chmod 600 .env
   ```

## Additional Resources

- [12-Factor App Configuration](https://12factor.net/config)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [AWS Secrets Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
