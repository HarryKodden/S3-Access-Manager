# 🔐 S3 Access Manager

[![Build Status](https://github.com/HarryKodden/S3-Access-Manager/actions/workflows/ci.yml/badge.svg)](https://github.com/HarryKodden/S3-Access-Manager/actions) [![Go Report Card](https://goreportcard.com/badge/github.com/HarryKodden/S3-Access-Manager)](https://goreportcard.com/report/github.com/HarryKodden/S3-Access-Manager) [![License](https://img.shields.io/github/license/HarryKodden/S3-Access-Manager)](LICENSE) [![GitHub release](https://img.shields.io/github/v/release/HarryKodden/S3-Access-Manager)](https://github.com/HarryKodden/S3-Access-Manager/releases) [![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/HarryKodden/S3-Access-Manager/pkgs/container/s3-gateway)

**Secure, policy-based S3 gateway with OIDC authentication, credential delegation, and web management UI.**

[Features](#features) • [Quick Start](#quick-start) • [Documentation](docs/README.md) • [Contributing](CONTRIBUTING.md)

## Features

- 🔐 **OIDC Authentication**: Auth0, Okta, Azure AD, Keycloak, Google Identity
- 🌐 **Web Management UI**: Modern interface for credential/bucket/policy management
- 🎯 **Role-Based Access Control**: Map OIDC claims to S3 policies
- 🔑 **Self-Service Credentials**: Users create S3 access keys with delegated policies
- 🛡️ **Policy-Based Permissions**: Fine-grained access control with custom policies
- 📊 **Dual Policy Sources**: Built-in + user-created policies
- 🌐 **S3 Browser**: Visual file management with upload/download
- 📈 **Prometheus Metrics**: Built-in monitoring endpoint
- 🐳 **Docker Ready**: Complete containerization
- 🏗️ **AWS CLI Backend**: AWS S3 integration with CLI-based operations
- 🧪 **Integration Tests**: Automated testing with OIDC simulation

## Architecture

```
Client → OIDC Auth → Policy Engine → S3 Proxy → S3 Backend
```

Key components:
- **OIDC Authentication**: Validates tokens, extracts user identity & roles
- **Policy Engine**: Enforces access control based on user roles
- **Credential Delegation**: Users create S3 keys with subset of their permissions
- **S3 Proxy**: Signs and forwards requests to S3 backends
- **AWS CLI Backend**: Manages users/policies via AWS CLI commands

## Quick Start

### Prerequisites
- Docker & Docker Compose
- OIDC provider (Auth0, Okta, Azure AD, Keycloak, etc.)
- S3 backend (MinIO, AWS S3, CEPH)

### Setup

1. **Clone and configure:**
```bash
git clone https://github.com/HarryKodden/S3-Access-Manager.git
cd S3-Access-Manager
cp config.example.yaml config.yaml
cp .env.example .env
```

2. **Configure environment variables (.env):**
```bash
# OIDC
OIDC_ISSUER=https://your-oidc-provider.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret

# S3 Backend
S3_ENDPOINT=https://s3.amazonaws.com
S3_REGION=us-east-1

# IAM Admin Credentials (for user/policy management)
IAM_ACCESS_KEY=your-admin-access-key
IAM_SECRET_KEY=your-admin-secret-key
```

3. **Configure S3 backend in config.yaml:**
```yaml
s3:
  endpoint: "${S3_ENDPOINT}"
  region: "${S3_REGION}"
  iam:
    access_key: "${IAM_ACCESS_KEY}"
    secret_key: "${IAM_SECRET_KEY}"
```

4. **Define policies in policies/ directory:**
```bash
mkdir -p policies
# Create policy files like admin.json, developer.json
```

### Running

```bash
docker compose up -d --build
```

Access at `http://localhost`:
- Web UI for credential/bucket management
- API endpoints: `/settings/*`, `/s3/*`, `/health`, `/metrics`

## Backend Support

### Supported Backend
- ✅ **AWS CLI**: AWS S3 with CLI-based user and policy management

### Configuration
The gateway uses AWS CLI for backend operations. Configure IAM credentials for admin operations.

## Policy Configuration

Policies use AWS IAM syntax and control S3 access:

### Policy Sources
1. **Built-in Policies** (`policies/`): Pre-defined, deployed with gateway
2. **User-Created Policies** (`data/policies/`): Created via web UI by admins

### Example Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": ["arn:aws:s3:::my-bucket/dev/*"]
    }
  ]
}
```

## Usage

### Authentication Flow
1. Client sends Bearer token
2. Gateway validates with OIDC provider
3. Extracts roles from configured claim
4. Evaluates applicable policies
5. Proxies authorized requests to S3

### Managing Credentials

**Via Web UI (Recommended):**
- Login at `http://localhost`
- Navigate to Credentials tab
- Create credentials with policy delegation
- Copy access keys and AWS CLI config

**Via API:**
```bash
# Create credential
curl -X POST http://localhost/settings/credentials \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "My App", "policies": ["developer"]}'

# List credentials
curl http://localhost/settings/credentials \
  -H "Authorization: Bearer TOKEN"
```

### Using Credentials

```bash
# AWS CLI
aws configure --profile s3-gateway
aws s3 ls s3://my-bucket/ --profile s3-gateway --endpoint-url http://localhost

# Direct API
curl -H "Authorization: Bearer TOKEN" http://localhost/s3/my-bucket/file.txt
```

## Web Frontend

Modern interface at `http://localhost`:

- **Authentication**: OIDC login with admin/regular user roles
- **Credentials**: Self-service creation with policy delegation
- **Buckets**: Visual browser with upload/download
- **Policies**: View (users) or manage (admins)
- **Admin Mode**: Toggle to test regular user experience

## Development

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Build
make build

# Run locally
./s3-gateway -config config.yaml
```

### Integration Testing

```bash
# Start services
docker compose up -d

# Run tests
./demo-flow.sh

```

## License

MIT