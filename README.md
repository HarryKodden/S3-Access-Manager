
# 🔐 S3 Access Manager

[![Build Status](https://github.com/HarryKodden/S3-Gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/HarryKodden/S3-Gateway/actions) [![Go Report Card](https://goreportcard.com/badge/github.com/HarryKodden/S3-Gateway)](https://goreportcard.com/report/github.com/HarryKodden/S3-Gateway) [![License](https://img.shields.io/github/license/HarryKodden/S3-Gateway)](LICENSE) [![GitHub release](https://img.shields.io/github/v/release/HarryKodden/S3-Gateway)](https://github.com/HarryKodden/S3-Gateway/releases) [![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/HarryKodden/S3-Gateway/pkgs/container/s3-gateway)

**A secure, policy-based S3 gateway that provides OIDC-authenticated access to S3 backends with credential delegation and a modern web-based management interface.**

[Features](#features) • [Quick Start](#quick-start) • [Documentation](docs/README.md) • [Contributing](CONTRIBUTING.md)

---

## Features

- 🔐 **OIDC Authentication**: Authenticate users via OpenID Connect providers
- 🔄 **Session Caching**: Configurable session timeout to reduce OIDC provider load
- 🌐 **Web Management UI**: Modern, user-friendly interface for all operations
- 🎯 **Role-Based Access Control**: Map OIDC claims to S3 policies with admin/user roles
- 🛡️ **Policy-Based Permissions**: Fine-grained access control with custom policies
- 🔑 **Self-Service Credentials**: Users create S3 access keys with delegated policies
- 🔒 **Secure Secret Management**: Secrets stored server-side, viewable with toggle
- 📊 **Dual Policy Sources**: Built-in policies + user-created policies
- 🔄 **Admin Mode Toggle**: Test regular user experience from admin account
- 🌐 **S3 Browser**: Visual file management with upload/download/inspect
- ✍️ **Request Signing**: Automatic AWS Signature V4 signing
- 📈 **Prometheus Metrics**: Built-in /metrics endpoint for monitoring
- 🐳 **Docker Ready**: Complete containerization with Docker Compose
- 🏥 **Health Checks**: Kubernetes and load balancer ready
- 📝 **Audit Trail**: Complete logging of user actions and decisions
- 🔄 **Credential Synchronization**: Automatic credential updates when policies/roles change
- 🏗️ **Multi-Backend Support**: MinIO, AWS S3, and CEPH RadosGW integration
- 🧪 **Comprehensive Testing**: Automated integration tests with OIDC simulation

### Supported OIDC Providers

- ✅ Auth0
- ✅ Okta
- ✅ Azure Active Directory
- ✅ Keycloak
- ✅ Google Identity Platform
- ✅ Any OIDC-compliant provider

### Supported S3 Operations

- ✅ GET (download objects)
- ✅ PUT (upload objects)
- ✅ DELETE (remove objects)
- ✅ HEAD (get metadata)
- ✅ LIST (list bucket contents)
- ✅ Query parameters (prefix, delimiter)
- 🚧 POST (multipart uploads - planned)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Application                      │
│                    (Browser, API, Mobile App)                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           │ HTTP Request
                           │ Authorization: Bearer <access_token>
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Private Route / VPC                        │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              S3 Access Manager (Go) - Port 80              │ │
│  │                                                            │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Middleware Stack                                     │  │ │
│  │  │  • Rate Limiting (10 req/s per IP, burst 20)         │  │ │
│  │  │  • Security Headers (X-Frame, CSP, etc.)             │  │ │
│  │  │  • Request Logging                                   │  │ │
│  │  │  • Error Recovery                                    │  │ │
│  │  │  • CORS                                              │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │                            │                               │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Static Frontend Serving (/*)                         │  │ │
│  │  │  • Web Management UI                                 │  │ │
│  │  │  • S3 Browser                                        │  │ │
│  │  │  • Credential Management                             │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │                            │                               │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ 1. OIDC Authentication (/settings/*, /s3/*)          │  │ │
│  │  │    • Verify access token                             │  │ │
│  │  │    • Extract user identity & roles                   │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │                            │                               │ │
│  │                            ▼                               │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ 2. Policy Engine                                     │  │ │
│  │  │    • Load policies for user roles                    │  │ │
│  │  │    • Evaluate S3 action permissions                  │  │ │
│  │  │    • Apply bucket & path restrictions                │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │                            │                               │ │
│  │                            ▼                               │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ 3. S3 Proxy Handler                                  │  │ │
│  │  │    • Sign requests with S3 credentials               │  │ │
│  │  │    • Forward to S3 backend                           │  │ │
│  │  │    • Stream response back to client                  │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │                            │                               │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ 4. Audit Logging & Metrics                           │  │ │
│  │  │    • Log all S3 operations                           │  │ │
│  │  │    • Track user actions                              │  │ │
│  │  │    • Export metrics (/metrics endpoint)              │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │                            │                               │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ 5. Backend Synchronization                           │  │ │
│  │  │    • Sync credentials with MinIO/AWS/CEPH            │  │ │
│  │  │    • Update policies when roles change               │  │ │
│  │  │    • Handle legacy credential migration              │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └────────────────────────┬───────────────────────────────────┘ │
└───────────────────────────┼─────────────────────────────────────┘
                            │
                            │ AWS Signature V4
                            │ Signed S3 API Request
                            │
                            ▼
         ┌──────────────────────────────────────────┐
         │      S3 Backend (AWS S3 / MinIO)         │
         │  • Object Storage                        │
         │  • Can be public or private              │
         │  • Accessed via gateway credentials      │
         └──────────────────────────────────────────┘
```

### Key Components

1. **OIDC Authentication**: Validates access tokens from your identity provider
2. **Policy Engine**: Enforces fine-grained access control based on user roles
3. **Credential Synchronization**: Automatically updates credentials when policies/roles change
4. **Backend Integration**: Manages users and policies in MinIO, AWS S3, or CEPH
5. **S3 Proxy**: Transparently forwards requests to S3 with re-signing
6. **Audit Logging**: Comprehensive logging of all operations
7. **Metrics**: Prometheus metrics for monitoring and alerting

## Quick Start

### Prerequisites

- Docker and Docker Compose
- OIDC provider (Auth0, Okta, Azure AD, Keycloak, etc.)
- S3 bucket credentials

### Manual Configuration

> **🔒 Security Best Practice:** Use environment variables for sensitive credentials instead of storing them in config files. See [Secure Configuration Guide](docs/SECURE_CONFIG.md) for details.

1. Copy the example configuration files:
```bash
cp config.example.yaml config.yaml
cp .env.example .env
```

2. Edit `config.yaml` for **non-sensitive settings** only:
```yaml
server:
  host: "0.0.0.0"
  port: 8080

policies:
  directory: "./policies"
  default_deny: true

logging:
  level: "info"
  format: "json"
```

3. Edit `.env` for **sensitive credentials** (recommended):
```bash
# OIDC Authentication
OIDC_ISSUER=https://your-oidc-provider.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret

# S3 Backend
S3_ENDPOINT=https://s3.amazonaws.com
S3_REGION=us-east-1
S3_ACCESS_KEY=your-access-key
S3_SECRET_KEY=your-secret-key
```

Secure the `.env` file:
```bash
chmod 600 .env
```

> **Note:** Environment variables take precedence over `config.yaml` values. The `.env` file is automatically loaded and should **never** be committed to version control.

4. Define your policies in `policies/`:
```bash
mkdir -p policies
```

### Running

```bash
docker compose up -d --build
```

The gateway will be available at `http://localhost`

Access the Web Management UI:
- Open browser to `http://localhost/`
- Login with your OIDC credentials
- Manage credentials and browse S3 buckets

API endpoints:
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `POST /settings/credentials` - Create credentials
- `GET /settings/credentials` - List credentials
- `GET /s3/*` - S3 proxy endpoints

## Deployment

### Using Pre-built Docker Images

Pull the latest release from GitHub Container Registry:

```bash
docker pull ghcr.io/harrykodden/s3-gateway:latest
```

Update your `docker-compose.yml`:

```yaml
services:
  s3-gateway:
    image: ghcr.io/harrykodden/s3-gateway:v1.0.0  # or :latest
    # ... rest of your configuration
```

Available tags:
- `latest` - Latest stable release
- `v1.0.0` - Specific version
- `v1.0` - Latest patch in v1.0.x
- `v1` - Latest minor in v1.x.x

### Building from Source

```bash
# Clone repository
git clone https://github.com/HarryKodden/S3-Gateway.git
cd S3-Gateway

# Build binary
make build

# Run
./s3-gateway -config config.yaml

# Show version
./s3-gateway -version
```

### CI/CD

This project uses GitHub Actions for continuous integration and delivery:

- **Automated Testing**: All commits are tested
- **Multi-arch Docker Images**: Built for amd64 and arm64
- **Automatic Releases**: Tagged commits create GitHub releases
- **Container Registry**: Images pushed to `ghcr.io`
- **Security Scanning**: Trivy vulnerability scans

See [RELEASE.md](RELEASE.md) for detailed release process.

## Backend Support

The S3 Access Manager supports multiple S3-compatible backends:

### Supported Backends

- ✅ **MinIO**: Full-featured S3-compatible object storage
- ✅ **AWS S3**: Amazon Web Services S3 service
- ✅ **CEPH RadosGW**: CEPH object storage gateway

### Configuration

Configure your backend in `config.yaml`:

```yaml
s3:
  backend: "minio"  # Options: minio, aws, ceph
  endpoint: "http://minio:9000"
  region: "us-east-1"
  access_key: "${S3_ACCESS_KEY}"
  secret_key: "${S3_SECRET_KEY}"
```

### Backend-Specific Features

- **MinIO**: Automatic user and policy management
- **AWS S3**: IAM integration and cross-account access
- **CEPH**: RadosGW user and bucket management

## Testing

The project includes comprehensive integration tests:

### Running Tests

```bash
# Install test dependencies
pip install -r test/test_requirements.txt

# Start services
docker compose up -d

# Run integration tests
python test/test_lifecycle.py
```

### Test Coverage

The test suite validates:
- OIDC authentication flow
- Policy and role management
- Credential creation and synchronization
- S3 access verification
- Backend integration
- Automatic credential updates

See [test/TEST_README.md](test/TEST_README.md) for detailed testing documentation.

## Policy Configuration

Policies control access to S3 resources and are managed through two sources:

### Policy Sources

1. **Built-in Policies** (`/policies` directory)
   - Pre-defined policies deployed with the gateway
   - Examples: `admin.json`
   - Loaded at startup from the filesystem

2. **User-Created Policies** (`./data/policies/` directory)
   - Created through the web UI by admin users
   - Dynamically managed and persisted
   - Examples: custom policies for specific teams or projects

### Admin User Enhancements

Admin users (configured via `admin_username` in config) automatically receive:
- All policies from the policy engine (`/policies` directory)
- All policies from the policy store (`./data/policies/`)
- Ability to create, edit, and delete policies via web UI
- Admin mode toggle to simulate regular user experience

Regular users only see and can use policies assigned to their OIDC roles.

### Policy Format

Policies are defined as JSON files using AWS IAM policy syntax:

Example policy (`policies/developer.json`):
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

1. Client requests a resource with Bearer token
2. Gateway validates token with OIDC provider
3. Gateway extracts roles from configured claim
4. Gateway evaluates applicable policies
5. If authorized, gateway proxies request to S3

### Accessing S3 Resources

```bash
# Direct S3 access via gateway
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost/my-bucket/dev/file.txt
```

### Managing Credentials

Users can create their own S3-compatible access keys for use with standard S3 clients. Credentials can be managed via the API or the web frontend.

#### Via Web Frontend (Recommended)
1. Log in to the web interface at `http://localhost/`
2. Navigate to the Credentials tab
3. Click "Create Credential"
4. Enter a name, optional description, and select policies to delegate
5. Copy the displayed access key and secret key (shown only once on creation)
6. Use the "Copy AWS Config" button to get a ready-to-use AWS CLI configuration
7. Inspect credentials later to view secret keys (with toggle visibility)

#### Via API

```bash
# List your credentials
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost/settings/credentials

# Create new credential (specify policies to delegate)
curl -X POST http://localhost/settings/credentials \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application",
    "description": "Credentials for production app",
    "policies": ["developer", "read-only"]
  }'

# Get credential details (includes secret key)
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost/settings/credentials/AKIAIOSFODNN7EXAMPLE

# Delete credential
curl -X DELETE http://localhost/settings/credentials/AKIAIOSFODNN7EXAMPLE \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Important Security Notes:**
- Generated credentials inherit only the policies you specify
- Selected policies must be a subset of your OIDC roles
- Credentials never have more permissions than the user who created them
- Secret keys are stored server-side in `data/credentials.json`
- Secret keys are retrievable via API or web UI with proper authentication
- Admin users automatically have access to all policies from both policy sources

### Using Generated Credentials with AWS CLI

Once you've created credentials through `/settings/credentials`, you can use them with any S3-compatible client:

```bash
# Configure AWS CLI with your generated credentials
aws configure --profile s3-gateway
# Enter: access_key, secret_key, region, output format

# Use with S3 commands
aws s3 ls s3://my-bucket/ \
  --profile s3-gateway \
  --endpoint-url http://localhost

aws s3 cp file.txt s3://my-bucket/path/ \
  --profile s3-gateway \
  --endpoint-url http://localhost
```

See [docs/CREDENTIALS.md](docs/CREDENTIALS.md) for detailed credential management documentation.

### Credential Synchronization

The gateway automatically synchronizes credentials when policies or roles change:

#### Automatic Updates
- **Policy Changes**: When policies are modified, all affected credentials are automatically updated
- **Role Changes**: When roles are modified or deleted, credentials are cleaned up and updated
- **Backend Integration**: Credentials are synchronized with MinIO, AWS S3, or CEPH backends
- **Legacy Support**: Handles credentials created before backend configuration

#### Admin Update All
Administrators can trigger a full credential synchronization:

```bash
# Update all credentials via API
curl -X POST http://localhost/settings/credentials/update-all \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Response:**
```json
{
  "message": "Credential update completed",
  "total_count": 25,
  "updated_count": 18,
  "roles_updated_count": 3,
  "errors": []
}
```

This ensures that all user credentials remain synchronized with the latest policy definitions and role assignments.

## Web Frontend

The S3 Access Manager includes a modern, feature-rich web interface for managing credentials, policies, buckets, and S3 operations.

### Accessing the Frontend

Once deployed with Docker Compose, the frontend is available at:

```
http://localhost/
```

### Key Features

#### Authentication & User Management
- **OIDC Login**: Secure authentication via OpenID Connect
- **Admin/Regular User Roles**: Automatic role detection from OIDC claims
- **Admin Mode Toggle**: Admins can simulate regular user view for testing

#### Credential Management
- **Self-Service Creation**: Users create their own S3 access keys
- **Policy Delegation**: Select which policies to assign (from your available roles)
- **Secret Key Security**: 
  - Secrets stored server-side in `data/credentials.json`
  - Hidden by default with toggle visibility (eye icon)
  - Full access to secrets for credential inspection
- **AWS Config Export**: One-click copy of AWS CLI configuration with real credentials
- **Credential Details**: View access key, secret key, policies, creation date

#### Policy Management
- **View Policies**: All users can view and inspect available policies
- **Admin Controls**: Only admins can create, edit, or delete policies
- **Dual Policy Sources**:
  - Built-in policies from `/policies` directory
  - User-created policies stored in `./data/policies/`
- **Admin Enhancement**: Admins automatically get all policies from both sources

#### Bucket & Object Management
- **Visual S3 Browser**: Browse buckets and navigate folders
- **File Upload**: Drag-and-drop or select files to upload
- **Object Listing**: View files with size and modification date
- **File Download**: One-click download of S3 objects
- **Bucket Creation**: Create new S3 buckets
- **Real-time Updates**: Bucket contents refresh after uploads

#### User Experience
- **Dashboard View**: Quick access to credentials, buckets, and policies
- **Real-time Status**: Monitor gateway connectivity and health
- **Toast Notifications**: Clear feedback for all operations
- **Responsive Design**: Works on desktop and mobile devices

### Screenshots & Workflow

1. **Login**: Authenticate via OIDC provider
2. **Credentials**: Create access keys, copy AWS config with real secrets
3. **Buckets**: Browse, upload, download files visually
4. **Policies**: View available policies (admin: create/edit/delete)
5. **Admin Toggle**: Switch between admin and regular user view

For detailed frontend documentation, see [Frontend Guide](docs/FRONTEND.md).

## Development

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o s3-gateway ./cmd/gateway

# Run locally
./s3-gateway -config config.yaml
```

### Integration Testing

The project includes comprehensive integration tests that validate the full authentication and authorization flow:

#### Local Testing
```bash
# Install test dependencies
pip install -r test/test_requirements.txt

# Start services with test OIDC provider
docker compose up -d

# Run integration tests
python test/test_lifecycle.py
```

#### Containerized Testing
For consistent testing environments, run tests in Docker containers:

```bash
# Run lifecycle integration tests (requires running services)
docker compose run --rm test-lifecycle

# Or run with full test profile (includes all services)
docker compose --profile test up --abort-on-container-exit

# View test logs
docker compose logs test-lifecycle
```

The test container includes:
- All Python dependencies pre-installed
- Test scripts mounted as read-only volumes
- Automatic service dependency checking
- Clean execution without affecting host environment

The test suite validates:
- OIDC authentication simulation
- Policy and role management
- Credential creation and synchronization
- S3 access verification
- Backend integration
- Automatic credential updates when policies/roles change

### Frontend Development

```bash
# Frontend is in the frontend/ directory
cd frontend

# Serve locally for development
python3 -m http.server 8081
# or
npx http-server -p 8081
```

## License

MIT

