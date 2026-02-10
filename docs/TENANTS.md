# Multi-Tenant Configuration

The S3 Access Manager supports multi-tenant deployments where each tenant has completely isolated configuration, data, and credentials. This allows running multiple independent S3 access management environments within a single gateway instance.

## Architecture

### Directory Structure
```
data/
├── tenant-a/
│   ├── config.yaml          # Tenant A configuration
│   ├── credentials.json     # User credentials for tenant A
│   ├── scim/
│   │   ├── Groups/          # SCIM groups for tenant A
│   │   └── Users/           # SCIM users for tenant A
│   ├── policies/            # IAM policies for tenant A
│   └── roles/               # Role mappings for tenant A
├── tenant-b/
│   ├── config.yaml          # Tenant B configuration
│   ├── credentials.json     # User credentials for tenant B
│   └── scim/
│       ├── Groups/          # SCIM groups for tenant B
│       └── Users/           # SCIM users for tenant B
└── shared/                  # Optional shared resources
```

### Configuration Hierarchy

1. **Global Config** (`config.yaml`): Server settings, monitoring, logging
2. **Tenant Config** (`data/<tenant>/config.yaml`): Tenant-specific OIDC, IAM, admins

## Setup

### 1. Global Configuration
Update `config.yaml` to specify the tenant:

```yaml
# Server configuration (global)
server:
  host: "0.0.0.0"
  port: 9000

# Tenant specification
tenant:
  name: "my-tenant"
  # data_dir: "./data/tenants/my-tenant"  # Optional, defaults to ./data/tenants/<name>

# Other global settings...
```

### 2. Create Tenant Directory
```bash
mkdir -p data/tenants/my-tenant
```

### 3. Tenant Configuration
Create `data/tenants/my-tenant/config.yaml`:

```yaml
# Tenant identifier (must match global config)
name: "my-tenant"

# OIDC Configuration (tenant-specific)
oidc:
  issuer: "https://my-oidc-provider.com"
  client_id: "tenant-specific-client"
  client_secret: "tenant-specific-secret"
  scopes: "openid profile email groups"
  groups_claim: "groups"
  user_claim: "preferred_username"
  email_claim: "email"

# Tenant Administrators (email addresses with admin access to this tenant)
tenant_admins:
  - "admin@company.com"
  - "superuser@company.com"

# IAM Credentials (tenant-specific)
iam:
  access_key: "AKIA_TENANT_SPECIFIC_KEY"
  secret_key: "tenant-specific-secret-key"

# SCIM Configuration (tenant-specific)
scim:
  api_key: "tenant-specific-scim-api-key"

# Optional: Custom directory names within tenant
policies_dir: "policies"
roles_dir: "roles"
groups_dir: "scim/Groups"
users_dir: "scim/Users"
```

### 4. Move Data Directories
Move the existing data directories into the tenant folder with the new scim structure:

```bash
# Create scim subdirectory
mkdir -p data/tenants/my-tenant/scim

# Move existing directories
mv data/Groups data/tenants/my-tenant/scim/
mv data/Users data/tenants/my-tenant/scim/
mv data/policies data/tenants/my-tenant/
mv data/roles data/tenants/my-tenant/
```

## SCIM Server Configuration

For multi-tenant deployments, each tenant should have its own SCIM server instance to maintain complete isolation:

### Single SCIM Server (Not Recommended for Multi-Tenant)
For simple single-tenant setups, use the default SCIM service in `docker-compose.yml`.

### Tenant-Specific SCIM Servers (Recommended for Multi-Tenant)
For multi-tenant setups, configure separate SCIM server instances per tenant:

1. **Update docker-compose.yml**:
   ```yaml
   services:
     # Tenant A SCIM Server
     scim-tenant-a:
       image: harrykodden/scim
       expose:
         - "8001"
       network_mode: host
       volumes:
         - ./data/tenants/tenant-a:/app/data
       environment:
         - DATA_PATH=/app/data
         - API_KEY=tenant-a-scim-api-key
       restart: unless-stopped

     # Tenant B SCIM Server  
     scim-tenant-b:
       image: harrykodden/scim
       expose:
         - "8002"
       network_mode: host
       volumes:
         - ./data/tenants/tenant-b:/app/data
       environment:
         - DATA_PATH=/app/data
         - API_KEY=tenant-b-scim-api-key
       restart: unless-stopped
   ```

2. **Update tenant configurations** to point to the correct SCIM server:
   ```yaml
   # data/tenants/tenant-a/config.yaml
   scim:
     api_key: "tenant-a-scim-api-key"
     # Optional: specify SCIM server URL if different from default
     # server_url: "http://localhost:8001"
   ```

### Security Benefits
- **API Key Isolation**: Each tenant has its own SCIM API key
- **Data Separation**: SCIM servers access only tenant-specific data directories
- **Network Isolation**: Separate server instances prevent cross-tenant access

## Migration from Single-Tenant

To migrate an existing single-tenant setup:

1. Create tenant directory: `mkdir data/<tenant-name>`
2. Create scim subdirectory: `mkdir -p data/<tenant-name>/scim`
3. Move existing data: `mv data/Groups data/<tenant-name>/scim/ && mv data/Users data/<tenant-name>/scim/ && mv data/policies data/<tenant-name>/ && mv data/roles data/<tenant-name>/`
4. Create tenant config: `data/<tenant-name>/config.yaml`
5. Update global config to include tenant section
6. Remove tenant-specific settings from `.env` (move to tenant config)

## Environment Variables

Global environment variables (`.env`) should only contain:
- Server settings
- Global S3 endpoint/region
- SCIM API keys

Tenant-specific settings (OIDC, IAM credentials, admins) move to `data/<tenant>/config.yaml`.

## API Behavior

- All APIs remain the same but are accessed via tenant-prefixed URLs
- Data isolation is automatic based on tenant configuration
- Each tenant sees only their own users, groups, policies, and credentials
- Cross-tenant access is prevented by design

## URL Routing

All tenant operations use tenant-prefixed URLs in the format `/tenant/{tenant-name}/...`:

### Authentication & Settings
- **OIDC Config**: `GET /tenant/{tenant}/oidc-config`
- **Credentials**: `GET/POST /tenant/{tenant}/settings/credentials`
- **Policies**: `GET/POST /tenant/{tenant}/settings/policies`
- **Users**: `GET/POST /tenant/{tenant}/settings/users`
- **Groups**: `GET/POST /tenant/{tenant}/settings/groups`

### S3 Operations
- **List Buckets**: `GET /tenant/{tenant}/`
- **Bucket Operations**: `GET/PUT/DELETE /tenant/{tenant}/{bucket}/...`
- **Object Operations**: `GET/PUT/DELETE /tenant/{tenant}/{bucket}/{key}`

### Web Interface
- **Frontend**: `GET /tenant/{tenant}/` (serves the web UI)
- **Static Files**: `GET /tenant/{tenant}/app.js`, `/tenant/{tenant}/styles.css`

### Backward Compatibility
- Root-level S3 operations (`/`, `/{bucket}/...`) remain available for AWS CLI compatibility
- These operations use the configured tenant from `config.yaml`

## Multiple Tenants

To support multiple tenants, you can:
1. Run separate gateway instances with different configs
2. Use a load balancer with tenant-based routing
3. Implement tenant selection in the application layer

## Example

See `data/example-tenant/` for a complete working example with:
- Tenant configuration
- Sample users and groups
- Policies and roles
- Proper directory structure</content>
<parameter name="filePath">/Users/kodde001/Projects/S3-Gateway/docs/TENANTS.md