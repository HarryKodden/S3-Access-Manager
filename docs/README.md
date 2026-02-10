# Documentation

## Quick Links

- **[API Reference](API.md)** - REST API endpoints and usage
- **[Credentials](CREDENTIALS.md)** - Credential management guide
- **[Frontend](FRONTEND.md)** - Web UI guide
- **[OIDC Authentication](OIDC_AUTHENTICATION.md)** - Authentication setup
- **[Policies](POLICIES.md)** - IAM policy configuration
- **[Secure Config](SECURE_CONFIG.md)** - Security best practices
- **[Multi-Tenant Setup](TENANTS.md)** - Multi-tenant configuration guide

## Directory Structure

```
./data/
├── scim/                    # Global SCIM data (shared across all tenants)
│   ├── Users/              # SCIM user provisioning
│   └── Groups/             # SCIM group provisioning
└── tenants/                # Tenant-specific data
    └── {tenant-name}/      # Per-tenant directory
        ├── config.yaml     # Tenant configuration
        ├── policies/       # Tenant-specific policies
        └── roles/          # Tenant-specific roles
```

## Getting Started

1. Start with the [main README](../README.md) for quick setup
2. Configure [OIDC Authentication](OIDC_AUTHENTICATION.md)
3. Set up [Policies](POLICIES.md) for access control
4. Use [Secure Config](SECURE_CONFIG.md) for production deployment

## Additional Resources

- [CHANGELOG](../CHANGELOG.md) - Version history
- [RELEASE](../RELEASE.md) - Release process
- [Makefile](../Makefile) - Build commands
