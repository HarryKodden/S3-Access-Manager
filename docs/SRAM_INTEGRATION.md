# SRAM Integration

The S3 Access Manager integrates with SRAM (SURF Research Access Management) to manage tenant administrator invitations. When a new tenant is created, a corresponding SRAM collaboration is automatically created, and the tenant administrator is invited to join.

## Overview

SRAM integration provides:

1. **Automatic Collaboration Creation**: When a tenant is created, a SRAM collaboration is automatically created with the same name
2. **Automatic Invitation**: The tenant administrator email is automatically invited to the SRAM collaboration
3. **Invitation Status Tracking**: Global administrators can view the status of invitations (pending, accepted, declined)

## Configuration

To enable SRAM integration, add the following configuration to your `config.yaml`:

```yaml
# SRAM Configuration (SURF Research Access Management)
sram:
  # SRAM API base URL
  api_url: "https://sram.surf.nl"
  
  # SRAM API key for authentication
  api_key: "<YOUR_SRAM_API_KEY>"
  
  # Enable/disable SRAM integration
  enabled: true
```

### Configuration Options

- **`api_url`**: The base URL of the SRAM API (default: `https://sram.surf.nl`)
- **`api_key`**: Your SRAM API authentication key (required when SRAM is enabled)
- **`enabled`**: Enable or disable SRAM integration (default: `false`)

## How It Works

### 1. Tenant Creation

When a global administrator creates a new tenant:

1. A new SRAM collaboration is created with:
   - Name: Same as tenant name
   - Short Name: Same as tenant name
   - Description: "S3 Access Manager tenant: {tenant_name}"
   - Initial admins: The tenant administrator email

2. An invitation is sent to the tenant administrator's email address with:
   - Role: `admin`
   - Message: "You have been invited to manage the {tenant_name} tenant in S3 Access Manager."

3. The SRAM collaboration ID is stored in the tenant's configuration:

```yaml
# data/{tenant_name}/config.yaml
tenant_admins:
- "admin@example.com"
sram_collaboration_id: "collab-12345"
iam:
  access_key: "..."
  secret_key: "..."
```

### 2. Invitation Status Tracking

Global administrators can view the status of SRAM invitations for any tenant through the web UI:

1. Navigate to the **Tenants** tab
2. Click the **Inspect** (eye) icon next to a tenant
3. View the **SRAM Invitation Status** section

The status can be:
- **Pending**: Invitation sent but not yet accepted
- **Accepted**: Administrator has accepted the invitation
- **Declined**: Administrator has declined the invitation

### 3. API Endpoints

#### Get SRAM Invitation Status

```http
GET /tenants/{name}/sram-invitations
Authorization: Bearer {access_token}
```

**Response:**
```json
{
  "tenant": "my-tenant",
  "collaboration_id": "collab-12345",
  "invitations": [
    {
      "id": "invite-67890",
      "email": "admin@example.com",
      "status": "accepted"
    }
  ],
  "invitation_count": 1
}
```

## SRAM API Reference

The integration uses the following SRAM API endpoints:

- **Create Collaboration**: `POST /api/v1/collaborations`
- **Send Invitation**: `POST /api/v1/invitations`
- **Get Collaboration Invitations**: `GET /api/v1/collaborations/{id}/invitations`
- **Get Invitation Status**: `GET /api/v1/invitations/{id}`

For more information, see the [SRAM API Documentation](https://sram.surf.nl/apidocs/).

## Error Handling

If SRAM integration is enabled but fails during tenant creation:

- **Collaboration Creation Fails**: The tenant creation is aborted, and an error is returned to the user
- **Invitation Sending Fails**: The tenant is still created, but a warning is logged. The invitation can be resent manually through SRAM

If SRAM is not enabled, tenant creation proceeds without SRAM integration.

## Best Practices

1. **Test Your API Key**: Before enabling SRAM in production, test your API key and ensure it has the necessary permissions
2. **Monitor Invitation Status**: Regularly check invitation statuses to ensure tenant administrators are accepting invitations
3. **Handle Declined Invitations**: If an administrator declines an invitation, you may need to resend it or assign a different administrator

## Troubleshooting

### SRAM Integration Not Working

1. **Check Configuration**: Ensure `sram.enabled` is set to `true` and `sram.api_key` is correctly configured
2. **Verify API Key**: Test your SRAM API key using the SRAM API documentation
3. **Check Network**: Ensure the S3 Gateway can reach the SRAM API endpoint
4. **Review Logs**: Check the application logs for any SRAM-related errors

### Invitation Status Not Showing

1. **Check SRAM Collaboration ID**: Ensure the tenant has a `sram_collaboration_id` in its configuration
2. **Verify API Permissions**: Ensure your API key has permission to read collaboration invitations
3. **Check Response Format**: The SRAM API response format may have changed; review the client code

### Creating Tenants Without SRAM

If you need to create tenants without SRAM integration:

1. Set `sram.enabled: false` in `config.yaml`
2. Restart the S3 Gateway
3. Create tenants as usual

Existing tenants with SRAM collaborations will continue to work, but new tenants will not have SRAM integration.

## Security Considerations

1. **API Key Security**: Store your SRAM API key securely. Use environment variables or secret management systems
2. **HTTPS Only**: Always use HTTPS for the SRAM API URL in production
3. **Rate Limiting**: Be aware of SRAM API rate limits and implement appropriate retry logic if needed
4. **Access Control**: Only global administrators can view SRAM invitation status

## Migration

To enable SRAM for existing tenants:

1. Enable SRAM in the configuration
2. For each existing tenant:
   - Create a SRAM collaboration manually via the SRAM API
   - Add the `sram_collaboration_id` to the tenant's `config.yaml`
   - Send invitations manually or via the SRAM API

A migration script may be provided in the future to automate this process.
