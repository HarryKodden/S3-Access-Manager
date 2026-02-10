# SRAM Integration Quick Reference

## For Users

### What is SRAM?
SRAM (SURF Research Access Management) is used to manage tenant administrators. When a tenant is created, a collaboration is automatically created in SRAM and invitations are sent to tenant administrators.

### How to Accept Your Invitation

1. **Check your email** for a SRAM invitation
2. **Click the invitation link** in the email
3. **Log into SRAM** (or create an account if needed)
4. **Accept the invitation** to join the tenant collaboration
5. **Note your SRAM username** (you'll need it for access)

Once accepted, a global administrator can sync your SRAM username to grant you tenant admin permissions in the S3 Gateway.

## For Global Administrators

### Creating a Tenant with SRAM

1. Log in to the S3 Gateway as a global admin
2. Click the **Tenants** tab
3. Click **Create New Tenant**
4. Fill in the form:
   - **Tenant Name**: Unique identifier (lowercase, hyphens allowed)
   - **Description**: Purpose of this tenant
   - **Tenant Admin Email**: Email to receive SRAM invitation
   - **IAM Credentials**: AWS/MinIO admin credentials
5. Click **Create Tenant**

**What happens next:**
- SRAM collaboration is created automatically
- Invitation email is sent to the tenant admin
- Tenant admin must accept invitation in SRAM
- You can sync accepted admins to grant permissions

### Viewing Invitation Status

1. Go to **Tenants** tab
2. Click **Edit** (pencil icon) on a tenant
3. Scroll to **SRAM Admin Invitations** section
4. You'll see:
   - Email addresses invited
   - Status badges:
     - 🟡 **Pending**: Waiting for acceptance
     - 🟢 **Accepted**: User has joined SRAM collaboration
     - 🔴 **Declined**: User declined invitation
   - SRAM usernames (for accepted invitations)

### Refreshing Invitation Status

1. Edit a tenant
2. In **SRAM Admin Invitations** section
3. Click **Refresh Status**
4. Latest statuses are fetched from SRAM
5. Accepted invitations show SRAM usernames

### Syncing Accepted Admins

**Purpose**: Add SRAM usernames to tenant configuration to grant tenant admin permissions

**Steps:**
1. Edit a tenant
2. Ensure invitations show "Accepted" status
3. Click **Sync Accepted Admins to Config**
4. Success message shows how many admins were added
5. Synced users immediately gain tenant admin access

**What gets updated:**
- `config.yaml` file is updated with SRAM usernames
- In-memory admin list is refreshed
- Synced users can now log in as tenant admins

### Troubleshooting

**Problem**: No invitations showing  
**Solution**: Check if SRAM is enabled in `config.yaml` and tenant has a collaboration ID

**Problem**: Status not updating  
**Solution**: Click "Refresh Status" to fetch latest data from SRAM

**Problem**: Accepted admin can't log in  
**Solution**: Ensure you clicked "Sync Accepted Admins to Config" after they accepted

**Problem**: Wrong SRAM username added  
**Solution**: Edit `config.yaml` manually to remove the incorrect username

## For Tenant Administrators

### After Accepting Your Invitation

1. **Confirm your SRAM username** by logging into SRAM
2. **Wait for sync**: Global admin must sync your username to the tenant
3. **Log in to S3 Gateway**: Use OIDC authentication
4. **Select your tenant**: From the tenant selection screen
5. **Manage your tenant**: You'll have access to:
   - **Policies tab**: Create/edit/delete S3 access policies
   - **Roles tab**: Create/edit/delete user groups
   - **Credentials tab**: View your own credentials

### Your Permissions

As a tenant admin, you can:
- ✅ Manage policies in your tenant
- ✅ Manage roles in your tenant
- ✅ View credentials in your tenant
- ❌ Manage other tenants
- ❌ Create new tenants
- ❌ View global admin features

### Switching Tenants

If you're an admin in multiple tenants:
1. Click your **tenant name badge** at the top
2. Select a different tenant
3. You'll have admin access only in your assigned tenants

## API Reference

### Get Invitation Status
```bash
GET /tenants/{tenant-name}/sram-invitations
Authorization: Bearer {token}

# Response
{
  "tenant": "my-tenant",
  "collaboration_id": "collab-123",
  "invitations": [
    {
      "id": "inv-1",
      "email": "admin@example.com",
      "status": "accepted",
      "sram_username": "john_doe"
    }
  ]
}
```

### Sync Accepted Admins
```bash
POST /tenants/{tenant-name}/sync-sram-admins
Authorization: Bearer {token}

# Response
{
  "message": "SRAM admins synced successfully",
  "synced": 1,
  "new_admins": ["john_doe"],
  "total_admins": 2
}
```

## Configuration

### Enable SRAM in config.yaml
```yaml
sram:
  enabled: true
  api_url: "https://sram.surf.nl"
  api_key: "your-sram-api-key"
```

### Tenant Configuration
```yaml
tenants:
  - name: my-tenant
    tenant_admins:
      - admin@example.com  # Email (before sync)
      - john_doe           # SRAM username (after sync)
    sram_collaboration_id: "collab-xyz"
```

## Best Practices

### For Global Admins
1. ✅ Refresh invitation status regularly to track progress
2. ✅ Sync accepted admins promptly to grant access
3. ✅ Monitor logs for SRAM API failures
4. ✅ Verify tenant admin access after syncing
5. ❌ Don't manually edit SRAM collaboration IDs in config

### For Tenant Admins
1. ✅ Accept SRAM invitations promptly
2. ✅ Remember your SRAM username
3. ✅ Test your access after sync
4. ✅ Report issues to global admin
5. ❌ Don't share your SRAM credentials

## Support

### Getting Help

**Check logs:** Look for SRAM-related errors in gateway logs
**Read docs:** See [SRAM Testing Guide](SRAM_TESTING_GUIDE.md) for detailed troubleshooting
**Contact admin:** Report issues to your S3 Gateway administrator

### Common Scenarios

**Scenario 1: New Tenant**
1. Global admin creates tenant → SRAM invitation sent
2. Tenant admin accepts invitation → Status shows "Accepted"
3. Global admin syncs admins → Tenant admin gains access
4. Tenant admin logs in → Can manage policies/roles

**Scenario 2: Adding Another Admin**
1. Global admin edits tenant config manually
2. Adds new email to `tenant_admins` list
3. SRAM sends invitation automatically (if implemented)
4. New admin accepts → Global admin syncs → Access granted

**Scenario 3: Removing an Admin**
1. Global admin edits tenant config manually
2. Removes email/username from `tenant_admins` list
3. Saves config → Admin access revoked immediately

## Related Documentation

- [SRAM Testing Guide](SRAM_TESTING_GUIDE.md) - Comprehensive testing procedures
- [SRAM Implementation Summary](SRAM_IMPLEMENTATION_SUMMARY.md) - Technical details
- [API Documentation](API.md) - Complete API reference
- [Usage Guide](USAGE_GUIDE.md) - General usage instructions
