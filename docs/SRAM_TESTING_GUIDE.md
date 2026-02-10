# SRAM Integration Testing Guide

This guide provides step-by-step instructions for testing the SRAM integration with the S3 Gateway.

## Prerequisites

1. **SRAM Account**: You need access to a SURF Research Access Management (SRAM) instance
2. **SRAM API Credentials**: API key with permissions to create collaborations and send invitations
3. **Test Email Addresses**: At least one email address that can receive SRAM invitations

## Configuration

Before testing, ensure your `config.yaml` has SRAM enabled:

```yaml
sram:
  enabled: true
  api_url: "https://sram.example.com"  # Your SRAM instance URL
  api_key: "your-sram-api-key-here"    # Your SRAM API key
```

## Test Scenarios

### 1. Automated Unit Tests

Verify that the SRAM client implementation works correctly:

```bash
cd /Users/kodde001/Projects/S3-Gateway
go test -v ./internal/sram/
```

**Expected Result**: All tests should pass
- `TestCreateCollaboration`: Verifies collaboration creation API call
- `TestSendInvitation`: Verifies invitation sending API call
- `TestGetInvitationStatus`: Verifies invitation status retrieval
- `TestGetCollaborationInvitations`: Verifies fetching all invitations for a collaboration
- `TestAPIErrors`: Verifies error handling for failed API calls

### 2. Manual Integration Test: Create Tenant with SRAM

This test verifies that creating a tenant automatically creates a SRAM collaboration and sends invitations.

#### Steps:

1. **Start the Gateway**:
   ```bash
   make run
   ```

2. **Log in as Global Admin**:
   - Navigate to the frontend (default: http://localhost:8080)
   - Log in with OIDC credentials
   - Ensure you are a global admin (listed in `config.yaml` under `oidc.admin_emails`)

3. **Create a New Tenant**:
   - Click on the "Tenants" tab
   - Click "Create New Tenant" button
   - Fill in the form:
     - **Tenant Name**: `test-tenant-1` (use lowercase, hyphens allowed)
     - **Description**: `Test tenant for SRAM integration`
     - **Tenant Admin Email**: Your test email address (e.g., `admin@example.com`)
     - **IAM Access Key**: Your AWS/MinIO access key
     - **IAM Secret Key**: Your AWS/MinIO secret key
   - Click "Create Tenant"

4. **Verify Backend SRAM API Calls**:
   Check the gateway logs for:
   ```
   INFO[...] Creating SRAM collaboration for tenant  tenant=test-tenant-1
   INFO[...] SRAM collaboration created successfully  collaboration_id=collab-xyz tenant=test-tenant-1
   INFO[...] Sending SRAM invitations                 tenant=test-tenant-1
   INFO[...] SRAM invitations sent successfully       count=1 tenant=test-tenant-1
   ```

   **What happened**:
   - Gateway called `POST /api/v1/collaborations` on SRAM API
   - SRAM created a new collaboration named `S3 Gateway - test-tenant-1`
   - Gateway stored the collaboration ID in the tenant config
   - Gateway called `POST /api/v1/invitations` to invite the tenant admin
   - SRAM sent an invitation email to `admin@example.com`

5. **Verify SRAM Collaboration Created**:
   - Log into your SRAM dashboard
   - Navigate to Collaborations
   - Find the collaboration: `S3 Gateway - test-tenant-1`
   - Verify it exists with status "Active"

6. **Verify SRAM Invitation Sent**:
   - In SRAM, click on the collaboration
   - Go to "Invitations" or "Members" tab
   - Verify that an invitation was sent to `admin@example.com`
   - Status should be "Pending"

### 3. Manual UI Test: View Invitation Status

This test verifies that the UI displays SRAM invitation status correctly.

#### Steps:

1. **Access Tenant Management** (as global admin):
   - Go to Dashboard → Tenants tab
   - Find the tenant you just created (`test-tenant-1`)

2. **Inspect Tenant**:
   - Click the "View" (eye) icon next to `test-tenant-1`
   - Scroll down to "SRAM Admin Invitations" section
   - Verify you see:
     - Email address of the invited admin
     - Status badge: "Pending" (yellow)
     - No SRAM username yet (since not accepted)

3. **Edit Tenant**:
   - Click "Edit" button on the tenant
   - Scroll down to "SRAM Admin Invitations" section
   - Verify the same information is displayed
   - Note the "Refresh Status" and "Sync Accepted Admins to Config" buttons

### 4. Manual Test: Accept Invitation

This test verifies the full invitation acceptance workflow.

#### Steps:

1. **Check Email**:
   - Open the email inbox for the invited admin (`admin@example.com`)
   - Find the SRAM invitation email
   - Subject should mention the collaboration name

2. **Accept Invitation**:
   - Click the invitation link in the email
   - Log into SRAM (or create an account if needed)
   - Accept the invitation to join the collaboration
   - Note your SRAM username (e.g., `john_doe`)

3. **Verify in SRAM**:
   - In SRAM, navigate to the collaboration
   - Go to "Members" tab
   - Verify you're listed as a member with role "Admin"
   - Status should be "Active"

4. **Refresh Status in Gateway UI**:
   - Return to S3 Gateway
   - Edit the tenant (`test-tenant-1`)
   - Scroll to "SRAM Admin Invitations"
   - Click "Refresh Status" button

5. **Verify Status Updated**:
   - Status badge should now show "Accepted" (green)
   - The invitation item should have a light green background
   - SRAM username should be displayed: `SRAM Username: john_doe`

### 5. Manual Test: Sync Accepted Admins

This test verifies that accepted SRAM usernames are added to the tenant configuration.

#### Steps:

1. **Sync SRAM Admins**:
   - In the Edit Tenant modal for `test-tenant-1`
   - With invitation status showing "Accepted"
   - Click "Sync Accepted Admins to Config" button

2. **Verify Success Message**:
   - Toast notification appears: `Synced 1 new admin(s): john_doe`
   - Invitation list refreshes automatically

3. **Verify Config Updated**:
   Check `config.yaml` or `data/test-tenant-1/config.yaml`:
   ```yaml
   tenants:
     - name: test-tenant-1
       tenant_admins:
         - admin@example.com      # Original email
         - john_doe               # NEW: SRAM username added
       sram_collaboration_id: collab-xyz
       ...
   ```

4. **Verify Tenant Admin Permissions**:
   - Log out of the gateway
   - Log in as the SRAM user (`john_doe`)
   - Select tenant `test-tenant-1`
   - Verify you have admin access to:
     - Policies tab (can create/edit/delete)
     - Roles tab (can create/edit/delete)
   - Verify you do NOT have access to:
     - Other tenants' policies/roles
     - Global Tenants tab (not a global admin)

### 6. Error Handling Tests

#### Test 6a: SRAM API Unavailable

1. Stop SRAM API or use invalid API URL
2. Try creating a tenant
3. **Expected**: Error message "Failed to create SRAM collaboration"
4. **Expected**: Tenant creation fails gracefully

#### Test 6b: Invalid API Key

1. Set invalid API key in `config.yaml`
2. Restart gateway
3. Try creating a tenant
4. **Expected**: Error message mentioning authentication failure
5. **Expected**: Check logs for "Unauthorized" or "403 Forbidden"

#### Test 6c: Refresh When SRAM Down

1. Edit a tenant with existing invitations
2. Stop SRAM API
3. Click "Refresh Status"
4. **Expected**: Error toast message
5. **Expected**: Previous invitation data still displayed

### 7. Multiple Invitations Test

This test verifies handling multiple tenant admins.

#### Steps:

1. **Modify Tenant Creation**:
   Currently, the UI only supports one admin email. To test multiple invitations, you can:
   - Edit `config.yaml` manually to add multiple emails to `tenant_admins`
   - Or modify the UI to accept comma-separated emails

2. **Create Tenant with Multiple Admins**:
   ```yaml
   tenant_admins:
     - admin1@example.com
     - admin2@example.com
     - admin3@example.com
   ```

3. **Verify Multiple Invitations**:
   - Inspect/Edit the tenant
   - Verify all three invitations are shown
   - Each should have status "Pending"

4. **Accept Some Invitations**:
   - Have 2 out of 3 admins accept
   - Refresh status
   - Verify 2 show "Accepted" (green) and 1 shows "Pending" (yellow)

5. **Sync SRAM Admins**:
   - Click "Sync Accepted Admins to Config"
   - Verify only the 2 accepted usernames are added
   - Verify the pending invitation is not added

## Troubleshooting

### Issue: "SRAM integration is not enabled"

**Solution**: Ensure `sram.enabled: true` in `config.yaml` and restart the gateway.

### Issue: No invitations showing in UI

**Check**:
1. Is SRAM enabled in config?
2. Does the tenant have a `sram_collaboration_id` in its config?
3. Check browser console for JavaScript errors
4. Check gateway logs for API errors

### Issue: Invitation status not updating

**Check**:
1. Did you actually accept the invitation in SRAM?
2. Click "Refresh Status" to fetch latest data
3. Check SRAM API connectivity
4. Verify API key has correct permissions

### Issue: Sync not adding usernames to config

**Check**:
1. Are invitations showing "Accepted" status?
2. Does the invitation response include `sram_username` field?
3. Check gateway logs for save errors
4. Verify file permissions on `config.yaml`

## Monitoring

### Backend Logs

Important log messages to watch for:

```
# Tenant creation with SRAM
INFO[...] Creating SRAM collaboration for tenant
INFO[...] SRAM collaboration created successfully
INFO[...] Sending SRAM invitations
INFO[...] SRAM invitations sent successfully

# Invitation status refresh
INFO[...] Fetching SRAM invitations for tenant

# Admin sync
INFO[...] Synced SRAM admins to tenant config  new_admins=[...]

# Errors
ERROR[...] Failed to create SRAM collaboration
ERROR[...] Failed to send SRAM invitations
ERROR[...] Failed to get SRAM invitations
```

### API Endpoints

The following endpoints are involved in SRAM integration:

1. **POST /tenants**
   - Creates tenant
   - Calls SRAM API: `POST /api/v1/collaborations`
   - Calls SRAM API: `POST /api/v1/invitations`

2. **GET /tenants/:name/sram-invitations**
   - Fetches invitation status
   - Calls SRAM API: `GET /api/v1/collaborations/{id}/invitations`
   - Returns: `{invitations: [...], collaboration_id: "...", tenant: "..."}`

3. **POST /tenants/:name/sync-sram-admins**
   - Syncs accepted admins to config
   - Calls SRAM API: `GET /api/v1/collaborations/{id}/invitations`
   - Updates: `config.yaml` tenant_admins list
   - Returns: `{synced: N, new_admins: [...], total_admins: N}`

## Success Criteria

✅ Unit tests pass  
✅ Tenant creation triggers SRAM collaboration creation  
✅ Tenant creation triggers SRAM invitation sending  
✅ SRAM collaboration appears in SRAM dashboard  
✅ SRAM invitation email is received  
✅ UI displays invitation status correctly  
✅ Accepting invitation updates status to "Accepted"  
✅ Accepted SRAM usernames are displayed in UI  
✅ Sync button adds accepted usernames to tenant config  
✅ Synced SRAM users gain tenant admin permissions  
✅ Error scenarios handled gracefully  

## Next Steps

After successful testing:

1. **Production Deployment**:
   - Update SRAM API URL to production instance
   - Use production SRAM API key
   - Test with real user emails

2. **Documentation**:
   - Update user documentation with SRAM workflow
   - Create admin guide for managing SRAM collaborations
   - Document permission model (global vs tenant admin)

3. **Monitoring**:
   - Set up alerts for SRAM API failures
   - Monitor invitation acceptance rates
   - Track tenant admin sync operations

4. **Enhancements** (future):
   - Automatic periodic sync of invitation statuses
   - Webhook from SRAM for immediate updates
   - UI for removing/revoking tenant admins
   - Bulk invitation management
