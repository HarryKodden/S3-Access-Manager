# RBAC Implementation - Multi-Level Access Control

## Overview

This document describes the implementation of Role-Based Access Control (RBAC) with three distinct user roles in the S3 Access Manager: **Global Administrators**, **Tenant Administrators**, and **Normal Users**.

## User Roles

### 1. Global Administrators
- **Configuration**: Listed in `config.yaml` under `global_admins`
- **Permissions**:
  - Full system access across all tenants
  - Create, modify, and delete tenants
  - Manage global OIDC/SCIM configuration
  - Access all tenant-specific resources
  - Perform any administrative operation

### 2. Tenant Administrators
- **Configuration**: Listed in tenant config under `tenant_admins`
- **Permissions**:
  - Administrative access within their specific tenant
  - Manage users, groups, policies, and roles for their tenant
  - Create and manage S3 credentials for tenant users
  - Cannot access other tenants or global configuration

### 3. Normal Users
- **Configuration**: Any authenticated user not in admin lists
- **Permissions**:
  - Create S3 credentials for groups they belong to
  - Access S3 resources based on their group policies
  - Cannot perform administrative operations

## Changes Implemented

### 1. Backend Authentication Layer

#### **internal/auth/oidc.go**
- **Replaced `IsAdmin` with `Role` field**: `UserInfo` struct now contains a `UserRole` enum
- **Role determination during authentication**: `determineUserRole()` function checks global and tenant admin lists
- **Admin users get expanded groups**: Admin users automatically get all policy names added to their groups

```go
type UserRole string

const (
    UserRoleGlobalAdmin UserRole = "global_admin"
    UserRoleTenantAdmin UserRole = "tenant_admin"
    UserRoleUser        UserRole = "user"
)

type UserInfo struct {
    Subject        string
    Email          string
    Groups         []string // Effective groups (includes all policies for admin users)
    OriginalGroups []string // Original OIDC groups (before policy expansion)
    Role           UserRole // User's role: global_admin, tenant_admin, or user
    Claims         map[string]interface{}
}
```

#### **internal/middleware/auth.go**
- **Updated `RequireAdmin()` middleware**: Now checks for `UserRoleGlobalAdmin` role
- **Returns 403 Forbidden**: Non-global-admin users attempting to access global admin endpoints get a clear error message

```go
func RequireAdmin(logger *logrus.Logger) gin.HandlerFunc {
    // Checks userInfo.Role == UserRoleGlobalAdmin
    // Returns 403 if not global admin
}
```

#### **cmd/gateway/main.go**
- **Role-based endpoint protection**: Applied appropriate middleware based on required access level
- **Global Admin Operations** (RequireAdmin middleware):
  - Tenant management endpoints
  - Global configuration endpoints
- **Admin Operations** (Tenant Admin + Global Admin):
  - Policy management within tenant
  - User management within tenant
  - Group management within tenant
  - Credential management within tenant

### 2. Handler Updates

#### **internal/handler/policies.go**
- **Updated `isAdmin()` method**: Now checks for both global and tenant admin roles
- **Allows tenant admins to manage policies**: Within their tenant scope

#### **internal/handler/users.go**
- **Updated admin checks**: Uses role-based checks instead of email comparison
- **Tenant admin access**: Can manage users within their tenant

#### **internal/handler/credentials.go**
- **Role-based credential creation**: Admins can create credentials for any group, users only for their groups
- **Updated API response**: `is_admin` flag returns true for both admin role types

### 3. Configuration Structure

#### **config.yaml** (Global)
```yaml
# Global administrators with full system access
global_admins:
  - "admin@example.com"
```

#### **data/<tenant>/config.yaml** (Tenant)
```yaml
# Tenant administrators with tenant-level admin access
tenant_admins:
  - "admin@tenant.com"
```

## Security Model

### Access Control Matrix

| Operation | Global Admin | Tenant Admin | Normal User |
|-----------|-------------|--------------|-------------|
| Create Tenant | ✅ | ❌ | ❌ |
| Delete Tenant | ✅ | ❌ | ❌ |
| Modify Global Config | ✅ | ❌ | ❌ |
| Manage Tenant Policies | ✅ | ✅ (own tenant) | ❌ |
| Manage Tenant Users | ✅ | ✅ (own tenant) | ❌ |
| Create Credentials | ✅ | ✅ (own tenant) | ✅ (own groups) |
| Access S3 Resources | ✅ | ✅ | ✅ (per policy) |

### Authentication Flow

1. **OIDC Authentication**: User authenticates via external OIDC provider
2. **Role Determination**:
   - Check if user email is in `global_admins` → Global Admin
   - Check if user email is in tenant's `tenant_admins` → Tenant Admin
   - Default → Normal User
3. **Group Expansion**: Admin users get all policy names added to their groups
4. **Request Processing**: Middleware and handlers check appropriate role levels
5. **Access Granted/Denied**: Based on role and operation requirements

## Benefits

✅ **Hierarchical Access Control**: Clear separation between global and tenant administration
✅ **Multi-Tenant Security**: Tenant admins cannot access other tenants
✅ **Flexible Configuration**: Easy to add/remove admins via configuration files
✅ **Backward Compatibility**: Existing API responses maintained
✅ **Scalable**: Supports complex enterprise deployments with multiple tenants

## Migration from Single Admin Flag

The previous implementation used a simple `IsAdmin` boolean flag. The new system provides:

- **Granular Control**: Three distinct role levels instead of binary admin/user
- **Multi-Tenant Support**: Proper isolation between tenant administrators
- **Configuration-Driven**: Admin roles defined in configuration files
- **Future-Proof**: Extensible role system for additional role types
settingsRoutes.DELETE("/policies/:name", adminMiddleware, policyHandler.DeletePolicy)

// ADMIN ONLY - Role management
settingsRoutes.GET("/roles", adminMiddleware, groupHandler.ListGroups)
settingsRoutes.POST("/roles", adminMiddleware, groupHandler.CreateGroup)
// ... etc
```

#### **internal/handler/credentials.go**
- **Added group membership validation**: Non-admin users can only create credentials for groups they are members of
- **Checks `OriginalGroups` from OIDC claims**: Validates that all requested groups are in the user's OIDC group membership
- **Admin users bypass validation**: Admin users can create credentials for any group

```go
// For non-admin users, validate that they can only create credentials for groups they are members of
if !isAdmin {
    userGroups := userInfo.OriginalGroups
    // Check that all requested groups are in the user's group membership
    for _, requestedGroup := range req.Groups {
        // Validation logic
    }
}
```

### 2. Frontend Access Control

#### **frontend/app.js**

**State Management:**
- **Added `userGroups` to state**: Stores the user's OIDC group membership
- **Updated `actualIsAdmin` handling**: Properly stores and uses admin status from backend

**UI Updates:**
- **`updateAdminUI()` function**: Dynamically shows/hides admin-only UI elements based on `IsAdmin` flag
- **Auto-redirect from admin tabs**: Non-admin users viewing admin tabs are automatically redirected to credentials tab
- **Admin indicator in header**: Shows "(Admin)" next to username for admin users

**Credential Creation:**
- **`loadAvailableRolesForCredential()` updated**: 
  - Admin users see all roles
  - Regular users only see roles matching their OIDC group membership (compares `role.scim_id` with `state.userGroups`)
  - Shows appropriate message when no roles are available

```javascript
// Filter roles based on user's OIDC group membership
if (!isAdmin && state.userGroups) {
    roles = roles.filter(role => state.userGroups.includes(role.scim_id));
}
```

#### **frontend/index.html**
- **Admin-only CSS class**: Tabs for Policies, Roles, and Users have the `admin-only` class for dynamic visibility control

### 3. Configuration

#### **config.yaml**
The admin username is configured in the `admin` section:

```yaml
admin:
  username: "admin@example.com"  # Email or subject from OIDC token
```

## User Roles

### ADMIN
**Capabilities:**
- ✅ Manage Policies (create, edit, delete)
- ✅ Manage Roles (create, edit, delete, view SCIM groups)
- ✅ Manage Users (view, delete)
- ✅ Create credentials for any group
- ✅ View all system resources

**UI Access:**
- Sees all navigation tabs (Credentials, Policies, Roles, Users)
- Can access all settings endpoints
- No group membership restrictions

### USER (Regular User)
**Capabilities:**
- ✅ Create credentials ONLY for groups they are a member of (via OIDC group claims)
- ✅ View their own credentials
- ✅ Delete their own credentials
- ❌ Cannot manage policies
- ❌ Cannot manage roles
- ❌ Cannot manage users

**UI Access:**
- Sees only "Credentials" tab
- Policies, Roles, and Users tabs are hidden
- When creating credentials, only sees roles for groups they belong to
- Gets 403 Forbidden error if attempting to access admin endpoints

## Security Flow

### Authentication Flow
1. User logs in via OIDC
2. Backend validates access token via `/userinfo` endpoint
3. Backend extracts user info including email and groups
4. Backend checks if user email matches `admin.username` in config
5. If admin, sets `IsAdmin = true` and adds all policy names to groups
6. UserInfo stored in request context with `IsAdmin` flag

### Authorization Flow

#### For Admin Endpoints (Policies, Roles, Users)
1. Request hits endpoint (e.g., GET `/settings/policies`)
2. `OIDCAuth` middleware validates token and sets `userInfo` in context
3. `RequireAdmin` middleware checks `userInfo.IsAdmin`
4. If `IsAdmin == false`, returns 403 Forbidden
5. If `IsAdmin == true`, request proceeds to handler

#### For Credential Creation (Users)
1. Request hits POST `/settings/credentials`
2. `OIDCAuth` middleware validates token
3. Handler checks `userInfo.IsAdmin`
4. If not admin, validates that all requested groups are in `userInfo.OriginalGroups`
5. If validation fails, returns 403 Forbidden with error message
6. If validation passes or user is admin, creates credential

### Frontend Protection
1. On login, frontend receives `is_admin` flag in `/settings/credentials` response
2. Frontend stores `actualIsAdmin` in state
3. `updateAdminUI()` hides/shows elements with `admin-only` class
4. When creating credentials, role dropdown is filtered by group membership
5. If user somehow navigates to admin tab, auto-redirects to credentials

## Testing Guide

### Test as ADMIN

1. **Configure admin user in config.yaml:**
   ```yaml
   admin:
     username: "admin@example.com"
   ```

2. **Login as admin user**
   - Login screen should show your email with "(Admin)" in header

3. **Verify admin access:**
   - ✅ Can see Credentials, Policies, Roles, Users tabs
   - ✅ Can view all policies
   - ✅ Can create/edit/delete policies
   - ✅ Can view all roles
   - ✅ Can create/edit/delete roles
   - ✅ Can view SCIM groups
   - ✅ Can create credentials for any group (all roles visible)

### Test as USER (Regular User)

1. **Login as non-admin user** (email not matching admin.username)

2. **Verify user restrictions:**
   - ✅ Can only see "Credentials" tab
   - ✅ Policies, Roles, Users tabs are hidden
   - ✅ When creating credential, only see roles for their OIDC groups
   - ❌ Cannot access `/settings/policies` (403 Forbidden)
   - ❌ Cannot access `/settings/roles` (403 Forbidden)
   - ❌ Cannot access `/settings/users` (403 Forbidden)

3. **Test credential creation:**
   - Click "Create Credential"
   - Should only see roles matching your OIDC groups
   - If you're not in any groups, shows: "No roles available for your groups. Contact your administrator."
   - Trying to create credential for group you don't belong to returns 403 error

4. **Test API directly (optional):**
   ```bash
   # Try to access policies endpoint (should fail)
   curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/settings/policies
   # Expected: {"error":"Admin access required"}
   ```

### Edge Cases to Test

1. **User with no OIDC groups:**
   - Should see "No roles available for your groups" message
   - Cannot create any credentials

2. **User tries to access admin endpoint via browser console:**
   - Returns 403 Forbidden
   - Frontend doesn't show tabs, but backend still enforces

3. **Admin creates credential:**
   - Sees all available roles
   - No group membership restrictions

4. **Switching between admin and non-admin accounts:**
   - UI should update correctly on login
   - Tabs show/hide appropriately

## Implementation Benefits

✅ **Security**: Backend enforces all authorization rules - frontend hiding is just UX  
✅ **Simplicity**: Single `IsAdmin` flag controls all admin access  
✅ **Flexibility**: Admin users determined by config file, easy to add multiple admins  
✅ **User Experience**: Non-admin users see clean UI without confusing admin options  
✅ **Group-based**: Regular users limited to their OIDC group membership  
✅ **Audit Trail**: All unauthorized attempts logged with user email and attempted endpoint  

## Configuration Example

```yaml
server:
  host: "0.0.0.0"
  port: 9000

oidc:
  issuer: "http://localhost:3000"
  client_id: "s3-gateway"
  groups_claim: "groups"
  user_claim: "sub"
  email_claim: "email"

admin:
  username: "admin@example.com"  # This user gets admin access
  # Can also use OIDC subject: "auth0|1234567890"

# Multiple admins can be added by modifying the code to accept a list
# Or by using a dedicated admin group in OIDC claims
```

## Deployment

All changes have been deployed to Docker containers:

```bash
docker-compose down
docker-compose up -d --build
```

Verify all containers are healthy:
```bash
docker-compose ps
# All should show (healthy) status
```

## Summary

This RBAC implementation provides clear separation between ADMIN and USER roles:

- **ADMIN**: Full system access - manages policies, roles, users, and can create credentials for any group
- **USER**: Limited access - can only create credentials for groups they are members of via OIDC group claims

The implementation is secure (backend enforced), user-friendly (clean UI), and flexible (config-based admin designation).
