# SRAM API Discovery Guide

## Issue

The SRAM API at `https://sram.data.surf.nl` is returning 404 for all tested endpoints. This means either:

1. The API requires authentication in a different format
2. The API paths are different than assumed
3. The API key provided doesn't have correct permissions
4. SRAM API is not publicly accessible or requires additional configuration

## What We Tested

All of these returned 404:
- `GET /api/v1/collaborations`
- `GET /api/collaborations`
- `GET /collaborations`
- `GET /api`

## Next Steps

### 1. Check SRAM Documentation

You need to find the official SRAM API documentation:

**SURF SRAM Documentation URLs to Check:**
- https://sram.data.surf.nl/api/docs
- https://sram.data.surf.nl/swagger
- https://sram.data.surf.nl/api-docs
- https://wiki.surfnet.nl/display/SRAM (SRAM Wiki)
- https://www.surf.nl/en/research-access-management-sram

### 2. Test API Manually

Try accessing the SRAM web interface:
1. Go to https://sram.data.surf.nl
2. Log in with your credentials
3. Look for:
   - API documentation link
   - Developer settings
   - API key management
   - Swagger/OpenAPI documentation

### 3. Contact SRAM Support

If documentation is not publicly available:

**SURF Support:**
- Email: support@surf.nl
- Or find support contact in the SRAM web interface

**Questions to Ask:**
- What is the base URL for the SRAM API?
- What endpoints are available for:
  - Creating collaborations
  - Sending invitations
  - Checking invitation status
- What authentication method should be used?
  - Bearer token?
  - API key header?
  - OAuth?
- Are there any examples or sample code?

### 4. Alternative: Check Network Tab

If you have access to the SRAM web interface:

1. Open browser DevTools (F12)
2. Go to Network tab
3. Perform actions in SRAM:
   - Create a collaboration
   - Send an invitation
   - Check invitation status
4. Look at the API calls made:
   - URL patterns
   - Headers used
   - Request/response format
   - Authentication method

### 5. Common SRAM API Patterns

SRAM might use one of these patterns:

**Pattern 1: Standard REST API**
```bash
GET  /api/v1/collaborations
POST /api/v1/collaborations
GET  /api/v1/invitations
POST /api/v1/invitations
```

**Pattern 2: GraphQL API**
```bash
POST /graphql
# With query in body
```

**Pattern 3: Custom API Structure**
```bash
GET  /sram/api/collaborations
POST /sram/api/invitations
```

### 6. Test Authentication Methods

Try different auth methods:

**Method 1: Bearer Token (currently used)**
```bash
Authorization: Bearer YOUR_API_KEY
```

**Method 2: API Key Header**
```bash
X-API-Key: YOUR_API_KEY
```

**Method 3: Basic Auth**
```bash
Authorization: Basic base64(username:password)
```

**Method 4: Cookie-based (web session)**
```bash
# Might need to log in first and use session cookie
```

## Testing Script Updates Needed

Once you find the correct API structure, we'll need to update:

1. **SRAM Client** (`internal/sram/client.go`)
   - Update base paths
   - Update authentication method
   - Update request/response structures

2. **Test Script** (`test-sram-api.sh`)
   - Update endpoint paths
   - Update authentication headers

3. **Configuration** (`.env` / `config.yaml`)
   - Verify correct API URL
   - Add any additional auth parameters

## Temporary Workaround

Until we have the correct SRAM API details, you can:

1. **Disable SRAM Integration** in config:
   ```yaml
   sram:
     enabled: false
   ```

2. **Manual Process**:
   - Create collaborations manually in SRAM web interface
   - Send invitations manually
   - Track SRAM usernames manually
   - Add usernames to `tenant_admins` list manually

3. **Use the Gateway Without SRAM**:
   - The gateway works perfectly without SRAM
   - Tenant admins can still be managed via email in config
   - SRAM integration is optional enhancement

## Current Implementation Status

✅ **What's Ready:**
- Complete SRAM client code (needs only endpoint/auth updates)
- Backend integration (ready when API details confirmed)
- Frontend UI (ready when API works)
- Unit tests (passing with mock API)
- Documentation (complete)

🔄 **What's Blocked:**
- Real API testing (needs correct endpoints)
- Live integration (needs working API connection)

## Action Items

**For You:**
1. [ ] Check SRAM web interface for API documentation link
2. [ ] Contact SURF/SRAM support for API documentation
3. [ ] Or use browser DevTools to inspect actual API calls
4. [ ] Share API documentation or network traces

**For Me (after you get API details):**
1. [ ] Update SRAM client with correct endpoints
2. [ ] Update authentication method if needed
3. [ ] Adjust request/response structures
4. [ ] Update test script
5. [ ] Retest with real SRAM API

## Example Information Needed

Please provide:

```
Base URL: https://sram.data.surf.nl/[WHAT_GOES_HERE]

Authentication:
  Method: [Bearer / API-Key / Basic / OAuth]
  Header: [Authorization / X-API-Key / etc]
  Format: [Bearer TOKEN / KEY / etc]

Endpoints:
  Create Collaboration: POST /[PATH]
  List Collaborations: GET /[PATH]
  Send Invitation: POST /[PATH]
  Get Invitation Status: GET /[PATH]
  List Invitations: GET /[PATH]

Request/Response Format:
  [JSON structure examples]
```

## Related Files

- Test script: `./test-sram-api.sh`
- SRAM client: `internal/sram/client.go`
- Testing guide: `docs/SRAM_TESTING_GUIDE.md`
- Environment: `.env`
