# OIDC Authentication Flow

The S3 Gateway frontend now implements a complete OAuth 2.0 / OIDC authentication flow with the following improvements:

## Key Features

### 1. **Automatic Configuration Loading**
- Frontend automatically fetches OIDC configuration from the backend via `/api/oidc-config`
- No need for users to manually enter OIDC Issuer URL or Client ID
- Configuration is read from the gateway's `.env` file
- Form fields are auto-populated and made read-only

### 2. **Standards-Compliant OIDC Flow**
- Implements OAuth 2.0 Authorization Code Flow with PKCE (Proof Key for Code Exchange)
- PKCE provides enhanced security for browser-based applications
- Follows OpenID Connect Discovery for automatic endpoint configuration
- State parameter for CSRF protection

### 3. **Security Best Practices**
- Code verifier and challenge generation using Web Crypto API
- SHA-256 hashing for PKCE challenge
- State parameter validation to prevent CSRF attacks
- Secure token storage in browser localStorage
- Automatic JWT parsing to extract user information

## Authentication Flow

```
┌─────────┐                                ┌──────────┐                              ┌─────────────┐
│         │                                │          │                              │             │
│ Browser │                                │ Frontend │                              │   Gateway   │
│         │                                │          │                              │             │
└────┬────┘                                └────┬─────┘                              └──────┬──────┘
     │                                          │                                           │
     │  1. Load login page                      │                                           │
     ├─────────────────────────────────────────>│                                           │
     │                                          │                                           │
     │                                          │  2. Fetch OIDC config                     │
     │                                          ├──────────────────────────────────────────>│
     │                                          │                                           │
     │                                          │  3. Return issuer & client_id             │
     │                                          │<──────────────────────────────────────────┤
     │                                          │                                           │
     │  4. Display login with auto-filled info  │                                           │
     │<─────────────────────────────────────────┤                                           │
     │                                          │                                           │
     │  5. User clicks "Sign In"                │                                           │
     ├─────────────────────────────────────────>│                                           │
     │                                          │                                           │
     │                                          │  6. Discover OIDC endpoints               │
     │                                          ├──────────────────────────────────────────>│
     │                                          │  (/.well-known/openid-configuration)      │
     │                                          │                                           │
     │                                          │  7. Generate PKCE parameters              │
     │                                          │     - code_verifier (random)              │
     │                                          │     - code_challenge (SHA256)             │
     │                                          │     - state (random)                      │
     │                                          │                                           │
     │  8. Redirect to OIDC provider            │                                           │
     │     with authorization request           │                                           │
     │<─────────────────────────────────────────┤                                           │
     │                                          │                                           │
     
┌────┴────┐
│  OIDC   │
│Provider │
│ (Auth0, │
│ Keycloak│
│ Google) │
└────┬────┘
     │  9. User authenticates
     │     at OIDC provider
     │
     │  10. OIDC provider redirects back
     │      with authorization code
     ├─────────────────────────────────────────>
     │                                          │
     │                                          │  11. Exchange code for tokens             │
     │                                          ├──────────────────────────────────────────>│
     │                                          │      POST /token                          │
     │                                          │      - grant_type: authorization_code     │
     │                                          │      - code: <auth_code>                  │
     │                                          │      - client_id: <client_id>             │
     │                                          │      - code_verifier: <verifier>          │
     │                                          │                                           │
     │                                          │  12. Return tokens                        │
     │                                          │<──────────────────────────────────────────┤
     │                                          │      - access_token (JWT)                 │
     │                                          │      - id_token (JWT with user info)      │
     │                                          │      - refresh_token (optional)           │
     │                                          │                                           │
     │                                          │  13. Parse JWT to extract user info       │
     │                                          │      - sub (user ID)                      │
     │                                          │      - email                              │
     │                                          │      - roles                              │
     │                                          │                                           │
     │  14. Display dashboard                   │                                           │
     │<─────────────────────────────────────────┤                                           │
```

## Configuration

### Backend (.env file)

```env
# OIDC Provider Configuration
OIDC_ISSUER=https://oauth2-server.playground.sdp.surf.nl
OIDC_CLIENT_ID=demo-dcache
OIDC_CLIENT_SECRET=your-client-secret
```

### Frontend (Automatic)

The frontend automatically fetches configuration from `/api/oidc-config`:

```javascript
{
  "issuer": "https://oauth2-server.playground.sdp.surf.nl",
  "client_id": "demo-dcache"
}
```

Note: Client secret is NEVER exposed to the frontend for security reasons.

## Implementation Details

### PKCE (Proof Key for Code Exchange)

PKCE protects against authorization code interception attacks. The flow:

1. **Generate Code Verifier**: Random 32-byte string, base64url-encoded
2. **Generate Code Challenge**: SHA-256 hash of verifier, base64url-encoded
3. **Send Challenge**: Include in authorization request
4. **Send Verifier**: Include in token exchange request
5. **Provider Validates**: Ensures verifier matches original challenge

```javascript
// Code Verifier Generation
const array = new Uint8Array(32);
crypto.getRandomValues(array);
const codeVerifier = base64URLEncode(array);

// Code Challenge Generation
const encoder = new TextEncoder();
const data = encoder.encode(codeVerifier);
const hash = await crypto.subtle.digest('SHA-256', data);
const codeChallenge = base64URLEncode(new Uint8Array(hash));
```

### State Parameter

Used for CSRF protection:

```javascript
// Generate state
const state = base64URLEncode(crypto.getRandomValues(new Uint8Array(16)));

// Store in session
sessionStorage.setItem('oauth_state', state);

// Validate on callback
if (storedState !== receivedState) {
    throw new Error('Invalid state - CSRF attack detected');
}
```

### Token Storage

Tokens are stored securely in browser storage:

- **localStorage**: Access tokens and user info (persists across sessions)
- **sessionStorage**: PKCE verifier and state (cleared after login)

```javascript
// Store tokens
localStorage.setItem('auth_token', tokens.access_token);
localStorage.setItem('user_info', JSON.stringify(userInfo));
localStorage.setItem('refresh_token', tokens.refresh_token);

// Store temporary PKCE data
sessionStorage.setItem('pkce_verifier', codeVerifier);
sessionStorage.setItem('oauth_state', state);
```

## Supported OIDC Providers

The implementation works with any OpenID Connect compliant provider:

### ✅ Tested Providers
- **SURF OAuth2 Playground**: `https://oauth2-server.playground.sdp.surf.nl`

### ✅ Compatible Providers
- **Google**: `https://accounts.google.com`
- **Auth0**: `https://your-tenant.auth0.com`
- **Keycloak**: `https://your-keycloak.com/realms/your-realm`
- **Azure AD**: `https://login.microsoftonline.com/{tenant}/v2.0`
- **Okta**: `https://your-domain.okta.com`
- **GitHub**: `https://github.com` (with GitHub OAuth App)

## Testing the Flow

### 1. Check OIDC Configuration

```bash
# Via gateway
curl http://localhost:9000/oidc-config

# Via frontend proxy
curl http://localhost:8081/api/oidc-config
```

Expected response:
```json
{
  "issuer": "https://oauth2-server.playground.sdp.surf.nl",
  "client_id": "demo-dcache"
}
```

### 2. Open Frontend

Navigate to http://localhost:8081

You should see:
- OIDC Issuer field pre-filled (read-only)
- Client ID field pre-filled (read-only)
- "Sign In" button active

### 3. Initiate Login

Click "Sign In" and you'll be:
1. Redirected to OIDC provider
2. Asked to authenticate
3. Redirected back to `/callback`
4. Automatically logged into dashboard

### 4. Verify Token

Check browser console or DevTools → Application → Local Storage:
- `auth_token`: JWT access token
- `user_info`: Decoded user information

## Troubleshooting

### "Failed to fetch OIDC configuration"

**Cause**: Gateway is not running or OIDC config is missing

**Solution**:
```bash
# Check gateway is running
docker ps | grep s3-gateway

# Verify .env has OIDC configuration
cat .env | grep OIDC_

# Restart gateway
docker-compose restart s3-gateway
```

### "Invalid redirect URI"

**Cause**: Redirect URI not registered with OIDC provider

**Solution**: Add `http://localhost:8081/callback` to allowed redirect URIs in your OIDC provider settings

### "PKCE challenge failed"

**Cause**: Browser doesn't support Web Crypto API or timing issue

**Solution**: Use a modern browser (Chrome, Firefox, Safari, Edge) and ensure HTTPS in production

### "Invalid state parameter"

**Cause**: Possible CSRF attack or session data lost

**Solution**: Clear browser cache and sessionStorage, then try again

## Security Considerations

### ✅ Implemented Security Features

1. **PKCE**: Prevents authorization code interception
2. **State Parameter**: Prevents CSRF attacks
3. **HTTPS Recommended**: Use HTTPS in production
4. **Token Validation**: JWT signature verification by gateway
5. **Secure Storage**: Tokens stored in browser localStorage (HTTPS only in production)
6. **Read-only Config**: Users cannot modify OIDC configuration

### 🔒 Production Requirements

1. **HTTPS Only**: Always use HTTPS in production
2. **Secure Cookies**: Consider using httpOnly cookies for tokens
3. **Short Token Lifetime**: Configure short-lived access tokens
4. **Refresh Tokens**: Implement token refresh for better UX
5. **Token Revocation**: Support logout and token revocation
6. **Content Security Policy**: Add CSP headers to prevent XSS

## Session Caching

The gateway implements session caching to reduce load on the OIDC provider's userinfo endpoint and improve performance.

### How It Works

1. **First Request**: Access token is validated via OIDC provider's `/userinfo` endpoint
2. **Subsequent Requests**: User info is retrieved from in-memory cache for the configured session timeout
3. **After Timeout**: Token is revalidated via `/userinfo` endpoint
4. **On Success**: Session is extended by another session timeout period
5. **On Failure**: Session is invalidated and user must re-authenticate

### Configuration

Set the session cache TTL in your configuration file or via environment variable:

**config.yaml:**
```yaml
oidc:
  session_cache_ttl: 15m  # Default: 15 minutes
```

**Environment Variable:**
```bash
export OIDC_SESSION_CACHE_TTL=15m
# Accepts Go duration format: 10m, 30m, 1h, 2h30m, etc.
```

**Docker Compose:**
```yaml
services:
  s3-gateway:
    environment:
      - OIDC_SESSION_CACHE_TTL=15m
```

### Benefits

- **Reduced OIDC Provider Load**: Fewer calls to `/userinfo` endpoint
- **Improved Performance**: Faster authentication for cached sessions
- **Better User Experience**: Seamless access during session validity
- **Configurable**: Adjust timeout based on your security requirements

### Cache Management

- Sessions are automatically cleaned up every 5 minutes
- Invalid tokens are immediately removed from cache
- Session cache is per-instance (not shared across multiple gateway instances)
- Sessions expire after the configured timeout and require revalidation

### Security Considerations

- **Shorter TTL**: More secure but more OIDC provider calls (e.g., `5m`)
- **Longer TTL**: Fewer calls but delayed revocation detection (e.g., `1h`)
- **Recommended**: 15 minutes balances security and performance
- **Token Revocation**: Changes at OIDC provider detected after cache expires

## Next Steps

1. Test with your OIDC provider
2. Configure proper redirect URIs
3. Enable HTTPS for production
4. Implement token refresh
5. Add logout functionality with token revocation
6. Monitor authentication metrics

## References

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
