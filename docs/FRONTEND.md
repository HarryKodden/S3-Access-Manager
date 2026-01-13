# Frontend Guide

Modern web UI for the S3 Access Manager.

## Features

- **OIDC Authentication**: Secure login with OpenID Connect
- **Credential Management**: Create, view, copy, delete credentials
- **S3 Browser**: Upload, download, delete objects
- **Policy Management**: View and edit IAM policies (admin only)
- **Admin Mode Toggle**: Test regular user experience
- **Secret Key Management**: View and copy secrets with toggle visibility

## Accessing

```bash
# After starting the gateway
http://localhost/

# Login with your OIDC provider
```

## Development

Frontend files are in `/frontend`:
- `index.html` - Main UI structure
- `app.js` - Application logic
- `styles.css` - Styling

Files are volume-mounted for live updates:
```yaml
volumes:
  - ./frontend:/app/frontend:ro
```

## API Integration

Frontend uses these endpoints:
- `GET /oidc-config` - OIDC configuration
- `GET /settings/*` - Credentials, policies, buckets
- `GET/PUT/DELETE /s3/*` - S3 operations

## OIDC Flow

1. User clicks "Login with OIDC"
2. Redirected to OIDC provider
3. After authentication, redirected to `/callback?code=...`
4. Frontend exchanges code for token
5. Token stored in localStorage
6. Used for API requests

## Customization

### Styling

Edit `frontend/styles.css`:
```css
:root {
  --primary-color: #4F46E5;  /* Change primary color */
  --border-radius: 12px;     /* Adjust roundness */
}
```

### Branding

Edit `frontend/index.html`:
```html
<title>Your Company - S3 Gateway</title>
<h1>Your Company S3 Access</h1>
```

### Features

Edit `frontend/app.js` to add/remove features or customize behavior.
