#!/usr/bin/env python3
"""
Standalone OIDC Provider Server

Run this server before starting the gateway when testing with OIDC.
The gateway can then validate tokens against this server.
"""

import json
import jwt
import os
import sys
import secrets
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT = 8888
JWT_SECRET = "test-jwt-secret-key-do-not-use-in-production"
# Use container name when running in docker, localhost otherwise
ISSUER = os.getenv('OIDC_ISSUER_URL', f"http://localhost:{PORT}")
CLIENT_ID = "test-client"
CLIENT_SECRET = "test-secret"
ROLES_CLAIM = os.getenv('OIDC_ROLES_CLAIM', 'Roles')

# Store authorization codes temporarily (in production, use Redis or similar)
AUTH_CODES = {}
# Store access token data (username, roles) for /userinfo endpoint
TOKEN_DATA = {}

class OIDCHandler(BaseHTTPRequestHandler):
    """OIDC provider HTTP handler"""
    
    def log_message(self, format, *args):
        """Log requests to stdout"""
        print(f"[{self.log_date_time_string()}] {format % args}")
    
    def log_error(self, format, *args):
        """Log errors, but suppress common connection errors"""
        # Don't log full tracebacks for client disconnections
        if isinstance(args[0] if args else None, str):
            error_msg = str(args[0]) if args else format
            if 'Broken pipe' in error_msg or 'Connection reset' in error_msg:
                return  # Silently ignore client disconnections
        print(f"[{self.log_date_time_string()}] ERROR: {format % args}")
    
    def handle(self):
        """Handle request with error catching"""
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # Client disconnected - this is normal, don't log scary tracebacks
            pass
        except Exception as e:
            print(f"[{self.log_date_time_string()}] Unexpected error: {e}")
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/.well-known/openid-configuration':
            self.send_discovery_document()
        elif parsed_path.path == '/authorize':
            self.handle_authorize()
        elif parsed_path.path == '/userinfo':
            self.send_userinfo()
        elif parsed_path.path == '/jwks':
            self.send_jwks()
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "not_found"}).encode())
    
    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/token':
            self.send_token()
        elif parsed_path.path == '/authorize':
            self.handle_authorize_post()
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "not_found"}).encode())
    
    def handle_authorize(self):
        """Handle authorization request - show login form"""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        
        client_id = params.get('client_id', [''])[0]
        redirect_uri = params.get('redirect_uri', [''])[0]
        state = params.get('state', [''])[0]
        response_type = params.get('response_type', [''])[0]
        code_challenge = params.get('code_challenge', [''])[0]
        
        if not redirect_uri:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_request"}).encode())
            return
        
        # Show HTML login form
        html = f'''
<!DOCTYPE html>
<html>
<head>
    <title>Sign In - OIDC Provider</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .login-container {{
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 400px;
            width: 100%;
        }}
        h1 {{
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
            text-align: center;
        }}
        .subtitle {{
            color: #666;
            text-align: center;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
            font-size: 14px;
        }}
        input[type="text"],
        input[type="password"] {{
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e1e4e8;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.3s;
        }}
        input[type="text"]:focus,
        input[type="password"]:focus {{
            outline: none;
            border-color: #667eea;
        }}
        button {{
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }}
        button:active {{
            transform: translateY(0);
        }}
        .info-box {{
            background: #f6f8fa;
            padding: 15px;
            border-radius: 6px;
            margin-top: 20px;
            font-size: 12px;
            color: #666;
        }}
        .info-box strong {{
            color: #333;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🔐 Sign In</h1>
        <p class="subtitle">OIDC Test Provider</p>
        <form method="POST" action="/authorize">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="state" value="{state}">
            <input type="hidden" name="response_type" value="{response_type}">
            <input type="hidden" name="code_challenge" value="{code_challenge}">
            <div class="form-group">
                <label for="username">Username / Email</label>
                <input type="text" id="username" name="username" value="test@example.com" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="(any value accepted)">
            </div>
            <div class="form-group">
                <label for="roles">Roles (comma-separated)</label>
                <input type="text" id="roles" name="roles" value="admin" placeholder="e.g., admin,user,developer">
            </div>
            <button type="submit">Sign In</button>
        </form>
        <div class="info-box">
            <strong>Test Provider:</strong><br>
            Enter any username and roles.<br>
            Password is ignored.
        </div>
    </div>
</body>
</html>
        '''
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_authorize_post(self):
        """Handle login form submission"""
        # Read POST data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        post_params = parse_qs(post_data)
        
        username = post_params.get('username', [''])[0]
        roles_input = post_params.get('roles', ['admin'])[0]
        
        # Parse roles (comma-separated)
        roles = [role.strip() for role in roles_input.split(',') if role.strip()]
        if not roles:
            roles = ['user']  # Default role if none specified
        
        # Accept any username (no password validation for testing)
        if username:
            # Get OAuth parameters from POST body (hidden form fields)
            client_id = post_params.get('client_id', [''])[0]
            redirect_uri = post_params.get('redirect_uri', [''])[0]
            state = post_params.get('state', [''])[0]
            code_challenge = post_params.get('code_challenge', [''])[0]
            
            # Generate authorization code
            auth_code = secrets.token_urlsafe(32)
            
            # Store code with associated data (expires in 5 minutes)
            AUTH_CODES[auth_code] = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'code_challenge': code_challenge,
                'username': username,
                'roles': roles,
                'expires': datetime.now(timezone.utc) + timedelta(minutes=5)
            }
            
            # Redirect back to the application with the code
            redirect_url = f"{redirect_uri}?code={auth_code}&state={state}"
            
            self.send_response(302)
            self.send_header('Location', redirect_url)
            self.end_headers()
        else:
            # Invalid credentials - show error
            html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Sign In Failed - OIDC Provider</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .error-container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 400px;
            text-align: center;
        }
        h1 { color: #e53e3e; margin-bottom: 15px; }
        p { color: #666; margin-bottom: 20px; }
        a {
            display: inline-block;
            padding: 12px 24px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
        }
        a:hover { background: #5568d3; }
    </style>
</head>
<body>
    <div class="error-container">
        <h1>❌ Authentication Failed</h1>
        <p>Username is required.</p>
        <a href="javascript:history.back()">Try Again</a>
    </div>
</body>
</html>
            '''
            self.send_response(401)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
    
    def send_discovery_document(self):
        """Send OpenID Connect discovery document"""
        # Use the request host to build URLs for external access
        host = self.headers.get('Host', f'localhost:{PORT}')
        base_url = f"http://{host}"
        
        discovery = {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/authorize",
            "token_endpoint": f"{base_url}/token",
            "userinfo_endpoint": f"{base_url}/userinfo",
            "jwks_uri": f"{base_url}/jwks",
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256"],
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(discovery, indent=2).encode())
    
    def send_token(self):
        """Send access token and ID token"""
        # Read POST data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)
        
        grant_type = params.get('grant_type', [''])[0]
        
        if grant_type == 'authorization_code':
            # Handle authorization code flow
            code = params.get('code', [''])[0]
            
            if code not in AUTH_CODES:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "invalid_grant"}).encode())
                return
            
            code_data = AUTH_CODES[code]
            
            # Check if code is expired
            if datetime.now(timezone.utc) > code_data['expires']:
                del AUTH_CODES[code]
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "expired_token"}).encode())
                return
            
            # Remove used code
            del AUTH_CODES[code]
        
        # Get user data from code data if available
        user_email = "test@example.com"
        user_roles = ["admin"]
        
        if grant_type == 'authorization_code':
            user_email = code_data.get('username', 'test@example.com')
            user_roles = code_data.get('roles', ['admin'])
        
        # Generate JWT token
        payload = {
            "iss": ISSUER,
            "sub": user_email,
            "aud": CLIENT_ID,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "email": user_email,
            ROLES_CLAIM: user_roles,
        }
        
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        
        # Store token data for /userinfo endpoint
        TOKEN_DATA[token] = {
            'username': user_email,
            'email': user_email,
            'roles': user_roles,
            'sub': user_email,
            'expires': datetime.now(timezone.utc) + timedelta(hours=1)
        }
        
        response = {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": token,
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def send_userinfo(self):
        """Send user info"""
        # Check for Authorization header
        auth_header = self.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unauthorized"}).encode())
            return
        
        # Extract token
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Look up token data
        if token in TOKEN_DATA:
            token_info = TOKEN_DATA[token]
            
            # Check if token is expired
            if datetime.now(timezone.utc) > token_info['expires']:
                del TOKEN_DATA[token]
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "token_expired"}).encode())
                return
            
            userinfo = {
                "sub": token_info['sub'],
                "email": token_info['email'],
                ROLES_CLAIM: token_info['roles'],
            }
        else:
            # Token not found, return default for backward compatibility
            userinfo = {
                "sub": "test@example.com",
                "email": "test@example.com",
                ROLES_CLAIM: ["admin"],
            }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(userinfo).encode())
    
    def send_jwks(self):
        """Send JSON Web Key Set"""
        jwks = {
            "keys": []
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode())

def main():
    """Start the OIDC Provider server"""
    print(f"🔧 Starting OIDCProvider Server")
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"Port: {PORT}")
    print(f"Issuer: {ISSUER}")
    print(f"Client ID: {CLIENT_ID}")
    print(f"Client Secret: {CLIENT_SECRET}")
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()
    print(f"✓ Discovery: {ISSUER}/.well-known/openid-configuration")
    print(f"✓ Token: {ISSUER}/token")
    print(f"✓ UserInfo: {ISSUER}/userinfo")
    print(f"✓ JWKS: {ISSUER}/jwks")
    print()
    print("Configure your .env with:")
    print(f"  OIDC_ISSUER={ISSUER}")
    print(f"  OIDC_CLIENT_ID={CLIENT_ID}")
    print(f"  OIDC_CLIENT_SECRET={CLIENT_SECRET}")
    print()
    print("Press Ctrl+C to stop...")
    print()
    
    try:
        server = HTTPServer(('0.0.0.0', PORT), OIDCHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down OIDCProvider server...")
        server.shutdown()
        print("✓ Server stopped")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
