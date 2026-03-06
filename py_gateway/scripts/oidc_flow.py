#!/usr/bin/env python3
import secrets
import hashlib
import base64
import http.client
import urllib.parse as up
import json

def make_pkce():
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge

def main():
    verifier, challenge = make_pkce()
    print("code_verifier:", verifier)
    print("code_challenge:", challenge)

    client_id = "test-client"
    redirect_uri = "http://localhost:9000/redirect_uri"

    # Submit login to test provider
    data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": secrets.token_urlsafe(16),
        "response_type": "code",
        "code_challenge": challenge,
        "username": "testuser",
        "roles": "admin",
    }

    # POST form to the test provider's /authorize endpoint
    form = up.urlencode(data)
    conn = http.client.HTTPConnection('localhost', 8888, timeout=10)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    conn.request('POST', '/authorize', body=form, headers=headers)
    r = conn.getresponse()
    if r.status not in (302, 303):
        print('Authorize failed, status:', r.status)
        print(r.read().decode())
        return
    location = r.getheader('Location')
    print("Redirect location:", location)
    if not location:
        print("No Location header")
        return

    # Extract code
    q = up.urlparse(location).query
    params = up.parse_qs(q)
    code = params.get('code', [None])[0]
    print("Auth code:", code)
    if not code:
        print("No code extracted")
        return

    # Exchange code at gateway
    payload = {"code": code, "code_verifier": verifier, "redirect_uri": redirect_uri}
    # POST JSON to gateway token endpoint
    conn2 = http.client.HTTPConnection('localhost', 9000, timeout=10)
    body = json.dumps(payload)
    headers2 = {'Content-Type': 'application/json'}
    conn2.request('POST', '/oidc/token', body=body, headers=headers2)
    resp = conn2.getresponse()
    resp_body = resp.read().decode()
    print('Token endpoint status:', resp.status)
    try:
        print(json.loads(resp_body))
    except Exception:
        print(resp_body)

if __name__ == '__main__':
    main()
