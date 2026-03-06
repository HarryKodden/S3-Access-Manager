import os
from typing import Optional
import httpx
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware


OIDC_ISSUER = os.getenv("OIDC_ISSUER", "http://localhost:8888")


async def fetch_userinfo(token: str) -> Optional[dict]:
    if not token:
        return None
    url = f"{OIDC_ISSUER}/userinfo"
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(url, headers=headers)
        except Exception:
            return None
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except Exception:
        return None


class OIDCMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth.split(None, 1)[1]
            userinfo = await fetch_userinfo(token)
            if userinfo:
                # Attach to request.state for handlers to use
                request.state.userinfo = userinfo
        return await call_next(request)


def require_auth(request: Request) -> dict:
    ui = getattr(request.state, "userinfo", None)
    if not ui:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return ui
