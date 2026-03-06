import os
from typing import Optional
import httpx
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import load_config


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


def require_admin(request: Request) -> dict:
    """Dependency to require global admin access.

    Checks, in order:
    - `request.state.userinfo` exists
    - If `is_admin` claim present and truthy -> allow
    - If user's email is listed in `global_admins` in config -> allow
    - If roles/groups claim contains 'admin' -> allow
    Otherwise raise 403
    """
    ui = getattr(request.state, "userinfo", None)
    if not ui:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # 1) explicit is_admin flag
    if isinstance(ui, dict) and ui.get("is_admin"):
        return ui

    # 2) check global_admins in config
    cfg = load_config("config.yaml")
    global_admins = cfg.get("global_admins") or cfg.get("globalAdmins") or []
    email = ui.get("email") if isinstance(ui, dict) else None
    if email and email in global_admins:
        return ui

    # 3) check roles/groups claim (common claim names: groups)
    groups = ui.get("groups") or ui.get("roles") or []
    if isinstance(groups, list) and "admin" in groups:
        return ui

    raise HTTPException(status_code=403, detail="Admin access required")
