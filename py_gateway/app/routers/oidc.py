from fastapi import APIRouter, HTTPException, Body, Request, Path
from pydantic import BaseModel
from typing import Optional
import httpx
from ..config import load_config
import os
import logging
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger("py_gateway.oidc")

router = APIRouter()


@router.get("/oidc-config")
def get_oidc_config():
    cfg = load_config("config.yaml")
    oidc_cfg = cfg.get("oidc", {}) or {}
    issuer = os.getenv("OIDC_ISSUER", oidc_cfg.get("issuer") or "http://localhost:8888")
    client_id = oidc_cfg.get("client_id") or oidc_cfg.get("clientID") or os.getenv("OIDC_CLIENT_ID") or ""
    scopes = oidc_cfg.get("scopes") or "openid email profile"
    # expose whether bypass mode is active so frontend can react if needed
    bypass = os.getenv("OIDC_BYPASS", "false").lower() in ("1", "true", "yes")
    bypass_info = None
    if bypass:
        bypass_info = {
            "email": os.getenv("BYPASS_EMAIL", "harry@kodden.nl"),
            "groups": [g.strip() for g in (os.getenv("BYPASS_GROUPS", "test-group") or "").split(",") if g.strip()]
        }
    return {
        "issuer": issuer,
        "client_id": client_id,
        "scopes": scopes,
        "bypass": bypass,
        "bypass_info": bypass_info,
    }


class TokenReq(BaseModel):
    code: str
    code_verifier: Optional[str] = None
    redirect_uri: str


@router.post("/oidc/token")
async def exchange_token(req: TokenReq = Body(...)):
    cfg = load_config("config.yaml")
    oidc_cfg = cfg.get("oidc", {}) or {}
    # Use an internal issuer for backend-to-backend discovery when provided
    issuer = os.getenv("OIDC_ISSUER") or oidc_cfg.get("issuer") or "http://localhost:8888"
    client_id = oidc_cfg.get("client_id") or oidc_cfg.get("clientID")
    client_secret = oidc_cfg.get("client_secret") or oidc_cfg.get("clientSecret") or ""

    # Discover token endpoint
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(discovery_url)
        except Exception as e:
            logger.exception("Failed to fetch discovery document %s", discovery_url)
            raise HTTPException(status_code=502, detail=f"Failed to discover OIDC endpoints: {e}")
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to fetch discovery document")
    try:
        discovery = r.json()
        token_endpoint = discovery.get("token_endpoint")
    except Exception as e:
        logger.exception("Invalid discovery document from %s", discovery_url)
        raise HTTPException(status_code=502, detail=f"Invalid discovery document: {e}")
    if not token_endpoint:
        raise HTTPException(status_code=502, detail="Token endpoint not found in discovery document")

    data = {
        "grant_type": "authorization_code",
        "code": req.code,
        "redirect_uri": req.redirect_uri,
        "client_id": client_id,
    }
    if req.code_verifier:
        data["code_verifier"] = req.code_verifier

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    auth = None
    if client_secret:
        # prefer Basic auth and do not send client_secret in body
        auth = (client_id, client_secret)

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            if auth:
                token_resp = await client.post(token_endpoint, data=data, auth=auth, headers=headers)
            else:
                token_resp = await client.post(token_endpoint, data=data, headers=headers)
        except Exception as e:
            logger.exception("Token request to %s failed", token_endpoint)
            raise HTTPException(status_code=502, detail=f"Token request failed: {e}")

    from fastapi.responses import Response
    content_type = token_resp.headers.get("content-type", "application/json")
    return Response(content=token_resp.content, status_code=token_resp.status_code, media_type=content_type)


@router.post("/tenant/{tenant}/oidc/token")
async def tenant_exchange_token(tenant: str = Path(...), req: TokenReq = Body(...)):
    # For now reuse global config; tenant-specific override could be implemented
    return await exchange_token(req)


@router.get("/tenant/{tenant}/oidc-config")
def get_tenant_oidc_config(tenant: str = Path(...)):
    # reuse global config for now; tenant-specific overrides may be added later
    return get_oidc_config()
