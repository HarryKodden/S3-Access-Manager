"""S3 proxy router – mirrors Go internal/handler/s3.go.

Endpoints under /tenant/{tenant}/s3/:
  GET    /tenant/{tenant}/s3/                     – list buckets
  GET    /tenant/{tenant}/s3/{bucket}             – list objects
  GET    /tenant/{tenant}/s3/{bucket}/{key:path}  – get object
  PUT    /tenant/{tenant}/s3/{bucket}/{key:path}  – put object
  DELETE /tenant/{tenant}/s3/{bucket}/{key:path}  – delete object (key required)
  HEAD   /tenant/{tenant}/s3/{bucket}/{key:path}  – head object

Authentication: bearer token (resolved by OIDCMiddleware) + X-S3-Credential-AccessKey header.
Authorization: policy evaluation based on the credential's groups and tenant policies.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, Header, HTTPException, Path as P, Request, Response
from fastapi.responses import StreamingResponse

from ..config import load_config

logger = logging.getLogger("py_gateway.s3")

router = APIRouter(prefix="/tenant/{tenant}/s3")


# ---------------------------------------------------------------------------
# Helpers: tenant data loading
# ---------------------------------------------------------------------------

def _tenant_cfg(tenant: str) -> dict:
    p = Path(f"./data/tenants/{tenant}/config.yaml")
    if not p.exists():
        return {}
    import yaml
    return yaml.safe_load(p.read_text()) or {}


def _credentials_for_tenant(tenant: str) -> list[dict]:
    cfg = _tenant_cfg(tenant)
    data_dir = cfg.get("data_dir") or f"./data/tenants/{tenant}"
    cred_file = cfg.get("credentials", {}).get("file") or f"{data_dir}/credentials.json"
    p = Path(cred_file)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text())
    except Exception:
        return []


def _policies_dir(tenant: str) -> Path:
    cfg = _tenant_cfg(tenant)
    data_dir = cfg.get("data_dir") or f"./data/tenants/{tenant}"
    return Path(cfg.get("policies", {}).get("directory") or f"{data_dir}/policies")


def _roles_dir(tenant: str) -> Path:
    cfg = _tenant_cfg(tenant)
    data_dir = cfg.get("data_dir") or f"./data/tenants/{tenant}"
    return Path(cfg.get("roles", {}).get("directory") or f"{data_dir}/roles")


def _load_policy_doc(tenant: str, policy_name: str) -> Optional[dict]:
    d = _policies_dir(tenant)
    for candidate in [f"{policy_name}.json", f"{policy_name.lower()}.json"]:
        p = d / candidate
        if p.exists():
            try:
                return json.loads(p.read_text())
            except Exception:
                return None
    return None


def _policies_for_groups(tenant: str, groups: list[str]) -> list[str]:
    """Resolve policy names from role files based on group/SCIM IDs."""
    d = _roles_dir(tenant)
    if not d.exists():
        return []
    role_by_id: dict[str, list[str]] = {}
    role_by_name: dict[str, list[str]] = {}
    for rf in d.glob("*.json"):
        try:
            data = json.loads(rf.read_text())
            scim_id = rf.stem
            policies = data.get("policies") or []
            role_by_id[scim_id] = policies
            if data.get("name"):
                role_by_name[data["name"]] = policies
        except Exception:
            continue

    result: set[str] = set()
    for g in groups:
        if g in role_by_id:
            result.update(role_by_id[g])
        elif g in role_by_name:
            result.update(role_by_name[g])
    return list(result)


# ---------------------------------------------------------------------------
# Policy evaluation (mirrors Go internal/policy/engine.go)
# ---------------------------------------------------------------------------

def _resource_matches(pattern: str, resource: str) -> bool:
    """Simple wildcard match: * matches any sequence of characters."""
    import fnmatch
    return fnmatch.fnmatch(resource, pattern)


def _action_matches(pattern: str, action: str) -> bool:
    import fnmatch
    return fnmatch.fnmatch(action.lower(), pattern.lower())


def _evaluate_policy(doc: dict, action: str, resource: str) -> Optional[str]:
    """
    Returns 'allow' | 'deny' | None (no match).
    Explicit Deny takes precedence inside a single document.
    """
    statements = doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]

    matched_allow = False
    for stmt in statements:
        effect = stmt.get("Effect", "")
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        action_matched = any(_action_matches(a, action) for a in actions)
        resource_matched = any(_resource_matches(r, resource) for r in resources)

        if action_matched and resource_matched:
            if effect == "Deny":
                return "deny"
            if effect == "Allow":
                matched_allow = True

    return "allow" if matched_allow else None


def _is_allowed(tenant: str, groups: list[str], action: str, resource: str) -> tuple[bool, str]:
    """
    Evaluate IAM policies for the given action+resource.
    Returns (allowed, reason).
    """
    policy_names = _policies_for_groups(tenant, groups)
    if not policy_names:
        return False, "no policies applicable for user's groups"

    any_allow = False
    for name in policy_names:
        doc = _load_policy_doc(tenant, name)
        if doc is None:
            continue
        result = _evaluate_policy(doc, action, resource)
        if result == "deny":
            return False, f"explicitly denied by policy '{name}'"
        if result == "allow":
            any_allow = True

    if any_allow:
        return True, "allowed"
    return False, "no policy allows this action"


# ---------------------------------------------------------------------------
# S3 client factory
# ---------------------------------------------------------------------------

def _s3_client(cred: dict, tenant: str):
    """Create a boto3 S3 client using the stored credential's access keys."""
    cfg = load_config("config.yaml")
    s3_cfg = cfg.get("s3") or {}

    # Tenant-level overrides take precedence
    t_cfg = _tenant_cfg(tenant)
    region = t_cfg.get("region") or s3_cfg.get("region") or "us-east-1"
    endpoint = t_cfg.get("endpoint") or s3_cfg.get("endpoint") or None

    kwargs: dict = {
        "aws_access_key_id": cred["access_key"],
        "aws_secret_access_key": cred["secret_key"],
        "region_name": region,
    }
    if cred.get("session_token"):
        kwargs["aws_session_token"] = cred["session_token"]
    if endpoint:
        kwargs["endpoint_url"] = endpoint

    import botocore.config as _bcfg
    extra = {}
    if s3_cfg.get("force_path_style", True):
        extra["config"] = _bcfg.Config(s3={"addressing_style": "path"})

    return boto3.client("s3", **kwargs, **extra)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _resolve_credential(tenant: str, access_key: str, user_email: str) -> dict:
    """Look up and validate a credential."""
    creds = _credentials_for_tenant(tenant)
    for c in creds:
        if c.get("access_key") == access_key:
            if c.get("user_id") != user_email:
                raise HTTPException(status_code=403, detail="Credential does not belong to you")
            return c
    raise HTTPException(status_code=404, detail="Credential not found")


def _user_info(request: Request) -> dict:
    ui = getattr(request.state, "userinfo", None)
    if not ui:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return ui


def _s3_error(code: str, message: str, status: int = 500) -> Response:
    xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f"<Error><Code>{code}</Code><Message>{message}</Message></Error>"
    )
    return Response(content=xml, status_code=status, media_type="application/xml")


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

@router.get("/")
def list_buckets(
    request: Request,
    tenant: str = P(...),
    x_s3_credential_access_key: Optional[str] = Header(None, alias="X-S3-Credential-AccessKey"),
):
    """List all buckets (mirrors Go ListBuckets handler)."""
    ui = _user_info(request)
    if not x_s3_credential_access_key:
        return _s3_error("InvalidRequest", "Missing X-S3-Credential-AccessKey header", 400)

    cred = _resolve_credential(tenant, x_s3_credential_access_key, ui.get("email", ""))
    groups = ui.get("groups") or []
    allowed, reason = _is_allowed(tenant, groups, "s3:ListAllMyBuckets", "*")
    if not allowed:
        return _s3_error("AccessDenied", f"Access denied: {reason}", 403)

    try:
        client = _s3_client(cred, tenant)
        result = client.list_buckets()
    except ClientError as e:
        logger.exception("list_buckets failed")
        return _s3_error("InternalError", str(e))

    buckets = [
        {"Name": b["Name"], "CreationDate": b["CreationDate"].isoformat()}
        for b in result.get("Buckets", [])
    ]
    # Return XML-compatible structure (AWS CLI expects XML, browser may accept JSON)
    import xml.etree.ElementTree as ET

    root = ET.Element("ListAllMyBucketsResult")
    bl = ET.SubElement(root, "Buckets")
    for b in buckets:
        bi = ET.SubElement(bl, "Bucket")
        ET.SubElement(bi, "Name").text = b["Name"]
        ET.SubElement(bi, "CreationDate").text = b["CreationDate"]
    xml_bytes = ET.tostring(root, encoding="unicode")
    return Response(content=xml_bytes, media_type="application/xml")


@router.get("/{bucket}")
def list_objects(
    request: Request,
    tenant: str = P(...),
    bucket: str = P(...),
    prefix: str = "",
    x_s3_credential_access_key: Optional[str] = Header(None, alias="X-S3-Credential-AccessKey"),
):
    """List objects in a bucket (mirrors Go handleListObjects)."""
    ui = _user_info(request)
    if not x_s3_credential_access_key:
        return _s3_error("InvalidRequest", "Missing X-S3-Credential-AccessKey header", 400)

    cred = _resolve_credential(tenant, x_s3_credential_access_key, ui.get("email", ""))
    groups = ui.get("groups") or []
    resource = f"arn:aws:s3:::{bucket}"
    allowed, reason = _is_allowed(tenant, groups, "s3:ListBucket", resource)
    if not allowed:
        return _s3_error("AccessDenied", f"Access denied: {reason}", 403)

    try:
        client = _s3_client(cred, tenant)
        kwargs: dict = {"Bucket": bucket}
        if prefix:
            kwargs["Prefix"] = prefix
        result = client.list_objects_v2(**kwargs)
    except ClientError as e:
        logger.exception("list_objects failed for bucket %s", bucket)
        code = e.response.get("Error", {}).get("Code", "InternalError")
        return _s3_error(code, str(e), 500)

    import xml.etree.ElementTree as ET

    root = ET.Element("ListBucketResult")
    ET.SubElement(root, "Name").text = bucket
    ET.SubElement(root, "KeyCount").text = str(result.get("KeyCount", 0))
    for obj in result.get("Contents", []):
        item = ET.SubElement(root, "Contents")
        ET.SubElement(item, "Key").text = obj["Key"]
        ET.SubElement(item, "Size").text = str(obj.get("Size", 0))
        ET.SubElement(item, "LastModified").text = obj["LastModified"].isoformat()
        if obj.get("ETag"):
            ET.SubElement(item, "ETag").text = obj["ETag"]

    xml_bytes = ET.tostring(root, encoding="unicode")
    return Response(content=xml_bytes, media_type="application/xml")


@router.get("/{bucket}/{key:path}")
def get_object(
    request: Request,
    tenant: str = P(...),
    bucket: str = P(...),
    key: str = P(...),
    x_s3_credential_access_key: Optional[str] = Header(None, alias="X-S3-Credential-AccessKey"),
):
    """Get or HEAD an object (mirrors Go handleGet)."""
    ui = _user_info(request)
    if not x_s3_credential_access_key:
        return _s3_error("InvalidRequest", "Missing X-S3-Credential-AccessKey header", 400)

    cred = _resolve_credential(tenant, x_s3_credential_access_key, ui.get("email", ""))
    groups = ui.get("groups") or []
    resource = f"arn:aws:s3:::{bucket}/{key}"
    allowed, reason = _is_allowed(tenant, groups, "s3:GetObject", resource)
    if not allowed:
        return _s3_error("AccessDenied", f"Access denied: {reason}", 403)

    try:
        client = _s3_client(cred, tenant)
        result = client.get_object(Bucket=bucket, Key=key)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "NoSuchKey")
        status = 404 if code in ("NoSuchKey", "NoSuchBucket") else 500
        return _s3_error(code, str(e), status)

    headers = {}
    if result.get("ContentType"):
        headers["Content-Type"] = result["ContentType"]
    if result.get("ETag"):
        headers["ETag"] = result["ETag"]
    if result.get("LastModified"):
        headers["Last-Modified"] = result["LastModified"].strftime("%a, %d %b %Y %H:%M:%S GMT")
    if result.get("ContentLength") is not None:
        headers["Content-Length"] = str(result["ContentLength"])

    body = result["Body"]
    return StreamingResponse(body, status_code=200, headers=headers, media_type=result.get("ContentType", "application/octet-stream"))


@router.put("/{bucket}/{key:path}")
async def put_object(
    request: Request,
    tenant: str = P(...),
    bucket: str = P(...),
    key: str = P(...),
    x_s3_credential_access_key: Optional[str] = Header(None, alias="X-S3-Credential-AccessKey"),
):
    """Upload an object (mirrors Go handlePut)."""
    ui = _user_info(request)
    if not x_s3_credential_access_key:
        return _s3_error("InvalidRequest", "Missing X-S3-Credential-AccessKey header", 400)

    cred = _resolve_credential(tenant, x_s3_credential_access_key, ui.get("email", ""))
    groups = ui.get("groups") or []
    resource = f"arn:aws:s3:::{bucket}/{key}"
    allowed, reason = _is_allowed(tenant, groups, "s3:PutObject", resource)
    if not allowed:
        return _s3_error("AccessDenied", f"Access denied: {reason}", 403)

    body = await request.body()
    content_type = request.headers.get("content-type", "application/octet-stream")

    try:
        client = _s3_client(cred, tenant)
        client.put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type)
    except ClientError as e:
        logger.exception("put_object failed for %s/%s", bucket, key)
        return _s3_error("InternalError", str(e))

    return Response(status_code=200)


@router.delete("/{bucket}/{key:path}")
def delete_object(
    request: Request,
    tenant: str = P(...),
    bucket: str = P(...),
    key: str = P(...),
    x_s3_credential_access_key: Optional[str] = Header(None, alias="X-S3-Credential-AccessKey"),
):
    """Delete an object (mirrors Go handleDelete)."""
    ui = _user_info(request)
    if not x_s3_credential_access_key:
        return _s3_error("InvalidRequest", "Missing X-S3-Credential-AccessKey header", 400)

    cred = _resolve_credential(tenant, x_s3_credential_access_key, ui.get("email", ""))
    groups = ui.get("groups") or []
    resource = f"arn:aws:s3:::{bucket}/{key}"
    allowed, reason = _is_allowed(tenant, groups, "s3:DeleteObject", resource)
    if not allowed:
        return _s3_error("AccessDenied", f"Access denied: {reason}", 403)

    try:
        client = _s3_client(cred, tenant)
        client.delete_object(Bucket=bucket, Key=key)
    except ClientError as e:
        logger.exception("delete_object failed for %s/%s", bucket, key)
        return _s3_error("InternalError", str(e))

    return Response(status_code=204)


@router.head("/{bucket}/{key:path}")
def head_object(
    request: Request,
    tenant: str = P(...),
    bucket: str = P(...),
    key: str = P(...),
    x_s3_credential_access_key: Optional[str] = Header(None, alias="X-S3-Credential-AccessKey"),
):
    """Head an object (mirrors Go handleHead)."""
    ui = _user_info(request)
    if not x_s3_credential_access_key:
        return _s3_error("InvalidRequest", "Missing X-S3-Credential-AccessKey header", 400)

    cred = _resolve_credential(tenant, x_s3_credential_access_key, ui.get("email", ""))
    groups = ui.get("groups") or []
    resource = f"arn:aws:s3:::{bucket}/{key}"
    allowed, reason = _is_allowed(tenant, groups, "s3:GetObject", resource)
    if not allowed:
        return _s3_error("AccessDenied", f"Access denied: {reason}", 403)

    try:
        client = _s3_client(cred, tenant)
        result = client.head_object(Bucket=bucket, Key=key)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "NoSuchKey")
        status = 404 if code in ("NoSuchKey", "NoSuchBucket", "404") else 500
        return Response(status_code=status)

    headers = {}
    if result.get("ContentType"):
        headers["Content-Type"] = result["ContentType"]
    if result.get("ETag"):
        headers["ETag"] = result["ETag"]
    if result.get("ContentLength") is not None:
        headers["Content-Length"] = str(result["ContentLength"])
    return Response(status_code=200, headers=headers)
