from fastapi import APIRouter, Path, HTTPException, Body, Request, Depends
from pydantic import BaseModel
from typing import List, Optional, Any
from pathlib import Path
import json
import os
import secrets
import yaml

router = APIRouter(prefix="/tenant/{tenant}/settings")


def load_tenant_config(tenant: str) -> dict:
    cfg_path = Path(f"./data/tenants/{tenant}/config.yaml")
    if not cfg_path.exists():
        return {}
    return yaml.safe_load(cfg_path.read_text()) or {}


def credentials_file_for_tenant(tenant: str) -> Path:
    cfg = load_tenant_config(tenant)
    data_dir = cfg.get("data_dir") or f"./data/tenants/{tenant}"
    cred_file = cfg.get("credentials", {}).get("file") or f"{data_dir}/credentials.json"
    return Path(cred_file)


def ensure_credentials_file(path: Path):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[]")


def read_credentials(path: Path) -> List[dict]:
    ensure_credentials_file(path)
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def write_credentials(path: Path, creds: List[dict]):
    path.write_text(json.dumps(creds, indent=2))


class CreateCredentialReq(BaseModel):
    user_id: str
    name: str
    description: Optional[str] = None
    groups: Optional[List[str]] = []
    access_key: Optional[str] = None
    secret_key: Optional[str] = None


@router.get("/credentials")
def list_credentials(tenant: str = Path(...)):
    path = credentials_file_for_tenant(tenant)
    creds = read_credentials(path)
    return {"tenant": tenant, "credentials": creds}


@router.get("/credentials/{access_key}")
def get_credential(access_key: str, tenant: str = Path(...)):
    path = credentials_file_for_tenant(tenant)
    creds = read_credentials(path)
    for c in creds:
        if c.get("access_key") == access_key:
            return c
    raise HTTPException(status_code=404, detail="credential not found")


@router.post("/credentials")
def create_credential(req: CreateCredentialReq, tenant: str = Path(...)):
    path = credentials_file_for_tenant(tenant)
    creds = read_credentials(path)

    access_key = req.access_key or ("AK" + secrets.token_urlsafe(15))
    secret_key = req.secret_key or ("SK" + secrets.token_urlsafe(30))

    new_cred = {
        "id": secrets.token_urlsafe(12),
        "user_id": req.user_id,
        "name": req.name,
        "access_key": access_key,
        "secret_key": secret_key,
        "session_token": "",
        "role_name": "",
        "groups": req.groups or [],
        "backend_data": {},
        "created_at": None,
        "last_used_at": None,
        "description": req.description or "",
    }

    creds.append(new_cred)
    write_credentials(path, creds)
    return new_cred


@router.post("/credentials/update-all")
def update_all_credentials(tenant: str = Path(...)):
    # Placeholder: Recreate AWS profiles or trigger sync in Go implementation
    return {"updated": True, "tenant": tenant}


@router.delete("/credentials/{access_key}")
def delete_credential(access_key: str, tenant: str = Path(...), user_id: Optional[str] = None):
    path = credentials_file_for_tenant(tenant)
    creds = read_credentials(path)
    new_creds = []
    found = False
    for c in creds:
        if c.get("access_key") == access_key:
            if user_id and c.get("user_id") != user_id:
                raise HTTPException(status_code=403, detail="permission denied")
            found = True
            continue
        new_creds.append(c)
    if not found:
        raise HTTPException(status_code=404, detail="credential not found")
    write_credentials(path, new_creds)
    return {"deleted": True}


# Policies and roles handlers
class PolicyReq(BaseModel):
    name: str
    description: Optional[str] = None
    policy: dict


def policies_dir_for_tenant(tenant: str) -> Path:
    cfg = load_tenant_config(tenant)
    data_dir = cfg.get("data_dir") or f"./data/tenants/{tenant}"
    policies_dir = cfg.get("policies", {}).get("directory") or f"{data_dir}/policies"
    return Path(policies_dir)


def roles_dir_for_tenant(tenant: str) -> Path:
    cfg = load_tenant_config(tenant)
    data_dir = cfg.get("data_dir") or f"./data/tenants/{tenant}"
    roles_dir = cfg.get("roles", {}).get("directory") or f"{data_dir}/roles"
    return Path(roles_dir)


def list_policy_files(dirpath: Path) -> List[str]:
    if not dirpath.exists():
        return []
    return [p.stem for p in dirpath.glob("*.json") if p.is_file()]


@router.get("/policies")
def list_policies(tenant: str = Path(...)):
    d = policies_dir_for_tenant(tenant)
    return {"tenant": tenant, "policies": list_policy_files(d)}


@router.get("/policies/{name}")
def get_policy(name: str, tenant: str = Path(...)):
    d = policies_dir_for_tenant(tenant)
    p = d / f"{name}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="policy not found")
    try:
        return json.loads(p.read_text())
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read policy")


def validate_policy_json(policy: Any) -> Optional[str]:
    if not isinstance(policy, dict):
        return "policy must be an object"
    if "Version" not in policy:
        return "missing required field: Version"
    if "Statement" not in policy:
        return "missing required field: Statement"
    stmts = policy["Statement"]
    if not isinstance(stmts, list) or len(stmts) == 0:
        return "Statement must be a non-empty array"
    for i, stmt in enumerate(stmts):
        if not isinstance(stmt, dict):
            return f"statement[{i}] must be an object"
        eff = stmt.get("Effect")
        if eff not in ("Allow", "Deny"):
            return f"statement[{i}] Effect must be 'Allow' or 'Deny'"
        if "Action" not in stmt:
            return f"statement[{i}] missing required field: Action"
        actions = stmt["Action"]
        action_list = []
        if isinstance(actions, str):
            action_list = [actions]
        elif isinstance(actions, list):
            action_list = [a for a in actions if isinstance(a, str)]
        else:
            return f"statement[{i}] Action must be string or array"
        for a in action_list:
            if not a.startswith("s3:") and a != "s3:*":
                return f"statement[{i}] contains non-S3 action '{a}'"
        if "Resource" not in stmt:
            return f"statement[{i}] missing required field: Resource"
    return None


def require_tenant_admin(request: Request, tenant: str = Path(...)) -> dict:
    ui = getattr(request.state, "userinfo", None)
    if not ui:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Check per-tenant admin list
    tenant_cfg = load_tenant_config(tenant)
    tenant_admins = tenant_cfg.get("tenant_admins") or tenant_cfg.get("tenantAdmins") or []
    email = ui.get("email") if isinstance(ui, dict) else None
    if email and email in tenant_admins:
        return ui

    # Allow global admins
    global_cfg = load_config("config.yaml")
    global_admins = global_cfg.get("global_admins") or global_cfg.get("globalAdmins") or []
    if email and email in global_admins:
        return ui

    # Check roles/groups claim
    groups = ui.get("groups") or ui.get("roles") or []
    if isinstance(groups, list) and "admin" in groups:
        return ui

    raise HTTPException(status_code=403, detail="Tenant admin access required")


@router.post("/policies/validate", dependencies=[Depends(require_tenant_admin)])
def validate_policy(body: dict = Body(...), tenant: str = Path(...)):
    err = validate_policy_json(body)
    if err:
        raise HTTPException(status_code=400, detail=err)
    return {"valid": True}


@router.post("/policies", dependencies=[Depends(require_tenant_admin)])
def create_policy(req: PolicyReq, tenant: str = Path(...)):
    d = policies_dir_for_tenant(tenant)
    d.mkdir(parents=True, exist_ok=True)
    name = req.name
    p = d / f"{name}.json"
    if p.exists():
        raise HTTPException(status_code=409, detail="policy already exists")
    err = validate_policy_json(req.policy)
    if err:
        raise HTTPException(status_code=400, detail=err)
    p.write_text(json.dumps(req.policy, indent=2))
    return {"created": True, "name": name}


@router.put("/policies/{name}", dependencies=[Depends(require_tenant_admin)])
def update_policy(name: str, body: dict = Body(...), tenant: str = Path(...)):
    d = policies_dir_for_tenant(tenant)
    p = d / f"{name}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="policy not found")
    err = validate_policy_json(body)
    if err:
        raise HTTPException(status_code=400, detail=err)
    p.write_text(json.dumps(body, indent=2))
    return {"updated": True, "name": name}


@router.delete("/policies/{name}", dependencies=[Depends(require_tenant_admin)])
def delete_policy(name: str, tenant: str = Path(...)):
    d = policies_dir_for_tenant(tenant)
    p = d / f"{name}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="policy not found")
    p.unlink()
    return {"deleted": True}


@router.get("/roles")
def list_roles(tenant: str = Path(...)):
    d = roles_dir_for_tenant(tenant)
    if not d.exists():
        return {"tenant": tenant, "roles": []}
    roles = []
    for p in d.glob("*.json"):
        try:
            data = json.loads(p.read_text())
            roles.append({"scim_id": p.stem, "name": data.get("name"), "policies": data.get("policies", [])})
        except Exception:
            continue
    return {"tenant": tenant, "roles": roles}


@router.get("/roles/{name}", dependencies=[Depends(require_tenant_admin)])
def get_role(name: str, tenant: str = Path(...)):
    d = roles_dir_for_tenant(tenant)
    p = d / f"{name}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="role not found")
    try:
        return json.loads(p.read_text())
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read role")


class RoleReq(BaseModel):
    name: str
    description: Optional[str] = None
    policies: List[str] = []


@router.post("/roles", dependencies=[Depends(require_tenant_admin)])
def create_role(req: RoleReq, tenant: str = Path(...)):
    d = roles_dir_for_tenant(tenant)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{secrets.token_urlsafe(8)}.json"
    content = {"name": req.name, "description": req.description or "", "policies": req.policies}
    p.write_text(json.dumps(content, indent=2))
    return {"created": True}


@router.put("/roles/{name}", dependencies=[Depends(require_tenant_admin)])
def update_role(name: str, req: RoleReq, tenant: str = Path(...)):
    d = roles_dir_for_tenant(tenant)
    p = d / f"{name}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="role not found")
    content = {"name": req.name, "description": req.description or "", "policies": req.policies}
    p.write_text(json.dumps(content, indent=2))
    return {"updated": True}


@router.delete("/roles/{name}", dependencies=[Depends(require_tenant_admin)])
def delete_role(name: str, tenant: str = Path(...)):
    d = roles_dir_for_tenant(tenant)
    p = d / f"{name}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="role not found")
    p.unlink()
    return {"deleted": True}


@router.get("/sram-groups", dependencies=[Depends(require_tenant_admin)])
def get_sram_groups(tenant: str = Path(...)):
    cfg = load_tenant_config(tenant)
    collab = cfg.get("sram_collaboration_id", "")
    # Read global SCIM groups and filter by URN if collaboration is configured
    scim_dir = Path("./data/scim/Groups")
    groups = []
    if scim_dir.exists():
        for p in scim_dir.glob("*.json"):
            try:
                g = json.loads(p.read_text())
                urn = ""
                ext = g.get("Extensions") or g.get("extensions") or {}
                # Best-effort extraction
                if isinstance(ext, dict):
                    for k, v in ext.items():
                        if isinstance(v, dict) and "urn" in v:
                            urn = v.get("urn")
                            break
                if collab and urn and not urn.startswith(collab):
                    continue
                groups.append({"id": g.get("id"), "displayName": g.get("displayName"), "shortName": urn})
            except Exception:
                continue
    return {"Resources": groups, "totalResults": len(groups)}


# User management endpoints (tenant-scoped) - tenant admin only
@router.get("/users", dependencies=[Depends(require_tenant_admin)])
def list_users(tenant: str = Path(...)):
    users_dir = Path("./data/scim/Users")
    users = []
    if users_dir.exists():
        for p in users_dir.glob("*.json"):
            try:
                u = json.loads(p.read_text())
                users.append({
                    "id": u.get("id"),
                    "userName": u.get("userName"),
                    "displayName": u.get("displayName"),
                    "emails": u.get("emails", []),
                })
            except Exception:
                continue
    return {"tenant": tenant, "users": users}


@router.get("/users/{username}/details", dependencies=[Depends(require_tenant_admin)])
def get_user_details(username: str, tenant: str = Path(...)):
    users_dir = Path("./data/scim/Users")
    if not users_dir.exists():
        raise HTTPException(status_code=404, detail="user not found")
    for p in users_dir.glob("*.json"):
        try:
            u = json.loads(p.read_text())
            if u.get("userName") == username or u.get("id") == username:
                return u
        except Exception:
            continue
    raise HTTPException(status_code=404, detail="user not found")


@router.delete("/users/{username}", dependencies=[Depends(require_tenant_admin)])
def delete_user(username: str, tenant: str = Path(...)):
    users_dir = Path("./data/scim/Users")
    if not users_dir.exists():
        raise HTTPException(status_code=404, detail="user not found")
    for p in users_dir.glob("*.json"):
        try:
            u = json.loads(p.read_text())
            if u.get("userName") == username or u.get("id") == username:
                p.unlink()
                return {"deleted": True}
        except Exception:
            continue
    raise HTTPException(status_code=404, detail="user not found")
