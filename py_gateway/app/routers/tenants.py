from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List
from app.config import load_config
from app.auth import require_admin

router = APIRouter()

class TenantCreate(BaseModel):
    name: str
    description: str | None = None
    admin_emails: List[str]


@router.get("/tenants")
def list_tenants():
    cfg = load_config("config.yaml")
    tenants = cfg.get("tenants", [])
    return {"tenants": tenants, "is_global_admin": False}


@router.post("/tenants", dependencies=[Depends(require_admin)])
def create_tenant(req: TenantCreate):
    # Placeholder: implement tenant creation logic (SRAM, directories, policies)
    return {"created": True, "name": req.name}
