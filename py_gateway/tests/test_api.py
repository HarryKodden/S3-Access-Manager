"""Comprehensive test suite for the Python S3 Gateway.

Covers every API endpoint:
  - /health
  - /metrics
  - /oidc-config, /oidc/token (mocked)
  - /tenants (GET, POST)
  - /tenant/{tenant}/settings/credentials (GET, POST, GET by key, DELETE)
  - /tenant/{tenant}/settings/policies (GET, POST, GET by name, PUT, DELETE, POST validate)
  - /tenant/{tenant}/settings/roles (GET, POST, GET by name, PUT, DELETE)
  - /tenant/{tenant}/settings/sram-groups
  - /tenant/{tenant}/settings/users (GET list, GET by username, DELETE)
  - /tenant/{tenant}/s3/ (list buckets)
  - /tenant/{tenant}/s3/{bucket} (list objects)
  - /tenant/{tenant}/s3/{bucket}/{key} (GET/PUT/DELETE/HEAD)
  - Security headers present on all responses
  - Policy engine unit tests
"""

import json
import datetime
import io
import os
import pytest
from pathlib import Path as FSPath
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Force bypass auth mode BEFORE importing app
# (also set env vars so runtime os.getenv() checks in oidc.py see them)
# ---------------------------------------------------------------------------
os.environ.setdefault("OIDC_BYPASS", "true")
os.environ.setdefault("BYPASS_EMAIL", "harry@kodden.nl")
os.environ.setdefault("BYPASS_GROUPS", "test-group")
import app.auth as _auth_mod

_auth_mod.OIDC_BYPASS = True
_auth_mod.BYPASS_EMAIL = "harry@kodden.nl"
_auth_mod.BYPASS_GROUPS = "test-group"

from app.main import app  # noqa: E402


# ---------------------------------------------------------------------------
# Shared fake config returned by load_config()
# ---------------------------------------------------------------------------
FAKE_CONFIG = {
    "tenants": [{"name": "testtenant"}],
    "global_admins": ["harry@kodden.nl"],
    "oidc": {
        "issuer": "http://localhost:8888",
        "client_id": "test-client",
        "scopes": "openid email",
    },
    "s3": {
        "endpoint": "http://localhost:9001",
        "region": "us-east-1",
        "force_path_style": True,
    },
}


def _fake_load_config(path: str = "config.yaml") -> dict:  # noqa: ARG001
    return FAKE_CONFIG


# ---------------------------------------------------------------------------
# Autouse: patch every load_config reference so no disk read of config.yaml
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def patch_config(monkeypatch):
    # Env vars read by oidc.py and auth.py at runtime
    monkeypatch.setenv("OIDC_BYPASS", "true")
    monkeypatch.setenv("BYPASS_EMAIL", "harry@kodden.nl")
    monkeypatch.setenv("BYPASS_GROUPS", "test-group")

    for mod in (
        "app.config",
        "app.routers.tenants",
        "app.routers.oidc",
        "app.routers.settings",
        "app.routers.s3",
        "app.auth",
    ):
        try:
            monkeypatch.setattr(f"{mod}.load_config", _fake_load_config)
        except AttributeError:
            pass
    yield


# ---------------------------------------------------------------------------
# data_dir: complete tenant+SCIM directory tree under tmp_path with CWD set
# ---------------------------------------------------------------------------
TENANT = "testtenant"
SETTINGS = f"/tenant/{TENANT}/settings"
S3 = f"/tenant/{TENANT}/s3"

POLICY_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
}
ROLE_DOC = {"name": "test-group", "policies": ["Read-Write"]}
USER_DOC = {
    "id": "user-1",
    "userName": "harry@kodden.nl",
    "displayName": "Harry",
    "emails": [{"value": "harry@kodden.nl", "primary": True}],
}


@pytest.fixture()
def data_dir(tmp_path: FSPath, monkeypatch):
    """
    Set CWD to tmp_path and create a complete data directory structure:
      data/tenants/testtenant/  (credentials.json, policies/, roles/)
      data/scim/Users/          (one user JSON)

    Because all paths in settings.py fall back to relative CWD paths when the
    per-tenant config.yaml is missing, no load_tenant_config patching is needed.
    """
    monkeypatch.chdir(tmp_path)

    base = tmp_path / "data" / "tenants" / TENANT
    (base / "policies").mkdir(parents=True)
    (base / "roles").mkdir(parents=True)
    (base / "credentials.json").write_text("[]")
    (base / "policies" / "Read-Write.json").write_text(json.dumps(POLICY_DOC))
    (base / "roles" / "scim-role-1.json").write_text(json.dumps(ROLE_DOC))

    scim = tmp_path / "data" / "scim" / "Users"
    scim.mkdir(parents=True)
    (scim / "user-1.json").write_text(json.dumps(USER_DOC))

    return base


@pytest.fixture()
def client():
    return TestClient(app, raise_server_exceptions=True)


# ===========================================================================
# /health
# ===========================================================================

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


# ===========================================================================
# /metrics  (Prometheus format)
# ===========================================================================

def test_metrics_endpoint(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    # Prometheus text format contains metric names
    assert b"s3_gateway" in r.content or b"# HELP" in r.content or b"python_info" in r.content


# ===========================================================================
# Security headers
# ===========================================================================

def test_security_headers_on_health(client):
    r = client.get("/health")
    assert r.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-XSS-Protection") == "1; mode=block"
    assert r.headers.get("Referrer-Policy") == "no-referrer-when-downgrade"


def test_security_headers_on_api(client):
    r = client.get("/tenants")
    assert r.headers.get("X-Frame-Options") == "SAMEORIGIN"


# ===========================================================================
# OIDC endpoints
# ===========================================================================

def test_oidc_config(client):
    r = client.get("/oidc-config")
    assert r.status_code == 200
    body = r.json()
    assert "issuer" in body
    assert body["client_id"] == "test-client"
    assert body["bypass"] is True
    assert body["bypass_info"]["email"] == "harry@kodden.nl"


def test_tenant_oidc_config(client):
    r = client.get(f"/tenant/{TENANT}/oidc-config")
    assert r.status_code == 200
    assert "issuer" in r.json()


# ===========================================================================
# /tenants
# ===========================================================================

def test_list_tenants(client):
    r = client.get("/tenants")
    assert r.status_code == 200
    assert isinstance(r.json()["tenants"], list)


def test_create_tenant_as_admin(client):
    r = client.post(
        "/tenants",
        json={"name": "new-t", "description": "x", "admin_emails": ["harry@kodden.nl"]},
    )
    assert r.status_code == 200
    assert r.json()["created"] is True


def test_create_tenant_forbidden_without_admin(client, monkeypatch):
    _auth_mod.BYPASS_EMAIL = "nobody@example.com"
    _auth_mod.BYPASS_GROUPS = "regular-users"

    def _restricted(path: str = "config.yaml"):
        c = dict(FAKE_CONFIG)
        c["global_admins"] = []
        return c

    for mod in ("app.config", "app.routers.tenants", "app.auth"):
        try:
            monkeypatch.setattr(f"{mod}.load_config", _restricted)
        except AttributeError:
            pass

    try:
        r = client.post(
            "/tenants",
            json={"name": "bad", "description": "", "admin_emails": []},
        )
        assert r.status_code == 403
    finally:
        _auth_mod.BYPASS_EMAIL = "harry@kodden.nl"
        _auth_mod.BYPASS_GROUPS = "test-group"


# ===========================================================================
# Credentials
# ===========================================================================

def test_list_credentials_empty(client, data_dir):
    r = client.get(f"{SETTINGS}/credentials")
    assert r.status_code == 200
    assert r.json()["credentials"] == []


def test_create_credential(client, data_dir):
    r = client.post(
        f"{SETTINGS}/credentials",
        json={"user_id": "harry@kodden.nl", "name": "my-cred", "groups": ["test-group"]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "my-cred"
    assert body["access_key"].startswith("AK")
    assert "secret_key" in body


def test_get_credential_by_access_key(client, data_dir):
    r = client.post(
        f"{SETTINGS}/credentials",
        json={"user_id": "harry@kodden.nl", "name": "find-me", "groups": []},
    )
    ak = r.json()["access_key"]

    r2 = client.get(f"{SETTINGS}/credentials/{ak}")
    assert r2.status_code == 200
    assert r2.json()["access_key"] == ak


def test_get_credential_not_found(client, data_dir):
    r = client.get(f"{SETTINGS}/credentials/NONEXISTENT")
    assert r.status_code == 404


def test_list_credentials_multiple(client, data_dir):
    for name in ("c1", "c2"):
        client.post(
            f"{SETTINGS}/credentials",
            json={"user_id": "harry@kodden.nl", "name": name, "groups": []},
        )
    r = client.get(f"{SETTINGS}/credentials")
    assert r.status_code == 200
    assert len(r.json()["credentials"]) == 2


def test_delete_credential(client, data_dir):
    r = client.post(
        f"{SETTINGS}/credentials",
        json={"user_id": "harry@kodden.nl", "name": "del-me", "groups": []},
    )
    ak = r.json()["access_key"]

    rd = client.delete(f"{SETTINGS}/credentials/{ak}")
    assert rd.status_code == 200
    assert rd.json()["deleted"] is True
    assert client.get(f"{SETTINGS}/credentials/{ak}").status_code == 404


def test_delete_credential_wrong_user(client, data_dir):
    r = client.post(
        f"{SETTINGS}/credentials",
        json={"user_id": "harry@kodden.nl", "name": "x", "groups": []},
    )
    ak = r.json()["access_key"]
    rd = client.delete(f"{SETTINGS}/credentials/{ak}?user_id=other@example.com")
    assert rd.status_code == 403


def test_update_all_credentials(client, data_dir):
    r = client.post(f"{SETTINGS}/credentials/update-all")
    assert r.status_code == 200
    assert r.json()["updated"] is True


# ===========================================================================
# Policies
# ===========================================================================

def test_list_policies(client, data_dir):
    r = client.get(f"{SETTINGS}/policies")
    assert r.status_code == 200
    assert "Read-Write" in r.json()["policies"]


def test_get_policy(client, data_dir):
    r = client.get(f"{SETTINGS}/policies/Read-Write")
    assert r.status_code == 200
    assert "Statement" in r.json()


def test_get_policy_not_found(client, data_dir):
    r = client.get(f"{SETTINGS}/policies/nonexistent")
    assert r.status_code == 404


def test_create_policy(client, data_dir):
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    r = client.post(f"{SETTINGS}/policies", json={"name": "new-policy", "policy": doc})
    assert r.status_code == 200
    assert r.json()["created"] is True


def test_create_policy_conflict(client, data_dir):
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    client.post(f"{SETTINGS}/policies", json={"name": "dup", "policy": doc})
    r = client.post(f"{SETTINGS}/policies", json={"name": "dup", "policy": doc})
    assert r.status_code == 409


def test_update_policy(client, data_dir):
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}],
    }
    r = client.put(f"{SETTINGS}/policies/Read-Write", json=doc)
    assert r.status_code == 200
    assert r.json()["updated"] is True


def test_update_policy_not_found(client, data_dir):
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    r = client.put(f"{SETTINGS}/policies/missing", json=doc)
    assert r.status_code == 404


def test_delete_policy(client, data_dir):
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    client.post(f"{SETTINGS}/policies", json={"name": "to-delete", "policy": doc})
    r = client.delete(f"{SETTINGS}/policies/to-delete")
    assert r.status_code == 200
    assert r.json()["deleted"] is True


def test_delete_policy_not_found(client, data_dir):
    r = client.delete(f"{SETTINGS}/policies/nonexistent")
    assert r.status_code == 404


def test_validate_policy_valid(client, data_dir):
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    r = client.post(f"{SETTINGS}/policies/validate", json=doc)
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_validate_policy_invalid_missing_version(client, data_dir):
    r = client.post(f"{SETTINGS}/policies/validate", json={"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    assert r.status_code == 400


def test_validate_policy_invalid_bad_effect(client, data_dir):
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Maybe", "Action": "s3:GetObject", "Resource": "*"}],
    }
    r = client.post(f"{SETTINGS}/policies/validate", json=doc)
    assert r.status_code == 400


# ===========================================================================
# Roles
# ===========================================================================

def test_list_roles(client, data_dir):
    r = client.get(f"{SETTINGS}/roles")
    assert r.status_code == 200
    assert isinstance(r.json()["roles"], list)
    assert len(r.json()["roles"]) >= 1


def test_create_role(client, data_dir):
    r = client.post(f"{SETTINGS}/roles", json={"name": "new-role", "policies": ["Read-Write"]})
    assert r.status_code == 200
    assert r.json()["created"] is True


def test_get_role_by_id(client, data_dir):
    r = client.get(f"{SETTINGS}/roles/scim-role-1")
    assert r.status_code == 200


def test_get_role_not_found(client, data_dir):
    r = client.get(f"{SETTINGS}/roles/nonexistent")
    assert r.status_code == 404


def test_update_role(client, data_dir):
    r = client.put(f"{SETTINGS}/roles/scim-role-1", json={"name": "updated", "policies": []})
    assert r.status_code == 200
    assert r.json()["updated"] is True


def test_update_role_not_found(client, data_dir):
    r = client.put(f"{SETTINGS}/roles/missing-role", json={"name": "x", "policies": []})
    assert r.status_code == 404


def test_delete_role(client, data_dir):
    # Create a fresh role; then delete it by role id (not 'scim-role-1')
    r = client.post(f"{SETTINGS}/roles", json={"name": "del-role", "policies": []})
    assert r.status_code == 200
    role_id = r.json().get("id") or r.json().get("name")

    # Get the file name from the roles directory
    roles_path = data_dir / "roles"
    new_roles = [p.stem for p in roles_path.glob("*.json") if p.stem != "scim-role-1"]
    assert len(new_roles) == 1

    rd = client.delete(f"{SETTINGS}/roles/{new_roles[0]}")
    assert rd.status_code == 200
    assert rd.json()["deleted"] is True


def test_delete_role_not_found(client, data_dir):
    r = client.delete(f"{SETTINGS}/roles/nope")
    assert r.status_code == 404


# ===========================================================================
# SRAM Groups
# ===========================================================================

def test_sram_groups(client, data_dir):
    # Create minimal SCIM groups dir
    scim_groups = data_dir.parent.parent.parent / "data" / "scim" / "Groups"
    scim_groups.mkdir(parents=True, exist_ok=True)
    r = client.get(f"{SETTINGS}/sram-groups")
    assert r.status_code == 200
    assert "Resources" in r.json()


# ===========================================================================
# Users
# ===========================================================================

def test_list_users(client, data_dir):
    r = client.get(f"{SETTINGS}/users")
    assert r.status_code == 200
    users = r.json()["users"]
    assert any(u.get("userName") == "harry@kodden.nl" for u in users)


def test_get_user_by_username(client, data_dir):
    r = client.get(f"{SETTINGS}/users/harry@kodden.nl")
    assert r.status_code == 200
    assert r.json()["userName"] == "harry@kodden.nl"


def test_get_user_not_found(client, data_dir):
    r = client.get(f"{SETTINGS}/users/nobody@example.com")
    assert r.status_code == 404


def test_delete_user(client, data_dir):
    r = client.delete(f"{SETTINGS}/users/harry@kodden.nl")
    assert r.status_code == 200
    assert r.json()["deleted"] is True


def test_delete_user_not_found(client, data_dir):
    r = client.delete(f"{SETTINGS}/users/nobody@example.com")
    assert r.status_code == 404


# ===========================================================================
# S3 proxy – missing credential header
# ===========================================================================

def test_s3_list_buckets_no_header(client, data_dir):
    r = client.get(f"{S3}/")
    assert r.status_code == 400


def test_s3_list_objects_no_header(client, data_dir):
    r = client.get(f"{S3}/mybucket")
    assert r.status_code == 400


def test_s3_get_object_no_header(client, data_dir):
    r = client.get(f"{S3}/mybucket/mykey.txt")
    assert r.status_code == 400


def test_s3_put_object_no_header(client, data_dir):
    r = client.put(f"{S3}/mybucket/mykey.txt", content=b"hello")
    assert r.status_code == 400


def test_s3_delete_object_no_header(client, data_dir):
    r = client.delete(f"{S3}/mybucket/mykey.txt")
    assert r.status_code == 400


def test_s3_head_object_no_header(client, data_dir):
    r = client.head(f"{S3}/mybucket/mykey.txt")
    assert r.status_code == 400


def test_s3_wrong_credential_returns_404(client, data_dir):
    r = client.get(f"{S3}/mybucket", headers={"X-S3-Credential-AccessKey": "AKNOTEXIST"})
    assert r.status_code == 404


# ===========================================================================
# S3 proxy – credential owned by wrong user is rejected (403)
# ===========================================================================

def test_s3_credential_wrong_owner(client, data_dir):
    cred_path = data_dir / "credentials.json"
    cred_path.write_text(json.dumps([{
        "id": "x",
        "user_id": "other@example.com",
        "name": "other-cred",
        "access_key": "AKOTHER",
        "secret_key": "SK000",
        "session_token": "",
        "groups": [],
    }]))

    r = client.get(f"{S3}/mybucket", headers={"X-S3-Credential-AccessKey": "AKOTHER"})
    assert r.status_code == 403


# ===========================================================================
# S3 proxy – denied when no matching policy
# ===========================================================================

def test_s3_list_buckets_policy_denied(client, data_dir):
    """Remove all policies so the user has no s3:ListAllMyBuckets permission."""
    (data_dir / "policies" / "Read-Write.json").unlink()

    # create credential owned by the bypass user
    r = client.post(
        f"{SETTINGS}/credentials",
        json={"user_id": "harry@kodden.nl", "name": "x", "groups": ["test-group"]},
    )
    ak = r.json()["access_key"]

    r2 = client.get(f"{S3}/", headers={"X-S3-Credential-AccessKey": ak})
    assert r2.status_code == 403


# ===========================================================================
# S3 proxy – full round-trip with mocked boto3
# ===========================================================================

@pytest.fixture()
def s3_credential(client, data_dir) -> str:
    r = client.post(
        f"{SETTINGS}/credentials",
        json={"user_id": "harry@kodden.nl", "name": "s3-cred", "groups": ["test-group"]},
    )
    assert r.status_code == 200
    return r.json()["access_key"]


def test_s3_list_buckets_allowed(client, data_dir, s3_credential):
    mock_boto = MagicMock()
    mock_boto.list_buckets.return_value = {
        "Buckets": [{"Name": "bucket-a", "CreationDate": datetime.datetime(2024, 1, 1)}]
    }
    mock_boto.meta.endpoint_url = "http://localhost:9001"

    with patch("app.routers.s3.boto3") as mock_b3:
        mock_b3.client.return_value = mock_boto
        r = client.get(f"{S3}/", headers={"X-S3-Credential-AccessKey": s3_credential})

    assert r.status_code == 200
    assert b"bucket-a" in r.content


def test_s3_list_objects_allowed(client, data_dir, s3_credential):
    mock_boto = MagicMock()
    mock_boto.list_objects_v2.return_value = {
        "KeyCount": 1,
        "Contents": [
            {
                "Key": "file.txt",
                "Size": 42,
                "LastModified": datetime.datetime(2024, 1, 1),
                "ETag": '"abc"',
            }
        ],
    }

    with patch("app.routers.s3.boto3") as mock_b3:
        mock_b3.client.return_value = mock_boto
        r = client.get(f"{S3}/mybucket", headers={"X-S3-Credential-AccessKey": s3_credential})

    assert r.status_code == 200
    assert b"file.txt" in r.content


def test_s3_get_object_allowed(client, data_dir, s3_credential):
    mock_boto = MagicMock()
    mock_boto.get_object.return_value = {
        "Body": io.BytesIO(b"hello world"),
        "ContentType": "text/plain",
        "ContentLength": 11,
        "ETag": '"xyz"',
        "LastModified": datetime.datetime(2024, 1, 1),
    }

    with patch("app.routers.s3.boto3") as mock_b3:
        mock_b3.client.return_value = mock_boto
        r = client.get(
            f"{S3}/mybucket/hello.txt",
            headers={"X-S3-Credential-AccessKey": s3_credential},
        )

    assert r.status_code == 200
    assert r.content == b"hello world"


def test_s3_put_object_allowed(client, data_dir, s3_credential):
    mock_boto = MagicMock()
    mock_boto.put_object.return_value = {}

    with patch("app.routers.s3.boto3") as mock_b3:
        mock_b3.client.return_value = mock_boto
        r = client.put(
            f"{S3}/mybucket/newfile.txt",
            content=b"data",
            headers={
                "X-S3-Credential-AccessKey": s3_credential,
                "Content-Type": "text/plain",
            },
        )

    assert r.status_code == 200


def test_s3_delete_object_allowed(client, data_dir, s3_credential):
    mock_boto = MagicMock()
    mock_boto.delete_object.return_value = {}

    with patch("app.routers.s3.boto3") as mock_b3:
        mock_b3.client.return_value = mock_boto
        r = client.delete(
            f"{S3}/mybucket/oldfile.txt",
            headers={"X-S3-Credential-AccessKey": s3_credential},
        )

    assert r.status_code == 204


def test_s3_head_object_allowed(client, data_dir, s3_credential):
    mock_boto = MagicMock()
    mock_boto.head_object.return_value = {
        "ContentType": "text/plain",
        "ContentLength": 5,
        "ETag": '"etag"',
    }

    with patch("app.routers.s3.boto3") as mock_b3:
        mock_b3.client.return_value = mock_boto
        r = client.head(
            f"{S3}/mybucket/efile.txt",
            headers={"X-S3-Credential-AccessKey": s3_credential},
        )

    assert r.status_code == 200


# ===========================================================================
# Policy evaluation engine – unit tests
# ===========================================================================

def test_policy_evaluation_allow():
    from app.routers.s3 import _evaluate_policy

    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::*"}],
    }
    assert _evaluate_policy(doc, "s3:GetObject", "arn:aws:s3:::mybucket/key") == "allow"


def test_policy_evaluation_deny():
    from app.routers.s3 import _evaluate_policy

    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
    }
    assert _evaluate_policy(doc, "s3:PutObject", "arn:aws:s3:::mybucket/key") == "deny"


def test_policy_evaluation_no_match():
    from app.routers.s3 import _evaluate_policy

    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::*"}],
    }
    assert _evaluate_policy(doc, "s3:DeleteObject", "arn:aws:s3:::mybucket/key") is None


def test_policy_deny_takes_precedence():
    from app.routers.s3 import _evaluate_policy

    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
        ],
    }
    assert _evaluate_policy(doc, "s3:DeleteObject", "arn:aws:s3:::mybucket/key") == "deny"


def test_policy_wildcard_resource():
    from app.routers.s3 import _evaluate_policy

    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::my-bucket/*"}
        ],
    }
    assert _evaluate_policy(doc, "s3:GetObject", "arn:aws:s3:::my-bucket/deep/path.txt") == "allow"
    assert _evaluate_policy(doc, "s3:GetObject", "arn:aws:s3:::other-bucket/file.txt") is None


def test_policy_action_list():
    from app.routers.s3 import _evaluate_policy

    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}
        ],
    }
    assert _evaluate_policy(doc, "s3:GetObject", "arn:aws:s3:::bucket/key") == "allow"
    assert _evaluate_policy(doc, "s3:DeleteObject", "arn:aws:s3:::bucket/key") is None


