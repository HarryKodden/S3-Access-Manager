"""SCIM-to-IAM background sync service.

Port of internal/sync/sync.go.

For each active SCIM user:
  1. Ensure an IAM user account exists.
  2. Revoke credentials whose group memberships no longer match SCIM reality.
  3. Attach IAM inline policies derived from current group memberships.

A separate pass logs inactive IAM users (deletion is left to manual operations,
mirroring the TODO comment in the Go implementation).
"""

import json
import logging
import threading
from pathlib import Path as FSPath
from typing import Callable, Dict, List, Optional

from .backend import AWSAdmin

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SCIM filesystem helpers  (mirrors internal/store)
# ---------------------------------------------------------------------------

def _load_scim_users(users_dir: str = "./data/scim/Users") -> List[dict]:
    d = FSPath(users_dir)
    if not d.exists():
        return []
    result = []
    for p in d.glob("*.json"):
        try:
            result.append(json.loads(p.read_text()))
        except Exception as exc:
            logger.warning("Skipping unreadable SCIM user file %s: %s", p, exc)
    return result


def _get_user_group_ids(user_id: str, groups_dir: str = "./data/scim/Groups") -> List[str]:
    """Return SCIM group IDs whose members list includes *user_id*."""
    d = FSPath(groups_dir)
    if not d.exists():
        return []
    ids: List[str] = []
    for p in d.glob("*.json"):
        try:
            g = json.loads(p.read_text())
            if any(m.get("value") == user_id for m in (g.get("members") or [])):
                ids.append(g.get("id") or p.stem)
        except Exception as exc:
            logger.warning("Skipping unreadable SCIM group file %s: %s", p, exc)
    return ids


def _get_policies_for_groups(group_ids: List[str], roles_dir: str) -> List[str]:
    """Map SCIM group IDs → role policy names.

    Each role file ``{roles_dir}/{scim_group_id}.json`` looks like::

        {"name": "...", "policies": ["Read-Only", ...]}
    """
    d = FSPath(roles_dir)
    if not d.exists():
        return []
    policy_set: Dict[str, bool] = {}
    for gid in group_ids:
        role_file = d / f"{gid}.json"
        if role_file.exists():
            try:
                role = json.loads(role_file.read_text())
                for p in (role.get("policies") or []):
                    policy_set[p] = True
            except Exception as exc:
                logger.warning("Failed to read role file %s: %s", role_file, exc)
    return list(policy_set)


# ---------------------------------------------------------------------------
# SyncService
# ---------------------------------------------------------------------------

class SyncService:
    """Per-tenant SCIM → IAM synchronisation service.

    Args:
        admin:              Initialised :class:`~app.backend.AWSAdmin` (or
                            ``None`` to skip all IAM operations – useful when
                            no IAM credentials are configured for a tenant).
        policies_dir:       Directory containing IAM policy JSON files.
        roles_dir:          Directory containing role files
                            (``{scim_group_id}.json ↦ {name, policies}``).
        credentials_file:   Path to the tenant ``credentials.json`` store.
        admin_username:     IAM username of the tenant administrator; always
                            receives the ``admin`` policy.
        scim_users_dir:     Override for the global SCIM users directory.
        scim_groups_dir:    Override for the global SCIM groups directory.
    """

    def __init__(
        self,
        admin: Optional[AWSAdmin],
        policies_dir: str,
        roles_dir: str,
        credentials_file: str,
        admin_username: str = "",
        scim_users_dir: str = "./data/scim/Users",
        scim_groups_dir: str = "./data/scim/Groups",
    ) -> None:
        self._admin = admin
        self._policies_dir = policies_dir
        self._roles_dir = roles_dir
        self._credentials_file = credentials_file
        self._admin_username = admin_username
        self._scim_users_dir = scim_users_dir
        self._scim_groups_dir = scim_groups_dir
        # Serialise concurrent calls (e.g. file-change events arriving quickly)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sync_all_scim(self, health_refresher: Optional[Callable] = None) -> None:
        """Synchronise all active SCIM users to IAM (thread-safe)."""
        if self._admin is None:
            logger.debug("IAM admin not configured – skipping SCIM sync")
            return
        with self._lock:
            self._run_sync(health_refresher)

    # ------------------------------------------------------------------
    # Private implementation
    # ------------------------------------------------------------------

    def _run_sync(self, health_refresher: Optional[Callable]) -> None:
        logger.info("SCIM → IAM sync started")
        users = _load_scim_users(self._scim_users_dir)
        active_users = [u for u in users if u.get("active", True)]
        logger.info("Found %d active SCIM user(s)", len(active_users))

        for user in active_users:
            uid = user.get("id", "")
            username = user.get("userName") or uid
            if not username:
                continue
            try:
                self._sync_user_to_iam(uid, username)
            except Exception as exc:
                logger.error("Failed to sync user %r: %s", username, exc)

        try:
            self._cleanup_inactive_users(active_users)
        except Exception as exc:
            logger.error("Failed to check inactive IAM users: %s", exc)

        logger.info("SCIM → IAM sync completed")
        if health_refresher:
            try:
                health_refresher()
            except Exception:
                pass

    def _sync_user_to_iam(self, user_id: str, username: str) -> None:
        # 1. Ensure the IAM user exists.
        try:
            self._admin.create_user(username)
        except Exception as exc:
            raise RuntimeError(f"create IAM user {username!r} failed: {exc}") from exc

        # 2. Determine current SCIM group memberships.
        group_ids = _get_user_group_ids(user_id, self._scim_groups_dir)

        # 3. Revoke stale credentials.
        self._cleanup_invalid_credentials(username, group_ids)

        # 4. Attach policies derived from group memberships.
        policy_names = _get_policies_for_groups(group_ids, self._roles_dir)
        if self._admin_username and username == self._admin_username:
            policy_names = list({*policy_names, "admin"})

        for policy_name in policy_names:
            try:
                self._attach_policy_to_user(username, policy_name)
            except Exception as exc:
                logger.warning(
                    "Attach policy %r → user %r failed: %s", policy_name, username, exc
                )

        logger.debug(
            "Synced %r  groups=%s  policies=%s", username, group_ids, policy_names
        )

    def _attach_policy_to_user(self, username: str, policy_name: str) -> None:
        policy_file = FSPath(self._policies_dir) / f"{policy_name}.json"
        if not policy_file.exists():
            logger.debug("Policy file %s not found – skipping attach", policy_file)
            return
        try:
            doc = json.loads(policy_file.read_text())
            iam_policy_name = f"{username}-{policy_name}-policy".replace("@", "-")
            self._admin.iam.put_user_policy(
                UserName=username,
                PolicyName=iam_policy_name,
                PolicyDocument=json.dumps(doc),
            )
            logger.debug("Attached policy %r to user %r", policy_name, username)
        except Exception as exc:
            logger.warning(
                "put_user_policy(%r, %r) failed: %s", username, policy_name, exc
            )

    def _cleanup_invalid_credentials(
        self, username: str, current_group_ids: List[str]
    ) -> None:
        """Revoke credentials for *username* whose groups are no longer current."""
        if not self._credentials_file:
            return
        creds_path = FSPath(self._credentials_file)
        if not creds_path.exists():
            return
        try:
            all_creds: List[dict] = json.loads(creds_path.read_text())
        except Exception as exc:
            logger.error("Failed to read %s: %s", creds_path, exc)
            return

        current_set = set(current_group_ids)
        to_keep: List[dict] = []
        changed = False

        for cred in all_creds:
            if cred.get("user_id") != username:
                to_keep.append(cred)
                continue
            # All of the credential's groups must still be in the user's current groups.
            if set(cred.get("groups") or []).issubset(current_set):
                to_keep.append(cred)
                continue
            access_key = cred.get("access_key", "")
            logger.warning(
                "Revoking credential %r for %r (group membership changed)",
                cred.get("name"),
                username,
            )
            # Delete from IAM first; only drop locally on success to stay consistent.
            if access_key and self._admin:
                try:
                    self._admin.iam.delete_access_key(
                        UserName=username, AccessKeyId=access_key
                    )
                    changed = True
                except Exception as exc:
                    logger.error(
                        "Failed to delete IAM access key %r for %r: %s",
                        access_key,
                        username,
                        exc,
                    )
                    to_keep.append(cred)  # Keep locally if IAM deletion failed.
            else:
                changed = True  # Local-only credential – just drop it.

        if changed:
            try:
                creds_path.write_text(json.dumps(to_keep, indent=2))
            except Exception as exc:
                logger.error("Failed to write credentials file: %s", exc)

    def _cleanup_inactive_users(self, active_users: List[dict]) -> None:
        """Log IAM users not present in SCIM (deletion left to manual ops)."""
        if not self._admin:
            return
        active_names = {u.get("userName") or u.get("id", "") for u in active_users}
        active_names.discard("")
        try:
            resp = self._admin.iam.list_users()
            iam_users = [u.get("UserName", "") for u in resp.get("Users", [])]
        except Exception as exc:
            logger.error("Failed to list IAM users: %s", exc)
            return
        for iam_user in iam_users:
            if iam_user and iam_user not in active_names and iam_user != self._admin_username:
                logger.info(
                    "IAM user %r has no active SCIM account – manual cleanup may be needed",
                    iam_user,
                )
