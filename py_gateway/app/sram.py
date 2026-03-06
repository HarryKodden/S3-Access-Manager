"""SRAM (SURF Research Access Management) API client.

Port of internal/sram/client.go.

All SRAM REST endpoints are wrapped as methods on :class:`SRAMClient`.
``httpx`` is used for HTTP (already a project dependency).
"""

import logging
from typing import List

import httpx

logger = logging.getLogger(__name__)


class SRAMClient:
    """HTTP client for the SRAM REST API.

    Args:
        base_url: SRAM API base URL, e.g. ``https://sram.surf.nl``
        api_key:  Bearer token used to authenticate against the API.
    """

    def __init__(self, base_url: str, api_key: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._http = httpx.Client(timeout=30.0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {self._api_key}"}

    def _json_headers(self) -> dict:
        return {**self._auth(), "Content-Type": "application/json"}

    def _check(self, resp: httpx.Response, *ok: int) -> None:
        if resp.status_code not in ok:
            raise RuntimeError(
                f"SRAM API {resp.request.method} {resp.url} "
                f"returned {resp.status_code}: {resp.text[:300]}"
            )

    # ------------------------------------------------------------------
    # Collaborations
    # ------------------------------------------------------------------

    def create_collaboration(self, req: dict) -> dict:
        """Create a new SRAM collaboration."""
        resp = self._http.post(
            f"{self._base_url}/api/collaborations/v1",
            json=req,
            headers=self._json_headers(),
        )
        self._check(resp, 200, 201)
        return resp.json()

    def get_collaboration(
        self, collaboration_identifier: str, service_identifier: str = ""
    ) -> dict:
        """Retrieve details of a collaboration.

        If *service_identifier* is provided and the collaboration has active
        admins, the service is automatically connected when not yet linked.
        """
        resp = self._http.get(
            f"{self._base_url}/api/collaborations/v1/{collaboration_identifier}",
            headers=self._auth(),
        )
        self._check(resp, 200)
        collab = resp.json()
        if service_identifier:
            try:
                self._ensure_service_connected_if_admins_active(collab, service_identifier)
            except Exception as exc:
                logger.warning(
                    "Auto-connect service %s → collab %s failed: %s",
                    service_identifier,
                    collaboration_identifier,
                    exc,
                )
        return collab

    def delete_collaboration(self, collaboration_identifier: str) -> None:
        """Delete a SRAM collaboration."""
        resp = self._http.delete(
            f"{self._base_url}/api/collaborations/v1/{collaboration_identifier}",
            headers=self._auth(),
        )
        self._check(resp, 200, 204)

    def get_collaboration_global_urn(self, collaboration_identifier: str) -> str:
        """Return the ``global_urn`` field of a collaboration."""
        collab = self.get_collaboration(collaboration_identifier)
        urn = collab.get("global_urn", "")
        if not urn:
            raise RuntimeError(
                f"No global_urn found in collaboration {collaboration_identifier!r}"
            )
        logger.debug("global_urn for %s: %s", collaboration_identifier, urn)
        return urn

    # ------------------------------------------------------------------
    # Invitations
    # ------------------------------------------------------------------

    def send_invitation(self, req: dict) -> List[dict]:
        """Send invitations to join a collaboration."""
        resp = self._http.put(
            f"{self._base_url}/api/invitations/v1/collaboration_invites",
            json=req,
            headers=self._json_headers(),
        )
        self._check(resp, 200, 201)
        return resp.json()

    def get_invitation_status(self, invitation_id: str) -> dict:
        """Get the current status of a specific invitation."""
        resp = self._http.get(
            f"{self._base_url}/api/invitations/v1/{invitation_id}",
            headers=self._auth(),
        )
        self._check(resp, 200)
        return resp.json()

    def get_collaboration_invitations(self, collaboration_id: str) -> List[dict]:
        """List all invitations for a collaboration."""
        resp = self._http.get(
            f"{self._base_url}/api/invitations/v1/invitations/{collaboration_id}",
            headers=self._auth(),
        )
        self._check(resp, 200)
        return resp.json()

    # ------------------------------------------------------------------
    # Service connections
    # ------------------------------------------------------------------

    def connect_collaboration_to_service(
        self, collaboration_identifier: str, service_entity_id: str
    ) -> None:
        """Connect a collaboration to an external service."""
        resp = self._http.put(
            f"{self._base_url}/api/collaborations_services/v1"
            f"/connect_collaboration_service/{collaboration_identifier}",
            json={"service_entity_id": service_entity_id},
            headers=self._json_headers(),
        )
        self._check(resp, 200, 201)

    def is_collaboration_connected_to_service(
        self, collaboration: dict, service_entity_id: str
    ) -> bool:
        """Return ``True`` if the service is already linked to the collaboration."""
        for svc in collaboration.get("services") or []:
            if svc.get("entity_id") == service_entity_id:
                return True
        return False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _ensure_service_connected_if_admins_active(
        self, collaboration: dict, service_entity_id: str
    ) -> None:
        """Auto-connect ``service_entity_id`` when active admins are present."""
        has_active_admin = any(
            m.get("role") == "admin" and m.get("status") == "active"
            for m in (collaboration.get("collaboration_memberships") or [])
        )
        if not has_active_admin:
            return
        if self.is_collaboration_connected_to_service(collaboration, service_entity_id):
            return
        identifier = collaboration.get("identifier", "")
        logger.info(
            "Auto-connecting service %s → collaboration %s (has active admins)",
            service_entity_id,
            identifier,
        )
        self.connect_collaboration_to_service(identifier, service_entity_id)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()
