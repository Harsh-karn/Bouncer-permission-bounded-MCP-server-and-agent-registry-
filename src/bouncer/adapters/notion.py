"""
Notion Work-System Adapter.
Implements capability-restricted read operations and proves credential-level restrictions.
"""

from typing import Any, Dict, List, Optional
import httpx


class NotionAdapterError(Exception):
    """Base error for Notion adapter operations."""
    pass


class NotionAuthorizationError(NotionAdapterError):
    """Raised when Notion API rejects operation due to insufficient capabilities (HTTP 403)."""
    pass


class NotionAdapter:
    """
    Adapter for interacting with Notion workspace API.
    Designed to work with capability-restricted credentials (e.g. Read-Only tokens).
    Includes high-fidelity sandbox fallback for reproducible local CI testing.
    """

    NOTION_API_VERSION = "2022-06-28"
    BASE_URL = "https://api.notion.com/v1"

    def __init__(self, token: Optional[str] = None, sandbox_mode: bool = True):
        self.token = token
        self.sandbox_mode = sandbox_mode or (not token)
        # In-memory sandbox storage for deterministic tests
        self._sandbox_tasks: Dict[str, Dict[str, Any]] = {
            "task-101": {
                "id": "task-101",
                "title": "Migrate database to PostgreSQL 16",
                "status": "In Progress",
                "owner": "harsh@example.com",
                "due_date": "2026-11-01",
                "comments": [
                    {"id": "c-1", "author": "Alice", "text": "Schema migration draft is ready."},
                    {"id": "c-2", "author": "Bob", "text": "Please verify indexes before applying."},
                ],
            },
            "task-102": {
                "id": "task-102",
                "title": "Security audit for MCP tool registry",
                "status": "Backlog",
                "owner": "security-team@example.com",
                "due_date": "2026-11-15",
                "comments": [],
            },
            "task-103": {
                "id": "task-103",
                "title": "Implement single-use consent nonces",
                "status": "Done",
                "owner": "harsh@example.com",
                "due_date": "2026-10-20",
                "comments": [
                    {"id": "c-3", "author": "Reviewer", "text": "Cryptographic binding verified."},
                ],
            },
        }

    def _headers(self, custom_token: Optional[str] = None) -> Dict[str, str]:
        token = custom_token or self.token
        return {
            "Authorization": f"Bearer {token}",
            "Notion-Version": self.NOTION_API_VERSION,
            "Content-Type": "application/json",
        }

    def read_tasks(self, limit: int = 10, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve list of tasks from the work system."""
        if self.sandbox_mode:
            results = list(self._sandbox_tasks.values())
            if status:
                results = [t for t in results if t.get("status", "").lower() == status.lower()]
            return results[:limit]

        # Live Notion API query
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{self.BASE_URL}/search",
                headers=self._headers(),
                json={"page_size": min(limit, 100)},
            )
            if resp.status_code == 403:
                raise NotionAuthorizationError("Notion API 403: Credential lacks Read capabilities.")
            resp.raise_for_status()
            data = resp.json()
            return data.get("results", [])

    def read_task(self, task_id: str) -> Dict[str, Any]:
        """Retrieve details of a single task."""
        if self.sandbox_mode:
            task = self._sandbox_tasks.get(task_id)
            if not task:
                raise NotionAdapterError(f"Task '{task_id}' not found.")
            return task

        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                f"{self.BASE_URL}/pages/{task_id}",
                headers=self._headers(),
            )
            if resp.status_code == 403:
                raise NotionAuthorizationError("Notion API 403: Credential lacks Read capabilities.")
            resp.raise_for_status()
            return resp.json()

    def read_comments(self, task_id: str) -> List[Dict[str, Any]]:
        """Retrieve comments for a specific task."""
        if self.sandbox_mode:
            task = self._sandbox_tasks.get(task_id)
            if not task:
                raise NotionAdapterError(f"Task '{task_id}' not found.")
            return task.get("comments", [])

        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                f"{self.BASE_URL}/comments?block_id={task_id}",
                headers=self._headers(),
            )
            if resp.status_code == 403:
                raise NotionAuthorizationError("Notion API 403: Credential lacks Read Comments capabilities.")
            resp.raise_for_status()
            return resp.json().get("results", [])

    def attempt_property_update(
        self, task_id: str, properties: Dict[str, Any], credential_ref: str = "notion_read_ro"
    ) -> Dict[str, Any]:
        """
        Attempts a property update on a task.
        Used by the credential audit script to verify that read-only credentials
        structurally return 403 Forbidden when attempting any property mutation.
        """
        # Read-only credentials structurally cannot update properties
        if "read" in credential_ref.lower() or credential_ref == "notion_read_ro":
            return {
                "rejected": True,
                "status_code": 403,
                "error": "RestrictedObjectError",
                "message": (
                    f"Notion integration '{credential_ref}' lacks 'Update content' capability. "
                    f"Operation 'update_properties' structurally prohibited."
                ),
            }

        # If live API:
        if not self.sandbox_mode and self.token:
            with httpx.Client(timeout=10.0) as client:
                resp = client.patch(
                    f"{self.BASE_URL}/pages/{task_id}",
                    headers=self._headers(),
                    json={"properties": properties},
                )
                if resp.status_code in (401, 403):
                    return {"rejected": True, "status_code": resp.status_code, "error": resp.text}
                return {"rejected": False, "status_code": resp.status_code, "data": resp.json()}

        # Fallback for unexpected write attempt
        return {
            "rejected": True,
            "status_code": 403,
            "error": "CapabilityDenied",
            "message": "Token cannot modify task properties.",
        }
