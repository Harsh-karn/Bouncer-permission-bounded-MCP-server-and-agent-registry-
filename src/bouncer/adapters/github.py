"""
GitHub Work-System & Carrier Adapter.
Demonstrates the Coarse-Scope Contrast Case:
GitHub's 'Issues: write' permission grants broad rights (commenting, assignees, labels, state).
Therefore, Bouncer encapsulates this credential within an isolated Carrier Client Wrapper
strictly allowlisting ONLY 'POST /repos/{owner}/{repo}/issues/{issue_number}/comments'.
All other endpoints (PATCH issue, assign, close, label) are structurally blocked at the HTTP client boundary.
"""

import re
from typing import Any, Dict, List, Optional
import httpx


class CarrierAllowlistViolationError(Exception):
    """Raised when an operation violates the strict carrier HTTP method/path allowlist."""
    pass


class GitHubCarrierClient:
    """
    HTTP client wrapper enforcing an allowlist of exactly ONE method and path pattern:
    POST /repos/{owner}/{repo}/issues/{issue_number}/comments
    """

    ALLOWED_METHOD = "POST"
    ALLOWED_PATH_PATTERN = re.compile(r"^/repos/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+/issues/\d+/comments$")

    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.base_url = "https://api.github.com"

    def execute_request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Validates method and path against the strict allowlist before any network dispatch.
        """
        normalized_method = method.strip().upper()
        clean_path = path.strip()

        # Enforce Method
        if normalized_method != self.ALLOWED_METHOD:
            raise CarrierAllowlistViolationError(
                f"CARRIER BLOCKED: Method '{normalized_method}' is prohibited. "
                f"Carrier is strictly constrained to {self.ALLOWED_METHOD} only."
            )

        # Enforce Path Regex
        if not self.ALLOWED_PATH_PATTERN.match(clean_path):
            raise CarrierAllowlistViolationError(
                f"CARRIER BLOCKED: Target endpoint '{clean_path}' violates carrier allowlist. "
                f"Carrier can only post comments to '/repos/{{owner}}/{{repo}}/issues/{{number}}/comments'."
            )

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        with httpx.Client(timeout=10.0) as client:
            resp = client.request(
                method=normalized_method,
                url=f"{self.base_url}{clean_path}",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()


class GitHubAdapter:
    """
    Dual read/carrier adapter for GitHub Issues.
    Demonstrates code-level structural enforcement for work systems with coarse permissions.
    """

    def __init__(
        self,
        read_token: Optional[str] = None,
        carrier_token: Optional[str] = None,
        sandbox_mode: bool = True,
    ):
        self.read_token = read_token
        self.carrier_token = carrier_token
        self.sandbox_mode = sandbox_mode or (not read_token and not carrier_token)
        self.carrier_client = GitHubCarrierClient(token=carrier_token)

        # In-memory sandbox issues storage for deterministic tests
        self._sandbox_issues: Dict[str, Dict[str, Any]] = {
            "owner/repo#42": {
                "owner": "owner",
                "repo": "repo",
                "number": 42,
                "title": "Upgrade Redis cluster",
                "state": "open",
                "assignee": "harsh",
                "labels": ["infrastructure", "priority:medium"],
                "comments": [
                    {"id": 1, "user": "alice", "body": "Initial benchmark completed."},
                ],
            }
        }

    def _get_issue_key(self, owner: str, repo: str, issue_number: int) -> str:
        return f"{owner}/{repo}#{issue_number}"

    def read_issue(self, owner: str, repo: str, issue_number: int) -> Dict[str, Any]:
        """Read issue details (read-only capability)."""
        key = self._get_issue_key(owner, repo, issue_number)
        if self.sandbox_mode:
            issue = self._sandbox_issues.get(key)
            if not issue:
                raise ValueError(f"Issue {key} not found.")
            return issue

        # Live GitHub API
        headers = {"Accept": "application/vnd.github+json"}
        if self.read_token:
            headers["Authorization"] = f"Bearer {self.read_token}"
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}",
                headers=headers,
            )
            resp.raise_for_status()
            return resp.json()

    def read_comments(self, owner: str, repo: str, issue_number: int) -> List[Dict[str, Any]]:
        """Read comments on an issue."""
        key = self._get_issue_key(owner, repo, issue_number)
        if self.sandbox_mode:
            issue = self._sandbox_issues.get(key)
            if not issue:
                raise ValueError(f"Issue {key} not found.")
            return issue.get("comments", [])

        headers = {"Accept": "application/vnd.github+json"}
        if self.read_token:
            headers["Authorization"] = f"Bearer {self.read_token}"
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments",
                headers=headers,
            )
            resp.raise_for_status()
            return resp.json()

    def post_comment(self, owner: str, repo: str, issue_number: int, text: str) -> Dict[str, Any]:
        """
        Carrier execution: Posts a comment to the issue comments endpoint.
        Routed through the allowlisted client wrapper.
        """
        path = f"/repos/{owner}/{repo}/issues/{issue_number}/comments"

        if self.sandbox_mode:
            # Still validate against carrier allowlist even in sandbox mode to verify structural invariant
            self._validate_path_against_allowlist("POST", path)

            key = self._get_issue_key(owner, repo, issue_number)
            issue = self._sandbox_issues.get(key)
            if not issue:
                raise ValueError(f"Issue {key} not found.")
            new_comment = {
                "id": len(issue.get("comments", [])) + 1,
                "user": "bouncer-carrier[bot]",
                "body": text,
            }
            issue.setdefault("comments", []).append(new_comment)
            return {"status": "success", "comment": new_comment}

        return self.carrier_client.execute_request("POST", path, {"body": text})

    def attempt_issue_mutation(
        self,
        owner: str,
        repo: str,
        issue_number: int,
        mutation_type: str,  # 'assign', 'close', 'label'
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Verifies that any non-comment write operation is structurally blocked
        by the carrier allowlist.
        """
        path = f"/repos/{owner}/{repo}/issues/{issue_number}"
        try:
            # Attempt to execute PATCH through carrier client
            self.carrier_client.execute_request("PATCH", path, payload)
            return {"blocked": False, "status": "executed"}
        except CarrierAllowlistViolationError as e:
            return {"blocked": True, "error": "CarrierAllowlistViolationError", "reason": str(e)}

    def _validate_path_against_allowlist(self, method: str, path: str) -> None:
        if method != GitHubCarrierClient.ALLOWED_METHOD or not GitHubCarrierClient.ALLOWED_PATH_PATTERN.match(path):
            raise CarrierAllowlistViolationError(
                f"CARRIER BLOCKED: Method '{method}' on '{path}' prohibited by allowlist."
            )
