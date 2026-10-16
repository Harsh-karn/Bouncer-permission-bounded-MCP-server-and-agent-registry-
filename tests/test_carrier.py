"""
Unit tests for Bouncer Carrier Pattern and Credential Isolation.
Verifies that coarse-scope integrations (GitHub) enforce strict HTTP allowlisting,
and fine-grained integrations (Notion) reject property updates at the credential level.
"""

import pytest

from src.bouncer.adapters.github import (
    CarrierAllowlistViolationError,
    GitHubAdapter,
    GitHubCarrierClient,
)
from src.bouncer.adapters.notion import NotionAdapter


def test_github_carrier_allows_comment_endpoint():
    """Allowlist allows POST to issue comments endpoint."""
    client = GitHubCarrierClient()
    # Test path validation logic
    assert client.ALLOWED_PATH_PATTERN.match("/repos/owner/repo/issues/42/comments")
    assert client.ALLOWED_PATH_PATTERN.match("/repos/org-name/my.service_v2/issues/1001/comments")


@pytest.mark.parametrize(
    "forbidden_method,forbidden_path,payload",
    [
        ("PATCH", "/repos/owner/repo/issues/42", {"assignee": "attacker"}),
        ("PATCH", "/repos/owner/repo/issues/42", {"state": "closed"}),
        ("PATCH", "/repos/owner/repo/issues/42", {"labels": ["pwned"]}),
        ("POST", "/repos/owner/repo/issues", {"title": "Rogue Issue"}),
        ("DELETE", "/repos/owner/repo/issues/42/comments/1", None),
        ("PUT", "/repos/owner/repo/issues/42/lock", {"lock_reason": "off-topic"}),
        ("GET", "/repos/owner/repo/pulls", None),
    ],
)
def test_github_carrier_blocks_non_comment_requests(forbidden_method, forbidden_path, payload):
    """HARD CONTROL: Any HTTP request outside POST comment endpoint is blocked."""
    client = GitHubCarrierClient()
    with pytest.raises(CarrierAllowlistViolationError) as exc_info:
        client.execute_request(forbidden_method, forbidden_path, payload)
    assert "CARRIER BLOCKED" in str(exc_info.value)


def test_github_adapter_attempt_mutation_blocked():
    """Attempting issue property mutation through GitHubAdapter is blocked by allowlist."""
    adapter = GitHubAdapter(sandbox_mode=True)
    res = adapter.attempt_issue_mutation(
        owner="owner",
        repo="repo",
        issue_number=42,
        mutation_type="assign",
        payload={"assignees": ["attacker"]},
    )
    assert res["blocked"] is True
    assert res["error"] == "CarrierAllowlistViolationError"
    assert "CARRIER BLOCKED" in res["reason"]


def test_github_adapter_post_comment_sandbox_success():
    """Carrier successfully posts comment to issue in sandbox mode."""
    adapter = GitHubAdapter(sandbox_mode=True)
    res = adapter.post_comment("owner", "repo", 42, "Deployment verified.")
    assert res["status"] == "success"
    assert res["comment"]["body"] == "Deployment verified."

    comments = adapter.read_comments("owner", "repo", 42)
    assert len(comments) == 2
    assert comments[-1]["body"] == "Deployment verified."


def test_notion_credential_restriction_proves_403_on_update():
    """Notion read-only credential structurally returns 403 on property updates."""
    adapter = NotionAdapter(sandbox_mode=True)
    audit_res = adapter.attempt_property_update(
        task_id="task-101",
        properties={"Status": "Done"},
        credential_ref="notion_read_ro",
    )
    assert audit_res["rejected"] is True
    assert audit_res["status_code"] == 403
    assert "lacks 'Update content' capability" in audit_res["message"]
