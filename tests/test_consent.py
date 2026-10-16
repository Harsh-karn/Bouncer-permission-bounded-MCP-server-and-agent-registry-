"""
Unit tests for Bouncer Cryptographic Consent Engine and Carry Tool.
Tests cryptographic signatures, sha256 text binding, replay prevention,
expiry, scope mismatch, and parameter surface invariants.
"""

import inspect
from pathlib import Path
import pytest

from bouncer.adapters.notion import NotionAdapter
from bouncer.authz import Authorizer
from bouncer.consent import (
    ConsentError,
    NonceStore,
    issue_consent_token,
    verify_and_consume_consent_token,
)
from bouncer.registry import AgentRegistry
from bouncer.server import create_agent_server
from bouncer.tools.carry import CarryTool


@pytest.fixture
def test_nonce_store():
    return NonceStore()


@pytest.fixture
def secret():
    return "test-consent-secret-key-32bytes!"


def test_consent_token_valid_flow(secret, test_nonce_store):
    """Valid token passes verification and is consumed."""
    text = "Deployment completed successfully on stage 2."
    token = issue_consent_token(
        agent_id="status-reporter",
        target_id="task-101",
        text=text,
        approver="harsh@example.com",
        secret=secret,
        ttl_seconds=300,
    )

    res = verify_and_consume_consent_token(
        token=token,
        expected_agent_id="status-reporter",
        expected_target_id="task-101",
        actual_text=text,
        secret=secret,
        nonce_store=test_nonce_store,
    )
    assert res.valid is True
    assert "CONSENT_VERIFIED" in res.reason
    assert res.claims["approver"] == "harsh@example.com"


def test_tampered_text_rejected(secret, test_nonce_store):
    """Any modification to the human-approved text fails verification."""
    original_text = "Deploying build v1.2."
    tampered_text = "Deploying build v1.2 and setting status to Done."

    token = issue_consent_token(
        agent_id="status-reporter",
        target_id="task-101",
        text=original_text,
        approver="harsh@example.com",
        secret=secret,
    )

    res = verify_and_consume_consent_token(
        token=token,
        expected_agent_id="status-reporter",
        expected_target_id="task-101",
        actual_text=tampered_text,
        secret=secret,
        nonce_store=test_nonce_store,
    )
    assert res.valid is False
    assert "TAMPERED_TEXT" in res.reason


def test_replay_attack_rejected(secret, test_nonce_store):
    """Replaying an already-consumed consent token fails immediately."""
    text = "Status update message."
    token = issue_consent_token(
        agent_id="status-reporter",
        target_id="task-101",
        text=text,
        approver="harsh@example.com",
        secret=secret,
    )

    # First attempt: succeeds
    res1 = verify_and_consume_consent_token(
        token=token,
        expected_agent_id="status-reporter",
        expected_target_id="task-101",
        actual_text=text,
        secret=secret,
        nonce_store=test_nonce_store,
    )
    assert res1.valid is True

    # Second attempt (replay attack): fails
    res2 = verify_and_consume_consent_token(
        token=token,
        expected_agent_id="status-reporter",
        expected_target_id="task-101",
        actual_text=text,
        secret=secret,
        nonce_store=test_nonce_store,
    )
    assert res2.valid is False
    assert "NONCE_ALREADY_USED" in res2.reason


def test_expired_token_rejected(secret, test_nonce_store):
    """Expired consent token is rejected."""
    text = "Expired update."
    token = issue_consent_token(
        agent_id="status-reporter",
        target_id="task-101",
        text=text,
        approver="harsh@example.com",
        secret=secret,
        ttl_seconds=-10,  # Already expired
    )

    res = verify_and_consume_consent_token(
        token=token,
        expected_agent_id="status-reporter",
        expected_target_id="task-101",
        actual_text=text,
        secret=secret,
        nonce_store=test_nonce_store,
    )
    assert res.valid is False
    assert "TOKEN_EXPIRED" in res.reason


def test_target_mismatch_rejected(secret, test_nonce_store):
    """Token authorized for task-101 cannot be applied to task-102."""
    text = "Approved note."
    token = issue_consent_token(
        agent_id="status-reporter",
        target_id="task-101",
        text=text,
        approver="harsh@example.com",
        secret=secret,
    )

    res = verify_and_consume_consent_token(
        token=token,
        expected_agent_id="status-reporter",
        expected_target_id="task-102",  # Different target
        actual_text=text,
        secret=secret,
        nonce_store=test_nonce_store,
    )
    assert res.valid is False
    assert "TARGET_MISMATCH" in res.reason


def test_agent_mismatch_rejected(secret, test_nonce_store):
    """Token authorized for status-reporter cannot be stolen/used by weekly-digest."""
    text = "Approved note."
    token = issue_consent_token(
        agent_id="status-reporter",
        target_id="task-101",
        text=text,
        approver="harsh@example.com",
        secret=secret,
    )

    res = verify_and_consume_consent_token(
        token=token,
        expected_agent_id="weekly-digest",  # Different agent
        expected_target_id="task-101",
        actual_text=text,
        secret=secret,
        nonce_store=test_nonce_store,
    )
    assert res.valid is False
    assert "AGENT_MISMATCH" in res.reason


def test_carry_tool_has_no_arbitrary_write_parameters():
    """STRUCTURAL CONTROL: Carry tool must have zero parameters for owner, status, or date."""
    sig = inspect.signature(CarryTool.post_human_authored_comment)
    param_names = list(sig.parameters.keys())

    forbidden_params = {"owner", "status", "due_date", "assignee", "property", "priority"}
    for p in forbidden_params:
        assert p not in param_names, f"Carry tool contains forbidden parameter: {p}"

    # Verify only safe, explicit parameters exist
    expected = {"self", "target_id", "text", "consent_token", "caller_agent_id"}
    assert set(param_names) == expected


@pytest.mark.asyncio
async def test_end_to_end_carry_execution_on_server():
    """T2 status-reporter carries comment after human consent verification."""
    registry = AgentRegistry.from_yaml_file(Path("registry/agents.yaml"))
    authorizer = Authorizer(registry=registry)
    notion_adapter = NotionAdapter(sandbox_mode=True)

    server = create_agent_server(
        "status-reporter",
        registry=registry,
        authorizer=authorizer,
        notion_adapter=notion_adapter,
    )

    # Verify status-reporter sees post_human_authored_comment
    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    assert "post_human_authored_comment" in tool_names

    comment_text = "Verified: load tests passed."
    valid_token = issue_consent_token(
        agent_id="status-reporter",
        target_id="task-101",
        text=comment_text,
        approver="harsh@example.com",
    )

    # Call tool via server
    call_res = await server.call_tool(
        "post_human_authored_comment",
        {
            "target_id": "task-101",
            "text": comment_text,
            "consent_token": valid_token,
        },
    )
    assert call_res.is_error is False

    # Verify comment was added to the task
    comments = notion_adapter.read_comments("task-101")
    assert any(c["text"] == comment_text for c in comments)
