"""
Unit tests for Bouncer Authorization Interceptor.
Tests grant enforcement, tier restrictions, forbidden tool blocking, and audit sink recording.
"""

from pathlib import Path
import pytest

from registry.schema import FORBIDDEN_TOOLS
from bouncer.authz import AuthorizationError, Authorizer
from bouncer.registry import AgentRegistry


@pytest.fixture
def registry():
    return AgentRegistry.from_yaml_file(Path("registry/agents.yaml"))


@pytest.fixture
def audit_events():
    events = []
    return events


@pytest.fixture
def authorizer(registry, audit_events):
    return Authorizer(registry=registry, audit_sink=lambda ev: audit_events.append(ev))


def test_authorized_tool_allowed(authorizer, audit_events):
    """Registered agent calling a tool in its grant is allowed."""
    res = authorizer.authorize("weekly-digest", "read_tasks", {"limit": 5})
    assert res.allowed is True
    assert res.decision == "allow"
    assert "AUTHORIZED_BY_GRANT" in res.reason
    assert res.agent_id == "weekly-digest"
    assert res.tier == "T0"

    assert len(audit_events) == 1
    assert audit_events[0]["decision"] == "allow"
    assert audit_events[0]["tool"] == "read_tasks"


def test_tool_not_in_grant_denied(authorizer, audit_events):
    """Agent calling a tool outside its grant is denied."""
    res = authorizer.authorize("weekly-digest", "create_draft", {"title": "Draft"})
    assert res.allowed is False
    assert res.decision == "deny"
    assert "TOOL_NOT_IN_GRANT" in res.reason

    assert len(audit_events) == 1
    assert audit_events[0]["decision"] == "deny"
    assert "TOOL_NOT_IN_GRANT" in audit_events[0]["reason"]


def test_unregistered_agent_denied(authorizer, audit_events):
    """Unregistered caller identity is rejected."""
    res = authorizer.authorize("unknown-rogue-agent", "read_tasks")
    assert res.allowed is False
    assert res.decision == "deny"
    assert "UNREGISTERED_AGENT" in res.reason


@pytest.mark.parametrize("forbidden_tool", list(FORBIDDEN_TOOLS))
def test_forbidden_tools_hard_blocked_for_any_agent(authorizer, forbidden_tool, audit_events):
    """HARD INVARIANT: Prohibited tools are blocked immediately for any caller."""
    res = authorizer.authorize("weekly-digest", forbidden_tool, {"owner": "attacker"})
    assert res.allowed is False
    assert res.decision == "deny"
    assert "FORBIDDEN_TOOL_HARD_BLOCK" in res.reason


def test_bearer_token_authorization(authorizer):
    """Authorizer correctly resolves bearer tokens to agent grants."""
    res = authorizer.authorize("Bearer agent:status-reporter", "post_human_authored_comment")
    assert res.allowed is True
    assert res.agent_id == "status-reporter"
    assert res.tier == "T2"


def test_authorize_or_raise_throws_on_deny(authorizer):
    """authorize_or_raise raises AuthorizationError when denied."""
    with pytest.raises(AuthorizationError) as exc_info:
        authorizer.authorize_or_raise("weekly-digest", "set_owner", {"owner": "me"})
    assert "FORBIDDEN_TOOL_HARD_BLOCK" in str(exc_info.value)
