"""
Unit tests for Bouncer Agent Registry and Pydantic Schema.
Tests structural integrity, mandatory fields, forbidden write tool rejection, and tier boundaries.
"""

from pathlib import Path
import pytest
from pydantic import ValidationError

from registry.schema import AgentEntry, AgentRegistryFile, FORBIDDEN_TOOLS, HumanGate, Tier
from src.bouncer.registry import AgentNotFoundError, AgentRegistry, RegistryValidationError


def test_valid_manifest_loads_successfully():
    """Verify default agents.yaml passes all structural and security validations."""
    registry = AgentRegistry.from_yaml_file(Path("registry/agents.yaml"))
    agents = registry.list_agents()
    assert len(agents) >= 4

    weekly_digest = registry.get_agent("weekly-digest")
    assert weekly_digest is not None
    assert weekly_digest.tier == Tier.T0
    assert weekly_digest.owner == "harsh@example.com"
    assert "read_tasks" in weekly_digest.tool_grant
    assert weekly_digest.credential_ref == "notion_read_ro"

    status_reporter = registry.get_agent("status-reporter")
    assert status_reporter is not None
    assert status_reporter.tier == Tier.T2
    assert "post_human_authored_comment" in status_reporter.tool_grant


@pytest.mark.parametrize("forbidden_tool", list(FORBIDDEN_TOOLS))
def test_hard_invariant_rejects_forbidden_tools(forbidden_tool):
    """HARD INVARIANT: No agent in any tier may ever be granted a forbidden write tool."""
    with pytest.raises(ValidationError) as exc_info:
        AgentEntry(
            id="rogue-agent",
            owner="attacker@example.com",
            tier=Tier.T2,
            tool_grant=["read_tasks", forbidden_tool],
            credential_ref="notion_read_ro",
            human_gate=HumanGate.REVIEW_BEFORE_SEND,
            eval_suite="gauntlet:rogue",
        )
    assert "HARD INVARIANT VIOLATION" in str(exc_info.value)
    assert forbidden_tool in str(exc_info.value)


def test_rejects_missing_owner():
    """Validator must reject agent missing owner field."""
    with pytest.raises(ValidationError):
        AgentEntry(
            id="no-owner-agent",
            tier=Tier.T0,
            tool_grant=["read_tasks"],
            credential_ref="notion_read_ro",
            human_gate=HumanGate.NONE,
            eval_suite="gauntlet:test",
        )


def test_rejects_missing_tier():
    """Validator must reject agent missing tier field."""
    with pytest.raises(ValidationError):
        AgentEntry(
            id="no-tier-agent",
            owner="harsh@example.com",
            tool_grant=["read_tasks"],
            credential_ref="notion_read_ro",
            human_gate=HumanGate.NONE,
            eval_suite="gauntlet:test",
        )


def test_rejects_missing_credential_ref():
    """Validator must reject agent missing credential_ref."""
    with pytest.raises(ValidationError):
        AgentEntry(
            id="no-cred-agent",
            owner="harsh@example.com",
            tier=Tier.T0,
            tool_grant=["read_tasks"],
            human_gate=HumanGate.NONE,
            eval_suite="gauntlet:test",
        )


def test_rejects_raw_secret_in_credential_ref():
    """Credential ref must be a secret identifier name, never a raw secret or API key."""
    with pytest.raises(ValidationError) as exc_info:
        AgentEntry(
            id="leaky-agent",
            owner="harsh@example.com",
            tier=Tier.T0,
            tool_grant=["read_tasks"],
            credential_ref="secret_live_abcd1234efgh5678",
            human_gate=HumanGate.NONE,
            eval_suite="gauntlet:test",
        )
    assert "credential_ref must be a secret reference name" in str(exc_info.value)


def test_tier_boundary_t0_cannot_have_write_or_draft_tools():
    """T0 agents are strictly read-only and cannot carry or draft."""
    with pytest.raises(ValidationError) as exc_info:
        AgentEntry(
            id="t0-escalator",
            owner="harsh@example.com",
            tier=Tier.T0,
            tool_grant=["read_tasks", "post_human_authored_comment"],
            credential_ref="notion_read_ro",
            human_gate=HumanGate.NONE,
            eval_suite="gauntlet:test",
        )
    assert "Tier violation" in str(exc_info.value)


def test_tier_boundary_t1_cannot_have_carry_tool():
    """T1 agents produce drafts only and cannot carry comments directly into work systems."""
    with pytest.raises(ValidationError) as exc_info:
        AgentEntry(
            id="t1-escalator",
            owner="harsh@example.com",
            tier=Tier.T1,
            tool_grant=["read_tasks", "create_draft", "post_human_authored_comment"],
            credential_ref="notion_read_ro",
            human_gate=HumanGate.REVIEW_BEFORE_SEND,
            eval_suite="gauntlet:test",
        )
    assert "Tier violation" in str(exc_info.value)


def test_t2_requires_human_gate():
    """T2 agents carry comments and require a review gate."""
    with pytest.raises(ValidationError) as exc_info:
        AgentEntry(
            id="ungated-carrier",
            owner="harsh@example.com",
            tier=Tier.T2,
            tool_grant=["read_tasks", "post_human_authored_comment"],
            credential_ref="notion_read_ro",
            human_gate=HumanGate.NONE,
            eval_suite="gauntlet:test",
        )
    assert "Tier T2 (Carry update) requires a human gate" in str(exc_info.value)


def test_bearer_token_resolution():
    """AgentRegistry correctly resolves caller identities from bearer token conventions."""
    registry = AgentRegistry.from_yaml_file(Path("registry/agents.yaml"))

    # Direct agent id
    a1 = registry.resolve_agent_from_bearer_token("weekly-digest")
    assert a1 is not None and a1.id == "weekly-digest"

    # Bearer agent:id
    a2 = registry.resolve_agent_from_bearer_token("Bearer agent:status-reporter")
    assert a2 is not None and a2.id == "status-reporter"

    # bouncer-id-token
    a3 = registry.resolve_agent_from_bearer_token("bouncer-triage-assistant-token")
    assert a3 is not None and a3.id == "triage-assistant"

    # Unknown token returns None
    assert registry.resolve_agent_from_bearer_token("Bearer agent:unknown-impostor") is None


def test_duplicate_agent_ids_rejected(tmp_path):
    """Duplicate agent IDs in YAML file must be rejected."""
    dup_yaml = tmp_path / "dup_agents.yaml"
    dup_yaml.write_text(
        """
version: "1.0"
agents:
  - id: agent-one
    owner: dev@example.com
    tier: T0
    tool_grant: [read_tasks]
    credential_ref: cred_ro
    human_gate: none
    eval_suite: gauntlet:one
  - id: agent-one
    owner: dev2@example.com
    tier: T0
    tool_grant: [read_tasks]
    credential_ref: cred_ro
    human_gate: none
    eval_suite: gauntlet:two
""",
        encoding="utf-8",
    )
    with pytest.raises(RegistryValidationError) as exc_info:
        AgentRegistry.from_yaml_file(dup_yaml)
    assert "Duplicate agent IDs found" in str(exc_info.value)


def test_unknown_agent_lookup_raises():
    """Querying an unknown agent with get_agent_or_raise raises AgentNotFoundError."""
    registry = AgentRegistry.from_yaml_file(Path("registry/agents.yaml"))
    with pytest.raises(AgentNotFoundError):
        registry.get_agent_or_raise("non-existent-agent-id")
