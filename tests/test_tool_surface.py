"""
Model-Free Tool-Surface Invariant Tests.
Phase 7a Requirement:
Directly tests list_tools() for every registered agent in the registry.
Asserts that no forbidden write tool ever appears on the protocol tool surface.
Needs no model and never flakes.
"""

from pathlib import Path
import pytest

from registry.schema import FORBIDDEN_TOOLS, Tier
from bouncer.registry import AgentRegistry
from bouncer.server import BouncerMCPServer, create_agent_server


@pytest.fixture
def registry():
    return AgentRegistry.from_yaml_file(Path("registry/agents.yaml"))


def get_all_registered_agent_ids():
    reg = AgentRegistry.from_yaml_file(Path("registry/agents.yaml"))
    return [a.id for a in reg.list_agents()]


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_id", get_all_registered_agent_ids())
async def test_tool_surface_never_contains_forbidden_tools(agent_id, registry):
    """
    HARD INVARIANT: list_tools() for EVERY agent must NOT contain any forbidden write tool.
    Proves structurally that prompt injection cannot invoke a tool that does not exist.
    """
    server = create_agent_server(agent_id, registry=registry)
    tools = await server.list_tools()
    tool_names = [t.name.lower() for t in tools]

    for forbidden in FORBIDDEN_TOOLS:
        assert forbidden not in tool_names, (
            f"CRITICAL INVARIANT VIOLATION: Forbidden tool '{forbidden}' found on tool surface for agent '{agent_id}'!"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_id", get_all_registered_agent_ids())
async def test_tool_surface_only_exposes_authorized_grant(agent_id, registry):
    """Every agent's tool surface is strictly limited to their explicit YAML grant."""
    agent = registry.get_agent(agent_id)
    server = create_agent_server(agent_id, registry=registry)
    tools = await server.list_tools()
    tool_names = set(t.name for t in tools)

    # Every exposed tool must be in agent's tool_grant
    for name in tool_names:
        assert name in agent.tool_grant, (
            f"Exposed tool '{name}' is not in agent '{agent_id}' grant {agent.tool_grant}"
        )


@pytest.mark.asyncio
async def test_unauthenticated_caller_sees_empty_tool_surface(registry):
    """Callers without a valid agent bearer identity see zero tools."""
    server = BouncerMCPServer(registry=registry)
    tools = await server.list_tools()
    assert tools == [], "Unauthenticated caller must see an empty tool surface ([])"


@pytest.mark.asyncio
async def test_t0_agents_cannot_see_carry_tool(registry):
    """T0 agents (read-only) never see post_human_authored_comment."""
    server = create_agent_server("weekly-digest", registry=registry)
    tools = await server.list_tools()
    tool_names = [t.name for t in tools]

    assert "post_human_authored_comment" not in tool_names
    assert "create_draft" not in tool_names
    assert all(name.startswith("read_") for name in tool_names)


@pytest.mark.asyncio
async def test_t2_agents_see_only_read_and_carry(registry):
    """T2 status-reporter only sees read tools plus post_human_authored_comment."""
    server = create_agent_server("status-reporter", registry=registry)
    tools = await server.list_tools()
    tool_names = set(t.name for t in tools)

    expected = {"read_tasks", "read_task", "read_comments", "post_human_authored_comment"}
    assert tool_names == expected
