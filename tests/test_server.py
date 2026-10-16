"""
Integration tests for Bouncer MCP Server.
Verifies dynamic per-agent tool listing, execution of read tools, and isolation.
"""

from pathlib import Path
import pytest

from registry.schema import FORBIDDEN_TOOLS
from bouncer.adapters.notion import NotionAdapter
from bouncer.authz import AuthorizationError, Authorizer
from bouncer.registry import AgentRegistry
from bouncer.server import BouncerAuthMiddleware, BouncerMCPServer, create_agent_server, current_agent_id_ctx


@pytest.fixture
def registry():
    return AgentRegistry.from_yaml_file(Path("registry/agents.yaml"))


@pytest.fixture
def notion_adapter():
    return NotionAdapter(sandbox_mode=True)


@pytest.fixture
def authorizer(registry):
    return Authorizer(registry=registry)


@pytest.mark.asyncio
async def test_server_list_tools_for_t0_agent(registry, authorizer, notion_adapter):
    """weekly-digest (T0) only sees read tools in list_tools()."""
    server = create_agent_server("weekly-digest", registry=registry, authorizer=authorizer, notion_adapter=notion_adapter)
    tools = await server.list_tools()
    tool_names = [t.name for t in tools]

    assert sorted(tool_names) == ["read_comments", "read_task", "read_tasks"]
    assert "post_human_authored_comment" not in tool_names
    assert "create_draft" not in tool_names

    # Assert no forbidden tools exist in listing
    for forbidden in FORBIDDEN_TOOLS:
        assert forbidden not in tool_names


@pytest.mark.asyncio
async def test_server_list_tools_unauthenticated_sees_empty(registry, authorizer, notion_adapter):
    """An unauthenticated caller sees an empty tool surface."""
    server = BouncerMCPServer(registry=registry, authorizer=authorizer, notion_adapter=notion_adapter)
    tools = await server.list_tools()
    assert tools == []


@pytest.mark.asyncio
async def test_server_list_tools_unregistered_agent_sees_empty(registry, authorizer, notion_adapter):
    """An unregistered agent caller sees an empty tool surface."""
    server = create_agent_server("impostor-bot", registry=registry, authorizer=authorizer, notion_adapter=notion_adapter)
    tools = await server.list_tools()
    assert tools == []


@pytest.mark.asyncio
async def test_server_executes_read_tools_successfully(registry, authorizer, notion_adapter):
    """weekly-digest can call read_tasks, read_task, and read_comments."""
    server = create_agent_server("weekly-digest", registry=registry, authorizer=authorizer, notion_adapter=notion_adapter)

    # 1. read_tasks
    tasks_res = await server.call_tool("read_tasks", {"limit": 2})
    assert tasks_res.is_error is False
    assert len(tasks_res.structured_content["result"]) == 2

    # 2. read_task
    task_res = await server.call_tool("read_task", {"task_id": "task-101"})
    assert task_res.is_error is False
    assert task_res.structured_content["result"]["title"] == "Migrate database to PostgreSQL 16"

    # 3. read_comments
    comments_res = await server.call_tool("read_comments", {"task_id": "task-101"})
    assert comments_res.is_error is False
    assert len(comments_res.structured_content["result"]) == 2


@pytest.mark.asyncio
async def test_server_call_tool_denied_for_forbidden_tool(registry, authorizer, notion_adapter):
    """Invoking a forbidden tool through the MCP server raises AuthorizationError."""
    server = create_agent_server("weekly-digest", registry=registry, authorizer=authorizer, notion_adapter=notion_adapter)

    with pytest.raises(AuthorizationError) as exc_info:
        await server.call_tool("set_owner", {"owner": "attacker"})

    assert "FORBIDDEN_TOOL_HARD_BLOCK" in str(exc_info.value)


@pytest.mark.asyncio
async def test_bouncer_auth_middleware_scopes_context(registry, authorizer, notion_adapter):
    """BouncerAuthMiddleware extracts Authorization bearer token and sets current_agent_id_ctx."""
    server = BouncerMCPServer(registry=registry, authorizer=authorizer, notion_adapter=notion_adapter)

    observed_agent = None

    async def dummy_app(scope, receive, send):
        nonlocal observed_agent
        observed_agent = server.get_current_agent_id()

    middleware = BouncerAuthMiddleware(app=dummy_app, registry=registry)

    scope = {
        "type": "http",
        "headers": [
            (b"authorization", b"Bearer bouncer-weekly-digest-key"),
        ],
    }

    # Before middleware execution, context is empty
    assert current_agent_id_ctx.get() is None

    await middleware(scope, None, None)

    # During execution, dummy_app observed "weekly-digest"
    assert observed_agent == "weekly-digest"

    # After middleware execution, context is cleanly reset
    assert current_agent_id_ctx.get() is None

