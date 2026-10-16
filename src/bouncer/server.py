"""
Bouncer MCP Server.
Implements dynamic per-agent tool filtering, authorization enforcement, and read tools.
Agents only see and can only invoke tools explicitly granted in their registry tier.
"""

from contextvars import ContextVar
from typing import Any, Dict, List, Optional
from mcp.server.mcpserver import MCPServer
from mcp.types import Tool

from registry.schema import FORBIDDEN_TOOLS
from bouncer.adapters.notion import NotionAdapter
from bouncer.authz import AuthorizationError, Authorizer
from bouncer.registry import AgentRegistry
from bouncer.tools.carry import CarryTool
from bouncer.tools.read import ReadTools


# Context variable tracking the currently authenticated caller agent
current_agent_id_ctx: ContextVar[Optional[str]] = ContextVar("current_agent_id_ctx", default=None)


class BouncerMCPServer(MCPServer):
    """
    Permission-bounded MCP Server.
    Enforces that:
      1. list_tools() returns ONLY tools granted to the active agent.
      2. Forbidden tools are never listed and have no code path.
      3. call_tool() executes through authorizer before dispatch.
    """

    def __init__(
        self,
        name: str = "bouncer",
        registry: Optional[AgentRegistry] = None,
        authorizer: Optional[Authorizer] = None,
        notion_adapter: Optional[NotionAdapter] = None,
        static_agent_id: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(name=name, **kwargs)
        self.registry = registry or AgentRegistry.from_yaml_file()
        self.authorizer = authorizer or Authorizer(registry=self.registry)
        self.notion_adapter = notion_adapter or NotionAdapter(sandbox_mode=True)
        self.read_tools = ReadTools(adapter=self.notion_adapter)
        self.carry_tool = CarryTool(
            adapter=self.notion_adapter,
            audit_sink=getattr(self.authorizer, "audit_sink", None),
        )
        self.static_agent_id = static_agent_id

        # Register server tools
        self._register_server_tools()

    def get_current_agent_id(self) -> Optional[str]:
        """Resolves active agent ID from async context or fallback static configuration."""
        return current_agent_id_ctx.get() or self.static_agent_id

    def set_active_agent(self, agent_id_or_token: str) -> None:
        """Sets the active agent ID on this server instance."""
        agent = self.registry.resolve_agent_from_bearer_token(agent_id_or_token)
        if agent:
            self.static_agent_id = agent.id
        else:
            self.static_agent_id = agent_id_or_token

    def _register_server_tools(self) -> None:
        """Registers read tools and consent-gated carry tools on the MCP server instance."""

        @self.tool(
            name="read_tasks",
            description="List tasks from the shared work system with optional status filtering.",
        )
        def read_tasks(limit: int = 10, status: Optional[str] = None) -> List[Dict[str, Any]]:
            return self.read_tools.read_tasks(limit=limit, status=status)

        @self.tool(
            name="read_task",
            description="Retrieve details and metadata for a specific task.",
        )
        def read_task(task_id: str) -> Dict[str, Any]:
            return self.read_tools.read_task(task_id=task_id)

        @self.tool(
            name="read_comments",
            description="Retrieve discussion comments associated with a specific task.",
        )
        def read_comments(task_id: str) -> List[Dict[str, Any]]:
            return self.read_tools.read_comments(task_id=task_id)

        @self.tool(
            name="post_human_authored_comment",
            description="Carries a human-authored comment into the work system guarded by a cryptographic consent token.",
        )
        def post_human_authored_comment(target_id: str, text: str, consent_token: str) -> Dict[str, Any]:
            active_agent = self.get_current_agent_id() or "unknown"
            return self.carry_tool.post_human_authored_comment(
                target_id=target_id,
                text=text,
                consent_token=consent_token,
                caller_agent_id=active_agent,
            )

    async def list_tools(self) -> List[Tool]:
        """
        Dynamically returns ONLY tools authorized for the calling agent.
        If unauthenticated or unregistered, returns an empty tool list.
        Forbidden write tools are strictly excluded under all circumstances.
        """
        all_tools = await super().list_tools()
        active_agent = self.get_current_agent_id()

        if not active_agent:
            # Unauthenticated caller sees zero tools
            return []

        agent_entry = self.registry.get_agent(active_agent)
        if not agent_entry:
            # Unregistered agent sees zero tools
            return []

        allowed_grant = set(agent_entry.tool_grant)

        # Filter strictly: must be in agent's grant AND must not be forbidden
        filtered = [
            t
            for t in all_tools
            if t.name in allowed_grant and t.name not in FORBIDDEN_TOOLS
        ]
        return filtered

    async def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None):
        """
        Intercepts tool execution, runs the authorizer gate, and records an audit row.
        """
        active_agent = self.get_current_agent_id() or "unauthenticated"
        args = arguments or {}

        # Authorize execution
        authz_result = self.authorizer.authorize(
            token_or_agent_id=active_agent,
            tool_name=name,
            arguments=args,
        )

        if not authz_result.allowed:
            raise AuthorizationError(authz_result)

        return await super().call_tool(name=name, arguments=args)


def create_agent_server(
    agent_id_or_token: str,
    registry: Optional[AgentRegistry] = None,
    notion_adapter: Optional[NotionAdapter] = None,
    authorizer: Optional[Authorizer] = None,
) -> BouncerMCPServer:
    """Helper factory that creates an MCP server pre-scoped to a specific agent identity."""
    reg = registry or AgentRegistry.from_yaml_file()
    authz = authorizer or Authorizer(registry=reg)
    server = BouncerMCPServer(
        name=f"bouncer-{agent_id_or_token}",
        registry=reg,
        authorizer=authz,
        notion_adapter=notion_adapter,
        static_agent_id=agent_id_or_token,
    )
    server.set_active_agent(agent_id_or_token)
    return server


class BouncerAuthMiddleware:
    """
    ASGI middleware that extracts Authorization headers from HTTP/SSE requests,
    resolves the agent identity from the bearer token via the registry,
    and binds current_agent_id_ctx for the duration of the request context.
    Prevents cross-tenant state bleed in multi-agent deployments.
    """

    def __init__(self, app: Any, registry: Optional[AgentRegistry] = None):
        self.app = app
        self.registry = registry or AgentRegistry.from_yaml_file()

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") in ("http", "websocket"):
            headers = dict(scope.get("headers", []))
            # Header keys in ASGI are lowercase bytes
            auth_header_bytes = headers.get(b"authorization") or headers.get(b"x-agent-token") or b""
            auth_token = auth_header_bytes.decode("utf-8", errors="ignore").strip()

            agent_id = None
            if auth_token:
                agent = self.registry.resolve_agent_from_bearer_token(auth_token)
                if agent:
                    agent_id = agent.id

            token = current_agent_id_ctx.set(agent_id)
            try:
                await self.app(scope, receive, send)
            finally:
                current_agent_id_ctx.reset(token)
        else:
            await self.app(scope, receive, send)
