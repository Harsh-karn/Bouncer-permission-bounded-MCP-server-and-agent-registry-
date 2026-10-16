"""
Bouncer Authorization Engine.
Evaluates agent identity, risk tier boundaries, and tool grants on every MCP tool call.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional
from registry.schema import ALLOWED_TOOLS_BY_TIER, FORBIDDEN_TOOLS, Tier
from src.bouncer.registry import AgentRegistry
from src.bouncer.audit import AuditLog


@dataclass
class AuthzResult:
    allowed: bool
    decision: str  # "allow" | "deny"
    reason: str
    agent_id: Optional[str] = None
    tier: Optional[str] = None


class AuthorizationError(Exception):
    """Raised when an unauthorized agent attempts a forbidden or ungranted operation."""
    def __init__(self, result: AuthzResult):
        super().__init__(f"Authorization Denied: {result.reason} (agent={result.agent_id}, tier={result.tier})")
        self.result = result


class Authorizer:
    """
    Enforces authorization invariants before any tool execution.
    Writes audit records for both allowed and denied decisions.
    """

    def __init__(
        self,
        registry: AgentRegistry,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_log: Optional[AuditLog] = None,
    ):
        self.registry = registry
        self.audit_sink = audit_sink
        self.audit_log = audit_log

    def authorize(
        self,
        token_or_agent_id: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> AuthzResult:
        """
        Validates caller identity, verifies tool grant, and enforces tier boundaries.
        Returns AuthzResult with 'allow' or 'deny' and explicit reason.
        """
        clean_name = tool_name.strip().lower()
        args = arguments or {}

        # 1. HARD INVARIANT: Prohibited write tools have zero code path
        if clean_name in FORBIDDEN_TOOLS:
            res = AuthzResult(
                allowed=False,
                decision="deny",
                reason=f"FORBIDDEN_TOOL_HARD_BLOCK: Tool '{tool_name}' is in the forbidden write set.",
                agent_id=token_or_agent_id,
            )
            self._record_audit(res, tool_name, args)
            return res

        # 2. Identify agent from token or ID
        agent = self.registry.resolve_agent_from_bearer_token(token_or_agent_id)
        if not agent:
            res = AuthzResult(
                allowed=False,
                decision="deny",
                reason=f"UNREGISTERED_AGENT: Caller identity '{token_or_agent_id}' is not in the registry.",
            )
            self._record_audit(res, tool_name, args)
            return res

        # 3. Check tool is in agent's explicit grant
        if clean_name not in agent.tool_grant:
            res = AuthzResult(
                allowed=False,
                decision="deny",
                reason=f"TOOL_NOT_IN_GRANT: Tool '{tool_name}' is not in agent '{agent.id}' grant {agent.tool_grant}.",
                agent_id=agent.id,
                tier=agent.tier.value,
            )
            self._record_audit(res, tool_name, args)
            return res

        # 4. Check tier boundary
        tier_allowed = ALLOWED_TOOLS_BY_TIER.get(agent.tier, set())
        if clean_name not in tier_allowed:
            res = AuthzResult(
                allowed=False,
                decision="deny",
                reason=f"TIER_BOUNDARY_EXCEEDED: Tool '{tool_name}' exceeds Tier {agent.tier.value} policy.",
                agent_id=agent.id,
                tier=agent.tier.value,
            )
            self._record_audit(res, tool_name, args)
            return res

        # 5. Authorization granted
        res = AuthzResult(
            allowed=True,
            decision="allow",
            reason=f"AUTHORIZED_BY_GRANT: Permitted for agent '{agent.id}' (Tier {agent.tier.value}).",
            agent_id=agent.id,
            tier=agent.tier.value,
        )
        self._record_audit(res, tool_name, args)
        return res

    def authorize_or_raise(
        self,
        token_or_agent_id: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> AuthzResult:
        """Runs authorize(), raising AuthorizationError if denied."""
        result = self.authorize(token_or_agent_id, tool_name, arguments)
        if not result.allowed:
            raise AuthorizationError(result)
        return result

    def _record_audit(self, result: AuthzResult, tool_name: str, arguments: Dict[str, Any]) -> None:
        """Dispatches decision to the audit log and sink."""
        if self.audit_log:
            try:
                self.audit_log.log(
                    agent_id=result.agent_id or "unknown",
                    tool=tool_name,
                    decision=result.decision,
                    reason=result.reason,
                    arguments=arguments,
                )
            except Exception:
                pass

        if self.audit_sink:
            try:
                self.audit_sink({
                    "agent_id": result.agent_id or "unknown",
                    "tier": result.tier,
                    "tool": tool_name,
                    "decision": result.decision,
                    "reason": result.reason,
                    "arguments": arguments,
                })
            except Exception:
                pass
