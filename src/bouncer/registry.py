"""
Bouncer Agent Registry Loader & Validator.
Enforces runtime agent lookup, grant resolution, and file validation.
"""

from pathlib import Path
from typing import Dict, List, Optional, Set, Union
import yaml
from pydantic import ValidationError

from registry.schema import AgentEntry, AgentRegistryFile, FORBIDDEN_TOOLS


DEFAULT_REGISTRY_PATH = Path("registry/agents.yaml")


class RegistryValidationError(Exception):
    """Raised when the agent registry YAML fails structural or security validation."""
    pass


class AgentNotFoundError(Exception):
    """Raised when an unregistered agent identity attempts access."""
    pass


class AgentRegistry:
    """
    In-memory registry instance loaded from validated YAML.
    Enforces strict identity checks, tier queries, and forbidden tool rejections.
    """

    def __init__(self, agents: List[AgentEntry], source_path: Optional[Path] = None):
        self._agents: Dict[str, AgentEntry] = {agent.id: agent for agent in agents}
        self.source_path = source_path

    @classmethod
    def from_yaml_file(cls, path: Union[str, Path] = DEFAULT_REGISTRY_PATH) -> "AgentRegistry":
        """Loads and strictly validates an agents.yaml registry file."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Agent registry file not found at: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f)
        except Exception as e:
            raise RegistryValidationError(f"Malformed YAML in registry file {file_path}: {e}") from e

        if not isinstance(raw_data, dict):
            raise RegistryValidationError(f"Registry file root must be a YAML mapping/dictionary: {file_path}")

        try:
            validated = AgentRegistryFile.model_validate(raw_data)
        except ValidationError as e:
            raise RegistryValidationError(f"Agent registry failed validation:\n{e}") from e

        return cls(agents=validated.agents, source_path=file_path)

    def get_agent(self, agent_id: str) -> Optional[AgentEntry]:
        """Lookup an agent by ID."""
        return self._agents.get(agent_id)

    def get_agent_or_raise(self, agent_id: str) -> AgentEntry:
        """Lookup an agent by ID or raise AgentNotFoundError."""
        agent = self.get_agent(agent_id)
        if not agent:
            raise AgentNotFoundError(f"Unregistered agent identity: '{agent_id}'")
        return agent

    def list_agents(self) -> List[AgentEntry]:
        """Return all registered agents."""
        return list(self._agents.values())

    def get_tools_for_agent(self, agent_id: str) -> Set[str]:
        """Return the allowed tools list for the agent."""
        agent = self.get_agent_or_raise(agent_id)
        return set(agent.tool_grant)

    def is_tool_granted(self, agent_id: str, tool_name: str) -> bool:
        """Checks if a tool is granted for a specific agent."""
        if tool_name in FORBIDDEN_TOOLS:
            return False
        agent = self.get_agent(agent_id)
        if not agent:
            return False
        return tool_name in agent.tool_grant

    def resolve_agent_from_bearer_token(self, token: str) -> Optional[AgentEntry]:
        """
        Resolves an agent from a bearer token.
        Supports standard tokens formatted as:
          - 'agent:<agent_id>'
          - 'Bearer agent:<agent_id>'
          - 'bouncer-<agent_id>-token'
          - direct agent ID match
        """
        cleaned = token.strip()
        if cleaned.lower().startswith("bearer "):
            cleaned = cleaned[7:].strip()

        if cleaned.startswith("agent:"):
            target_id = cleaned.split(":", 1)[1]
            return self.get_agent(target_id)

        if cleaned.startswith("bouncer-") and cleaned.endswith("-token"):
            target_id = cleaned[len("bouncer-") : -len("-token")]
            return self.get_agent(target_id)

        return self.get_agent(cleaned)
