"""
Pydantic schema definitions for Bouncer Agent Registry and Risk Tiers.
Enforces structural immutability, forbidden tool prohibitions, and tier policies.
"""

from enum import Enum
import re
from typing import List, Optional, Set
from pydantic import BaseModel, Field, field_validator, model_validator


class Tier(str, Enum):
    T0 = "T0"  # Read-only internal data
    T1 = "T1"  # Produces drafts for a human (stored, not sent)
    T2 = "T2"  # Carries a human-authored update after consent
    T3 = "T3"  # External-facing output


class HumanGate(str, Enum):
    NONE = "none"
    REVIEW_BEFORE_SEND = "review_before_send"
    APPROVE_EACH_ACTION = "approve_each_action"


# HARD INVARIANT: Under NO circumstances may any agent ever have tools from this set.
FORBIDDEN_TOOLS: Set[str] = {
    "set_owner",
    "set_due_date",
    "set_status",
    "update_property",
    "update_any_property",
    "assign",
    "delete_page",
    "delete_issue",
}

# Permitted tools by tier
ALLOWED_TOOLS_BY_TIER = {
    Tier.T0: {"read_tasks", "read_task", "read_comments"},
    Tier.T1: {"read_tasks", "read_task", "read_comments", "create_draft"},
    Tier.T2: {"read_tasks", "read_task", "read_comments", "create_draft", "post_human_authored_comment"},
    Tier.T3: {
        "read_tasks",
        "read_task",
        "read_comments",
        "create_draft",
        "post_human_authored_comment",
        "send_external_message",
    },
}


class AgentEntry(BaseModel):
    """
    Representation of an authorized agent in the Bouncer registry.
    Every single field is mandatory; partial or untracked registrations are rejected.
    """
    id: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-z0-9_-]+$")
    owner: str = Field(..., min_length=3, description="Named human owner (e.g. email or username)")
    tier: Tier = Field(..., description="Risk tier: T0 (read-only), T1 (draft), T2 (carry), T3 (external)")
    tool_grant: List[str] = Field(..., min_length=1, description="List of authorized tool names")
    credential_ref: str = Field(..., min_length=2, description="Name of secret identifier, never the secret itself")
    human_gate: HumanGate = Field(..., description="Required human gate mechanism")
    eval_suite: str = Field(..., min_length=3, description="Evaluation suite identifier (e.g. gauntlet:weekly-digest)")
    description: Optional[str] = Field(None, description="Optional description of the agent's purpose")

    @field_validator("owner")
    @classmethod
    def validate_owner(cls, v: str) -> str:
        if "@" not in v and not re.match(r"^[a-zA-Z0-9_.-]+$", v):
            raise ValueError(f"Owner must be a valid email or username: {v}")
        return v.strip()

    @field_validator("credential_ref")
    @classmethod
    def validate_credential_ref(cls, v: str) -> str:
        # Prevent accidentally committing raw secret values into the registry
        raw_token_prefixes = ("secret_", "ntn_", "ghp_", "github_pat_", "sk-", "Bearer ")
        if any(v.startswith(prefix) for prefix in raw_token_prefixes) or len(v) > 80:
            raise ValueError(
                f"credential_ref must be a secret reference name (e.g. 'notion_read_ro'), "
                f"never a raw secret or API key."
            )
        return v.strip()

    @field_validator("tool_grant")
    @classmethod
    def validate_tool_grant_forbidden(cls, tools: List[str]) -> List[str]:
        # HARD RULE: The mere presence of any forbidden write tool causes validation to fail.
        violating = [t for t in tools if t.strip().lower() in FORBIDDEN_TOOLS]
        if violating:
            raise ValueError(
                f"HARD INVARIANT VIOLATION: Tool grant contains forbidden write tool(s): {violating}. "
                f"Write tools for owner, status, due dates, or page mutation have no code path in Bouncer."
            )
        return tools

    @model_validator(mode="after")
    def validate_tier_and_gates(self) -> "AgentEntry":
        # Ensure tool grants conform to the allowed tools for the specific tier
        permitted = ALLOWED_TOOLS_BY_TIER.get(self.tier, set())
        disallowed = [t for t in self.tool_grant if t not in permitted]
        if disallowed:
            raise ValueError(
                f"Tier violation: Agent '{self.id}' assigned to Tier {self.tier.value} "
                f"cannot be granted tools {disallowed}. Allowed tools for {self.tier.value}: {sorted(permitted)}"
            )

        # Gate consistency checks
        if self.tier == Tier.T2 and self.human_gate == HumanGate.NONE:
            raise ValueError("Tier T2 (Carry update) requires a human gate (review_before_send or approve_each_action).")
        if self.tier == Tier.T3 and self.human_gate != HumanGate.APPROVE_EACH_ACTION:
            raise ValueError("Tier T3 (External-facing) strictly requires human_gate='approve_each_action'.")

        return self


class AgentRegistryFile(BaseModel):
    """Container model for agents.yaml"""
    version: str = Field(default="1.0")
    agents: List[AgentEntry] = Field(..., min_length=1)

    @model_validator(mode="after")
    def validate_unique_agent_ids(self) -> "AgentRegistryFile":
        ids = [agent.id for agent in self.agents]
        duplicates = [x for x in ids if ids.count(x) > 1]
        if duplicates:
            raise ValueError(f"Duplicate agent IDs found in registry: {set(duplicates)}")
        return self
