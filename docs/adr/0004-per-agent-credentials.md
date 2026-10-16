# ADR 0004: Risk Tiers and Per-Agent Credential Isolation

## Status
Accepted

## Context
In multi-agent systems, agents frequently share a single monolithic API key or credential pool. Under this architecture:
- If a low-privilege summarization bot is compromised via prompt injection, the attacker inherits all privileges of high-tier agents.
- The system of record cannot attribute audit events to specific individual agents.
- Tool listings expose powerful mutation tools to agents that only need read access, increasing the attack surface.

## Decision
We implemented **Risk Tiers (T0 to T3)** paired with strict per-agent credential references and dynamic tool surface filtering:
1. **Four Explicit Risk Tiers:**
   - `T0` (Read-Only Internal): Allowed tools: `[read_tasks, read_task, read_comments]`.
   - `T1` (Draft Producer): Allowed tools: Read tools plus `[create_draft]` (stored locally, not sent).
   - `T2` (Carrier): Allowed tools: Read tools plus `[post_human_authored_comment]` (consent token required).
   - `T3` (External Output): Everything in T2 plus outbound broadcast tools (strict human approval per action).
2. **Per-Agent Identity & Token Scoping:** Every agent authenticates with a distinct bearer token mapped in `registry/agents.yaml`.
3. **Dynamic Protocol Hiding:** The MCP server's `list_tools()` dynamically returns *only* tools present in that agent's grant. An agent never sees tools outside its tier grant.
4. **Hard Prohibitions in Registry Validator:** The registry schema strictly fails build and startup if any agent grant contains forbidden tool names (`set_owner`, `set_due_date`, `set_status`, `update_property`, `assign`).

## Consequences
- Horizontal privilege escalation is structurally prevented.
- Complete audit trail accountability per agent.
- Prevents models from hallucinating calls to tools they cannot see or execute.
