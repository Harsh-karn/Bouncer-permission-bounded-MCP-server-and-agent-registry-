# ADR 0001: Why Notion as Primary Work System

## Status
Accepted

## Context
AI agents need to integrate with shared collaboration systems of record (e.g. project boards, issue trackers, documentation wikis). However, traditional enterprise systems often use coarse access tokens where possessing write access allows modifying core commitments (assignees, milestones, statuses, and due dates).

We needed a primary work-system integration for Bouncer that enables structural credential-level restriction rather than relying purely on software guards.

## Decision
We chose the **Notion API** as Bouncer's primary work-system adapter because Notion provides granular, capability-level permission isolation:
1. **Separation of Capabilities:** In Notion integration settings, an integration token can be configured with:
   - `Read content` ONLY (used by Bouncer's read tools and Tier T0 agents).
   - `Insert comments` capability (used exclusively by the isolated carrier).
   - NO `Update content` capability.
2. **Credential-Level 403 Rejection:** When an agent using a read-only credential attempts to update page properties (such as Status, Owner, or Due Date) via `PATCH /v1/pages/{id}`, the Notion API itself returns `403 Forbidden` (`RestrictedObjectError`).
3. **Defense-in-Depth:** Even if an attacker achieves complete prompt injection or arbitrary code execution within the agent loop, the bearer token transmitted to Notion structurally cannot alter page properties.

## Consequences
- Guarantees true credential-level least privilege for agents.
- Provides a verifiable proof point in credential audit scripts.
- Workspaces must explicitly share target database pages with the restricted integration.
