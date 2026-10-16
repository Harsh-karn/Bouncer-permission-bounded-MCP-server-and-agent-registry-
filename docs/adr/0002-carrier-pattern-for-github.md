# ADR 0002: Carrier Pattern for Coarse-Scope APIs (GitHub Issues)

## Status
Accepted

## Context
Unlike Notion, many popular systems of record have coarse permission models. For example, GitHub's fine-grained personal access tokens and GitHub Apps bundle issue commenting into the `Issues: write` permission. Possessing `Issues: write` permits:
- Posting comments
- Changing issue state (open/closed)
- Assigning and reassigning users
- Adding, editing, and deleting labels
- Setting milestones

If an agent were given a direct GitHub token with `Issues: write`, prompt injection could instruct the agent to reassign the issue or close it, and the GitHub API would permit it.

## Decision
We implemented the **Isolated Carrier Pattern** for coarse-scope integrations like GitHub:
1. **Secret Isolation:** The GitHub token with `Issues: write` is strictly held in an isolated Carrier client and is never exposed to the agent loop, environment variables, or read tools.
2. **HTTP Client Allowlist Wrapper:** All network calls from the Carrier wrapper must pass through a strict regex allowlist validating:
   - Method: `POST` only (rejecting `PATCH`, `DELETE`, `PUT`).
   - Path Pattern: `^/repos/[^/]+/[^/]+/issues/\d+/comments$` exclusively.
3. **Cryptographic Human Consent Gate:** The Carrier only invokes `execute_request()` after cryptographic validation of a human-signed consent token binding `sha256(text)` and the specific issue target.

## Consequences
- Enables safe agent integration with systems that lack fine-grained comment-only API credentials.
- Shuts down arbitrary parameter smuggling and out-of-scope mutations at the transport wrapper layer.
- Clearly documented in architecture as code-level isolation rather than credential-level isolation.
