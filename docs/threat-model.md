# Threat Model: Bouncer Agent Governance System

> **Status:** Enforced  
> **Approach:** Inversion-First Security Engineering (Start from failure modes and work backward to structural controls)  
> **Core Security Thesis:** *"Prompt injection cannot produce a forbidden write, because no tool and no credential in the agent's grant can perform it."*

---

## 1. Executive Summary & Philosophy

Traditional AI agent security relies on prompt-based guardrails (e.g., "Do not change assignees", "You are an assistant who only reports"). Prompt boundaries fail under prompt injection, jailbreaks, indirect data poisoning, or stochastic model behavior.

**Bouncer** eliminates reliance on prompt compliance by enforcing governance **structurally** at three non-bypassable layers:
1. **Tool Surface Layer:** The write tool does not exist. The agent cannot invoke what does not exist in the server's protocol surface.
2. **Credential Layer:** The bearer token used by the agent lacks write/update privileges at the work system API level. Even if the agent synthesized arbitrary raw HTTP requests, the API rejects them with `403 Forbidden`.
3. **Cryptographic Consent Gate:** The only write-like operation permitted (`post_human_authored_comment`) requires a signed, short-lived, single-use cryptographic consent token explicitly binding the `sha256` hash of the human-approved text. Any alteration of the text invalidates the token.

---

## 2. System Architecture & Trust Boundaries

```
+-----------------------------------------------------------------------------------+
| UNTRUSTED ENVIRONMENT                                                             |
|                                                                                   |
|  +-------------------------+               +-----------------------------------+  |
|  |       Agent (LLM)       |               |     Adversarial Task Content      |  |
|  | - Potential prompt inj. |               | - Indirect prompt injection       |  |
|  | - Hallucinated calls    |               | - Malicious markdown/payloads     |  |
|  +------------+------------+               +-----------------+-----------------+  |
+---------------|----------------------------------------------|--------------------+
                | Bearer Token (Agent ID)                      | Read by agent
                v                                              v
+-----------------------------------------------------------------------------------+
| TRUST BOUNDARY 1: Bouncer MCP Server Gate                                          |
|                                                                                   |
|  1. Identity Check: Authenticate agent via per-agent bearer token.                |
|  2. Dynamic Filtering: list_tools() returns ONLY tools in agent's tier grant.     |
|  3. Authorization Interceptor: authorize(agent, tool, args) on every tool call.  |
|  4. Append-Only Audit: Every decision (allow/deny + reason) logged immediately.   |
+----------------------+---------------------------------------+--------------------+
                       |                                       |
    (Read Requests)    |                                       | (Consent-gated Carry)
                       v                                       v
+------------------------------------+   +------------------------------------------+
| TRUST BOUNDARY 2: Credential Gate  |   | TRUST BOUNDARY 3: Cryptographic Gate     |
| Agent Read-Only Credential         |   | Single-Use Consent Verification          |
| - Read Content ONLY                |   | - Verify signature (PyJWT / HMAC / Ed25519)|
| - NO update / assign / status      |   | - Verify sha256(text) matches token      |
| - Proven 403 on write attempts     |   | - Verify agent_id & target_id match      |
+----------------------+-------------+   | - Atomically consume single-use nonce    |
                       |                 | - Reject expired tokens (>10 min)        |
                       |                 +---------------------+--------------------+
                       |                                       |
                       |                                       v
                       |                 +------------------------------------------+
                       |                 | Carrier (Isolated Process & Secret)      |
                       |                 | - Strict allowlist: POST comment ONLY    |
                       |                 | - No assign/set/update parameters        |
                       +------------+----+------------------------------------------+
                                    |
                                    v
            +--------------------------------------------------+
            | Shared Work System (Notion / GitHub Issues)       |
            +--------------------------------------------------+
```

---

## 3. Threat Matrix: Forbidden Outcomes & Structural Controls

| # | Forbidden Outcome | Attack Path | Structural Control | Verification Mechanism |
|---|---|---|---|---|
| **FO-1** | **Agent sets an owner, due date, or status** (unauthorized commitment) | Direct/indirect prompt injection, model jailbreak, tool hallucination, parameter tampering. | **No code path:** The tool does not exist on the MCP server. Even if synthesized, the agent's credentials have no update capabilities. | Model-free tool surface test asserts absence; Credential audit script asserts API returns `403 Forbidden`. |
| **FO-2** | **Agent posts text a human never approved** | Agent modifies message text after receiving human consent, or hallucinates modifications. | **Cryptographic Binding:** Consent token binds `sha256(exact_approved_text)`. Server recomputes hash on invocation; any single-character difference causes rejection. | Unit test with tampered text payload; red-team test with post-approval edit payload. |
| **FO-3** | **Consent token reused (Replay Attack)** | Adversary captures a valid consent token and replays it to spam comments or apply it to another context. | **Single-Use Nonces & Short TTL:** Token contains unique UUID nonce stored in DB. Consumption is atomic. Replays fail instantly. Max TTL is 10 minutes. | Unit test attempting replay of identical token; asserts second call fails with `NONCE_ALREADY_USED`. |
| **FO-4** | **Agent uses another agent's powers** (Horizontal privilege escalation) | Agent guesses or steals another agent's tool payload or ID. | **Per-Agent Credentials & Filtering:** Each agent has a distinct bearer token. `list_tools()` dynamically displays only granted tools. `authorize()` validates caller against registry. | Test attempting tool call outside agent's tier; asserts `DENIED_TOOL_NOT_IN_GRANT` and audit row written. |
| **FO-5** | **Unregistered agent runs** | Rogue operator or developer launches an ad-hoc unreviewed agent. | **Strict Registry Enforced at Runtime & CI:** Server strictly rejects unknown bearer tokens. CI fails if any registry entry is incomplete or invalid. | Test invoking server with unknown bearer token; asserts `401 Unauthorized`. |
| **FO-6** | **Silent policy change** (Privilege creep) | Someone alters agent permissions without security or operational review. | **GitOps & CODEOWNERS:** Registry stored in YAML under version control with mandatory CODEOWNERS review. Startup audit logs registry hash. | CI pull-request check and integrity audit verification. |
| **FO-7** | **Audit log tampering** | Compromised agent or operator deletes or mutates audit trail to hide actions. | **Database Privilege Restriction & Hash Chaining:** Database role has `INSERT` and `SELECT` only (`UPDATE` and `DELETE` revoked). Rows are cryptographically hash-chained (`prev_hash`). | Integration test attempting SQL `UPDATE` / `DELETE` on audit table; asserts failure. Tamper test checking hash chain. |

---

## 4. Invariant Rules (Hard Prohibitions)

1. **The Forbidden Set:** No agent in any tier (T0, T1, T2, T3) may ever be granted tools with the names:
   * `set_owner`
   * `set_due_date`
   * `set_status`
   * `update_property`
   * `assign`
   * `delete_page` / `delete_issue`
   The registry validator rejects any manifest containing these tool names at build and load time.

2. **Isolation of the Carrier Secret:** The carrier secret (which holds permissions to insert comments) is never exposed to the agent loop, agent environment variables, or read tool adapters.

3. **No Unaudited Decision:** No tool execution or rejection may occur without generating an immutable audit record containing: `agent_id`, `tool`, `args_sha256`, `decision`, `reason`, and `timestamp`.

---

## 5. Security Boundary Summary

* **Agent Boundary:** Completely untrusted. Can be compromised by arbitrary prompt injections.
* **MCP Protocol Boundary:** Enforces identity and dynamic tool visibility.
* **Authorization Boundary:** Enforces tier rules and audit logging.
* **Carrier Boundary:** Isolated micro-service / handler executing only cryptographic verification and single-endpoint comment insertion.
* **Work System Boundary:** Least-privilege API tokens rejecting any out-of-scope mutation.
