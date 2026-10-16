# Bouncer

> **A permission-bounded MCP server and agent registry where the forbidden write has no code path, proven by credential audits and prompt-injection tests.**

[![Governance](https://img.shields.io/badge/governance-structurally--enforced-blue.svg)](docs/threat-model.md)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 1. Objective

Build governance that is enforced by structure, not by instructions in a prompt.

**The Rule:** An agent may read and report, may carry a human-authored update into a system of record after a human consents, but may **never** autonomously write a commitment (an owner, a due date, a status) into a shared work system.

**Bouncer makes that last part impossible:** The tool does not exist, and the credential behind it cannot do it either.

> *"Prompt injection cannot produce a forbidden write, because no tool and no credential in the agent's grant can perform it. I can show you the audit that proves it."*

---

## 2. Threat Model Overview

The full inversion-first threat model is detailed in [`docs/threat-model.md`](docs/threat-model.md).

| Forbidden Outcome | Attack Path | Structural Control |
|---|---|---|
| **Agent sets an owner, due date, or status** | Prompt injection in task text, model error, tool misuse | No such tool exists; credential has no update capability; audit proves `403` |
| **Agent posts text a human never approved** | Model edits text after approval | Consent token binds a `sha256` of exact text; any change fails verification |
| **Consent token reused** | Replay of an old token | Single-use nonce stored in database, short expiry (10m) |
| **Agent uses another agent's powers** | Stolen or guessed token | Per-agent credentials, tool list filtered by identity, `authorize()` on every call |
| **Unregistered agent runs** | Someone adds an agent informally | Server refuses unknown identities; CI fails on incomplete registry entries |
| **Silent policy change** | Edit grants without review | Registry in version control, `CODEOWNERS` review, audit log of loads |
| **Audit log tampering** | Agent or operator deletes rows | Insert-only privileges; hash-chained audit rows |

---

## 3. Project Architecture Roadmap

- **Section 1: Repository Scaffolding & Threat Model** (Complete)
- **Section 2: Registry & Risk Tiers (T0–T3)**
- **Section 3: Dynamic FastMCP Server & Read Tools**
- **Section 4: Consent-Gated Carry Tool with PyJWT & Nonces**
- **Section 5: Carrier Pattern & Work-System Adapters (Notion & GitHub)**
- **Section 6: Append-Only Tamper-Evident Decision Audit Log**
- **Section 7: Credential Audit Engine & Model-Free Tool-Surface Tests**
- **Section 8: Red-Team Prompt-Injection Suite, ADRs & CI/CD**
