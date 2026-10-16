# ADR 0003: Single-Use Nonces and SHA-256 Bound Consent Tokens

## Status
Accepted

## Context
When a human operator reviews and approves a message drafted or carried by an agent, several severe threat vectors emerge:
1. **Post-Approval Text Mutation:** An agent (or intervening attacker) modifies the text after the human clicks "Approve", injecting instructions or altering commitments.
2. **Replay Attacks:** An adversary captures a valid consent token from network logs or memory and re-executes it to spam duplicate updates or apply it against an unintended target.
3. **Target Substitution:** A token approved for a safe sandbox task is submitted against a critical production task.

## Decision
We chose signed, single-use, cryptographically bound consent tokens powered by PyJWT (HMAC-SHA256 / Ed25519) with the following invariants:
1. **Exact Text Hash Binding:** Every token includes `text_sha256 = sha256(canonical_utf8(text))`. The carrier recomputes the SHA-256 hash of the received text payload on execution; any single-character difference immediately causes verification failure.
2. **Atomic Single-Use Nonce Tracking:** Every token contains a unique UUID `jti` (nonce). The verification engine atomically checks and records the nonce in an append-only store (`consent_nonces`). Subsequent invocation attempts with the identical token are rejected with `NONCE_ALREADY_USED`.
3. **Tight Expiration Window (TTL):** Tokens are short-lived (default 10 minutes / 600s).
4. **Scope Binding:** The token explicitly binds `agent_id` and `target_id`. Cross-agent or cross-target reuse fails verification.

## Consequences
- Guarantees that only verbatim human-approved text enters the shared work system.
- Completely neutralizes token replay and target confusion attacks.
- Requires stateful tracking of consumed nonces until token expiration.
