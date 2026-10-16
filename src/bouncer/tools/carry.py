"""
Consent-Gated Carry Tool for Bouncer MCP Server.
Allows agents to post ONLY human-authored and human-approved comments.
Structurally eliminates parameters for owner, status, due date, or page assignment.
"""

from typing import Any, Callable, Dict, Optional
from src.bouncer.adapters.notion import NotionAdapter
from src.bouncer.consent import (
    ConsentError,
    NonceStore,
    verify_and_consume_consent_token,
)


class CarryTool:
    """
    Implements the carrier pattern for human-approved comments.
    Enforces that:
      1. Every write operation requires an unexpired, signed, single-use consent token.
      2. The text parameter's sha256 must match the approved hash byte-for-byte.
      3. Nonces cannot be reused.
      4. No other write or property update parameters exist on the tool signature.
    """

    def __init__(
        self,
        adapter: Optional[NotionAdapter] = None,
        nonce_store: Optional[NonceStore] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.adapter = adapter or NotionAdapter(sandbox_mode=True)
        self.nonce_store = nonce_store
        self.audit_sink = audit_sink

    def post_human_authored_comment(
        self,
        target_id: str,
        text: str,
        consent_token: str,
        caller_agent_id: str = "unknown",
    ) -> Dict[str, Any]:
        """
        Carries a human-authored comment into the work system after cryptographic verification.

        Arguments:
            target_id: The ID of the task/issue to comment on (e.g. 'task-101').
            text: The exact human-approved comment text to carry.
            consent_token: Single-use cryptographic consent token issued by a human reviewer.
            caller_agent_id: Injected by the server runtime representing the authenticated agent.
        """
        # Verify cryptographic consent token and atomically consume nonce
        verification = verify_and_consume_consent_token(
            token=consent_token,
            expected_agent_id=caller_agent_id,
            expected_target_id=target_id,
            actual_text=text,
            nonce_store=self.nonce_store,
        )

        if not verification.valid:
            if self.audit_sink:
                self.audit_sink({
                    "agent_id": caller_agent_id,
                    "tool": "post_human_authored_comment",
                    "decision": "deny",
                    "reason": verification.reason,
                    "target_id": target_id,
                })
            raise ConsentError(verification.reason)

        # Token is cryptographically valid and nonce consumed. Dispatch to carrier.
        result = self.adapter.post_comment(task_id=target_id, text=text)

        if self.audit_sink:
            self.audit_sink({
                "agent_id": caller_agent_id,
                "tool": "post_human_authored_comment",
                "decision": "allow",
                "reason": "CONSENT_VERIFIED_AND_POSTED",
                "target_id": target_id,
                "approver": verification.claims.get("approver") if verification.claims else None,
                "nonce": verification.claims.get("jti") if verification.claims else None,
            })

        return result
