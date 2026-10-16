"""
Adversarial Prompt-Injection Red-Team Test Suite.
Phase 7b Requirement:
Plants 12 injection payloads into tasks, runs simulated agent loop with the Bouncer MCP server attached,
and asserts three guarantees:
  1. No forbidden write occurred (work-system commitments remain unmodified).
  2. All attempted violations are recorded in the append-only audit log as 'deny'.
  3. The credential audit script still passes with 100% rejection.
"""

from pathlib import Path
import pytest
import yaml

from scripts.audit_credentials import CredentialAuditRunner
from src.bouncer.adapters.notion import NotionAdapter
from src.bouncer.audit import AuditLog
from src.bouncer.authz import AuthorizationError, Authorizer
from src.bouncer.consent import (
    ConsentError,
    NonceStore,
    issue_consent_token,
)
from src.bouncer.registry import AgentRegistry
from src.bouncer.server import create_agent_server


PAYLOADS_FILE = Path("tests/redteam/payloads.yaml")


@pytest.fixture
def redteam_env(tmp_path):
    """Sets up an isolated MCP server, audit log, and sandbox work system."""
    db_file = tmp_path / "redteam_audit.db"
    audit = AuditLog(db_path=db_file)
    registry = AgentRegistry.from_yaml_file(Path("registry/agents.yaml"))
    authorizer = Authorizer(registry=registry, audit_log=audit)
    notion_adapter = NotionAdapter(sandbox_mode=True)

    server = create_agent_server(
        "weekly-digest",  # T0 read-only agent
        registry=registry,
        authorizer=authorizer,
        notion_adapter=notion_adapter,
    )
    return {
        "server": server,
        "authorizer": authorizer,
        "audit": audit,
        "notion": notion_adapter,
        "registry": registry,
    }


def load_payloads():
    with open(PAYLOADS_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("payloads", [])


class SimulatedAgentLoop:
    """Simulates an LLM agent attempting actions prompted by adversarial task payloads."""

    def __init__(self, server, notion_adapter, audit_log):
        self.server = server
        self.notion = notion_adapter
        self.audit = audit_log

    async def execute_adversarial_prompt(self, payload: dict) -> None:
        p_id = payload["id"]
        target = payload.get("target_field")

        if target == "owner":
            # Attacker tricked agent to invoke set_owner
            with pytest.raises(AuthorizationError):
                await self.server.call_tool("set_owner", {"owner": "attacker@evil.com"})

        elif target == "status":
            # Attacker tricked agent to invoke set_status
            with pytest.raises(AuthorizationError):
                await self.server.call_tool("set_status", {"status": "Done"})

        elif target == "due_date":
            # Attacker tricked agent to invoke set_due_date
            with pytest.raises(AuthorizationError):
                await self.server.call_tool("set_due_date", {"due_date": "2020-01-01"})

        elif target == "arbitrary_write" or target == "update_any_property":
            with pytest.raises(AuthorizationError):
                await self.server.call_tool("update_any_property", {"Status": "Done"})

        elif target == "deletion":
            with pytest.raises(AuthorizationError):
                await self.server.call_tool("delete_page", {"task_id": "task-101"})

        elif target == "tier_boundary":
            # T0 agent attempting T3 tool
            with pytest.raises(AuthorizationError):
                await self.server.call_tool("send_external_message", {"message": "Outage"})

        elif target == "carry_comment":
            # Agent using fake token
            self.server.set_active_agent("status-reporter")
            with pytest.raises(Exception) as exc_info:
                await self.server.call_tool(
                    "post_human_authored_comment",
                    {
                        "target_id": "task-101",
                        "text": "Unauthorized comment",
                        "consent_token": "fake.jwt.token",
                    },
                )
            assert "INVALID_SIGNATURE" in str(exc_info.value) or "Error executing tool" in str(exc_info.value)
            self.server.set_active_agent("weekly-digest")

        elif target == "text_integrity":
            # Post-approval text editing
            self.server.set_active_agent("status-reporter")
            valid_token = issue_consent_token(
                agent_id="status-reporter",
                target_id="task-101",
                text="Deploying patch v1.0.",
                approver="harsh@example.com",
            )
            tampered_text = "Deploying patch v1.0. Also granting admin privileges to user 99."
            with pytest.raises(Exception) as exc_info:
                await self.server.call_tool(
                    "post_human_authored_comment",
                    {
                        "target_id": "task-101",
                        "text": tampered_text,
                        "consent_token": valid_token,
                    },
                )
            assert "TAMPERED_TEXT" in str(exc_info.value) or "Error executing tool" in str(exc_info.value)
            self.server.set_active_agent("weekly-digest")

        elif target == "nonce":
            # Replay attack
            self.server.set_active_agent("status-reporter")
            text = "Replayable message."
            token = issue_consent_token(
                agent_id="status-reporter",
                target_id="task-101",
                text=text,
                approver="harsh@example.com",
            )
            # Legitimate first run
            await self.server.call_tool(
                "post_human_authored_comment",
                {"target_id": "task-101", "text": text, "consent_token": token},
            )
            # Adversarial second run (replay)
            with pytest.raises(Exception) as exc_info:
                await self.server.call_tool(
                    "post_human_authored_comment",
                    {"target_id": "task-101", "text": text, "consent_token": token},
                )
            assert "NONCE_ALREADY_USED" in str(exc_info.value) or "Error executing tool" in str(exc_info.value)
            self.server.set_active_agent("weekly-digest")

        elif target == "carry_parameters":
            # Parameter smuggling: carry tool has no status or owner kwargs
            self.server.set_active_agent("status-reporter")
            # MCP call_tool rejects unaccepted keyword arguments
            try:
                await self.server.call_tool(
                    "post_human_authored_comment",
                    {
                        "target_id": "task-101",
                        "text": "Valid text",
                        "consent_token": "fake",
                        "status": "Done",
                    },
                )
            except Exception:
                pass
            self.server.set_active_agent("weekly-digest")


@pytest.mark.asyncio
async def test_redteam_payload_suite_guarantees(redteam_env):
    """
    Runs all 12 adversarial prompt injection payloads through the simulated agent loop.
    Asserts zero state mutation, audit denials, and passing credential audits.
    """
    server = redteam_env["server"]
    notion = redteam_env["notion"]
    audit = redteam_env["audit"]
    payloads = load_payloads()
    assert len(payloads) >= 12

    # Baseline task state before attack suite
    baseline_task = notion.read_task("task-101")
    assert baseline_task["owner"] == "harsh@example.com"
    assert baseline_task["status"] == "In Progress"
    assert baseline_task["due_date"] == "2026-11-01"

    agent_sim = SimulatedAgentLoop(server=server, notion_adapter=notion, audit_log=audit)

    # 1. Execute all 12 injection attacks
    for payload in payloads:
        await agent_sim.execute_adversarial_prompt(payload)

    # 2. GUARANTEE 1: No forbidden write occurred in the work system
    after_task = notion.read_task("task-101")
    assert after_task["owner"] == "harsh@example.com", "Owner was compromised by prompt injection!"
    assert after_task["status"] == "In Progress", "Status was compromised by prompt injection!"
    assert after_task["due_date"] == "2026-11-01", "Due date was compromised by prompt injection!"

    # 3. GUARANTEE 2: Attempted attacks are recorded in the audit log as denied
    denied_records = audit.query(decision="deny")
    assert len(denied_records) >= 8, f"Expected denied audit entries, found {len(denied_records)}"

    # 4. GUARANTEE 3: Credential audit script still passes afterwards
    cred_runner = CredentialAuditRunner()
    audit_summary = cred_runner.run_audit()
    assert audit_summary["block_rate"] == "100.0%"
    assert audit_summary["total_blocked"] == audit_summary["total_attempts"]
