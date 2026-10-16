"""
Unit tests for Bouncer Decision Audit Log.
Tests append-only immutability triggers, cryptographic hash chaining (prev_hash),
tamper detection, and query filtering.
"""

from pathlib import Path
import sqlite3
import pytest

from bouncer.audit import (
    AuditImmutabilityError,
    AuditLog,
    GENESIS_HASH,
    compute_row_hash,
)
from bouncer.authz import Authorizer
from bouncer.registry import AgentRegistry


@pytest.fixture
def temp_audit_db(tmp_path):
    db_file = tmp_path / "test_audit.db"
    return AuditLog(db_path=db_file)


def test_log_decision_appends_records(temp_audit_db):
    """Appending decisions assigns IDs, computes hashes, and chains them."""
    rec1 = temp_audit_db.log(
        agent_id="weekly-digest",
        tool="read_tasks",
        decision="allow",
        reason="AUTHORIZED_BY_GRANT",
        arguments={"limit": 10},
    )
    assert rec1.prev_hash == GENESIS_HASH
    assert rec1.row_hash != ""
    assert rec1.decision == "allow"

    rec2 = temp_audit_db.log(
        agent_id="weekly-digest",
        tool="set_owner",
        decision="deny",
        reason="FORBIDDEN_TOOL_HARD_BLOCK",
        arguments={"owner": "attacker"},
    )
    assert rec2.prev_hash == rec1.row_hash
    assert rec2.decision == "deny"


def test_immutability_triggers_reject_update(temp_audit_db):
    """Database trigger strictly rejects any UPDATE operation on audit_log."""
    rec = temp_audit_db.log(
        agent_id="weekly-digest",
        tool="read_tasks",
        decision="allow",
        reason="AUTHORIZED_BY_GRANT",
    )

    with pytest.raises(AuditImmutabilityError) as exc_info:
        temp_audit_db.attempt_update(rec.id, "tampered reason")
    assert "UPDATE is prohibited" in str(exc_info.value)


def test_immutability_triggers_reject_delete(temp_audit_db):
    """Database trigger strictly rejects any DELETE operation on audit_log."""
    rec = temp_audit_db.log(
        agent_id="weekly-digest",
        tool="read_tasks",
        decision="allow",
        reason="AUTHORIZED_BY_GRANT",
    )

    with pytest.raises(AuditImmutabilityError) as exc_info:
        temp_audit_db.attempt_delete(rec.id)
    assert "DELETE is prohibited" in str(exc_info.value)


def test_hash_chain_integrity_verification_succeeds(temp_audit_db):
    """Untampered audit log passes cryptographic chain verification."""
    for i in range(10):
        temp_audit_db.log(
            agent_id="status-reporter",
            tool="read_task",
            decision="allow",
            reason=f"Call {i}",
            arguments={"task_id": f"task-{i}"},
        )

    is_valid, err = temp_audit_db.verify_chain_integrity()
    assert is_valid is True
    assert err is None


def test_tamper_detection_flags_corrupted_row(tmp_path):
    """If an attacker modifies a row behind the scenes, verification fails."""
    db_file = tmp_path / "tamper_test.db"
    audit = AuditLog(db_path=db_file)

    rec1 = audit.log("weekly-digest", "read_tasks", "allow", "Reason 1")
    rec2 = audit.log("weekly-digest", "read_tasks", "allow", "Reason 2")
    rec3 = audit.log("weekly-digest", "read_tasks", "allow", "Reason 3")

    # Simulate raw out-of-band tampering by disabling triggers temporarily to alter data
    raw_conn = sqlite3.connect(str(db_file))
    cursor = raw_conn.cursor()
    cursor.execute("DROP TRIGGER IF EXISTS trg_prevent_audit_update")
    cursor.execute("UPDATE audit_log SET reason = 'ATTACKER_MUTATED' WHERE id = ?", (rec2.id,))
    raw_conn.commit()
    raw_conn.close()

    is_valid, err = audit.verify_chain_integrity()
    assert is_valid is False
    assert "Tampered row detected" in err
    assert rec2.id in err


def test_query_filtering(temp_audit_db):
    """Audit query correctly filters by agent, decision, and tool."""
    temp_audit_db.log("weekly-digest", "read_tasks", "allow", "Ok 1")
    temp_audit_db.log("weekly-digest", "set_owner", "deny", "Forbidden")
    temp_audit_db.log("status-reporter", "read_tasks", "allow", "Ok 2")
    temp_audit_db.log("status-reporter", "post_human_authored_comment", "allow", "Ok 3")

    # Filter by agent
    weekly_recs = temp_audit_db.query(agent_id="weekly-digest")
    assert len(weekly_recs) == 2

    # Filter by decision
    denied_recs = temp_audit_db.query(decision="deny")
    assert len(denied_recs) == 1
    assert denied_recs[0].tool == "set_owner"

    # Filter by tool
    comment_recs = temp_audit_db.query(tool="post_human_authored_comment")
    assert len(comment_recs) == 1


def test_authorizer_integrates_with_audit_log(tmp_path):
    """Authorizer automatically logs decisions to AuditLog."""
    db_file = tmp_path / "authz_audit.db"
    audit = AuditLog(db_path=db_file)
    registry = AgentRegistry.from_yaml_file(Path("registry/agents.yaml"))
    authorizer = Authorizer(registry=registry, audit_log=audit)

    # Allowed call
    authorizer.authorize("weekly-digest", "read_tasks", {"limit": 5})

    # Denied forbidden call
    authorizer.authorize("weekly-digest", "set_owner", {"owner": "attacker"})

    recs = audit.query()
    assert len(recs) == 2
    assert recs[0].decision == "deny"
    assert recs[1].decision == "allow"

    is_valid, _ = audit.verify_chain_integrity()
    assert is_valid is True
