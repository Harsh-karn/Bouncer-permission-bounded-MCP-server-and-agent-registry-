"""
Bouncer Decision Audit Log Engine.
Implements append-only storage, SQL trigger immutability, cryptographic hash chaining (prev_hash),
and audit query reporting.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid


GENESIS_HASH = "0" * 64
DEFAULT_DB_PATH = Path("bouncer_audit.db")


class AuditTamperError(Exception):
    """Raised when the cryptographic audit chain verification detects data tampering or deletion."""
    pass


class AuditImmutabilityError(Exception):
    """Raised when an attempt is made to UPDATE or DELETE an append-only audit row."""
    pass


@dataclass
class AuditRecord:
    id: str
    ts: str
    agent_id: str
    tool: str
    args_sha256: str
    decision: str  # "allow" | "deny"
    reason: str
    consent_nonce: Optional[str] = None
    run_id: Optional[str] = None
    prev_hash: str = GENESIS_HASH
    row_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_args_sha256(args: Optional[Dict[str, Any]]) -> str:
    """Computes a deterministic SHA-256 digest of tool invocation arguments."""
    if not args:
        return hashlib.sha256(b"{}").hexdigest()
    try:
        serialized = json.dumps(args, sort_keys=True, default=str)
    except Exception:
        serialized = str(sorted(args.items()))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_row_hash(
    prev_hash: str,
    ts: str,
    agent_id: str,
    tool: str,
    args_sha256: str,
    decision: str,
    reason: str,
    consent_nonce: Optional[str],
    run_id: Optional[str],
) -> str:
    """Computes cryptographic block digest binding previous row hash and current row payload."""
    payload = "|".join([
        prev_hash,
        ts,
        agent_id,
        tool,
        args_sha256,
        decision,
        reason,
        consent_nonce or "",
        run_id or "",
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    """
    Append-only decision audit log backed by SQLite with SQL trigger immutability
    and cryptographic hash chaining.
    """

    def __init__(self, db_path: Union[str, Path] = DEFAULT_DB_PATH):
        self.db_path = str(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes tables and immutability triggers."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # 1. Audit Log Table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    ts TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    args_sha256 TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
                    reason TEXT NOT NULL,
                    consent_nonce TEXT,
                    run_id TEXT,
                    prev_hash TEXT NOT NULL,
                    row_hash TEXT NOT NULL
                )
                """
            )
            # 2. Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_log(decision)")

            # 3. Immutability Triggers (Prevent UPDATE and DELETE)
            cursor.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_update
                BEFORE UPDATE ON audit_log
                BEGIN
                    SELECT RAISE(FAIL, 'SECURITY INVARIANT VIOLATION: audit_log is append-only. UPDATE is prohibited.');
                END;
                """
            )
            cursor.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_delete
                BEFORE DELETE ON audit_log
                BEGIN
                    SELECT RAISE(FAIL, 'SECURITY INVARIANT VIOLATION: audit_log is append-only. DELETE is prohibited.');
                END;
                """
            )
            conn.commit()

    def get_latest_row_hash(self) -> str:
        """Retrieves the hash of the most recent audit row, or GENESIS_HASH if empty."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT row_hash FROM audit_log ORDER BY rowid DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                return row["row_hash"]
            return GENESIS_HASH

    def log(
        self,
        agent_id: str,
        tool: str,
        decision: str,
        reason: str,
        arguments: Optional[Dict[str, Any]] = None,
        consent_nonce: Optional[str] = None,
        run_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> AuditRecord:
        """
        Appends an immutable audit decision to the log with hash chaining.
        """
        record_id = str(uuid.uuid4())
        ts_str = (timestamp or datetime.now(timezone.utc)).isoformat()
        args_hash = compute_args_sha256(arguments)
        prev_hash = self.get_latest_row_hash()

        row_hash = compute_row_hash(
            prev_hash=prev_hash,
            ts=ts_str,
            agent_id=agent_id,
            tool=tool,
            args_sha256=args_hash,
            decision=decision,
            reason=reason,
            consent_nonce=consent_nonce,
            run_id=run_id,
        )

        record = AuditRecord(
            id=record_id,
            ts=ts_str,
            agent_id=agent_id,
            tool=tool,
            args_sha256=args_hash,
            decision=decision,
            reason=reason,
            consent_nonce=consent_nonce,
            run_id=run_id,
            prev_hash=prev_hash,
            row_hash=row_hash,
        )

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_log (
                    id, ts, agent_id, tool, args_sha256, decision, reason,
                    consent_nonce, run_id, prev_hash, row_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.id,
                    record.ts,
                    record.agent_id,
                    record.tool,
                    record.args_sha256,
                    record.decision,
                    record.reason,
                    record.consent_nonce,
                    record.run_id,
                    record.prev_hash,
                    record.row_hash,
                ),
            )
            conn.commit()

        return record

    def query(
        self,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
        tool: Optional[str] = None,
        since_iso: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditRecord]:
        """Queries audit decisions based on filtering criteria."""
        query_sql = "SELECT * FROM audit_log WHERE 1=1"
        params: List[Any] = []

        if agent_id:
            query_sql += " AND agent_id = ?"
            params.append(agent_id)
        if decision:
            query_sql += " AND decision = ?"
            params.append(decision.lower())
        if tool:
            query_sql += " AND tool = ?"
            params.append(tool)
        if since_iso:
            query_sql += " AND ts >= ?"
            params.append(since_iso)

        query_sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)

        records: List[AuditRecord] = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query_sql, params)
            for row in cursor.fetchall():
                records.append(
                    AuditRecord(
                        id=row["id"],
                        ts=row["ts"],
                        agent_id=row["agent_id"],
                        tool=row["tool"],
                        args_sha256=row["args_sha256"],
                        decision=row["decision"],
                        reason=row["reason"],
                        consent_nonce=row["consent_nonce"],
                        run_id=row["run_id"],
                        prev_hash=row["prev_hash"],
                        row_hash=row["row_hash"],
                    )
                )
        return records

    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Cryptographically verifies the complete hash chain from row 0 to N.
        Detects any row modifications, insertions, or deletions.
        Returns: (is_valid, error_message_if_invalid)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_log ORDER BY rowid ASC")
            rows = cursor.fetchall()

        expected_prev_hash = GENESIS_HASH
        for idx, row in enumerate(rows):
            # Check prev_hash linkage
            if row["prev_hash"] != expected_prev_hash:
                return (
                    False,
                    f"Chain broken at row index {idx} (ID: {row['id']}): "
                    f"prev_hash '{row['prev_hash']}' does not match expected '{expected_prev_hash}'.",
                )

            # Recompute row hash
            calculated_hash = compute_row_hash(
                prev_hash=row["prev_hash"],
                ts=row["ts"],
                agent_id=row["agent_id"],
                tool=row["tool"],
                args_sha256=row["args_sha256"],
                decision=row["decision"],
                reason=row["reason"],
                consent_nonce=row["consent_nonce"],
                run_id=row["run_id"],
            )

            if calculated_hash != row["row_hash"]:
                return (
                    False,
                    f"Tampered row detected at index {idx} (ID: {row['id']}): "
                    f"Stored hash '{row['row_hash']}' does not match recomputed '{calculated_hash}'.",
                )

            expected_prev_hash = row["row_hash"]

        return True, None

    def attempt_update(self, record_id: str, new_reason: str) -> None:
        """
        Attempts to UPDATE a row.
        Used by tests to verify SQL triggers raise an immutability violation.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE audit_log SET reason = ? WHERE id = ?",
                    (new_reason, record_id),
                )
                conn.commit()
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            raise AuditImmutabilityError(f"UPDATE rejected by database trigger: {e}") from e

    def attempt_delete(self, record_id: str) -> None:
        """
        Attempts to DELETE a row.
        Used by tests to verify SQL triggers raise an immutability violation.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM audit_log WHERE id = ?", (record_id,))
                conn.commit()
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            raise AuditImmutabilityError(f"DELETE rejected by database trigger: {e}") from e
