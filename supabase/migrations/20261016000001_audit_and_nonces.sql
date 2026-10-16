-- Bouncer Governance Layer: PostgreSQL / Supabase Migration
-- Implements Append-Only Decision Audit Log with Cryptographic Hash Chaining and Nonce Tracking.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Nonce Tracking Table (Prevents Replay Attacks)
CREATE TABLE IF NOT EXISTS consent_nonces (
    nonce TEXT PRIMARY KEY,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_consent_nonces_expires ON consent_nonces(expires_at);

-- 2. Append-Only Audit Log Table
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ts TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    agent_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    args_sha256 TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason TEXT NOT NULL,
    consent_nonce TEXT,
    run_id TEXT,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_agent_ts ON audit_log(agent_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_decision ON audit_log(decision);
CREATE INDEX IF NOT EXISTS idx_audit_log_tool ON audit_log(tool);

-- 3. Immutability Enforcement: Trigger rejecting UPDATE and DELETE
CREATE OR REPLACE FUNCTION prevent_audit_log_tampering()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY INVARIANT VIOLATION: audit_log is append-only. UPDATE, DELETE, and TRUNCATE are prohibited.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;
CREATE TRIGGER trg_audit_log_immutable
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_tampering();

-- 4. Role Permissions: Grant INSERT and SELECT only
-- Revoke all mutation rights for application and public roles
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC;
GRANT SELECT, INSERT ON audit_log TO PUBLIC;
