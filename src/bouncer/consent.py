"""
Bouncer Cryptographic Consent Engine.
Issues and validates signed, single-use consent tokens bound to exact text sha256.
Enforces non-replayability via atomic persistent nonce consumption and short TTL.
"""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, Optional, Protocol
import uuid
import jwt


DEFAULT_DEV_SECRET = "bouncer-dev-consent-signing-key-32bytes!"
DEFAULT_TTL_SECONDS = 600  # 10 minutes


def get_consent_secret() -> str:
    """
    Retrieves the HMAC secret key for signing consent tokens.
    Fails closed in production environments if unconfigured.
    """
    secret = os.getenv("BOUNCER_CONSENT_SECRET")
    if not secret:
        env_mode = os.getenv("ENV", os.getenv("BOUNCER_ENV", "development")).lower()
        if env_mode in ("production", "prod"):
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: "
                "BOUNCER_CONSENT_SECRET must be explicitly set in production environments."
            )
        return DEFAULT_DEV_SECRET
    return secret


try:
    from mcp.server.mcpserver.exceptions import ToolError
    class ConsentError(ToolError):
        """Base exception for consent verification failures."""
        pass
except ImportError:
    class ConsentError(Exception):
        """Base exception for consent verification failures."""
        pass


class NonceAlreadyUsedError(ConsentError):
    """Raised when a consent token is replayed."""
    pass


class TextTamperedError(ConsentError):
    """Raised when the payload text does not match the approved sha256 hash."""
    pass


class ConsentExpiredError(ConsentError):
    """Raised when a consent token has expired."""
    pass


class ConsentScopeMismatchError(ConsentError):
    """Raised when agent or target mismatch token claims."""
    pass


@dataclass
class ConsentVerificationResult:
    valid: bool
    reason: str
    claims: Optional[Dict[str, Any]] = None


class BaseNonceStore(Protocol):
    def consume(self, nonce: str, expires_at: float) -> bool:
        ...
    def is_consumed(self, nonce: str) -> bool:
        ...


class InMemoryNonceStore:
    """Thread-safe in-memory storage tracking consumed token nonces."""

    def __init__(self):
        self._consumed: Dict[str, float] = {}

    def consume(self, nonce: str, expires_at: float) -> bool:
        now = time.time()
        if len(self._consumed) > 1000:
            self._consumed = {n: exp for n, exp in self._consumed.items() if exp > now}

        if nonce in self._consumed:
            return False

        self._consumed[nonce] = expires_at
        return True

    def is_consumed(self, nonce: str) -> bool:
        return nonce in self._consumed


class SqliteNonceStore:
    """
    Persistent, restart-proof and multi-process nonce store backed by SQLite.
    Prevents token replay attacks across process restarts and horizontal workers.
    """

    def __init__(self, db_path: Path = Path("bouncer_audit.db")):
        self.db_path = str(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS consent_nonces (
                    nonce TEXT PRIMARY KEY,
                    consumed_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nonces_expires ON consent_nonces(expires_at)")
            conn.commit()

    def consume(self, nonce: str, expires_at: float) -> bool:
        """
        Atomically records nonce into database using PRIMARY KEY uniqueness.
        Returns True if newly inserted, False if already consumed.
        """
        now = time.time()
        try:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO consent_nonces (nonce, consumed_at, expires_at) VALUES (?, ?, ?)",
                    (nonce, now, expires_at),
                )
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Primary key collision means nonce was already consumed
            return False

    def is_consumed(self, nonce: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM consent_nonces WHERE nonce = ?", (nonce,))
            return cursor.fetchone() is not None


# Backwards-compatible alias
NonceStore = InMemoryNonceStore

# Global singleton persistent nonce store
GLOBAL_NONCE_STORE = SqliteNonceStore()


def compute_text_sha256(text: str) -> str:
    """Computes the SHA-256 hex digest of the canonical normalized UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def issue_consent_token(
    agent_id: str,
    target_id: str,
    text: str,
    approver: str,
    secret: Optional[str] = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    custom_nonce: Optional[str] = None,
) -> str:
    """
    Issues a signed cryptographic consent token.
    Claims bound:
      - agent_id: authorized executor
      - target_id: work system entity (e.g. task/issue ID)
      - text_sha256: exact digest of approved text
      - approver: identity of human who approved
      - iat: issuance timestamp
      - exp: expiration timestamp (max 10 minutes)
      - jti: unique random single-use nonce
    """
    now = int(time.time())
    nonce = custom_nonce or str(uuid.uuid4())
    text_hash = compute_text_sha256(text)
    active_secret = secret or get_consent_secret()

    payload = {
        "agent_id": agent_id,
        "target_id": target_id,
        "text_sha256": text_hash,
        "approver": approver,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": nonce,
    }

    token = jwt.encode(payload, active_secret, algorithm="HS256")
    return token


def verify_and_consume_consent_token(
    token: str,
    expected_agent_id: str,
    expected_target_id: str,
    actual_text: str,
    secret: Optional[str] = None,
    nonce_store: Optional[Any] = None,
) -> ConsentVerificationResult:
    """
    Validates signature, expiration, agent/target matching, text hash integrity,
    and atomically consumes the nonce.
    """
    store = nonce_store or GLOBAL_NONCE_STORE
    active_secret = secret or get_consent_secret()

    # 1. Decode & Verify JWT signature and expiration
    try:
        claims = jwt.decode(
            token,
            active_secret,
            algorithms=["HS256"],
            options={"require": ["agent_id", "target_id", "text_sha256", "approver", "exp", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        return ConsentVerificationResult(
            valid=False,
            reason="TOKEN_EXPIRED: Consent token has expired. Request fresh human approval.",
        )
    except jwt.InvalidTokenError as e:
        return ConsentVerificationResult(
            valid=False,
            reason=f"INVALID_SIGNATURE: Consent token signature invalid or malformed ({e}).",
        )

    # 2. Verify agent_id match
    if claims.get("agent_id") != expected_agent_id:
        return ConsentVerificationResult(
            valid=False,
            reason=(
                f"AGENT_MISMATCH: Token was granted to agent '{claims.get('agent_id')}', "
                f"but caller is '{expected_agent_id}'."
            ),
            claims=claims,
        )

    # 3. Verify target_id match
    if claims.get("target_id") != expected_target_id:
        return ConsentVerificationResult(
            valid=False,
            reason=(
                f"TARGET_MISMATCH: Token was granted for target '{claims.get('target_id')}', "
                f"but action attempted on '{expected_target_id}'."
            ),
            claims=claims,
        )

    # 4. Verify text SHA-256 integrity (Anti-tamper check)
    computed_hash = compute_text_sha256(actual_text)
    if computed_hash != claims.get("text_sha256"):
        return ConsentVerificationResult(
            valid=False,
            reason=(
                f"TAMPERED_TEXT: The submitted text does not match the approved human-signed hash. "
                f"Expected {claims.get('text_sha256')}, got {computed_hash}."
            ),
            claims=claims,
        )

    # 5. Atomically consume the nonce to prevent replay attacks
    nonce = claims.get("jti")
    exp = claims.get("exp", time.time() + 600)
    if not store.consume(nonce, exp):
        return ConsentVerificationResult(
            valid=False,
            reason=f"NONCE_ALREADY_USED: Token nonce '{nonce}' has already been consumed. Replay attack blocked.",
            claims=claims,
        )

    # Verification successful
    return ConsentVerificationResult(
        valid=True,
        reason="CONSENT_VERIFIED: Token signature, text hash, and nonce valid.",
        claims=claims,
    )
