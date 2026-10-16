"""
Bouncer Cryptographic Consent Engine.
Issues and validates signed, single-use consent tokens bound to exact text sha256.
Enforces non-replayability via atomic nonce consumption and short TTL.
"""

from dataclasses import dataclass
import hashlib
import os
import time
from typing import Any, Dict, Optional, Set
import uuid
import jwt


DEFAULT_SECRET = os.getenv("BOUNCER_CONSENT_SECRET", "bouncer-dev-consent-signing-key-32bytes!")
DEFAULT_TTL_SECONDS = 600  # 10 minutes


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


class NonceStore:
    """Thread-safe storage tracking consumed token nonces to prevent replay attacks."""

    def __init__(self):
        self._consumed: Dict[str, float] = {}  # nonce -> expiry timestamp

    def consume(self, nonce: str, expires_at: float) -> bool:
        """
        Atomically attempts to consume a nonce.
        Returns True if newly consumed, False if already used.
        """
        now = time.time()
        # Clean expired nonces occasionally
        if len(self._consumed) > 1000:
            self._consumed = {n: exp for n, exp in self._consumed.items() if exp > now}

        if nonce in self._consumed:
            return False

        self._consumed[nonce] = expires_at
        return True

    def is_consumed(self, nonce: str) -> bool:
        return nonce in self._consumed


# Global singleton nonce store for the process
GLOBAL_NONCE_STORE = NonceStore()


def compute_text_sha256(text: str) -> str:
    """Computes the SHA-256 hex digest of the canonical normalized UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def issue_consent_token(
    agent_id: str,
    target_id: str,
    text: str,
    approver: str,
    secret: str = DEFAULT_SECRET,
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

    payload = {
        "agent_id": agent_id,
        "target_id": target_id,
        "text_sha256": text_hash,
        "approver": approver,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": nonce,
    }

    token = jwt.encode(payload, secret, algorithm="HS256")
    return token


def verify_and_consume_consent_token(
    token: str,
    expected_agent_id: str,
    expected_target_id: str,
    actual_text: str,
    secret: str = DEFAULT_SECRET,
    nonce_store: Optional[NonceStore] = None,
) -> ConsentVerificationResult:
    """
    Validates signature, expiration, agent/target matching, text hash integrity,
    and atomically consumes the nonce.
    """
    store = nonce_store or GLOBAL_NONCE_STORE

    # 1. Decode & Verify JWT signature and expiration
    try:
        claims = jwt.decode(
            token,
            secret,
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
