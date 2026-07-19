"""
HMAC-SHA256 vote signing.

Originally vendored from PrivateVault.ai's coordination/mesh/signing.py
(raw message signing only). Extended 2026-07 (P0-6): raw signatures
bound only a message hash, so a captured vote replayed into any other
action sharing that hash, and nothing bound the vote VALUE -- an
APPROVE signature was indistinguishable from a REJECT signature over
the same hash.

pv-vote/1 signs a canonical payload binding:
    action_id | agent_id | vote | message_hash | nonce | issued_at | expires_at

sign_message / verify_signature remain for non-vote raw-message
authentication and for verifying the legacy primitive in tests.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from typing import Dict

_SECRET_KEYS: Dict[str, str] = {}

VOTE_PROTOCOL = "pv-vote/1"
CLOCK_SKEW_SECONDS = 30.0
DEFAULT_VOTE_TTL = 300.0


def register_key(agent_id: str, secret: str) -> None:
    _SECRET_KEYS[agent_id] = secret


# ---------------------------------------------------------------------------
# raw message primitive (non-vote uses; legacy)
# ---------------------------------------------------------------------------

def sign_message(agent_id: str, message_hash: str) -> str:
    secret = _SECRET_KEYS.get(agent_id)
    if secret is None:
        raise KeyError(f"no registered key for agent_id {agent_id!r}")
    return hmac.new(
        secret.encode(), message_hash.encode(), hashlib.sha256
    ).hexdigest()


def verify_signature(agent_id: str, message_hash: str, signature: str) -> bool:
    try:
        expected = sign_message(agent_id, message_hash)
    except KeyError:
        return False
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# pv-vote/1 -- replay-bound vote signatures
# ---------------------------------------------------------------------------

def vote_payload(
    action_id: str, agent_id: str, vote: str, message_hash: str,
    nonce: str, issued_at: float, expires_at: float,
) -> str:
    """Canonical signed payload. Every field an attacker could swap
    (target action, vote value, freshness) is inside the MAC."""
    return "|".join([
        VOTE_PROTOCOL, action_id, agent_id, vote, message_hash,
        nonce, str(float(issued_at)), str(float(expires_at)),
    ])


def sign_vote(
    agent_id: str, *, action_id: str, vote: str, message_hash: str,
    nonce: str, issued_at: float, expires_at: float,
) -> str:
    return sign_message(
        agent_id,
        vote_payload(action_id, agent_id, vote, message_hash,
                     nonce, issued_at, expires_at),
    )


def verify_vote(
    agent_id: str, *, action_id: str, vote: str, message_hash: str,
    nonce: str, issued_at: float, expires_at: float,
    signature: str, now: float,
) -> bool:
    """Signature AND freshness. Fail-closed on any malformed field."""
    try:
        issued = float(issued_at)
        expires = float(expires_at)
    except (TypeError, ValueError):
        return False
    if not (expires > issued):
        return False
    if issued > now + CLOCK_SKEW_SECONDS:      # from the future
        return False
    if now >= expires:                          # expired
        return False
    if not verify_signature(
        agent_id,
        vote_payload(action_id, agent_id, vote, message_hash,
                     nonce, issued, expires),
        signature,
    ):
        return False
    return True


def cast_vote(
    agent_id: str, action_id: str, vote: str, message_hash: str,
    ttl: float = DEFAULT_VOTE_TTL, now: float | None = None,
) -> dict:
    """Build a complete, signed pv-vote/1 vote dict -- the shape
    consumed by SecureQuorum.submit and by consensus evidence."""
    issued_at = time.time() if now is None else float(now)
    expires_at = issued_at + float(ttl)
    nonce = str(uuid.uuid4())
    return {
        "agent_id": agent_id,
        "vote": vote,
        "message_hash": message_hash,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "signature": sign_vote(
            agent_id, action_id=action_id, vote=vote,
            message_hash=message_hash, nonce=nonce,
            issued_at=issued_at, expires_at=expires_at,
        ),
    }
