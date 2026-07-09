"""
Vendored from PrivateVault.ai's coordination/mesh/signing.py.
HMAC-SHA256 vote signing. Unmodified logic. No tests existed for
this in the source repo prior to vendoring.
"""

import hashlib
import hmac
from typing import Dict

_SECRET_KEYS: Dict[str, str] = {}


def register_key(agent_id: str, secret: str) -> None:
    _SECRET_KEYS[agent_id] = secret


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
