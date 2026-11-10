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
import json
import math
import time
import uuid
from typing import Any

_SECRET_KEYS: dict[str, str] = {}

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
    return hmac.new(secret.encode(), message_hash.encode(), hashlib.sha256).hexdigest()


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
    action_id: str,
    agent_id: str,
    vote: str,
    message_hash: str,
    nonce: str,
    issued_at: float,
    expires_at: float,
) -> str:
    """Canonical signed payload. Every field an attacker could swap
    (target action, vote value, freshness) is inside the MAC.

    Encoded as a JSON array. The fields used to be joined with "|" and
    not escaped, so one signed string had more than one reading: a REJECT
    on action id ``x|bob|APPROVE|h`` was byte-identical to an APPROVE on
    action ``x``. A JSON array has exactly one parse.
    """
    return json.dumps(
        [
            VOTE_PROTOCOL,
            action_id,
            agent_id,
            vote,
            message_hash,
            nonce,
            str(float(issued_at)),
            str(float(expires_at)),
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )


def sign_vote(
    agent_id: str,
    *,
    action_id: str,
    vote: str,
    message_hash: str,
    nonce: str,
    issued_at: float,
    expires_at: float,
) -> str:
    return sign_message(
        agent_id,
        vote_payload(
            action_id, agent_id, vote, message_hash, nonce, issued_at, expires_at
        ),
    )


def verify_vote(
    agent_id: str,
    *,
    action_id: str,
    vote: str,
    message_hash: str,
    nonce: str,
    issued_at: float,
    expires_at: float,
    signature: str,
    now: float,
) -> bool:
    """Signature AND freshness. Fail-closed on any malformed field."""
    try:
        issued = float(issued_at)
        expires = float(expires_at)
    except (TypeError, ValueError):
        return False
    if not (expires > issued):
        return False
    if issued > now + CLOCK_SKEW_SECONDS:  # from the future
        return False
    if now >= expires:  # expired
        return False
    if not verify_signature(
        agent_id,
        vote_payload(action_id, agent_id, vote, message_hash, nonce, issued, expires),
        signature,
    ):
        return False
    return True


def cast_vote(
    agent_id: str,
    action_id: str,
    vote: str,
    message_hash: str,
    ttl: float = DEFAULT_VOTE_TTL,
    now: float | None = None,
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
            agent_id,
            action_id=action_id,
            vote=vote,
            message_hash=message_hash,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        ),
    }


# ---------------------------------------------------------------------------
# pv-vote/2 -- Ed25519 votes bound to the action under decision
# ---------------------------------------------------------------------------
#
# pv-vote/1 is HMAC with a per-agent shared secret: whoever verifies a vote
# can also forge it, and the service had no way to be given the secrets
# outside a demo. pv-vote/2 votes are signed with the voter's own Ed25519
# key; the service holds only public keys, pinned by the operator.

VOTE_PROTOCOL_V2 = "pv-vote/2"
APPROVE = "APPROVE"
REJECT = "REJECT"
MAX_VOTE_TTL = 3600.0


def consensus_action_id(
    agent_id: str, capability: str, arguments: dict[str, Any] | None
) -> str:
    """The identifier voters sign and the service recomputes.

    sha256 over the canonical JSON of the acting agent, the capability and
    the arguments. A vote therefore approves one exact action: change the
    payee or the amount and it no longer verifies.
    """
    canonical = json.dumps(
        {
            "agent_id": agent_id,
            "arguments": arguments or {},
            "capability": capability,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def vote_payload_v2(
    action_id: str,
    agent_id: str,
    vote: str,
    nonce: str,
    issued_at: float,
    expires_at: float,
) -> bytes:
    return json.dumps(
        {
            "action_id": action_id,
            "agent_id": agent_id,
            "expires_at": float(expires_at),
            "issued_at": float(issued_at),
            "nonce": nonce,
            "protocol": VOTE_PROTOCOL_V2,
            "vote": vote,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def generate_voter_keypair() -> dict[str, str]:
    """A voter's Ed25519 keypair, hex. The public key goes in the roster."""
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey

    key = SigningKey.generate()
    return {
        "signing_key": key.encode(encoder=HexEncoder).decode(),
        "public_key": key.verify_key.encode(encoder=HexEncoder).decode(),
    }


def cast_vote_v2(
    signing_key_hex: str,
    *,
    agent_id: str,
    action_id: str,
    vote: str,
    ttl: float = DEFAULT_VOTE_TTL,
    now: float | None = None,
) -> dict[str, Any]:
    """Build one signed pv-vote/2 vote, the shape ConsensusChecker consumes."""
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey

    if vote not in (APPROVE, REJECT):
        raise ValueError(f"vote must be {APPROVE} or {REJECT}, got {vote!r}")
    issued_at = time.time() if now is None else float(now)
    expires_at = issued_at + float(ttl)
    nonce = uuid.uuid4().hex
    key = SigningKey(signing_key_hex.encode(), encoder=HexEncoder)
    signature = key.sign(
        vote_payload_v2(action_id, agent_id, vote, nonce, issued_at, expires_at)
    ).signature.hex()
    return {
        "agent_id": agent_id,
        "vote": vote,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "signature": signature,
    }


def verify_vote_v2(  # noqa: C901 - ordered refusal checklist
    vote: dict[str, Any], *, action_id: str, public_key: str, now: float
) -> bool:
    """Signature, vote value and freshness. Fail-closed on anything odd."""
    try:
        from nacl.encoding import HexEncoder
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:
        return False

    value = vote.get("vote")
    nonce = vote.get("nonce")
    agent_id = vote.get("agent_id")
    signature = vote.get("signature")
    issued_at = vote.get("issued_at")
    expires_at = vote.get("expires_at")
    if value not in (APPROVE, REJECT):
        return False
    if not isinstance(nonce, str) or not isinstance(agent_id, str):
        return False
    if not isinstance(signature, str) or len(signature) != 128:
        return False
    for stamp in (issued_at, expires_at):
        if isinstance(stamp, bool) or not isinstance(stamp, int | float):
            return False
        if not math.isfinite(stamp):
            return False
    issued, expires = float(issued_at), float(expires_at)  # type: ignore[arg-type]
    if not (expires > issued) or expires - issued > MAX_VOTE_TTL:
        return False
    if issued > now + CLOCK_SKEW_SECONDS or now >= expires:
        return False
    try:
        VerifyKey(public_key.encode(), encoder=HexEncoder).verify(
            vote_payload_v2(action_id, agent_id, value, nonce, issued, expires),
            bytes.fromhex(signature),
        )
    except (BadSignatureError, ValueError):
        return False
    return True
