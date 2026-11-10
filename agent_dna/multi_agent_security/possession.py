"""Receiver-issued, single-use proof of the final delegate's signing key.

The receiver owns this object, not the submitting agent. Challenges bind
the delegation, receiver audience, action and SHA-256 of the exact request
bytes. The signing helper belongs in the agent's trusted credential broker,
never in the model. Challenge delivery must use authenticated transport.

Pending challenges are local to this instance: another instance or a
restart refuses them. This is not a distributed execution/idempotency ledger.
"""

from __future__ import annotations

import json
import math
import secrets
import threading
import time
from typing import Any

SPEC = "pv-delegation-proof/1"
MAX_CHALLENGE_TTL = 60.0
_TAG = b"pv-delegation-proof/1:"


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _request(
    chain_hash: str,
    agent_id: str,
    capability: str,
    amount: float | None,
    request_hash: str,
) -> dict[str, Any]:
    if not _hash(chain_hash) or not _hash(request_hash):
        raise ValueError("chain_hash and request_hash must be lowercase SHA-256 hex")
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError("agent_id must be a non-empty string")
    if not isinstance(capability, str) or not capability:
        raise ValueError("capability must be a non-empty string")
    if amount is not None:
        try:
            valid = (
                type(amount) in (int, float) and math.isfinite(amount) and amount >= 0
            )
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("amount must be null or a finite nonnegative number")
    return {
        "chain_hash": chain_hash,
        "agent_id": agent_id,
        "capability": capability,
        "amount": amount,
        "request_hash": request_hash,
    }


def sign_possession(signing_key_hex: str, challenge: dict[str, Any]) -> dict[str, Any]:
    """Sign a receiver's challenge after the broker checks the proposed request."""
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey

    snapshot = json.loads(_canonical(challenge))
    key = SigningKey(signing_key_hex.encode(), encoder=HexEncoder)
    signature = key.sign(_TAG + _canonical(snapshot)).signature.hex()
    return {"challenge": snapshot, "signature": signature}


class DelegationChallenges:
    """Receiver-owned challenge state, shared by all its authorization threads.

    A proof is consumed atomically only after chain/scope checks and a valid
    signature. Failed guesses do not spend the holder's challenge. Expired,
    unknown and consumed challenges all fail closed.
    """

    def __init__(self, audience: str, *, max_pending: int = 1024) -> None:
        if not isinstance(audience, str) or not audience:
            raise ValueError("a receiver audience is required")
        if type(max_pending) is not int or max_pending <= 0:
            raise ValueError("max_pending must be a positive integer")
        self.audience = audience
        self.max_pending = max_pending
        self._pending: dict[str, tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    def _prune(self) -> None:
        moment = time.monotonic()
        self._pending = {
            nonce: entry for nonce, entry in self._pending.items() if entry[1] > moment
        }

    def issue(
        self,
        *,
        chain_hash: str,
        agent_id: str,
        capability: str,
        request_hash: str,
        amount: float | None = None,
        ttl: float = MAX_CHALLENGE_TTL,
    ) -> dict[str, Any]:
        """Issue for the request bytes the receiver will actually execute.

        ``request_hash`` must be computed by the receiver from those bytes,
        not accepted as an unchecked digest supplied by the agent.
        """
        request = _request(chain_hash, agent_id, capability, amount, request_hash)
        if type(ttl) not in (int, float) or not 0 < ttl <= MAX_CHALLENGE_TTL:
            raise ValueError(f"ttl must be within (0, {MAX_CHALLENGE_TTL:g}] seconds")
        with self._lock:
            self._prune()
            if len(self._pending) >= self.max_pending:
                raise ValueError("too many pending delegation challenges")
            nonce = secrets.token_hex(32)
            challenge = {
                "spec": SPEC,
                "audience": self.audience,
                "nonce": nonce,
                "expires_at": time.time() + ttl,
                **request,
            }
            self._pending[nonce] = (_canonical(challenge), time.monotonic() + ttl)
        return challenge

    def verify_and_consume(  # noqa: C901 - ordered refusal checklist
        self,
        proof: Any,
        *,
        public_key: str,
        chain_hash: str,
        agent_id: str,
        capability: str,
        request_hash: str,
        amount: float | None = None,
    ) -> str | None:
        """Called by authorize with the final delegate's operator-pinned key."""
        from nacl.encoding import HexEncoder
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey

        if not isinstance(proof, dict) or set(proof) != {"challenge", "signature"}:
            return "malformed proof"
        challenge, signature = proof["challenge"], proof["signature"]
        if not isinstance(challenge, dict) or not _hash(challenge.get("nonce")):
            return "malformed challenge"
        if not isinstance(signature, str) or len(signature) != 128:
            return "malformed proof signature"
        try:
            encoded = _canonical(challenge)
            request = _request(chain_hash, agent_id, capability, amount, request_hash)
        except (TypeError, ValueError, RecursionError):
            return "malformed proof or request"
        with self._lock:
            self._prune()
            pending = self._pending.get(challenge["nonce"])
            if pending is None:
                return "unknown, expired or consumed challenge"
            if encoded != pending[0]:
                return "challenge contents changed"
            # Use our saved bytes even if a caller mutates its dict concurrently.
            held = json.loads(pending[0])
            if time.time() >= held["expires_at"]:
                del self._pending[held["nonce"]]
                return "expired challenge"
            held_request = {field: held[field] for field in request}
            if _canonical(request) != _canonical(held_request):
                return "proof does not cover this delegation and request"
            if not _hash(public_key):
                return "final delegate has no valid pinned key"
            try:
                VerifyKey(public_key.encode(), encoder=HexEncoder).verify(
                    _TAG + pending[0], bytes.fromhex(signature)
                )
            except (BadSignatureError, ValueError):
                return "proof does not verify under the final delegate's pinned key"
            del self._pending[held["nonce"]]
        return None
