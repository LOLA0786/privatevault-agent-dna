"""Key rotation as a governed action.

``signer.rotate_key`` produces a correct rotation envelope binding
old key to new, signed by the old key -- but nothing consumed it, so
a rotation left no trace in the audit chain despite the function's
own docstring calling for rotation events to be logged. A signing key
that can change without a record undermines every signature made
before and after it: a verifier cannot tell an authorised rotation
from a key compromise.

This module closes that gap without touching the DRP wire format.
Rotation is modelled as what it actually is -- an action taken by a
principal against a security capability -- so it descends the same
precedence ladder as any other action, is authorised or refused by
the same rules, and lands in the same hash chain:

    decide  ->  refuse unless explicitly allowed
    record  ->  seal the authorisation into the agent's chain
    rotate  ->  perform the key operation
    outcome ->  anchor the result, carrying the new public key

Failure ordering is deliberate. The decision is recorded BEFORE the
rotation is attempted, so a rotation that fails midway is visible as
an authorised action with an error outcome rather than vanishing.
"""

from __future__ import annotations

import json
import time
from typing import Any

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from .decision import Decision
from .signer import rotate_key
from .trace import AgentAction

ROTATION_CAPABILITY = "security.rotate_signing_key"


class RotationRefused(PermissionError):  # noqa: N818 — refusal, not a fault
    """The precedence ladder did not authorise the rotation."""


def _public_key_from_seed(seed_hex: str) -> str:
    try:
        key = SigningKey(seed_hex.encode("ascii"), encoder=HexEncoder)
    except Exception as exc:
        raise ValueError("invalid rotation seed") from exc
    return key.verify_key.encode(encoder=HexEncoder).decode()


def rotate_and_record(
    *,
    engine: Any,
    recorder: Any,
    agent_id: str,
    old_seed_hex: str,
    new_seed_hex: str | None = None,
    reason: str = "",
    timestamp: float | None = None,
) -> dict[str, Any]:
    """Authorise, seal, then perform a signing-key rotation.

    ``new_seed_hex`` is required. Validation and public-key derivation
    happen before any rotation record is written. Returns public
    metadata, the rotation envelope, and key identifier — never the seed.
    """
    if new_seed_hex is None or new_seed_hex == "":
        raise ValueError("new_seed_hex is required")
    old_public_key = _public_key_from_seed(old_seed_hex)
    new_public_key = _public_key_from_seed(new_seed_hex)

    arguments: dict[str, Any] = {
        "old_public_key": old_public_key,
        "new_public_key": new_public_key,
    }
    if reason:
        arguments["reason"] = reason

    action = AgentAction(
        agent_id=agent_id,
        capability=ROTATION_CAPABILITY,
        timestamp=time.time() if timestamp is None else timestamp,
        arguments=arguments,
    )

    result = engine.decide(action)
    if result.decision is not Decision.ALLOW:
        recorder.record(action, result)
        raise RotationRefused(
            f"key rotation refused: {result.decision.value} "
            f"({result.triggered_by}: {result.reason})"
        )

    record = recorder.record(action, result)

    try:
        rotation = rotate_key(old_seed_hex, new_seed_hex)
        if rotation["new_public_key"] != new_public_key:
            raise ValueError("rotation public key mismatch")
    except Exception:
        recorder.report_outcome(record.decision_id, "error", "rotation failed")
        raise

    detail = json.dumps(
        {
            "decision_id": record.decision_id,
            "old_public_key": old_public_key,
            "new_public_key": rotation["new_public_key"],
            "key_id": rotation["key_id"],
            "rotation_envelope": rotation["rotation_envelope"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    recorder.report_outcome(record.decision_id, "ok", detail)
    rotation["decision_id"] = record.decision_id
    return rotation
