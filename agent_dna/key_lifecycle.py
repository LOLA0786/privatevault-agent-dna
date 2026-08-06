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

import time
from typing import Any

from .decision import Decision
from .signer import rotate_key
from .trace import AgentAction

ROTATION_CAPABILITY = "security.rotate_signing_key"


class RotationRefused(PermissionError):  # noqa: N818 — refusal, not a fault
    """The precedence ladder did not authorise the rotation."""


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

    Returns the rotation result from ``rotate_key`` with the sealed
    ``decision_id`` attached. Raises ``RotationRefused`` if the ladder
    did not return ALLOW -- rotation is capability-gated like any
    other privileged action, never a side door.
    """
    action = AgentAction(
        agent_id=agent_id,
        capability=ROTATION_CAPABILITY,
        timestamp=time.time() if timestamp is None else timestamp,
        arguments={"reason": reason} if reason else {},
    )

    result = engine.decide(action)
    if result.decision is not Decision.ALLOW:
        # Refusals are recorded too: an attempted rotation that was
        # denied is exactly the event a security review wants to see.
        recorder.record(action, result)
        raise RotationRefused(
            f"key rotation refused: {result.decision.value} "
            f"({result.triggered_by}: {result.reason})"
        )

    record = recorder.record(action, result)

    try:
        rotation = rotate_key(old_seed_hex, new_seed_hex)
    except Exception as exc:
        recorder.report_outcome(record.decision_id, "error", f"rotation failed: {exc}")
        raise

    recorder.report_outcome(
        record.decision_id,
        "ok",
        f"new_public_key={rotation['new_public_key']}",
    )
    rotation["decision_id"] = record.decision_id
    return rotation
