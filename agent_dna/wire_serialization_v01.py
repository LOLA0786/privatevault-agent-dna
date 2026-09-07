"""Trusted request-body serialization for action↔wire binding.

Decide seals an execution action and a dispatch context that names one of
these serializers. Authorize then re-derives the wire bytes from
``action.parameters`` under that named contract and refuses any
``expected_wire_bytes_digest`` that does not match. Callers cannot bind two
independent hashes and claim they are the same purchase.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from agent_dna.authority_v01 import AuthorityFormatError

WIRE_SERIALIZATION_JSON_PARAMETERS_V01 = "pv-json-parameters/0.1"

KNOWN_WIRE_SERIALIZATIONS = frozenset(
    {
        WIRE_SERIALIZATION_JSON_PARAMETERS_V01,
    }
)

AUTHORIZE_WIRE_ACTION_MISMATCH = "AUTHORIZE_WIRE_ACTION_MISMATCH"
AUTHORIZE_WIRE_SERIALIZATION_UNKNOWN = "AUTHORIZE_WIRE_SERIALIZATION_UNKNOWN"
AUTHORIZE_WIRE_SERIALIZATION_REQUIRED = "AUTHORIZE_WIRE_SERIALIZATION_REQUIRED"


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def require_wire_serialization(spec: Any, *, path: str = "serialization") -> str:
    if not isinstance(spec, str) or not spec:
        raise AuthorityFormatError(f"{path}: expected non-empty string")
    if spec not in KNOWN_WIRE_SERIALIZATIONS:
        raise AuthorityFormatError(
            f"{path}: unknown wire serialization {spec!r}; "
            f"known={sorted(KNOWN_WIRE_SERIALIZATIONS)}"
        )
    return spec


def serialize_parameters_wire(
    parameters: Any,
    *,
    serialization: str,
    path: str = "parameters",
) -> bytes:
    """Deterministic wire bytes for one named serialization contract."""
    spec = require_wire_serialization(serialization)
    if not isinstance(parameters, Mapping):
        raise AuthorityFormatError(f"{path}: expected object")

    if spec == WIRE_SERIALIZATION_JSON_PARAMETERS_V01:
        try:
            return json.dumps(
                dict(parameters),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise AuthorityFormatError(
                f"{path}: not encodable under {spec}"
            ) from exc

    raise AuthorityFormatError(f"unhandled wire serialization {spec!r}")


def wire_bytes_digest_from_action(
    action: Mapping[str, Any],
    *,
    serialization: str,
) -> tuple[str, int, bytes]:
    """Return ``(sha256:digest, length, wire_bytes)`` for ``action.parameters``."""
    parameters = action.get("parameters")
    wire = serialize_parameters_wire(
        parameters,
        serialization=serialization,
        path="action.parameters",
    )
    return _sha256_bytes(wire), len(wire), wire


def wire_action_binding_reason(
    *,
    action: Mapping[str, Any],
    serialization: Any,
    expected_wire_bytes_digest: Any,
    expected_wire_bytes_length: Any,
) -> str | None:
    """Return a reason code when the wire digest is not the action body."""
    if not isinstance(serialization, str) or not serialization:
        return AUTHORIZE_WIRE_SERIALIZATION_REQUIRED
    if serialization not in KNOWN_WIRE_SERIALIZATIONS:
        return AUTHORIZE_WIRE_SERIALIZATION_UNKNOWN

    try:
        digest, length, _ = wire_bytes_digest_from_action(
            action,
            serialization=serialization,
        )
    except (AuthorityFormatError, TypeError, ValueError):
        return AUTHORIZE_WIRE_ACTION_MISMATCH

    if not isinstance(expected_wire_bytes_digest, str):
        return AUTHORIZE_WIRE_ACTION_MISMATCH
    if digest != expected_wire_bytes_digest:
        return AUTHORIZE_WIRE_ACTION_MISMATCH
    if expected_wire_bytes_length != length:
        return AUTHORIZE_WIRE_ACTION_MISMATCH
    return None


__all__ = [
    "AUTHORIZE_WIRE_ACTION_MISMATCH",
    "AUTHORIZE_WIRE_SERIALIZATION_REQUIRED",
    "AUTHORIZE_WIRE_SERIALIZATION_UNKNOWN",
    "KNOWN_WIRE_SERIALIZATIONS",
    "WIRE_SERIALIZATION_JSON_PARAMETERS_V01",
    "require_wire_serialization",
    "serialize_parameters_wire",
    "wire_action_binding_reason",
    "wire_bytes_digest_from_action",
]
