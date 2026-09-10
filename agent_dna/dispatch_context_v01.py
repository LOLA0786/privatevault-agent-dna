"""Versioned dispatch-context digest (D1 / Phase 1, extended for wire binding).

Sealed separately from ``action_v01``. Does **not** widen
``EXECUTION_ACTION_FIELDS``. ``serialization`` names the trusted contract
that maps ``action.parameters`` onto wire bytes so authorize can refuse a
permit whose body is not the sealed action.

``pv-dispatch-context/0.1`` (five fields, no serialization) remains
readable for audit of historical records but is not accepted for new
mintable decide requests.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_dna.authority_v01 import (
    AuthorityFormatError,
    sha256_digest,
)
from agent_dna.wire_serialization_v01 import require_wire_serialization

DISPATCH_CONTEXT_SPEC = "pv-dispatch-context/0.2"
DISPATCH_CONTEXT_SPEC_V01 = "pv-dispatch-context/0.1"
AUDIT_ONLY_SERIALIZATION = "pv-audit-only/0.1"

DISPATCH_CONTEXT_FIELDS = frozenset(
    {
        "adapter",
        "transport",
        "operation",
        "destination",
        "wire_content_type",
        "serialization",
    }
)

_STRING_FIELDS = (
    "adapter",
    "transport",
    "operation",
    "destination",
    "wire_content_type",
    "serialization",
)


def validate_dispatch_context(
    context: Any,
    path: str = "dispatch_context",
) -> dict[str, Any]:
    """Strictly validate the six-field dispatch context (0.2)."""
    if not isinstance(context, Mapping):
        raise AuthorityFormatError(f"{path}: expected object")

    present = set(context)
    missing = DISPATCH_CONTEXT_FIELDS - present
    unexpected = present - DISPATCH_CONTEXT_FIELDS
    if missing:
        raise AuthorityFormatError(f"{path}: missing field(s) {sorted(missing)}")
    if unexpected:
        raise AuthorityFormatError(f"{path}: unexpected field(s) {sorted(unexpected)}")

    out: dict[str, Any] = {}
    for field in _STRING_FIELDS:
        value = context[field]
        if not isinstance(value, str) or not value:
            raise AuthorityFormatError(f"{path}.{field}: expected non-empty string")
        out[field] = value
    if out["serialization"] != AUDIT_ONLY_SERIALIZATION:
        require_wire_serialization(out["serialization"], path=f"{path}.serialization")
    return out


def legacy_dispatch_context_digest(context: Any) -> str:
    """Read-only v0.1 digest; never inserts a serializer or upgrades authority."""
    fields = DISPATCH_CONTEXT_FIELDS - {"serialization"}
    if not isinstance(context, Mapping) or set(context) != fields:
        raise AuthorityFormatError("legacy dispatch_context: expected five fields")
    if any(not isinstance(v, str) or not v for v in context.values()):
        raise AuthorityFormatError(
            "legacy dispatch_context: expected non-empty strings"
        )
    return sha256_digest({"spec": DISPATCH_CONTEXT_SPEC_V01, **context})


def dispatch_context_digest(
    context: Any,
    path: str = "dispatch_context",
) -> str:
    """Derive-only digest. Callers cannot supply a digest to trust."""
    validated = validate_dispatch_context(context, path)
    return sha256_digest(
        {
            "spec": DISPATCH_CONTEXT_SPEC,
            "adapter": validated["adapter"],
            "transport": validated["transport"],
            "operation": validated["operation"],
            "destination": validated["destination"],
            "wire_content_type": validated["wire_content_type"],
            "serialization": validated["serialization"],
        }
    )


def dispatch_context_from_ea_dispatch(
    dispatch: Any,
    path: str = "dispatch",
) -> dict[str, Any]:
    """Project an EA-shaped dispatch object onto the sealed context fields.

    ``adapter`` may be omitted on legacy EA dispatch objects; in that case
    it defaults to ``transport``. ``serialization`` is required on mintable
    EA dispatch objects so authorize can re-derive wire bytes from the
    sealed action.
    """
    if not isinstance(dispatch, Mapping):
        raise AuthorityFormatError(f"{path}: expected object")

    transport = dispatch.get("transport")
    adapter = dispatch.get("adapter")
    if not isinstance(adapter, str) or not adapter:
        if isinstance(transport, str) and transport:
            adapter = transport
        else:
            raise AuthorityFormatError(
                f"{path}.adapter: expected non-empty string "
                "(or non-empty transport to default from)"
            )

    return validate_dispatch_context(
        {
            "adapter": adapter,
            "transport": transport,
            "operation": dispatch.get("operation"),
            "destination": dispatch.get("destination"),
            "wire_content_type": dispatch.get("wire_content_type"),
            "serialization": dispatch.get("serialization"),
        },
        path=path,
    )
