"""Versioned dispatch-context digest (D1 / Phase 1).

Sealed separately from ``action_v01``. Does **not** widen
``EXECUTION_ACTION_FIELDS``. Does **not** claim exact wire-byte
enforcement — only the decide-time intent for adapter/transport,
operation, destination, and content type.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_dna.authority_v01 import (
    AuthorityFormatError,
    sha256_digest,
)

DISPATCH_CONTEXT_SPEC = "pv-dispatch-context/0.1"

DISPATCH_CONTEXT_FIELDS = frozenset(
    {
        "adapter",
        "transport",
        "operation",
        "destination",
        "wire_content_type",
    }
)

_STRING_FIELDS = (
    "adapter",
    "transport",
    "operation",
    "destination",
    "wire_content_type",
)


def validate_dispatch_context(
    context: Any,
    path: str = "dispatch_context",
) -> dict[str, Any]:
    """Strictly validate the five-field dispatch context."""
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
    return out


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
        }
    )


def dispatch_context_from_ea_dispatch(
    dispatch: Any,
    path: str = "dispatch",
) -> dict[str, Any]:
    """Project an EA-shaped dispatch object onto the sealed context fields.

    ``adapter`` may be omitted on legacy EA dispatch objects; in that case
    it defaults to ``transport`` (still validated as a non-empty string).
    Extra EA fields (tool digests, encodings, etc.) are ignored for the
    decide-time digest — wire-byte binding remains authorize/dispatch-time.
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
        },
        path=path,
    )
