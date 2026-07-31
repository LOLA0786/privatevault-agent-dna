"""Execution closure record v0.1-experimental."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    RFC3339_UTC_RE,
    SHA256_RE,
    SIGNATURE_RE,
    AuthorityFormatError,
    canonicalize,
    sha256_digest,
    sign_document,
)

CLOSURE_RECORD_SPEC = (
    "pv-execution-closure/0.1-experimental"
)

DISPATCH_OUTCOMES = frozenset(
    {
        "ACKNOWLEDGED",
        "REJECTED",
        "TRANSPORT_ERROR",
        "INDETERMINATE",
    }
)

EFFECT_STATES = frozenset(
    {
        "CONFIRMED",
        "UNCONFIRMED",
        "UNKNOWN",
    }
)

_CLOSURE_FIELDS = frozenset(
    {
        "spec",
        "canonicalization",
        "closure_id",
        "organisation_id",
        "request_id",
        "execution_authorization_id",
        "execution_authorization_digest",
        "dispatch_witness_id",
        "dispatch_witness_digest",
        "closed_at",
        "closure_component_id",
        "dispatch_outcome",
        "response_status",
        "response_bytes_digest",
        "response_bytes_length",
        "effect_state",
        "effect_evidence_digest",
        "idempotency_key_digest",
        "authorization_use_count",
        "trust_bundle_digest",
        "signer_key_id",
        "signature",
    }
)

_CLOSURE_METADATA_FIELDS = frozenset(
    {
        "closure_id",
        "closed_at",
        "closure_component_id",
        "dispatch_outcome",
        "response_status",
        "effect_state",
        "signer_key_id",
    }
)


def _require_object(
    value: Any,
    path: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AuthorityFormatError(
            f"{path}: expected object"
        )
    return value


def _require_exact_fields(
    value: Mapping[str, Any],
    expected: frozenset[str],
    path: str,
) -> None:
    actual = frozenset(value)
    missing = expected - actual
    unexpected = actual - expected

    if missing:
        raise AuthorityFormatError(
            f"{path}: missing fields {sorted(missing)}"
        )

    if unexpected:
        raise AuthorityFormatError(
            f"{path}: unexpected fields "
            f"{sorted(unexpected)}"
        )


def _require_string(
    value: Any,
    path: str,
) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorityFormatError(
            f"{path}: expected non-empty string"
        )
    return value


def _require_optional_string(
    value: Any,
    path: str,
) -> str | None:
    if value is None:
        return None
    return _require_string(value, path)


def _require_digest(
    value: Any,
    path: str,
) -> str:
    if (
        not isinstance(value, str)
        or not SHA256_RE.fullmatch(value)
    ):
        raise AuthorityFormatError(
            f"{path}: malformed SHA-256 digest"
        )
    return value


def _require_optional_digest(
    value: Any,
    path: str,
) -> str | None:
    if value is None:
        return None
    return _require_digest(value, path)


def _require_optional_length(
    value: Any,
    path: str,
) -> int | None:
    if value is None:
        return None

    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
    ):
        raise AuthorityFormatError(
            f"{path}: expected integer >= 0 or null"
        )

    return value


def _parse_timestamp(
    value: Any,
    path: str,
) -> datetime:
    if (
        not isinstance(value, str)
        or not RFC3339_UTC_RE.fullmatch(value)
    ):
        raise AuthorityFormatError(
            f"{path}: expected RFC3339 UTC timestamp"
        )

    try:
        return datetime.fromisoformat(
            value.removesuffix("Z") + "+00:00"
        )
    except ValueError as exc:
        raise AuthorityFormatError(
            f"{path}: invalid timestamp"
        ) from exc


def validate_closure_record(  # noqa: C901
    closure: Any,
    path: str = "closure_record",
) -> Mapping[str, Any]:
    """Strictly validate a signed execution closure record."""

    value = _require_object(closure, path)
    _require_exact_fields(
        value,
        _CLOSURE_FIELDS,
        path,
    )

    if value["spec"] != CLOSURE_RECORD_SPEC:
        raise AuthorityFormatError(
            f"{path}.spec: unsupported spec"
        )

    if value["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError(
            f"{path}.canonicalization: unsupported"
        )

    for field in (
        "closure_id",
        "organisation_id",
        "request_id",
        "execution_authorization_id",
        "dispatch_witness_id",
        "closure_component_id",
        "signer_key_id",
    ):
        _require_string(
            value[field],
            f"{path}.{field}",
        )

    for field in (
        "execution_authorization_digest",
        "dispatch_witness_digest",
        "idempotency_key_digest",
        "trust_bundle_digest",
    ):
        _require_digest(
            value[field],
            f"{path}.{field}",
        )

    _parse_timestamp(
        value["closed_at"],
        f"{path}.closed_at",
    )

    outcome = value["dispatch_outcome"]
    if outcome not in DISPATCH_OUTCOMES:
        raise AuthorityFormatError(
            f"{path}.dispatch_outcome: unsupported outcome"
        )

    effect_state = value["effect_state"]
    if effect_state not in EFFECT_STATES:
        raise AuthorityFormatError(
            f"{path}.effect_state: unsupported state"
        )

    response_status = _require_optional_string(
        value["response_status"],
        f"{path}.response_status",
    )
    response_digest = _require_optional_digest(
        value["response_bytes_digest"],
        f"{path}.response_bytes_digest",
    )
    response_length = _require_optional_length(
        value["response_bytes_length"],
        f"{path}.response_bytes_length",
    )

    response_presence = (
        response_status is not None,
        response_digest is not None,
        response_length is not None,
    )
    if any(response_presence) and not all(
        response_presence
    ):
        raise AuthorityFormatError(
            f"{path}: response status, digest, and length "
            "must be all present or all null"
        )

    has_response = all(response_presence)

    if outcome in {"ACKNOWLEDGED", "REJECTED"} and (
        not has_response
    ):
        raise AuthorityFormatError(
            f"{path}: {outcome} requires response evidence"
        )

    if outcome == "TRANSPORT_ERROR" and has_response:
        raise AuthorityFormatError(
            f"{path}: TRANSPORT_ERROR cannot include "
            "response evidence"
        )

    effect_digest = _require_optional_digest(
        value["effect_evidence_digest"],
        f"{path}.effect_evidence_digest",
    )
    if (
        effect_state == "CONFIRMED"
        and effect_digest is None
    ):
        raise AuthorityFormatError(
            f"{path}: CONFIRMED effect requires evidence"
        )

    authorization_use_count = value[
        "authorization_use_count"
    ]
    if (
        isinstance(authorization_use_count, bool)
        or not isinstance(authorization_use_count, int)
        or authorization_use_count != 1
    ):
        raise AuthorityFormatError(
            f"{path}.authorization_use_count: "
            "expected integer 1"
        )

    signature = value["signature"]
    if (
        not isinstance(signature, str)
        or not SIGNATURE_RE.fullmatch(signature)
    ):
        raise AuthorityFormatError(
            f"{path}.signature: malformed Ed25519 signature"
        )

    canonicalize(value)
    return value


def sign_closure_record(
    closure: Mapping[str, Any],
    signing_key: SigningKey,
) -> dict[str, Any]:
    """Sign every closure-record field except the detached signature.

    Validation runs after signing rather than before. A malformed closure
    then fails here, at the moment it is produced, instead of surfacing as
    an unverifiable record in front of an auditor.
    """

    signed = sign_document(
        closure,
        signing_key,
        signature_field="signature",
    )
    validate_closure_record(signed)
    return signed


def closure_record_digest(
    closure: Any,
) -> str:
    """Digest the complete signed closure record.

    Validation runs first. This digest is what a ledger entry or external
    checkpoint links to, so a malformed record must never become
    permanently referenced.
    """

    validated = validate_closure_record(closure)
    return sha256_digest(validated)
