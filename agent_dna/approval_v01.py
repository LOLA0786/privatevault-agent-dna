"""Evidence-bound approval requests v0.1-experimental."""

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

APPROVAL_REQUEST_SPEC = "pv-approval-request/0.1-experimental"
APPROVAL_ARTIFACT_SPEC = "pv-approval-artifact/0.1-experimental"
APPROVAL_DECISIONS = frozenset({"APPROVE", "DENY"})

_REQUEST_FIELDS = frozenset(
    {
        "spec",
        "canonicalization",
        "approval_request_id",
        "organisation_id",
        "request_id",
        "created_at",
        "expires_at",
        "nonce",
        "decision_input_digest",
        "action",
        "action_digest",
        "evidence_manifest_digest",
        "presentation_digest",
        "approval_requirement_digest",
    }
)

_ACTION_FIELDS = frozenset(
    {
        "subject_principal",
        "subject_key_id",
        "action",
        "resource",
        "parameters",
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
    required: frozenset[str],
    path: str,
) -> None:
    actual = set(value)
    missing = sorted(required - actual)
    extra = sorted(actual - required)

    if missing:
        raise AuthorityFormatError(
            f"{path}: missing fields {missing}"
        )

    if extra:
        raise AuthorityFormatError(
            f"{path}: unexpected fields {extra}"
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


def _require_digest(
    value: Any,
    path: str,
) -> str:
    if not isinstance(value, str):
        raise AuthorityFormatError(
            f"{path}: expected SHA-256 digest"
        )

    if not SHA256_RE.fullmatch(value):
        raise AuthorityFormatError(
            f"{path}: malformed SHA-256 digest"
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


def validate_approval_request(
    request: Any,
) -> Mapping[str, Any]:
    """Validate an immutable request presented for approval."""

    value = _require_object(
        request,
        "approval_request",
    )
    _require_exact_fields(
        value,
        _REQUEST_FIELDS,
        "approval_request",
    )

    if value["spec"] != APPROVAL_REQUEST_SPEC:
        raise AuthorityFormatError(
            "approval_request.spec: unsupported spec"
        )

    if value["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError(
            "approval_request.canonicalization: "
            "unsupported canonicalization"
        )

    for field in (
        "approval_request_id",
        "organisation_id",
        "request_id",
    ):
        _require_string(
            value[field],
            f"approval_request.{field}",
        )

    created_at = _parse_timestamp(
        value["created_at"],
        "approval_request.created_at",
    )
    expires_at = _parse_timestamp(
        value["expires_at"],
        "approval_request.expires_at",
    )

    if created_at >= expires_at:
        raise AuthorityFormatError(
            "approval_request.expires_at: "
            "must be after created_at"
        )

    nonce = _require_string(
        value["nonce"],
        "approval_request.nonce",
    )
    if not 16 <= len(nonce) <= 256:
        raise AuthorityFormatError(
            "approval_request.nonce: "
            "length must be between 16 and 256"
        )

    for field in (
        "decision_input_digest",
        "action_digest",
        "evidence_manifest_digest",
        "presentation_digest",
        "approval_requirement_digest",
    ):
        _require_digest(
            value[field],
            f"approval_request.{field}",
        )

    action = _require_object(
        value["action"],
        "approval_request.action",
    )
    _require_exact_fields(
        action,
        _ACTION_FIELDS,
        "approval_request.action",
    )

    for field in (
        "subject_principal",
        "subject_key_id",
        "action",
        "resource",
    ):
        _require_string(
            action[field],
            f"approval_request.action.{field}",
        )

    _require_object(
        action["parameters"],
        "approval_request.action.parameters",
    )

    canonicalize(value)

    expected_action_digest = sha256_digest(action)
    if value["action_digest"] != expected_action_digest:
        raise AuthorityFormatError(
            "approval_request.action_digest: "
            "does not match action"
        )

    return value


def approval_request_digest(
    request: Any,
) -> str:
    """Digest the complete validated approval request."""

    validated = validate_approval_request(request)
    return sha256_digest(validated)

_ARTIFACT_FIELDS = frozenset(
    {
        "spec",
        "canonicalization",
        "approval_id",
        "approval_request_id",
        "approval_request_digest",
        "organisation_id",
        "request_id",
        "decision_input_digest",
        "action_digest",
        "evidence_manifest_digest",
        "presentation_digest",
        "approval_requirement_digest",
        "approver_principal",
        "approver_key_id",
        "approver_authority_digest",
        "decision",
        "decided_at",
        "expires_at",
        "signature",
    }
)


def validate_approval_artifact(
    artifact: Any,
) -> Mapping[str, Any]:
    """Validate the structure of a signed reviewer decision."""

    value = _require_object(
        artifact,
        "approval_artifact",
    )
    _require_exact_fields(
        value,
        _ARTIFACT_FIELDS,
        "approval_artifact",
    )

    if value["spec"] != APPROVAL_ARTIFACT_SPEC:
        raise AuthorityFormatError(
            "approval_artifact.spec: unsupported spec"
        )

    if value["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError(
            "approval_artifact.canonicalization: "
            "unsupported canonicalization"
        )

    for field in (
        "approval_id",
        "approval_request_id",
        "organisation_id",
        "request_id",
        "approver_principal",
        "approver_key_id",
    ):
        _require_string(
            value[field],
            f"approval_artifact.{field}",
        )

    for field in (
        "approval_request_digest",
        "decision_input_digest",
        "action_digest",
        "evidence_manifest_digest",
        "presentation_digest",
        "approval_requirement_digest",
        "approver_authority_digest",
    ):
        _require_digest(
            value[field],
            f"approval_artifact.{field}",
        )

    decision = value["decision"]
    if decision not in APPROVAL_DECISIONS:
        raise AuthorityFormatError(
            "approval_artifact.decision: "
            "expected APPROVE or DENY"
        )

    decided_at = _parse_timestamp(
        value["decided_at"],
        "approval_artifact.decided_at",
    )
    expires_at = _parse_timestamp(
        value["expires_at"],
        "approval_artifact.expires_at",
    )

    if decided_at >= expires_at:
        raise AuthorityFormatError(
            "approval_artifact.expires_at: "
            "must be after decided_at"
        )

    signature = value["signature"]
    if (
        not isinstance(signature, str)
        or not SIGNATURE_RE.fullmatch(signature)
    ):
        raise AuthorityFormatError(
            "approval_artifact.signature: "
            "malformed Ed25519 signature"
        )

    canonicalize(value)
    return value


def sign_approval_artifact(
    artifact: Mapping[str, Any],
    signing_key: SigningKey,
) -> dict[str, Any]:
    """Sign every artifact field with the approver's key."""

    signed = sign_document(
        artifact,
        signing_key,
        signature_field="signature",
    )
    validate_approval_artifact(signed)
    return signed


def approval_artifact_digest(
    artifact: Any,
) -> str:
    """Digest the complete signed approval artifact."""

    validated = validate_approval_artifact(artifact)
    return sha256_digest(validated)
