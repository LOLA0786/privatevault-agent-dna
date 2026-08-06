"""Evidence-bound approval requests v0.1-experimental."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

from nacl.exceptions import BadSignatureError

if TYPE_CHECKING:
    from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    RFC3339_UTC_RE,
    SHA256_RE,
    SIGNATURE_RE,
    AuthorityFormatError,
    DecisionConformance,
    EvidenceState,
    VerificationReport,
    canonicalize,
    receipt_digest,
    sha256_digest,
    sign_document,
    validate_trust_bundle,
    verify_document_signature,
    verify_receipt,
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
        raise AuthorityFormatError(f"{path}: expected object")
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
        raise AuthorityFormatError(f"{path}: missing fields {missing}")

    if extra:
        raise AuthorityFormatError(f"{path}: unexpected fields {extra}")


def _require_string(
    value: Any,
    path: str,
) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorityFormatError(f"{path}: expected non-empty string")
    return value


def _require_digest(
    value: Any,
    path: str,
) -> str:
    if not isinstance(value, str):
        raise AuthorityFormatError(f"{path}: expected SHA-256 digest")

    if not SHA256_RE.fullmatch(value):
        raise AuthorityFormatError(f"{path}: malformed SHA-256 digest")

    return value


def _parse_timestamp(
    value: Any,
    path: str,
) -> datetime:
    if not isinstance(value, str) or not RFC3339_UTC_RE.fullmatch(value):
        raise AuthorityFormatError(f"{path}: expected RFC3339 UTC timestamp")

    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise AuthorityFormatError(f"{path}: invalid timestamp") from exc


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
        raise AuthorityFormatError("approval_request.spec: unsupported spec")

    if value["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError(
            "approval_request.canonicalization: unsupported canonicalization"
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
            "approval_request.expires_at: must be after created_at"
        )

    nonce = _require_string(
        value["nonce"],
        "approval_request.nonce",
    )
    if not 16 <= len(nonce) <= 256:
        raise AuthorityFormatError(
            "approval_request.nonce: length must be between 16 and 256"
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
            "approval_request.action_digest: does not match action"
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
        raise AuthorityFormatError("approval_artifact.spec: unsupported spec")

    if value["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError(
            "approval_artifact.canonicalization: unsupported canonicalization"
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
            "approval_artifact.decision: expected APPROVE or DENY"
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
            "approval_artifact.expires_at: must be after decided_at"
        )

    signature = value["signature"]
    if not isinstance(signature, str) or not SIGNATURE_RE.fullmatch(signature):
        raise AuthorityFormatError(
            "approval_artifact.signature: malformed Ed25519 signature"
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


APPROVAL_AUTHORITY_ACTION = "approval.decide"


def _approval_invalid(
    reason_code: str,
    detail: str,
) -> VerificationReport:
    return VerificationReport(
        EvidenceState.INVALID,
        DecisionConformance.NOT_ASSESSABLE,
        reason_code,
        (detail,),
    )


def verify_approval_for_execution(  # noqa: C901
    request: Any,
    artifact: Any,
    trust_bundle: Mapping[str, Any] | None,
    approver_authority_receipt: Mapping[str, Any] | None,
    *,
    at_time: Any,
) -> VerificationReport:
    """Verify that a signed approval is executable at ``at_time``.

    Verification binds the artifact to the immutable approval request,
    resolves the approver key from an out-of-band trust bundle, verifies
    the artifact signature and key usage, and independently verifies the
    approver's authority receipt for this exact approval request.
    """

    if trust_bundle is None:
        return VerificationReport(
            EvidenceState.UNVERIFIABLE,
            DecisionConformance.NOT_ASSESSABLE,
            "TRUST_BUNDLE_UNAVAILABLE",
            ("no out-of-band trust bundle was supplied",),
        )

    if approver_authority_receipt is None:
        return VerificationReport(
            EvidenceState.ABSENT,
            DecisionConformance.NOT_ASSESSABLE,
            "APPROVER_AUTHORITY_ABSENT",
            ("no approver authority receipt was supplied",),
        )

    try:
        validated_request = validate_approval_request(request)
        validated_artifact = validate_approval_artifact(artifact)
        keys = validate_trust_bundle(trust_bundle)
        execution_time = _parse_timestamp(
            at_time,
            "approval_verification.at_time",
        )
    except AuthorityFormatError as exc:
        return _approval_invalid(
            "SCHEMA_INVALID",
            str(exc),
        )

    organisation_id = validated_request["organisation_id"]

    if (
        trust_bundle["organisation_id"] != organisation_id
        or validated_artifact["organisation_id"] != organisation_id
    ):
        return _approval_invalid(
            "ORGANISATION_MISMATCH",
            "request, artifact, and trust bundle organisations differ",
        )

    key_id = validated_artifact["approver_key_id"]
    key = keys.get(key_id)

    if key is None:
        return _approval_invalid(
            "TRUST_ROOT_UNKNOWN",
            f"approver key {key_id!r} is absent from trust bundle",
        )

    approver_principal = validated_artifact["approver_principal"]

    if key["principal"] != approver_principal:
        return _approval_invalid(
            "KEY_CONTINUITY_BROKEN",
            f"key {key_id!r} belongs to {key['principal']!r}, "
            f"not {approver_principal!r}",
        )

    if "approval_signer" not in key["usages"]:
        return _approval_invalid(
            "KEY_USAGE_INVALID",
            f"key {key_id!r} lacks required usage 'approval_signer'",
        )

    try:
        verify_document_signature(
            validated_artifact,
            signature_field="signature",
            public_key=key["public_key"],
        )
    except (AuthorityFormatError, BadSignatureError):
        return _approval_invalid(
            "APPROVAL_SIGNATURE_INVALID",
            "approval artifact signature is invalid",
        )

    authority_report = verify_receipt(
        approver_authority_receipt,
        trust_bundle,
    )

    if authority_report.evidence_state is not EvidenceState.VERIFIED:
        return VerificationReport(
            authority_report.evidence_state,
            DecisionConformance.NOT_ASSESSABLE,
            ("APPROVER_AUTHORITY_" + (authority_report.reason_code or "INVALID")),
            authority_report.failures,
            authority_report.accountable_principal,
        )

    request_digest = approval_request_digest(validated_request)
    failures: list[str] = []

    expected_bindings = (
        ("approval_request_id", "approval_request_id"),
        ("organisation_id", "organisation_id"),
        ("request_id", "request_id"),
        ("decision_input_digest", "decision_input_digest"),
        ("action_digest", "action_digest"),
        (
            "evidence_manifest_digest",
            "evidence_manifest_digest",
        ),
        ("presentation_digest", "presentation_digest"),
        (
            "approval_requirement_digest",
            "approval_requirement_digest",
        ),
    )

    for artifact_field, request_field in expected_bindings:
        if validated_artifact[artifact_field] != validated_request[request_field]:
            failures.append(
                f"approval_artifact.{artifact_field} does not "
                f"match approval_request.{request_field}"
            )

    if validated_artifact["approval_request_digest"] != request_digest:
        failures.append(
            "approval_artifact.approval_request_digest does not "
            "match the supplied approval request"
        )

    if validated_artifact["decision"] != "APPROVE":
        failures.append("approval artifact decision is not APPROVE")

    request_created = _parse_timestamp(
        validated_request["created_at"],
        "approval_request.created_at",
    )
    request_expires = _parse_timestamp(
        validated_request["expires_at"],
        "approval_request.expires_at",
    )
    decided_at = _parse_timestamp(
        validated_artifact["decided_at"],
        "approval_artifact.decided_at",
    )
    artifact_expires = _parse_timestamp(
        validated_artifact["expires_at"],
        "approval_artifact.expires_at",
    )

    if not request_created <= decided_at < request_expires:
        failures.append("approval decision is outside the request validity window")

    if artifact_expires > request_expires:
        failures.append("approval artifact outlives its approval request")

    if not decided_at <= execution_time < artifact_expires:
        failures.append("approval artifact is not valid at execution time")

    if execution_time >= request_expires:
        failures.append("approval request is expired at execution time")

    expected_authority_digest = receipt_digest(approver_authority_receipt)

    if validated_artifact["approver_authority_digest"] != expected_authority_digest:
        failures.append(
            "approver_authority_digest does not match the supplied authority receipt"
        )

    authority_requested = approver_authority_receipt["requested"]
    expected_resource = "approval_request:" + validated_request["approval_request_id"]

    if approver_authority_receipt["organisation_id"] != organisation_id:
        failures.append("approver authority receipt organisation does not match")

    if (
        approver_authority_receipt["request_id"]
        != validated_request["approval_request_id"]
    ):
        failures.append(
            "approver authority receipt request_id does not bind the approval request"
        )

    if approver_authority_receipt["decision_input_digest"] != request_digest:
        failures.append(
            "approver authority receipt does not bind the approval request digest"
        )

    if (
        authority_requested["subject_principal"] != approver_principal
        or authority_requested["subject_key_id"] != key_id
    ):
        failures.append("approver authority subject does not match the artifact signer")

    if authority_requested["action"] != APPROVAL_AUTHORITY_ACTION:
        failures.append("approver authority action is not approval.decide")

    if authority_requested["resource"] != expected_resource:
        failures.append(
            "approver authority resource does not target this approval request"
        )

    if approver_authority_receipt["final_verdict"] != "ALLOW":
        failures.append("approver authority receipt does not allow approval")

    authority_time = _parse_timestamp(
        approver_authority_receipt["decision_timestamp"],
        "approver_authority_receipt.decision_timestamp",
    )

    if authority_time > decided_at:
        failures.append(
            "approver authority was established after the approval decision"
        )

    if not authority_report.ok:
        failures.extend(authority_report.failures)

    return VerificationReport(
        EvidenceState.VERIFIED,
        (
            DecisionConformance.NON_CONFORMANT
            if failures
            else DecisionConformance.CONFORMANT
        ),
        "APPROVAL_NON_CONFORMANT" if failures else None,
        tuple(failures),
        authority_report.accountable_principal,
    )
