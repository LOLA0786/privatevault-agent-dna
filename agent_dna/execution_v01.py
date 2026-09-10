"""Execution authorization and closure artifacts v0.1-experimental."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

from nacl.exceptions import BadSignatureError

if TYPE_CHECKING:
    from nacl.signing import SigningKey

from agent_dna.action_v01 import (
    execution_action_digest,
    validate_execution_action,
)
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
    sha256_digest,
    sign_document,
    validate_trust_bundle,
    verify_document_signature,
)
from agent_dna.authorize_binding import EXECUTION_AUTHORIZATION_CONSUMED
from agent_dna.wire_serialization_v01 import require_wire_serialization

EXECUTION_AUTHORIZATION_SPEC = "pv-execution-authorization/0.1-experimental"

_AUTHORIZATION_FIELDS = frozenset(
    {
        "spec",
        "canonicalization",
        "execution_authorization_id",
        "organisation_id",
        "request_id",
        "issued_at",
        "not_before",
        "expires_at",
        "nonce",
        "decision_receipt_digest",
        "authority_receipt_digest",
        "approval_artifact_digest",
        "action",
        "action_digest",
        "expected_wire_bytes_digest",
        "expected_wire_bytes_length",
        "expected_peer_identity_digest",
        "dispatch",
        "state_snapshot_digest",
        "policy_bundle_digest",
        "trust_bundle_digest",
        "obligations_digest",
        "max_uses",
        "signer_key_id",
        "signature",
    }
)

_DISPATCH_FIELDS = frozenset(
    {
        "transport",
        "destination",
        "operation",
        "wire_content_type",
        "wire_content_encoding",
        "tool_id",
        "tool_schema_digest",
        "tool_artifact_digest",
        "credential_audience",
        "idempotency_key_digest",
        "retry_policy_digest",
        "serialization",
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
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise AuthorityFormatError(f"{path}: malformed SHA-256 digest")
    return value


def _require_optional_digest(
    value: Any,
    path: str,
) -> str | None:
    if value is None:
        return None
    return _require_digest(value, path)


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


def sha256_bytes_digest(
    value: Any,
    path: str = "bytes",
) -> str:
    """Digest exact bytes without JSON reserialization."""

    if not isinstance(
        value,
        (bytes, bytearray, memoryview),
    ):
        raise AuthorityFormatError(f"{path}: expected bytes")

    return "sha256:" + hashlib.sha256(bytes(value)).hexdigest()


def validate_execution_authorization(  # noqa: C901
    authorization: Any,
    path: str = "execution_authorization",
) -> Mapping[str, Any]:
    """Strictly validate an execution authorization."""

    value = _require_object(authorization, path)
    _require_exact_fields(
        value,
        _AUTHORIZATION_FIELDS,
        path,
    )

    if value["spec"] != EXECUTION_AUTHORIZATION_SPEC:
        raise AuthorityFormatError(f"{path}.spec: unsupported spec")

    if value["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError(f"{path}.canonicalization: unsupported")

    for field in (
        "execution_authorization_id",
        "organisation_id",
        "request_id",
        "signer_key_id",
    ):
        _require_string(
            value[field],
            f"{path}.{field}",
        )

    issued_at = _parse_timestamp(
        value["issued_at"],
        f"{path}.issued_at",
    )
    not_before = _parse_timestamp(
        value["not_before"],
        f"{path}.not_before",
    )
    expires_at = _parse_timestamp(
        value["expires_at"],
        f"{path}.expires_at",
    )

    if issued_at > not_before:
        raise AuthorityFormatError(f"{path}: issued_at must be at or before not_before")

    if not_before >= expires_at:
        raise AuthorityFormatError(f"{path}: not_before must be before expires_at")

    nonce = _require_string(
        value["nonce"],
        f"{path}.nonce",
    )
    if not 16 <= len(nonce) <= 256:
        raise AuthorityFormatError(f"{path}.nonce: expected 16 to 256 characters")

    for field in (
        "decision_receipt_digest",
        "authority_receipt_digest",
        "action_digest",
        "expected_wire_bytes_digest",
        "expected_peer_identity_digest",
        "state_snapshot_digest",
        "policy_bundle_digest",
        "trust_bundle_digest",
        "obligations_digest",
    ):
        _require_digest(
            value[field],
            f"{path}.{field}",
        )

    _require_optional_digest(
        value["approval_artifact_digest"],
        f"{path}.approval_artifact_digest",
    )

    action = validate_execution_action(
        value["action"],
        f"{path}.action",
    )

    expected_action_digest = execution_action_digest(
        action,
        f"{path}.action",
    )
    if value["action_digest"] != expected_action_digest:
        raise AuthorityFormatError(f"{path}.action_digest: does not match action")

    dispatch = _require_object(
        value["dispatch"],
        f"{path}.dispatch",
    )
    _require_exact_fields(
        dispatch,
        _DISPATCH_FIELDS,
        f"{path}.dispatch",
    )

    for field in (
        "transport",
        "destination",
        "operation",
        "wire_content_type",
        "wire_content_encoding",
        "tool_id",
        "credential_audience",
        "serialization",
    ):
        _require_string(
            dispatch[field],
            f"{path}.dispatch.{field}",
        )

    for field in (
        "tool_schema_digest",
        "tool_artifact_digest",
        "idempotency_key_digest",
        "retry_policy_digest",
    ):
        _require_digest(
            dispatch[field],
            f"{path}.dispatch.{field}",
        )

    expected_wire_bytes_length = value["expected_wire_bytes_length"]
    require_wire_serialization(
        dispatch["serialization"], path=f"{path}.dispatch.serialization"
    )
    if (
        isinstance(expected_wire_bytes_length, bool)
        or not isinstance(expected_wire_bytes_length, int)
        or expected_wire_bytes_length < 0
    ):
        raise AuthorityFormatError(
            f"{path}.expected_wire_bytes_length: expected integer >= 0"
        )

    max_uses = value["max_uses"]
    if isinstance(max_uses, bool) or not isinstance(max_uses, int) or max_uses != 1:
        raise AuthorityFormatError(f"{path}.max_uses: expected integer 1")

    signature = value["signature"]
    if not isinstance(signature, str) or not SIGNATURE_RE.fullmatch(signature):
        raise AuthorityFormatError(f"{path}.signature: malformed Ed25519 signature")

    canonicalize(value)
    return value


def sign_execution_authorization(
    authorization: Mapping[str, Any],
    signing_key: SigningKey,
) -> dict[str, Any]:
    """Sign every execution-authorization field."""

    signed = sign_document(
        authorization,
        signing_key,
        signature_field="signature",
    )
    validate_execution_authorization(signed)
    return signed


def execution_authorization_digest(
    authorization: Any,
) -> str:
    """Digest the complete signed execution authorization."""

    validated = validate_execution_authorization(authorization)
    return sha256_digest(validated)


def _execution_invalid(
    reason_code: str,
    detail: str,
) -> VerificationReport:
    return VerificationReport(
        EvidenceState.INVALID,
        DecisionConformance.NOT_ASSESSABLE,
        reason_code,
        (detail,),
    )


def verify_execution_authorization(  # noqa: C901
    authorization: Any,
    trust_bundle: Mapping[str, Any] | None,
    *,
    expected_request_id: Any,
    expected_action: Any,
    expected_dispatch: Any,
    expected_decision_receipt_digest: Any,
    expected_authority_receipt_digest: Any,
    expected_approval_artifact_digest: Any,
    expected_state_snapshot_digest: Any,
    expected_policy_bundle_digest: Any,
    expected_obligations_digest: Any,
    expected_wire_bytes: Any,
    expected_peer_identity_bytes: Any,
    at_time: Any,
    already_consumed: Any,
    consume_ledger: Any | None = None,
    check_peer_identity: bool = True,
) -> VerificationReport:
    """Verify an authorization against the exact dispatch context.

    ``already_consumed`` may only tighten refusal. When ``consume_ledger``
    is supplied, successful verification atomically claims the id in that
    durable ledger; a second claim fails with
    ``EXECUTION_AUTHORIZATION_CONSUMED``.
    """

    if trust_bundle is None:
        return VerificationReport(
            EvidenceState.UNVERIFIABLE,
            DecisionConformance.NOT_ASSESSABLE,
            "TRUST_BUNDLE_UNAVAILABLE",
            ("no out-of-band trust bundle was supplied",),
        )

    try:
        validated = validate_execution_authorization(authorization)
        keys = validate_trust_bundle(trust_bundle)
        execution_time = _parse_timestamp(
            at_time,
            "execution_verification.at_time",
        )
        expected_request_id = _require_string(
            expected_request_id,
            "execution_verification.expected_request_id",
        )
        expected_action = _require_object(
            expected_action,
            "execution_verification.expected_action",
        )
        expected_dispatch = _require_object(
            expected_dispatch,
            "execution_verification.expected_dispatch",
        )
        expected_decision_receipt_digest = _require_digest(
            expected_decision_receipt_digest,
            ("execution_verification.expected_decision_receipt_digest"),
        )
        expected_authority_receipt_digest = _require_digest(
            expected_authority_receipt_digest,
            ("execution_verification.expected_authority_receipt_digest"),
        )
        expected_approval_artifact_digest = _require_optional_digest(
            expected_approval_artifact_digest,
            ("execution_verification.expected_approval_artifact_digest"),
        )
        expected_state_snapshot_digest = _require_digest(
            expected_state_snapshot_digest,
            ("execution_verification.expected_state_snapshot_digest"),
        )
        expected_policy_bundle_digest = _require_digest(
            expected_policy_bundle_digest,
            ("execution_verification.expected_policy_bundle_digest"),
        )
        expected_obligations_digest = _require_digest(
            expected_obligations_digest,
            ("execution_verification.expected_obligations_digest"),
        )
        measured_wire_digest = sha256_bytes_digest(
            expected_wire_bytes,
            ("execution_verification.expected_wire_bytes"),
        )
        measured_wire_length = len(bytes(expected_wire_bytes))
        measured_peer_digest = None
        if check_peer_identity:
            measured_peer_digest = sha256_bytes_digest(
                expected_peer_identity_bytes,
                ("execution_verification.expected_peer_identity_bytes"),
            )

        if not isinstance(already_consumed, bool):
            raise AuthorityFormatError(
                "execution_verification.already_consumed: expected boolean"
            )

        canonicalize(expected_action)
        canonicalize(expected_dispatch)
    except (AuthorityFormatError, TypeError, ValueError) as exc:
        return _execution_invalid(
            "SCHEMA_INVALID",
            str(exc),
        )

    organisation_id = validated["organisation_id"]

    if trust_bundle["organisation_id"] != organisation_id:
        return _execution_invalid(
            "ORGANISATION_MISMATCH",
            "authorization and trust bundle organisations differ",
        )

    key_id = validated["signer_key_id"]
    key = keys.get(key_id)

    if key is None:
        return _execution_invalid(
            "TRUST_ROOT_UNKNOWN",
            f"execution signer key {key_id!r} is absent from trust bundle",
        )

    if "execution_authorization_signer" not in key["usages"]:
        return _execution_invalid(
            "KEY_USAGE_INVALID",
            f"key {key_id!r} lacks required usage 'execution_authorization_signer'",
        )

    try:
        verify_document_signature(
            validated,
            signature_field="signature",
            public_key=key["public_key"],
        )
    except (AuthorityFormatError, BadSignatureError):
        return _execution_invalid(
            "EXECUTION_AUTHORIZATION_SIGNATURE_INVALID",
            "execution authorization signature is invalid",
        )

    actual_trust_bundle_digest = sha256_digest(trust_bundle)
    if validated["trust_bundle_digest"] != actual_trust_bundle_digest:
        return _execution_invalid(
            "TRUST_BUNDLE_DIGEST_MISMATCH",
            "authorization does not bind the supplied trust bundle",
        )

    failures: list[str] = []

    if validated["request_id"] != expected_request_id:
        failures.append("authorization request_id does not match the execution request")

    expected_action_digest = sha256_digest(expected_action)
    if validated["action_digest"] != expected_action_digest:
        failures.append(
            "authorization action_digest does not match the observed action"
        )

    if canonicalize(validated["action"]) != canonicalize(expected_action):
        failures.append(
            "authorization action does not exactly match the observed action"
        )

    if canonicalize(validated["dispatch"]) != canonicalize(expected_dispatch):
        failures.append(
            "authorization dispatch does not exactly match the observed dispatch"
        )

    if validated["expected_wire_bytes_digest"] != measured_wire_digest:
        failures.append("authorization does not bind the intended outbound bytes")

    if validated["expected_wire_bytes_length"] != measured_wire_length:
        failures.append("authorization does not bind the intended outbound byte length")

    if (
        check_peer_identity
        and validated["expected_peer_identity_digest"] != measured_peer_digest
    ):
        failures.append("authorization does not bind the intended peer identity")

    expected_bindings = (
        (
            "decision_receipt_digest",
            expected_decision_receipt_digest,
        ),
        (
            "authority_receipt_digest",
            expected_authority_receipt_digest,
        ),
        (
            "approval_artifact_digest",
            expected_approval_artifact_digest,
        ),
        (
            "state_snapshot_digest",
            expected_state_snapshot_digest,
        ),
        (
            "policy_bundle_digest",
            expected_policy_bundle_digest,
        ),
        (
            "obligations_digest",
            expected_obligations_digest,
        ),
    )

    for field, expected in expected_bindings:
        if validated[field] != expected:
            failures.append(
                f"authorization {field} does not match the verified execution context"
            )

    not_before = _parse_timestamp(
        validated["not_before"],
        "execution_authorization.not_before",
    )
    expires_at = _parse_timestamp(
        validated["expires_at"],
        "execution_authorization.expires_at",
    )

    if not not_before <= execution_time < expires_at:
        failures.append("execution authorization is not valid at dispatch time")

    # Caller attestation may only tighten: True means refuse even if the
    # durable ledger has not yet recorded consumption.
    if already_consumed:
        return VerificationReport(
            EvidenceState.VERIFIED,
            DecisionConformance.NON_CONFORMANT,
            EXECUTION_AUTHORIZATION_CONSUMED,
            ("execution authorization has already been consumed",),
            key["principal"],
        )

    if failures:
        return VerificationReport(
            EvidenceState.VERIFIED,
            DecisionConformance.NON_CONFORMANT,
            "EXECUTION_AUTHORIZATION_NON_CONFORMANT",
            tuple(failures),
            key["principal"],
        )

    if consume_ledger is not None:
        try:
            claimed = consume_ledger.try_consume_execution_authorization(
                validated["execution_authorization_id"],
                organisation_id=organisation_id,
                consumed_at=str(at_time),
            )
        except Exception as exc:
            return _execution_invalid(
                "CONSUME_LEDGER_UNAVAILABLE",
                f"consume ledger refused the claim: {type(exc).__name__}",
            )
        if not claimed:
            return VerificationReport(
                EvidenceState.VERIFIED,
                DecisionConformance.NON_CONFORMANT,
                EXECUTION_AUTHORIZATION_CONSUMED,
                ("execution authorization has already been consumed",),
                key["principal"],
            )

    return VerificationReport(
        EvidenceState.VERIFIED,
        DecisionConformance.CONFORMANT,
        None,
        (),
        key["principal"],
    )
