"""Independent dispatch-boundary witness v0.1-experimental."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any, NoReturn

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
    sha256_digest,
    sign_document,
    validate_trust_bundle,
    verify_document_signature,
)
from agent_dna.execution_v01 import (
    execution_authorization_digest,
    sha256_bytes_digest,
    validate_execution_authorization,
)

DISPATCH_WITNESS_SPEC = "pv-dispatch-witness/0.1-experimental"

_WITNESS_FIELDS = frozenset(
    {
        "spec",
        "canonicalization",
        "dispatch_witness_id",
        "organisation_id",
        "request_id",
        "execution_authorization_id",
        "execution_authorization_digest",
        "observed_at",
        "attempt",
        "witness_component_id",
        "observed_action_digest",
        "observed_dispatch",
        "wire_content_type",
        "wire_content_encoding",
        "wire_bytes_digest",
        "wire_bytes_length",
        "peer_identity_digest",
        "trust_bundle_digest",
        "signer_key_id",
        "signature",
    }
)

_OBSERVED_DISPATCH_FIELDS = frozenset(
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

_WITNESS_METADATA_FIELDS = frozenset(
    {
        "dispatch_witness_id",
        "observed_at",
        "attempt",
        "witness_component_id",
        "wire_content_type",
        "wire_content_encoding",
        "signer_key_id",
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
    expected: frozenset[str],
    path: str,
) -> None:
    actual = frozenset(value)
    missing = expected - actual
    unexpected = actual - expected

    if missing:
        raise AuthorityFormatError(f"{path}: missing fields {sorted(missing)}")

    if unexpected:
        raise AuthorityFormatError(f"{path}: unexpected fields {sorted(unexpected)}")


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


def _validate_observed_dispatch(
    dispatch: Any,
    path: str = "observed_dispatch",
) -> Mapping[str, Any]:
    value = _require_object(dispatch, path)
    _require_exact_fields(
        value,
        _OBSERVED_DISPATCH_FIELDS,
        path,
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
            value[field],
            f"{path}.{field}",
        )

    for field in (
        "tool_schema_digest",
        "tool_artifact_digest",
        "idempotency_key_digest",
        "retry_policy_digest",
    ):
        _require_digest(
            value[field],
            f"{path}.{field}",
        )

    canonicalize(value)
    return value


def validate_dispatch_witness(  # noqa: C901
    witness: Any,
    path: str = "dispatch_witness",
) -> Mapping[str, Any]:
    """Strictly validate an independently signed dispatch witness."""

    value = _require_object(witness, path)
    _require_exact_fields(
        value,
        _WITNESS_FIELDS,
        path,
    )

    if value["spec"] != DISPATCH_WITNESS_SPEC:
        raise AuthorityFormatError(f"{path}.spec: unsupported spec")

    if value["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError(f"{path}.canonicalization: unsupported")

    for field in (
        "dispatch_witness_id",
        "organisation_id",
        "request_id",
        "execution_authorization_id",
        "witness_component_id",
        "wire_content_type",
        "wire_content_encoding",
        "signer_key_id",
    ):
        _require_string(
            value[field],
            f"{path}.{field}",
        )

    _parse_timestamp(
        value["observed_at"],
        f"{path}.observed_at",
    )

    attempt = value["attempt"]
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise AuthorityFormatError(f"{path}.attempt: expected integer >= 1")

    for field in (
        "execution_authorization_digest",
        "observed_action_digest",
        "wire_bytes_digest",
        "peer_identity_digest",
        "trust_bundle_digest",
    ):
        _require_digest(
            value[field],
            f"{path}.{field}",
        )

    observed_dispatch = _validate_observed_dispatch(
        value["observed_dispatch"],
        f"{path}.observed_dispatch",
    )

    for field in (
        "wire_content_type",
        "wire_content_encoding",
    ):
        if value[field] != observed_dispatch[field]:
            raise AuthorityFormatError(
                f"{path}.{field}: does not match observed_dispatch.{field}"
            )

    wire_bytes_length = value["wire_bytes_length"]
    if (
        isinstance(wire_bytes_length, bool)
        or not isinstance(wire_bytes_length, int)
        or wire_bytes_length < 0
    ):
        raise AuthorityFormatError(f"{path}.wire_bytes_length: expected integer >= 0")

    signature = value["signature"]
    if not isinstance(signature, str) or not SIGNATURE_RE.fullmatch(signature):
        raise AuthorityFormatError(f"{path}.signature: malformed Ed25519 signature")

    canonicalize(value)
    return value


def create_dispatch_witness(
    metadata: Mapping[str, Any],
    *,
    authorization: Any,
    trust_bundle: Any,
    observed_action: Any,
    observed_dispatch: Any,
    wire_bytes: Any,
    peer_identity_bytes: Any,
    signing_key: SigningKey,
) -> dict[str, Any]:
    """Measure and sign evidence at the final dispatch boundary."""

    metadata = _require_object(
        metadata,
        "dispatch_witness_metadata",
    )
    _require_exact_fields(
        metadata,
        _WITNESS_METADATA_FIELDS,
        "dispatch_witness_metadata",
    )

    validated_authorization = validate_execution_authorization(authorization)
    validate_trust_bundle(trust_bundle)
    trust = _require_object(
        trust_bundle,
        "trust_bundle",
    )

    if trust["organisation_id"] != validated_authorization["organisation_id"]:
        raise AuthorityFormatError(
            "authorization and trust bundle organisations differ"
        )

    observed_action = _require_object(
        observed_action,
        "observed_action",
    )
    canonicalize(observed_action)

    observed_dispatch = _validate_observed_dispatch(observed_dispatch)

    wire_digest = sha256_bytes_digest(
        wire_bytes,
        "wire_bytes",
    )
    exact_wire_bytes = bytes(wire_bytes)
    peer_digest = sha256_bytes_digest(
        peer_identity_bytes,
        "peer_identity_bytes",
    )

    unsigned = {
        "spec": DISPATCH_WITNESS_SPEC,
        "canonicalization": CANONICALIZATION,
        "dispatch_witness_id": (metadata["dispatch_witness_id"]),
        "organisation_id": (validated_authorization["organisation_id"]),
        "request_id": (validated_authorization["request_id"]),
        "execution_authorization_id": (
            validated_authorization["execution_authorization_id"]
        ),
        "execution_authorization_digest": (
            execution_authorization_digest(validated_authorization)
        ),
        "observed_at": metadata["observed_at"],
        "attempt": metadata["attempt"],
        "witness_component_id": (metadata["witness_component_id"]),
        "observed_action_digest": sha256_digest(observed_action),
        "observed_dispatch": dict(observed_dispatch),
        "wire_content_type": (metadata["wire_content_type"]),
        "wire_content_encoding": (metadata["wire_content_encoding"]),
        "wire_bytes_digest": wire_digest,
        "wire_bytes_length": len(exact_wire_bytes),
        "peer_identity_digest": peer_digest,
        "trust_bundle_digest": sha256_digest(trust),
        "signer_key_id": metadata["signer_key_id"],
    }

    signed = sign_document(
        unsigned,
        signing_key,
        signature_field="signature",
    )
    validate_dispatch_witness(signed)
    return signed


def dispatch_witness_digest(
    witness: Any,
) -> str:
    """Digest the complete signed dispatch witness."""

    validated = validate_dispatch_witness(witness)
    return sha256_digest(validated)


class _DispatchEvidenceError(Exception):
    def __init__(
        self,
        reason_code: str,
        detail: str,
    ):
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


def _dispatch_fail(
    reason_code: str,
    detail: str,
) -> NoReturn:
    raise _DispatchEvidenceError(
        reason_code,
        detail,
    )


def _dispatch_report(
    evidence_state: EvidenceState,
    reason_code: str,
    detail: str,
) -> VerificationReport:
    return VerificationReport(
        evidence_state,
        DecisionConformance.NOT_ASSESSABLE,
        reason_code,
        (detail,),
    )


def _verify_dispatch_signatures(
    witness: Mapping[str, Any],
    authorization: Mapping[str, Any],
    keys: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    authorization_key_id = authorization["signer_key_id"]
    authorization_key = keys.get(authorization_key_id)

    if authorization_key is None:
        _dispatch_fail(
            "AUTHORIZATION_TRUST_ROOT_UNKNOWN",
            f"authorization key {authorization_key_id!r} is absent from trust bundle",
        )

    if "execution_authorization_signer" not in authorization_key["usages"]:
        _dispatch_fail(
            "AUTHORIZATION_KEY_USAGE_INVALID",
            f"key {authorization_key_id!r} lacks required "
            "usage 'execution_authorization_signer'",
        )

    witness_key_id = witness["signer_key_id"]
    witness_key = keys.get(witness_key_id)

    if witness_key is None:
        _dispatch_fail(
            "WITNESS_TRUST_ROOT_UNKNOWN",
            f"witness key {witness_key_id!r} is absent from trust bundle",
        )

    if "dispatch_witness_signer" not in witness_key["usages"]:
        _dispatch_fail(
            "WITNESS_KEY_USAGE_INVALID",
            f"key {witness_key_id!r} lacks required usage 'dispatch_witness_signer'",
        )

    if (
        authorization_key_id == witness_key_id
        or authorization_key["public_key"] == witness_key["public_key"]
        or authorization_key["principal"] == witness_key["principal"]
    ):
        _dispatch_fail(
            "WITNESS_NOT_INDEPENDENT",
            "execution authorization and dispatch witness "
            "must use distinct keys and principals",
        )

    try:
        verify_document_signature(
            authorization,
            signature_field="signature",
            public_key=authorization_key["public_key"],
        )
    except (AuthorityFormatError, BadSignatureError):
        _dispatch_fail(
            "EXECUTION_AUTHORIZATION_SIGNATURE_INVALID",
            "execution authorization signature is invalid",
        )

    try:
        verify_document_signature(
            witness,
            signature_field="signature",
            public_key=witness_key["public_key"],
        )
    except (AuthorityFormatError, BadSignatureError):
        _dispatch_fail(
            "DISPATCH_WITNESS_SIGNATURE_INVALID",
            "dispatch witness signature is invalid",
        )

    return witness_key


def _prepare_dispatch_verification(
    witness: Any,
    authorization: Any,
    trust_bundle: Any,
    observed_action: Any,
    observed_dispatch: Any,
    wire_bytes: Any,
    peer_identity_bytes: Any,
) -> tuple[
    Mapping[str, Any],
    Mapping[str, Any],
    Mapping[str, Any],
    Mapping[str, Any],
    Mapping[str, Any],
    dict[str, Mapping[str, Any]],
    str,
    int,
    str,
]:
    validated_witness = validate_dispatch_witness(witness)
    validated_authorization = validate_execution_authorization(authorization)
    keys = validate_trust_bundle(trust_bundle)
    trust = _require_object(
        trust_bundle,
        "trust_bundle",
    )
    observed_action = _require_object(
        observed_action,
        "dispatch_verification.observed_action",
    )
    canonicalize(observed_action)
    observed_dispatch = _validate_observed_dispatch(
        observed_dispatch,
        "dispatch_verification.observed_dispatch",
    )

    measured_wire_digest = sha256_bytes_digest(
        wire_bytes,
        "dispatch_verification.wire_bytes",
    )
    measured_wire_length = len(bytes(wire_bytes))
    measured_peer_digest = sha256_bytes_digest(
        peer_identity_bytes,
        ("dispatch_verification.peer_identity_bytes"),
    )

    return (
        validated_witness,
        validated_authorization,
        trust,
        observed_action,
        observed_dispatch,
        keys,
        measured_wire_digest,
        measured_wire_length,
        measured_peer_digest,
    )


def _dispatch_binding_failures(  # noqa: C901
    witness: Mapping[str, Any],
    authorization: Mapping[str, Any],
    observed_action: Mapping[str, Any],
    observed_dispatch: Mapping[str, Any],
    measured_wire_digest: str,
    measured_wire_length: int,
    measured_peer_digest: str,
) -> list[str]:
    failures: list[str] = []

    for field in (
        "organisation_id",
        "request_id",
        "execution_authorization_id",
    ):
        authorization_field = (
            "execution_authorization_id"
            if field == "execution_authorization_id"
            else field
        )
        if witness[field] != authorization[authorization_field]:
            failures.append(
                f"dispatch witness {field} does not match the execution authorization"
            )

    expected_authorization_digest = execution_authorization_digest(authorization)
    if witness["execution_authorization_digest"] != expected_authorization_digest:
        failures.append(
            "dispatch witness does not bind the supplied execution authorization"
        )

    measured_action_digest = sha256_digest(observed_action)
    if witness["observed_action_digest"] != measured_action_digest:
        failures.append(
            "dispatch witness action digest does not match the observed action"
        )

    if authorization["action_digest"] != measured_action_digest:
        failures.append("observed action is not the authorized action")

    if canonicalize(authorization["action"]) != canonicalize(observed_action):
        failures.append("observed action does not exactly match the authorized action")

    if canonicalize(witness["observed_dispatch"]) != canonicalize(observed_dispatch):
        failures.append("dispatch witness does not exactly match the observed dispatch")

    if canonicalize(authorization["dispatch"]) != canonicalize(observed_dispatch):
        failures.append(
            "observed dispatch does not exactly match the authorized dispatch"
        )

    if witness["wire_bytes_digest"] != measured_wire_digest:
        failures.append(
            "dispatch witness wire digest does not match the observed outbound bytes"
        )

    if authorization["expected_wire_bytes_digest"] != measured_wire_digest:
        failures.append(
            "observed outbound bytes are not the exact bytes authorized by the permit"
        )

    if witness["wire_bytes_length"] != measured_wire_length:
        failures.append(
            "dispatch witness wire length does not match the observed outbound bytes"
        )

    if authorization["expected_wire_bytes_length"] != measured_wire_length:
        failures.append(
            "observed outbound byte length does not match the signed permit"
        )

    if witness["peer_identity_digest"] != measured_peer_digest:
        failures.append(
            "dispatch witness peer identity does not match the observed peer"
        )

    if authorization["expected_peer_identity_digest"] != measured_peer_digest:
        failures.append(
            "observed peer identity is not the peer authorized by the permit"
        )

    observed_at = _parse_timestamp(
        witness["observed_at"],
        "dispatch_witness.observed_at",
    )
    not_before = _parse_timestamp(
        authorization["not_before"],
        "execution_authorization.not_before",
    )
    expires_at = _parse_timestamp(
        authorization["expires_at"],
        "execution_authorization.expires_at",
    )

    if not not_before <= observed_at < expires_at:
        failures.append("dispatch occurred outside the authorization validity window")

    if witness["attempt"] != 1:
        failures.append("single-use authorization cannot witness a retry attempt")

    return failures


def verify_dispatch_witness(  # noqa: C901
    witness: Any,
    authorization: Any,
    trust_bundle: Mapping[str, Any] | None,
    *,
    observed_action: Any,
    observed_dispatch: Any,
    wire_bytes: Any,
    peer_identity_bytes: Any,
) -> VerificationReport:
    """Verify exact permit-to-dispatch correspondence."""

    if trust_bundle is None:
        return _dispatch_report(
            EvidenceState.UNVERIFIABLE,
            "TRUST_BUNDLE_UNAVAILABLE",
            "no out-of-band trust bundle was supplied",
        )

    absent_inputs = (
        (
            witness,
            "DISPATCH_WITNESS_ABSENT",
            "no dispatch witness was supplied",
        ),
        (
            authorization,
            "EXECUTION_AUTHORIZATION_ABSENT",
            "no execution authorization was supplied",
        ),
        (
            observed_action,
            "OBSERVED_ACTION_ABSENT",
            "no independently observed action was supplied",
        ),
        (
            observed_dispatch,
            "OBSERVED_DISPATCH_ABSENT",
            "no independently observed dispatch was supplied",
        ),
        (
            wire_bytes,
            "WIRE_BYTES_ABSENT",
            "no observed outbound bytes were supplied",
        ),
        (
            peer_identity_bytes,
            "PEER_IDENTITY_ABSENT",
            "no observed peer identity was supplied",
        ),
    )

    for value, reason_code, detail in absent_inputs:
        if value is None:
            return _dispatch_report(
                EvidenceState.ABSENT,
                reason_code,
                detail,
            )

    try:
        (
            validated_witness,
            validated_authorization,
            trust,
            measured_action,
            measured_dispatch,
            keys,
            measured_wire_digest,
            measured_wire_length,
            measured_peer_digest,
        ) = _prepare_dispatch_verification(
            witness,
            authorization,
            trust_bundle,
            observed_action,
            observed_dispatch,
            wire_bytes,
            peer_identity_bytes,
        )
    except (AuthorityFormatError, TypeError, ValueError) as exc:
        return _dispatch_report(
            EvidenceState.INVALID,
            "SCHEMA_INVALID",
            str(exc),
        )

    organisation_id = validated_authorization["organisation_id"]
    if (
        trust["organisation_id"] != organisation_id
        or validated_witness["organisation_id"] != organisation_id
    ):
        return _dispatch_report(
            EvidenceState.INVALID,
            "ORGANISATION_MISMATCH",
            "witness, authorization, and trust bundle organisations differ",
        )

    try:
        witness_key = _verify_dispatch_signatures(
            validated_witness,
            validated_authorization,
            keys,
        )
    except _DispatchEvidenceError as exc:
        return _dispatch_report(
            EvidenceState.INVALID,
            exc.reason_code,
            exc.detail,
        )

    actual_trust_bundle_digest = sha256_digest(trust)
    if (
        validated_authorization["trust_bundle_digest"] != actual_trust_bundle_digest
        or validated_witness["trust_bundle_digest"] != actual_trust_bundle_digest
    ):
        return _dispatch_report(
            EvidenceState.INVALID,
            "TRUST_BUNDLE_DIGEST_MISMATCH",
            "authorization or witness does not bind the supplied trust bundle",
        )

    failures = _dispatch_binding_failures(
        validated_witness,
        validated_authorization,
        measured_action,
        measured_dispatch,
        measured_wire_digest,
        measured_wire_length,
        measured_peer_digest,
    )

    return VerificationReport(
        EvidenceState.VERIFIED,
        (
            DecisionConformance.NON_CONFORMANT
            if failures
            else DecisionConformance.CONFORMANT
        ),
        ("DISPATCH_NON_CONFORMANT" if failures else None),
        tuple(failures),
        witness_key["principal"],
    )
