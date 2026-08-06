"""Execution closure record v0.1-experimental."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any, NoReturn

if TYPE_CHECKING:
    from nacl.signing import SigningKey

from nacl.exceptions import BadSignatureError

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
from agent_dna.dispatch_v01 import (
    dispatch_witness_digest,
    validate_dispatch_witness,
)
from agent_dna.execution_v01 import (
    execution_authorization_digest,
    validate_execution_authorization,
)

CLOSURE_RECORD_SPEC = "pv-execution-closure/0.1-experimental"

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


def _require_optional_length(
    value: Any,
    path: str,
) -> int | None:
    if value is None:
        return None

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuthorityFormatError(f"{path}: expected integer >= 0 or null")

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
        raise AuthorityFormatError(f"{path}.spec: unsupported spec")

    if value["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError(f"{path}.canonicalization: unsupported")

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
        raise AuthorityFormatError(f"{path}.dispatch_outcome: unsupported outcome")

    effect_state = value["effect_state"]
    if effect_state not in EFFECT_STATES:
        raise AuthorityFormatError(f"{path}.effect_state: unsupported state")

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
    if any(response_presence) and not all(response_presence):
        raise AuthorityFormatError(
            f"{path}: response status, digest, and length "
            "must be all present or all null"
        )

    has_response = all(response_presence)

    if outcome in {"ACKNOWLEDGED", "REJECTED"} and (not has_response):
        raise AuthorityFormatError(f"{path}: {outcome} requires response evidence")

    if outcome == "TRANSPORT_ERROR" and has_response:
        raise AuthorityFormatError(
            f"{path}: TRANSPORT_ERROR cannot include response evidence"
        )

    effect_digest = _require_optional_digest(
        value["effect_evidence_digest"],
        f"{path}.effect_evidence_digest",
    )
    if effect_state == "CONFIRMED" and effect_digest is None:
        raise AuthorityFormatError(f"{path}: CONFIRMED effect requires evidence")

    authorization_use_count = value["authorization_use_count"]
    if (
        isinstance(authorization_use_count, bool)
        or not isinstance(authorization_use_count, int)
        or authorization_use_count != 1
    ):
        raise AuthorityFormatError(
            f"{path}.authorization_use_count: expected integer 1"
        )

    signature = value["signature"]
    if not isinstance(signature, str) or not SIGNATURE_RE.fullmatch(signature):
        raise AuthorityFormatError(f"{path}.signature: malformed Ed25519 signature")

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


class _ClosureEvidenceError(Exception):
    """Structural or cryptographic failure that makes the record unusable."""

    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(detail)


def _closure_fail(reason_code: str, detail: str) -> NoReturn:
    raise _ClosureEvidenceError(reason_code, detail)


def _closure_invalid(
    reason_code: str,
    detail: str,
) -> VerificationReport:
    return VerificationReport(
        EvidenceState.INVALID,
        DecisionConformance.NOT_ASSESSABLE,
        reason_code,
        (detail,),
    )


def _verify_closure_signer(
    closure: Mapping[str, Any],
    keys: Mapping[str, Mapping[str, Any]],
    authorization_signer_key_id: str,
    witness_signer_key_id: str | None,
    require_witness_independence: bool,
) -> None:
    key_id = closure["signer_key_id"]
    key = keys.get(key_id)
    if key is None:
        _closure_fail(
            "CLOSURE_TRUST_ROOT_UNKNOWN",
            f"closure key {key_id!r} is absent from trust bundle",
        )

    if "closure_signer" not in key["usages"]:
        _closure_fail(
            "CLOSURE_KEY_USAGE_INVALID",
            f"key {key_id!r} lacks required usage 'closure_signer'",
        )

    # The component that authorised the action must not also certify its
    # outcome. Otherwise one compromised key fabricates the whole chain
    # from decision to settlement.
    authorization_key = keys.get(authorization_signer_key_id)
    if authorization_key is not None and (
        key_id == authorization_signer_key_id
        or key["public_key"] == authorization_key["public_key"]
        or key["principal"] == authorization_key["principal"]
    ):
        _closure_fail(
            "CLOSURE_NOT_INDEPENDENT_OF_AUTHORIZATION",
            "execution authorization and closure must use distinct keys and principals",
        )

    # Observing the dispatch and recording the outcome are often the same
    # component, so this is opt-in rather than assumed.
    if require_witness_independence and witness_signer_key_id is not None:
        witness_key = keys.get(witness_signer_key_id)
        if witness_key is not None and (
            key_id == witness_signer_key_id
            or key["public_key"] == witness_key["public_key"]
            or key["principal"] == witness_key["principal"]
        ):
            _closure_fail(
                "CLOSURE_NOT_INDEPENDENT_OF_WITNESS",
                "dispatch witness and closure must use distinct keys and principals",
            )

    try:
        verify_document_signature(
            closure,
            signature_field="signature",
            public_key=key["public_key"],
        )
    except (AuthorityFormatError, BadSignatureError):
        _closure_fail(
            "CLOSURE_SIGNATURE_INVALID",
            "closure record signature is invalid",
        )


def verify_closure_record(
    closure: Any,
    trust_bundle: Mapping[str, Any] | None,
    *,
    expected_authorization_digest: Any,
    expected_witness_digest: Any,
    authorization_signer_key_id: Any,
    witness_signer_key_id: Any = None,
    require_witness_independence: bool = False,
) -> VerificationReport:
    """Verify a closure record against the execution it claims to close.

    Two axes, deliberately separate. A malformed or unsigned record is
    INVALID and nothing can be concluded from it. A soundly signed record
    that claims to close an execution it was never bound to is VERIFIED
    and NON_CONFORMANT -- the evidence is real and the claim is false,
    which is a different and more serious finding than broken evidence.
    """

    if trust_bundle is None:
        return VerificationReport(
            EvidenceState.UNVERIFIABLE,
            DecisionConformance.NOT_ASSESSABLE,
            "TRUST_BUNDLE_UNAVAILABLE",
            ("no out-of-band trust bundle was supplied",),
        )

    try:
        validated = validate_closure_record(closure)
        keys = validate_trust_bundle(trust_bundle)
        expected_authorization_digest = _require_digest(
            expected_authorization_digest,
            "closure_verification.expected_authorization_digest",
        )
        expected_witness_digest = _require_digest(
            expected_witness_digest,
            "closure_verification.expected_witness_digest",
        )
        authorization_signer_key_id = _require_string(
            authorization_signer_key_id,
            "closure_verification.authorization_signer_key_id",
        )
        _verify_closure_signer(
            validated,
            keys,
            authorization_signer_key_id,
            witness_signer_key_id,
            require_witness_independence,
        )
    except _ClosureEvidenceError as exc:
        return _closure_invalid(exc.reason_code, exc.detail)
    except AuthorityFormatError as exc:
        return _closure_invalid("CLOSURE_MALFORMED", str(exc))

    failures: list[str] = []

    if validated["execution_authorization_digest"] != (expected_authorization_digest):
        failures.append("closure is bound to a different execution authorization")

    if validated["dispatch_witness_digest"] != expected_witness_digest:
        failures.append("closure is bound to a different dispatch witness")

    return VerificationReport(
        EvidenceState.VERIFIED,
        (
            DecisionConformance.NON_CONFORMANT
            if failures
            else DecisionConformance.CONFORMANT
        ),
        ("CLOSURE_NON_CONFORMANT" if failures else None),
        tuple(failures),
    )


def _chain_linkage_failures(
    authorization: Mapping[str, Any],
    witness: Mapping[str, Any],
    closure: Mapping[str, Any],
) -> list[str]:
    """Recompute every bound digest rather than trusting what was supplied.

    A caller who hands over a substituted authorization alongside matching
    expectations would otherwise verify cleanly. The digests are derived
    from the documents themselves, so substitution shows up here.
    """

    failures: list[str] = []

    measured_authorization = execution_authorization_digest(authorization)
    if closure["execution_authorization_digest"] != measured_authorization:
        failures.append("closure does not bind the supplied execution authorization")

    measured_witness = dispatch_witness_digest(witness)
    if closure["dispatch_witness_digest"] != measured_witness:
        failures.append("closure does not bind the supplied dispatch witness")

    if witness["execution_authorization_digest"] != measured_authorization:
        failures.append(
            "dispatch witness does not bind the supplied execution authorization"
        )

    for field in ("organisation_id", "request_id"):
        if not (authorization[field] == witness[field] == closure[field]):
            failures.append(
                f"{field} differs across authorization, witness and closure"
            )

    for record, label in ((witness, "witness"), (closure, "closure")):
        if (
            record["execution_authorization_id"]
            != authorization["execution_authorization_id"]
        ):
            failures.append(
                f"{label} execution_authorization_id does not match the authorization"
            )

    if closure["dispatch_witness_id"] != witness["dispatch_witness_id"]:
        failures.append("closure dispatch_witness_id does not match the witness")

    if closure["trust_bundle_digest"] != authorization["trust_bundle_digest"]:
        failures.append(
            "closure was evaluated against different trust roots than the authorization"
        )

    return failures


def verify_closure_chain(
    authorization: Any,
    witness: Any,
    closure: Any,
    trust_bundle: Mapping[str, Any] | None,
    *,
    require_witness_independence: bool = False,
) -> VerificationReport:
    """Verify a closure against the execution it claims to close.

    Digests are recomputed from the supplied documents rather than taken
    on trust, which is the difference between checking that a claim is
    internally consistent and checking that it is about the right thing.

    Authorization and witness signatures are deliberately not re-verified
    here; that belongs to verify_execution_authorization and
    verify_dispatch_witness. Two implementations of the same check drift
    apart, and the standalone verifier calls all three.
    """

    if trust_bundle is None:
        return VerificationReport(
            EvidenceState.UNVERIFIABLE,
            DecisionConformance.NOT_ASSESSABLE,
            "TRUST_BUNDLE_UNAVAILABLE",
            ("no out-of-band trust bundle was supplied",),
        )

    try:
        validated_authorization = validate_execution_authorization(authorization)
        validated_witness = validate_dispatch_witness(witness)
        validated_closure = validate_closure_record(closure)
        keys = validate_trust_bundle(trust_bundle)
        _verify_closure_signer(
            validated_closure,
            keys,
            validated_authorization["signer_key_id"],
            validated_witness["signer_key_id"],
            require_witness_independence,
        )
    except _ClosureEvidenceError as exc:
        return _closure_invalid(exc.reason_code, exc.detail)
    except AuthorityFormatError as exc:
        return _closure_invalid("CLOSURE_CHAIN_MALFORMED", str(exc))

    failures = _chain_linkage_failures(
        validated_authorization,
        validated_witness,
        validated_closure,
    )

    return VerificationReport(
        EvidenceState.VERIFIED,
        (
            DecisionConformance.NON_CONFORMANT
            if failures
            else DecisionConformance.CONFORMANT
        ),
        ("CLOSURE_CHAIN_NON_CONFORMANT" if failures else None),
        tuple(failures),
    )
