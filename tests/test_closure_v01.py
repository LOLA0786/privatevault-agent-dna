"""Tests for execution closure record v0.1-experimental."""

from hashlib import sha256
from typing import Any

import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    AuthorityFormatError,
    DecisionConformance,
    EvidenceState,
    encode_public_key,
    sign_document,
    verify_document_signature,
)
from agent_dna.closure_v01 import (
    CLOSURE_RECORD_SPEC,
    closure_record_digest,
    sign_closure_record,
    validate_closure_record,
    verify_closure_record,
)


def _digest(value: str) -> str:
    return f"sha256:{sha256(value.encode()).hexdigest()}"


def _valid_closure() -> dict[str, Any]:
    record: dict[str, Any] = {
        "spec": CLOSURE_RECORD_SPEC,
        "canonicalization": CANONICALIZATION,
        "closure_id": "closure-001",
        "organisation_id": "org-privatevault",
        "request_id": "request-001",
        "execution_authorization_id": "execution-auth-001",
        "execution_authorization_digest": _digest(
            "execution-authorization"
        ),
        "dispatch_witness_id": "dispatch-witness-001",
        "dispatch_witness_digest": _digest(
            "dispatch-witness"
        ),
        "closed_at": "2026-07-30T20:30:00Z",
        "closure_component_id": "closure-component-001",
        "dispatch_outcome": "ACKNOWLEDGED",
        "response_status": "200",
        "response_bytes_digest": _digest("response"),
        "response_bytes_length": 2,
        "effect_state": "CONFIRMED",
        "effect_evidence_digest": _digest(
            "effect-evidence"
        ),
        "idempotency_key_digest": _digest(
            "idempotency-key"
        ),
        "authorization_use_count": 1,
        "trust_bundle_digest": _digest("trust-bundle"),
        "signer_key_id": "closure-key-001",
        "signature": "",
    }
    return sign_document(
        record,
        SigningKey.generate(),
        signature_field="signature",
    )


def test_valid_closure_record_is_accepted() -> None:
    record = _valid_closure()

    validated = validate_closure_record(record)

    assert validated == record


def test_missing_field_is_rejected() -> None:
    record = _valid_closure()
    del record["dispatch_witness_digest"]

    with pytest.raises(AuthorityFormatError):
        validate_closure_record(record)


def test_unexpected_field_is_rejected() -> None:
    record = _valid_closure()
    record["unexpected"] = "value"

    with pytest.raises(AuthorityFormatError):
        validate_closure_record(record)


@pytest.mark.parametrize("use_count", [True, 0, 2])
def test_authorization_must_be_used_exactly_once(
    use_count: Any,
) -> None:
    record = _valid_closure()
    record["authorization_use_count"] = use_count

    with pytest.raises(AuthorityFormatError):
        validate_closure_record(record)


@pytest.mark.parametrize(
    "missing_field",
    [
        "response_status",
        "response_bytes_digest",
        "response_bytes_length",
    ],
)
def test_response_evidence_is_atomic(
    missing_field: str,
) -> None:
    record = _valid_closure()
    record[missing_field] = None

    with pytest.raises(AuthorityFormatError):
        validate_closure_record(record)


@pytest.mark.parametrize(
    "outcome",
    ["ACKNOWLEDGED", "REJECTED"],
)
def test_terminal_response_outcomes_require_evidence(
    outcome: str,
) -> None:
    record = _valid_closure()
    record["dispatch_outcome"] = outcome
    record["response_status"] = None
    record["response_bytes_digest"] = None
    record["response_bytes_length"] = None

    with pytest.raises(AuthorityFormatError):
        validate_closure_record(record)


def test_transport_error_forbids_response_evidence() -> None:
    record = _valid_closure()
    record["dispatch_outcome"] = "TRANSPORT_ERROR"

    with pytest.raises(AuthorityFormatError):
        validate_closure_record(record)


def test_transport_error_without_response_is_valid() -> None:
    record = _valid_closure()
    record["dispatch_outcome"] = "TRANSPORT_ERROR"
    record["response_status"] = None
    record["response_bytes_digest"] = None
    record["response_bytes_length"] = None
    record["effect_state"] = "UNKNOWN"
    record["effect_evidence_digest"] = None

    assert validate_closure_record(record) == record


def test_confirmed_effect_requires_evidence() -> None:
    record = _valid_closure()
    record["effect_evidence_digest"] = None

    with pytest.raises(AuthorityFormatError):
        validate_closure_record(record)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dispatch_outcome", "SUCCEEDED"),
        ("effect_state", "ASSUMED"),
    ],
)
def test_unknown_states_are_rejected(
    field: str,
    value: str,
) -> None:
    record = _valid_closure()
    record[field] = value

    with pytest.raises(AuthorityFormatError):
        validate_closure_record(record)


def test_malformed_signature_is_rejected() -> None:
    record = _valid_closure()
    record["signature"] = "not-an-ed25519-signature"



# --- signing and digest -------------------------------------------------
#
# The two functions below are what a ledger entry or external checkpoint
# will eventually reference, so the invariants they rely on are tested
# here rather than assumed: a malformed closure must never be signable,
# and an unvalidated object must never yield a digest.


def _signing_key() -> SigningKey:
    return SigningKey(b"\x01" * 32)


def _unsigned_closure() -> dict[str, Any]:
    return {
        key: value
        for key, value in _valid_closure().items()
        if key != "signature"
    }


def test_signed_closure_verifies_against_its_public_key() -> None:
    key = _signing_key()
    signed = sign_closure_record(_unsigned_closure(), key)

    assert verify_document_signature(
        signed,
        signature_field="signature",
        public_key=encode_public_key(key),
    )


def test_closure_digest_is_stable() -> None:
    signed = sign_closure_record(_unsigned_closure(), _signing_key())

    assert closure_record_digest(signed) == closure_record_digest(signed)


def test_closure_digest_ignores_key_order() -> None:
    """RFC 8785 canonicalisation. If this fails, every cross-record digest
    comparison downstream silently stops working."""
    signed = sign_closure_record(_unsigned_closure(), _signing_key())
    reordered = dict(reversed(list(signed.items())))

    assert closure_record_digest(reordered) == closure_record_digest(signed)


def test_tampered_closure_changes_digest_and_breaks_signature() -> None:
    key = _signing_key()
    signed = sign_closure_record(_unsigned_closure(), key)

    tampered = dict(signed)
    tampered["closure_component_id"] = signed["closure_component_id"] + "-x"

    assert closure_record_digest(tampered) != closure_record_digest(signed)
    with pytest.raises(BadSignatureError):
        verify_document_signature(
            tampered,
            signature_field="signature",
            public_key=encode_public_key(key),
        )


def test_malformed_closure_cannot_be_signed() -> None:
    """Signing validates afterwards, so a bad record fails where it is
    produced rather than surfacing as unverifiable evidence later."""
    closure = _unsigned_closure()
    closure["dispatch_outcome"] = "NOT_A_REAL_OUTCOME"

    with pytest.raises(AuthorityFormatError):
        sign_closure_record(closure, _signing_key())


def test_unvalidated_object_cannot_produce_a_digest() -> None:
    with pytest.raises(AuthorityFormatError):
        closure_record_digest({"spec": "wrong"})


def test_double_use_closure_cannot_produce_a_digest() -> None:
    """An authorisation consumed twice must never be referenceable."""
    signed = sign_closure_record(_unsigned_closure(), _signing_key())
    doubled = dict(signed)
    doubled["authorization_use_count"] = 2

    with pytest.raises(AuthorityFormatError):
        closure_record_digest(doubled)


# --- trust-bundle verification ------------------------------------------
#
# Two axes, kept separate on purpose. A record that is malformed or
# unsigned is INVALID and supports no conclusion at all. A record that is
# soundly signed and bound to the wrong execution is VERIFIED and
# NON_CONFORMANT -- real evidence making a false claim, which is the more
# serious finding and the one a scan exists to surface.


def _key(seed: int) -> SigningKey:
    return SigningKey(bytes([seed]) * 32)


def _bundle_key(
    key_id: str,
    principal: str,
    signing_key: SigningKey,
    usages: list[str],
) -> dict[str, Any]:
    return {
        "key_id": key_id,
        "principal": principal,
        "algorithm": "ed25519",
        "public_key": encode_public_key(signing_key),
        "usages": usages,
    }


def _closure_bundle(
    closure_usages: list[str] | None = None,
    include_closure_key: bool = True,
) -> dict[str, Any]:
    keys = [
        _bundle_key(
            "auth-signer",
            "runtime@example.com",
            _key(2),
            ["execution_authorization_signer"],
        )
    ]
    if include_closure_key:
        keys.append(
            _bundle_key(
                "closure-signer",
                "closure@example.com",
                _key(1),
                closure_usages
                if closure_usages is not None
                else ["closure_signer"],
            )
        )
    return {
        "spec": "pv-trust-bundle/0.1-experimental",
        "canonicalization": CANONICALIZATION,
        "organisation_id": "bank.example",
        "bundle_version": 1,
        "pinned_at": "2026-07-30T00:00:00Z",
        "keys": keys,
    }


def _signed_closure() -> dict[str, Any]:
    closure = _unsigned_closure()
    closure["signer_key_id"] = "closure-signer"
    return sign_closure_record(closure, _key(1))


def _verify(closure: dict[str, Any], bundle: Any, **kwargs: Any) -> Any:
    params: dict[str, Any] = {
        "expected_authorization_digest": closure[
            "execution_authorization_digest"
        ],
        "expected_witness_digest": closure["dispatch_witness_digest"],
        "authorization_signer_key_id": "auth-signer",
    }
    params.update(kwargs)
    return verify_closure_record(closure, bundle, **params)


def test_valid_closure_verifies_and_conforms() -> None:
    report = _verify(_signed_closure(), _closure_bundle())

    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.CONFORMANT


def test_absent_trust_bundle_is_unverifiable_not_invalid() -> None:
    """Missing evidence is not evidence of misconduct."""
    report = _verify(_signed_closure(), None)

    assert report.evidence_state is EvidenceState.UNVERIFIABLE
    assert report.reason_code == "TRUST_BUNDLE_UNAVAILABLE"


def test_unknown_signer_key_is_invalid() -> None:
    report = _verify(
        _signed_closure(),
        _closure_bundle(include_closure_key=False),
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "CLOSURE_TRUST_ROOT_UNKNOWN"


def test_key_without_closure_signer_usage_is_invalid() -> None:
    """Being in the bundle is not permission to sign closures."""
    report = _verify(
        _signed_closure(),
        _closure_bundle(closure_usages=["receipt_signer"]),
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "CLOSURE_KEY_USAGE_INVALID"


def test_tampered_closure_fails_signature() -> None:
    closure = _signed_closure()
    closure["closure_component_id"] = closure["closure_component_id"] + "-x"

    report = _verify(closure, _closure_bundle())

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "CLOSURE_SIGNATURE_INVALID"


def test_closure_signed_by_authorization_key_is_invalid() -> None:
    """The component that authorised an action must not certify its
    outcome. One compromised key would otherwise produce a complete,
    internally consistent, entirely fictional chain."""
    bundle = _closure_bundle()
    bundle["keys"][1]["principal"] = "runtime@example.com"

    report = _verify(_signed_closure(), bundle)

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "CLOSURE_NOT_INDEPENDENT_OF_AUTHORIZATION"


def test_closure_bound_to_wrong_authorization_is_non_conformant() -> None:
    """The finding this whole chain exists to produce: the evidence is
    cryptographically sound and the claim it makes is false."""
    report = _verify(
        _signed_closure(),
        _closure_bundle(),
        expected_authorization_digest=_digest("a-different-authorization"),
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.NON_CONFORMANT
    assert report.reason_code == "CLOSURE_NON_CONFORMANT"


def test_closure_bound_to_wrong_witness_is_non_conformant() -> None:
    report = _verify(
        _signed_closure(),
        _closure_bundle(),
        expected_witness_digest=_digest("a-different-witness"),
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.NON_CONFORMANT
