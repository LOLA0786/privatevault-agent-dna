"""Tests for execution closure record v0.1-experimental."""

from hashlib import sha256
from typing import Any

import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    AuthorityFormatError,
    encode_public_key,
    sign_document,
    verify_document_signature,
)
from agent_dna.closure_v01 import (
    CLOSURE_RECORD_SPEC,
    closure_record_digest,
    sign_closure_record,
    validate_closure_record,
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
