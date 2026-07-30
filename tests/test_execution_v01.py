"""Execution Closure v0.1 authorization acceptance tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from nacl.signing import SigningKey

import agent_dna.execution_v01 as execution_module
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    AuthorityFormatError,
    sha256_digest,
)
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    execution_authorization_digest,
    sha256_bytes_digest,
    sign_execution_authorization,
    validate_execution_authorization,
)

ZERO_DIGEST = "sha256:" + ("0" * 64)
ONE_DIGEST = "sha256:" + ("1" * 64)
WIRE_BYTES = (
    b'{"account":"4471","amount":400000,'
    b'"currency":"INR"}'
)
PEER_IDENTITY_BYTES = (
    b"tls-spki:payments.store.example:v3"
)


def _unsigned_authorization():
    action = {
        "subject_principal": (
            "refund-agent@store.example"
        ),
        "subject_key_id": "refund-agent-01",
        "action": "payments.refund",
        "resource": "account:4471",
        "parameters": {
            "amount": {
                "minor_units": 400000,
                "currency": "INR",
            },
            "case_id": "case-7821",
        },
    }

    dispatch = {
        "transport": "https",
        "destination": "payments.store.example",
        "operation": "POST /v1/refunds",
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "payments.refund.v3",
        "tool_schema_digest": ZERO_DIGEST,
        "tool_artifact_digest": ONE_DIGEST,
        "credential_audience": (
            "payments.store.example"
        ),
        "idempotency_key_digest": ZERO_DIGEST,
        "retry_policy_digest": ONE_DIGEST,
    }

    return {
        "spec": EXECUTION_AUTHORIZATION_SPEC,
        "canonicalization": CANONICALIZATION,
        "execution_authorization_id": (
            "execution-authorization-001"
        ),
        "organisation_id": "store.example",
        "request_id": "request-001",
        "issued_at": "2026-07-31T12:00:00Z",
        "not_before": "2026-07-31T12:00:00Z",
        "expires_at": "2026-07-31T12:01:00Z",
        "nonce": "execution-nonce-0001",
        "decision_receipt_digest": ZERO_DIGEST,
        "authority_receipt_digest": ONE_DIGEST,
        "approval_artifact_digest": ZERO_DIGEST,
        "action": action,
        "action_digest": sha256_digest(action),
        "expected_wire_bytes_digest": (
            sha256_bytes_digest(WIRE_BYTES)
        ),
        "expected_wire_bytes_length": len(WIRE_BYTES),
        "expected_peer_identity_digest": (
            sha256_bytes_digest(
                PEER_IDENTITY_BYTES
            )
        ),
        "dispatch": dispatch,
        "state_snapshot_digest": ZERO_DIGEST,
        "policy_bundle_digest": ONE_DIGEST,
        "trust_bundle_digest": ZERO_DIGEST,
        "obligations_digest": ONE_DIGEST,
        "max_uses": 1,
        "signer_key_id": "execution-signer-01",
    }


def _signed_authorization():
    return sign_execution_authorization(
        _unsigned_authorization(),
        SigningKey.generate(),
    )


def test_signed_execution_authorization_is_valid():
    authorization = _signed_authorization()

    assert (
        validate_execution_authorization(authorization)
        == authorization
    )
    assert execution_authorization_digest(
        authorization
    ).startswith("sha256:")


def test_changed_action_parameters_are_rejected():
    authorization = _signed_authorization()
    authorization["action"]["parameters"]["amount"][
        "minor_units"
    ] = 500000

    with pytest.raises(
        AuthorityFormatError,
        match="does not match action",
    ):
        validate_execution_authorization(
            authorization
        )


def test_unexpected_top_level_field_is_rejected():
    authorization = _signed_authorization()
    authorization["untrusted_claim"] = "executable"

    with pytest.raises(
        AuthorityFormatError,
        match="unexpected fields",
    ):
        validate_execution_authorization(
            authorization
        )


def test_unexpected_dispatch_field_is_rejected():
    authorization = _signed_authorization()
    authorization["dispatch"]["untrusted_target"] = (
        "attacker.example"
    )

    with pytest.raises(
        AuthorityFormatError,
        match="unexpected fields",
    ):
        validate_execution_authorization(
            authorization
        )


def test_key_order_does_not_change_digest():
    authorization = _signed_authorization()
    reordered = dict(
        reversed(list(authorization.items()))
    )

    assert (
        execution_authorization_digest(authorization)
        == execution_authorization_digest(reordered)
    )


def test_changed_dispatch_changes_digest():
    original = _unsigned_authorization()
    changed = copy.deepcopy(original)
    changed["dispatch"]["destination"] = (
        "alternate-payments.store.example"
    )
    key = SigningKey.generate()

    original = sign_execution_authorization(
        original,
        key,
    )
    changed = sign_execution_authorization(
        changed,
        key,
    )

    assert (
        execution_authorization_digest(original)
        != execution_authorization_digest(changed)
    )


def test_issued_at_cannot_follow_not_before():
    authorization = _unsigned_authorization()
    authorization["issued_at"] = (
        "2026-07-31T12:00:01Z"
    )

    with pytest.raises(
        AuthorityFormatError,
        match="issued_at must be at or before not_before",
    ):
        sign_execution_authorization(
            authorization,
            SigningKey.generate(),
        )


def test_expiry_must_follow_not_before():
    authorization = _unsigned_authorization()
    authorization["expires_at"] = (
        authorization["not_before"]
    )

    with pytest.raises(
        AuthorityFormatError,
        match="not_before must be before expires_at",
    ):
        sign_execution_authorization(
            authorization,
            SigningKey.generate(),
        )


@pytest.mark.parametrize("max_uses", [0, 2, True])
def test_authorization_must_be_single_use(max_uses):
    authorization = _unsigned_authorization()
    authorization["max_uses"] = max_uses

    with pytest.raises(
        AuthorityFormatError,
        match="expected integer 1",
    ):
        sign_execution_authorization(
            authorization,
            SigningKey.generate(),
        )


def test_short_nonce_is_rejected():
    authorization = _unsigned_authorization()
    authorization["nonce"] = "too-short"

    with pytest.raises(
        AuthorityFormatError,
        match="expected 16 to 256 characters",
    ):
        sign_execution_authorization(
            authorization,
            SigningKey.generate(),
        )


def test_approval_digest_may_be_null():
    authorization = _unsigned_authorization()
    authorization["approval_artifact_digest"] = None

    signed = sign_execution_authorization(
        authorization,
        SigningKey.generate(),
    )

    assert (
        validate_execution_authorization(signed)
        == signed
    )


def test_malformed_signature_is_rejected():
    authorization = _signed_authorization()
    authorization["signature"] = "not-a-signature"

    with pytest.raises(
        AuthorityFormatError,
        match="malformed Ed25519 signature",
    ):
        validate_execution_authorization(
            authorization
        )


def test_malformed_dispatch_digest_is_rejected():
    authorization = _unsigned_authorization()
    authorization["dispatch"][
        "tool_artifact_digest"
    ] = "sha256:not-a-digest"

    with pytest.raises(
        AuthorityFormatError,
        match="malformed SHA-256 digest",
    ):
        sign_execution_authorization(
            authorization,
            SigningKey.generate(),
        )


def test_action_parameters_must_be_object():
    authorization = _unsigned_authorization()
    authorization["action"]["parameters"] = []

    with pytest.raises(
        AuthorityFormatError,
        match="parameters: expected object",
    ):
        sign_execution_authorization(
            authorization,
            SigningKey.generate(),
        )


def _execution_schema():
    schema_path = Path(
        "spec/execution-v01/"
        "execution-authorization.schema.json"
    )
    schema = json.loads(
        schema_path.read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    return schema


def test_signed_authorization_matches_published_schema():
    schema = _execution_schema()
    validator = Draft202012Validator(schema)

    validator.validate(_signed_authorization())


def test_runtime_fields_match_published_schema():
    schema = _execution_schema()

    assert set(schema["required"]) == set(
        execution_module._AUTHORIZATION_FIELDS
    )
    assert set(
        schema["$defs"]["action"]["required"]
    ) == set(execution_module._ACTION_FIELDS)
    assert set(
        schema["$defs"]["dispatch"]["required"]
    ) == set(execution_module._DISPATCH_FIELDS)


def test_schema_rejects_unexpected_field():
    schema = _execution_schema()
    authorization = _signed_authorization()
    authorization["untrusted_claim"] = "executable"

    errors = list(
        Draft202012Validator(schema).iter_errors(
            authorization
        )
    )

    assert any(
        error.validator == "additionalProperties"
        for error in errors
    )
