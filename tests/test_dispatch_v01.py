"""Independent dispatch witness v0.1 acceptance tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from nacl.signing import SigningKey

import agent_dna.dispatch_v01 as dispatch_module
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    AuthorityFormatError,
    DecisionConformance,
    EvidenceState,
    encode_public_key,
    sha256_digest,
    sign_document,
)
from agent_dna.dispatch_v01 import (
    create_dispatch_witness,
    dispatch_witness_digest,
    validate_dispatch_witness,
    verify_dispatch_witness,
)
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    execution_authorization_digest,
    sha256_bytes_digest,
    sign_execution_authorization,
)

ZERO_DIGEST = "sha256:" + ("0" * 64)
ONE_DIGEST = "sha256:" + ("1" * 64)
WIRE_BYTES = b'{"account":"4471","amount":400000,"currency":"INR"}'
PEER_IDENTITY_BYTES = b"tls-spki:payments.store.example:v3"
_USE_CONTEXT = object()


def _context():
    execution_key = SigningKey.generate()
    witness_key = SigningKey.generate()

    trust_bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": "store.example",
        "bundle_version": 1,
        "pinned_at": "2026-07-31T11:00:00Z",
        "keys": [
            {
                "key_id": "execution-signer-01",
                "principal": ("execution-runtime@store.example"),
                "algorithm": "ed25519",
                "public_key": encode_public_key(execution_key),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "dispatch-witness-01",
                "principal": ("dispatch-boundary@store.example"),
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness_key),
                "usages": ["dispatch_witness_signer"],
            },
        ],
    }

    action = {
        "subject_principal": ("refund-agent@store.example"),
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
        "credential_audience": ("payments.store.example"),
        "idempotency_key_digest": ZERO_DIGEST,
        "retry_policy_digest": ONE_DIGEST,
        "serialization": "pv-json-parameters/0.1",
    }

    authorization = sign_execution_authorization(
        {
            "spec": EXECUTION_AUTHORIZATION_SPEC,
            "canonicalization": CANONICALIZATION,
            "execution_authorization_id": ("execution-authorization-001"),
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
            "expected_wire_bytes_digest": (sha256_bytes_digest(WIRE_BYTES)),
            "expected_wire_bytes_length": len(WIRE_BYTES),
            "expected_peer_identity_digest": (sha256_bytes_digest(PEER_IDENTITY_BYTES)),
            "dispatch": dispatch,
            "state_snapshot_digest": ZERO_DIGEST,
            "policy_bundle_digest": ONE_DIGEST,
            "trust_bundle_digest": sha256_digest(trust_bundle),
            "obligations_digest": ONE_DIGEST,
            "max_uses": 1,
            "signer_key_id": "execution-signer-01",
        },
        execution_key,
    )

    return {
        "authorization": authorization,
        "trust_bundle": trust_bundle,
        "execution_key": execution_key,
        "action": copy.deepcopy(action),
        "dispatch": copy.deepcopy(dispatch),
        "wire_bytes": WIRE_BYTES,
        "peer_identity_bytes": PEER_IDENTITY_BYTES,
        "witness_key": witness_key,
        "metadata": {
            "dispatch_witness_id": "dispatch-witness-001",
            "observed_at": "2026-07-31T12:00:30Z",
            "attempt": 1,
            "witness_component_id": ("egress-boundary-01"),
            "wire_content_type": "application/json",
            "wire_content_encoding": "identity",
            "signer_key_id": "dispatch-witness-01",
        },
    }


def _create(context, **overrides):
    arguments = {
        "authorization": context["authorization"],
        "trust_bundle": context["trust_bundle"],
        "observed_action": context["action"],
        "observed_dispatch": context["dispatch"],
        "wire_bytes": context["wire_bytes"],
        "peer_identity_bytes": (context["peer_identity_bytes"]),
        "signing_key": context["witness_key"],
    }
    arguments.update(overrides)

    return create_dispatch_witness(
        context["metadata"],
        **arguments,
    )


def test_valid_witness_derives_boundary_evidence():
    context = _context()
    witness = _create(context)

    assert validate_dispatch_witness(witness) == witness
    assert witness["execution_authorization_digest"] == (
        execution_authorization_digest(context["authorization"])
    )
    assert witness["observed_action_digest"] == (sha256_digest(context["action"]))
    assert witness["wire_bytes_digest"] == (sha256_bytes_digest(context["wire_bytes"]))
    assert witness["wire_bytes_length"] == len(context["wire_bytes"])
    assert witness["peer_identity_digest"] == (
        sha256_bytes_digest(context["peer_identity_bytes"])
    )
    assert dispatch_witness_digest(witness).startswith("sha256:")


def test_non_bytes_wire_input_is_rejected():
    context = _context()

    with pytest.raises(
        AuthorityFormatError,
        match="wire_bytes: expected bytes",
    ):
        _create(
            context,
            wire_bytes=5,
        )


def _verify(
    context,
    *,
    witness=_USE_CONTEXT,
    authorization=_USE_CONTEXT,
    trust_bundle=_USE_CONTEXT,
    observed_action=_USE_CONTEXT,
    observed_dispatch=_USE_CONTEXT,
    wire_bytes=_USE_CONTEXT,
    peer_identity_bytes=_USE_CONTEXT,
):
    if witness is _USE_CONTEXT:
        witness = _create(context)
    if authorization is _USE_CONTEXT:
        authorization = context["authorization"]
    if trust_bundle is _USE_CONTEXT:
        trust_bundle = context["trust_bundle"]
    if observed_action is _USE_CONTEXT:
        observed_action = context["action"]
    if observed_dispatch is _USE_CONTEXT:
        observed_dispatch = context["dispatch"]
    if wire_bytes is _USE_CONTEXT:
        wire_bytes = context["wire_bytes"]
    if peer_identity_bytes is _USE_CONTEXT:
        peer_identity_bytes = context["peer_identity_bytes"]

    return verify_dispatch_witness(
        witness,
        authorization,
        trust_bundle,
        observed_action=observed_action,
        observed_dispatch=observed_dispatch,
        wire_bytes=wire_bytes,
        peer_identity_bytes=peer_identity_bytes,
    )


def test_valid_dispatch_witness_is_conformant():
    context = _context()

    report = _verify(context)

    assert report.ok
    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.CONFORMANT
    assert report.accountable_principal == ("dispatch-boundary@store.example")


def test_missing_witness_is_absent():
    context = _context()

    report = _verify(
        context,
        witness=None,
    )

    assert report.evidence_state is EvidenceState.ABSENT
    assert report.reason_code == ("DISPATCH_WITNESS_ABSENT")


def test_missing_trust_bundle_is_unverifiable():
    context = _context()

    report = _verify(
        context,
        trust_bundle=None,
    )

    assert report.evidence_state is EvidenceState.UNVERIFIABLE
    assert report.reason_code == ("TRUST_BUNDLE_UNAVAILABLE")


def test_forged_witness_signature_is_invalid():
    context = _context()
    witness = sign_document(
        _create(context),
        SigningKey.generate(),
        signature_field="signature",
    )

    report = _verify(
        context,
        witness=witness,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == ("DISPATCH_WITNESS_SIGNATURE_INVALID")


def test_forged_authorization_signature_is_invalid():
    context = _context()
    authorization = sign_execution_authorization(
        context["authorization"],
        SigningKey.generate(),
    )

    report = _verify(
        context,
        authorization=authorization,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == ("EXECUTION_AUTHORIZATION_SIGNATURE_INVALID")


def _assert_non_conformant(
    report,
    failure_fragment,
):
    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.NON_CONFORMANT
    assert not report.ok
    assert any(failure_fragment in failure for failure in report.failures)


def test_one_changed_wire_byte_blocks_dispatch():
    context = _context()
    changed = bytearray(context["wire_bytes"])
    changed[-2] = ord("1")

    report = _verify(
        context,
        wire_bytes=bytes(changed),
    )

    _assert_non_conformant(
        report,
        "wire digest does not match",
    )


def test_changed_peer_identity_blocks_dispatch():
    context = _context()

    report = _verify(
        context,
        peer_identity_bytes=(b"tls-spki:attacker.example:v1"),
    )

    _assert_non_conformant(
        report,
        "peer identity does not match",
    )


def test_changed_observed_action_blocks_dispatch():
    context = _context()
    action = copy.deepcopy(context["action"])
    action["parameters"]["amount"]["minor_units"] = 500000

    report = _verify(
        context,
        observed_action=action,
    )

    _assert_non_conformant(
        report,
        "observed action is not the authorized action",
    )


def test_changed_observed_destination_blocks_dispatch():
    context = _context()
    dispatch = copy.deepcopy(context["dispatch"])
    dispatch["destination"] = "attacker.example"

    report = _verify(
        context,
        observed_dispatch=dispatch,
    )

    _assert_non_conformant(
        report,
        "observed dispatch does not exactly match",
    )


def test_retry_attempt_blocks_single_use_authorization():
    context = _context()
    witness = copy.deepcopy(_create(context))
    witness["attempt"] = 2
    witness = sign_document(
        witness,
        context["witness_key"],
        signature_field="signature",
    )

    report = _verify(
        context,
        witness=witness,
    )

    _assert_non_conformant(
        report,
        "cannot witness a retry attempt",
    )


def test_dispatch_outside_authorization_window_blocks():
    context = _context()
    witness = copy.deepcopy(_create(context))
    witness["observed_at"] = "2026-07-31T12:01:00Z"
    witness = sign_document(
        witness,
        context["witness_key"],
        signature_field="signature",
    )

    report = _verify(
        context,
        witness=witness,
    )

    _assert_non_conformant(
        report,
        "outside the authorization validity window",
    )


def test_wrong_witness_key_usage_is_invalid():
    context = _context()
    trust_bundle = copy.deepcopy(context["trust_bundle"])
    trust_bundle["keys"][1]["usages"] = ["receipt_signer"]

    report = _verify(
        context,
        trust_bundle=trust_bundle,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == ("WITNESS_KEY_USAGE_INVALID")


def test_same_principal_is_not_independent():
    context = _context()
    trust_bundle = copy.deepcopy(context["trust_bundle"])
    trust_bundle["keys"][1]["principal"] = trust_bundle["keys"][0]["principal"]

    report = _verify(
        context,
        trust_bundle=trust_bundle,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "WITNESS_NOT_INDEPENDENT"


def test_same_public_key_is_not_independent():
    context = _context()
    trust_bundle = copy.deepcopy(context["trust_bundle"])
    trust_bundle["keys"][1]["public_key"] = trust_bundle["keys"][0]["public_key"]

    report = _verify(
        context,
        trust_bundle=trust_bundle,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "WITNESS_NOT_INDEPENDENT"


def test_different_trust_bundle_digest_is_invalid():
    context = _context()
    trust_bundle = copy.deepcopy(context["trust_bundle"])
    trust_bundle["bundle_version"] = 2

    report = _verify(
        context,
        trust_bundle=trust_bundle,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == ("TRUST_BUNDLE_DIGEST_MISMATCH")


def test_changed_authorization_link_is_non_conformant():
    context = _context()
    witness = copy.deepcopy(_create(context))
    witness["execution_authorization_digest"] = ZERO_DIGEST
    witness = sign_document(
        witness,
        context["witness_key"],
        signature_field="signature",
    )

    report = _verify(
        context,
        witness=witness,
    )

    _assert_non_conformant(
        report,
        "does not bind the supplied execution authorization",
    )


def test_signed_wire_length_lie_is_non_conformant():
    context = _context()
    witness = copy.deepcopy(_create(context))
    witness["wire_bytes_length"] += 1
    witness = sign_document(
        witness,
        context["witness_key"],
        signature_field="signature",
    )

    report = _verify(
        context,
        witness=witness,
    )

    _assert_non_conformant(
        report,
        "wire length does not match",
    )


def _dispatch_schema():
    path = Path("spec/execution-v01/dispatch-witness.schema.json")
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


def test_witness_matches_published_schema():
    schema = _dispatch_schema()

    Draft202012Validator(schema).validate(_create(_context()))


def test_witness_runtime_fields_match_schema():
    schema = _dispatch_schema()

    assert set(schema["required"]) == set(dispatch_module._WITNESS_FIELDS)
    assert set(schema["$defs"]["observedDispatch"]["required"]) == set(
        dispatch_module._OBSERVED_DISPATCH_FIELDS
    )


def test_witness_schema_rejects_unknown_field():
    schema = _dispatch_schema()
    witness = _create(_context())
    witness["copied_permit_claim"] = True

    errors = list(Draft202012Validator(schema).iter_errors(witness))

    assert any(error.validator == "additionalProperties" for error in errors)


def test_truthful_witness_cannot_expand_authorized_bytes():
    context = _context()
    changed = bytearray(context["wire_bytes"])
    changed[-2] = ord("1")
    changed = bytes(changed)
    witness = _create(
        context,
        wire_bytes=changed,
    )

    report = _verify(
        context,
        witness=witness,
        wire_bytes=changed,
    )

    _assert_non_conformant(
        report,
        "not the exact bytes authorized by the permit",
    )


def test_truthful_witness_cannot_change_authorized_peer():
    context = _context()
    changed_peer = b"tls-spki:attacker.example:v1"
    witness = _create(
        context,
        peer_identity_bytes=changed_peer,
    )

    report = _verify(
        context,
        witness=witness,
        peer_identity_bytes=changed_peer,
    )

    _assert_non_conformant(
        report,
        "not the peer authorized by the permit",
    )
