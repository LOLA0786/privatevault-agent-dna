"""Execution-time authorization verification acceptance tests."""

from __future__ import annotations

import copy

import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    DecisionConformance,
    EvidenceState,
    encode_public_key,
    sha256_digest,
)
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    sha256_bytes_digest,
    sign_execution_authorization,
    verify_execution_authorization,
)

ZERO_DIGEST = "sha256:" + ("0" * 64)
ONE_DIGEST = "sha256:" + ("1" * 64)
WIRE_BYTES = b'{"account":"4471","amount":400000,"currency":"INR"}'
PEER_IDENTITY_BYTES = b"tls-spki:payments.store.example:v3"
_USE_CONTEXT = object()


def _context():
    signer_key = SigningKey.generate()

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
                "public_key": encode_public_key(signer_key),
                "usages": ["execution_authorization_signer"],
            }
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
    }

    unsigned = {
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
    }

    authorization = sign_execution_authorization(
        unsigned,
        signer_key,
    )

    return {
        "signer_key": signer_key,
        "trust_bundle": trust_bundle,
        "authorization": authorization,
        "action": copy.deepcopy(action),
        "dispatch": copy.deepcopy(dispatch),
    }


def _verify(
    context,
    authorization=None,
    trust_bundle=_USE_CONTEXT,
    **overrides,
):
    artifact = context["authorization"] if authorization is None else authorization
    bundle = context["trust_bundle"] if trust_bundle is _USE_CONTEXT else trust_bundle

    arguments = {
        "expected_request_id": "request-001",
        "expected_action": context["action"],
        "expected_dispatch": context["dispatch"],
        "expected_decision_receipt_digest": (ZERO_DIGEST),
        "expected_authority_receipt_digest": (ONE_DIGEST),
        "expected_approval_artifact_digest": (ZERO_DIGEST),
        "expected_state_snapshot_digest": (ZERO_DIGEST),
        "expected_policy_bundle_digest": (ONE_DIGEST),
        "expected_obligations_digest": ONE_DIGEST,
        "expected_wire_bytes": WIRE_BYTES,
        "expected_peer_identity_bytes": (PEER_IDENTITY_BYTES),
        "at_time": "2026-07-31T12:00:30Z",
        "already_consumed": False,
    }
    arguments.update(overrides)

    return verify_execution_authorization(
        artifact,
        bundle,
        **arguments,
    )


def test_valid_authorization_is_executable():
    context = _context()

    report = _verify(context)

    assert report.ok
    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.CONFORMANT
    assert report.accountable_principal == ("execution-runtime@store.example")


def test_missing_trust_bundle_is_unverifiable():
    context = _context()

    report = _verify(
        context,
        trust_bundle=None,
    )

    assert report.evidence_state is EvidenceState.UNVERIFIABLE
    assert report.reason_code == "TRUST_BUNDLE_UNAVAILABLE"


def test_forged_signature_is_invalid():
    context = _context()
    forged = sign_execution_authorization(
        context["authorization"],
        SigningKey.generate(),
    )

    report = _verify(
        context,
        authorization=forged,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == ("EXECUTION_AUTHORIZATION_SIGNATURE_INVALID")


def test_wrong_key_usage_is_invalid():
    context = _context()
    trust_bundle = copy.deepcopy(context["trust_bundle"])
    trust_bundle["keys"][0]["usages"] = ["receipt_signer"]

    report = _verify(
        context,
        trust_bundle=trust_bundle,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "KEY_USAGE_INVALID"


def test_observed_action_mismatch_is_non_conformant():
    context = _context()
    observed = copy.deepcopy(context["action"])
    observed["parameters"]["amount"]["minor_units"] = 500000

    report = _verify(
        context,
        expected_action=observed,
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.NON_CONFORMANT
    assert not report.ok


def test_observed_dispatch_mismatch_is_non_conformant():
    context = _context()
    observed = copy.deepcopy(context["dispatch"])
    observed["destination"] = "attacker.example"

    report = _verify(
        context,
        expected_dispatch=observed,
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.NON_CONFORMANT
    assert any(
        "dispatch does not exactly match" in failure for failure in report.failures
    )


@pytest.mark.parametrize(
    ("argument", "mismatched_digest"),
    [
        (
            "expected_decision_receipt_digest",
            ONE_DIGEST,
        ),
        (
            "expected_authority_receipt_digest",
            ZERO_DIGEST,
        ),
        (
            "expected_approval_artifact_digest",
            None,
        ),
        (
            "expected_state_snapshot_digest",
            ONE_DIGEST,
        ),
        (
            "expected_policy_bundle_digest",
            ZERO_DIGEST,
        ),
        (
            "expected_obligations_digest",
            ZERO_DIGEST,
        ),
    ],
)
def test_verified_context_digest_mismatch_blocks(
    argument,
    mismatched_digest,
):
    context = _context()

    report = _verify(
        context,
        **{argument: mismatched_digest},
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.NON_CONFORMANT
    assert not report.ok


def test_request_id_mismatch_is_non_conformant():
    context = _context()

    report = _verify(
        context,
        expected_request_id="request-002",
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert not report.ok
    assert any("request_id does not match" in failure for failure in report.failures)


@pytest.mark.parametrize(
    "at_time",
    [
        "2026-07-31T11:59:59Z",
        "2026-07-31T12:01:00Z",
    ],
)
def test_outside_validity_window_blocks(at_time):
    context = _context()

    report = _verify(
        context,
        at_time=at_time,
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert not report.ok
    assert any("not valid at dispatch time" in failure for failure in report.failures)


def test_consumed_authorization_blocks_replay():
    context = _context()

    report = _verify(
        context,
        already_consumed=True,
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert not report.ok
    assert report.reason_code == "EXECUTION_AUTHORIZATION_CONSUMED"
    assert any("already been consumed" in failure for failure in report.failures)


def test_non_boolean_consumption_state_is_invalid():
    context = _context()

    report = _verify(
        context,
        already_consumed="unknown",
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "SCHEMA_INVALID"


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


def test_unknown_execution_signer_is_invalid():
    context = _context()
    trust_bundle = copy.deepcopy(context["trust_bundle"])
    trust_bundle["keys"][0]["key_id"] = "different-execution-signer"

    report = _verify(
        context,
        trust_bundle=trust_bundle,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "TRUST_ROOT_UNKNOWN"


def test_organisation_mismatch_is_invalid():
    context = _context()
    trust_bundle = copy.deepcopy(context["trust_bundle"])
    trust_bundle["organisation_id"] = "attacker.example"

    report = _verify(
        context,
        trust_bundle=trust_bundle,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "ORGANISATION_MISMATCH"


def test_intended_wire_bytes_mismatch_blocks():
    context = _context()
    changed = bytearray(WIRE_BYTES)
    changed[-2] = ord("1")

    report = _verify(
        context,
        expected_wire_bytes=bytes(changed),
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert not report.ok
    assert any(
        "does not bind the intended outbound bytes" in failure
        for failure in report.failures
    )


def test_intended_peer_identity_mismatch_blocks():
    context = _context()

    report = _verify(
        context,
        expected_peer_identity_bytes=(b"tls-spki:attacker.example:v1"),
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert not report.ok
    assert any(
        "does not bind the intended peer identity" in failure
        for failure in report.failures
    )


def test_non_bytes_intended_wire_is_invalid():
    context = _context()

    report = _verify(
        context,
        expected_wire_bytes=5,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "SCHEMA_INVALID"
