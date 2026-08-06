"""Verified escalation v0.1 acceptance tests."""

from __future__ import annotations

import copy

import pytest
from nacl.signing import SigningKey

from agent_dna.approval_v01 import (
    APPROVAL_ARTIFACT_SPEC,
    APPROVAL_REQUEST_SPEC,
    approval_artifact_digest,
    approval_request_digest,
    sign_approval_artifact,
    validate_approval_artifact,
    validate_approval_request,
)
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    AuthorityFormatError,
    sha256_digest,
)

ZERO_DIGEST = "sha256:" + ("0" * 64)
ONE_DIGEST = "sha256:" + ("1" * 64)


def _approval_request():
    action = {
        "subject_principal": "refund-agent@store.example",
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

    return {
        "spec": APPROVAL_REQUEST_SPEC,
        "canonicalization": CANONICALIZATION,
        "approval_request_id": "approval-request-001",
        "organisation_id": "store.example",
        "request_id": "request-001",
        "created_at": "2026-07-30T12:00:00Z",
        "expires_at": "2026-07-30T12:10:00Z",
        "nonce": "approval-nonce-0001",
        "decision_input_digest": ZERO_DIGEST,
        "action": action,
        "action_digest": sha256_digest(action),
        "evidence_manifest_digest": ZERO_DIGEST,
        "presentation_digest": ZERO_DIGEST,
        "approval_requirement_digest": ZERO_DIGEST,
    }


def test_valid_approval_request():
    request = _approval_request()

    assert validate_approval_request(request) == request
    assert approval_request_digest(request).startswith("sha256:")


def test_changed_action_parameters_are_rejected():
    request = _approval_request()
    request["action"]["parameters"]["amount"]["minor_units"] = 500000

    with pytest.raises(
        AuthorityFormatError,
        match="does not match action",
    ):
        validate_approval_request(request)


def test_unexpected_field_is_rejected():
    request = _approval_request()
    request["untrusted_claim"] = "approved"

    with pytest.raises(
        AuthorityFormatError,
        match="unexpected fields",
    ):
        validate_approval_request(request)


def test_expiry_must_follow_creation():
    request = _approval_request()
    request["expires_at"] = request["created_at"]

    with pytest.raises(
        AuthorityFormatError,
        match="must be after created_at",
    ):
        validate_approval_request(request)


def test_short_nonce_is_rejected():
    request = _approval_request()
    request["nonce"] = "too-short"

    with pytest.raises(
        AuthorityFormatError,
        match="length must be between",
    ):
        validate_approval_request(request)


def test_key_order_does_not_change_request_digest():
    request = _approval_request()
    reordered = dict(reversed(list(request.items())))

    assert approval_request_digest(request) == approval_request_digest(reordered)


def test_different_evidence_changes_request_digest():
    original = _approval_request()
    changed = copy.deepcopy(original)
    changed["evidence_manifest_digest"] = ONE_DIGEST

    assert approval_request_digest(original) != approval_request_digest(changed)


def _unsigned_approval_artifact(request):
    return {
        "spec": APPROVAL_ARTIFACT_SPEC,
        "canonicalization": CANONICALIZATION,
        "approval_id": "approval-001",
        "approval_request_id": (request["approval_request_id"]),
        "approval_request_digest": (approval_request_digest(request)),
        "organisation_id": request["organisation_id"],
        "request_id": request["request_id"],
        "decision_input_digest": (request["decision_input_digest"]),
        "action_digest": request["action_digest"],
        "evidence_manifest_digest": (request["evidence_manifest_digest"]),
        "presentation_digest": (request["presentation_digest"]),
        "approval_requirement_digest": (request["approval_requirement_digest"]),
        "approver_principal": "reviewer@store.example",
        "approver_key_id": "reviewer-01",
        "approver_authority_digest": ONE_DIGEST,
        "decision": "APPROVE",
        "decided_at": "2026-07-30T12:01:00Z",
        "expires_at": "2026-07-30T12:05:00Z",
    }


def test_signed_approval_artifact_is_valid():
    request = _approval_request()
    key = SigningKey.generate()

    artifact = sign_approval_artifact(
        _unsigned_approval_artifact(request),
        key,
    )

    assert validate_approval_artifact(artifact) == artifact
    assert artifact["signature"].startswith("ed25519:")
    assert approval_artifact_digest(artifact).startswith("sha256:")


def test_artifact_rejects_unknown_decision():
    request = _approval_request()
    artifact = _unsigned_approval_artifact(request)
    artifact["decision"] = "IGNORE"

    with pytest.raises(
        AuthorityFormatError,
        match="expected APPROVE or DENY",
    ):
        sign_approval_artifact(
            artifact,
            SigningKey.generate(),
        )


def test_artifact_expiry_must_follow_decision():
    request = _approval_request()
    artifact = _unsigned_approval_artifact(request)
    artifact["expires_at"] = artifact["decided_at"]

    with pytest.raises(
        AuthorityFormatError,
        match="must be after decided_at",
    ):
        sign_approval_artifact(
            artifact,
            SigningKey.generate(),
        )


def test_artifact_rejects_unexpected_field():
    request = _approval_request()
    artifact = _unsigned_approval_artifact(request)
    artifact["self_asserted_role"] = "finance-admin"

    with pytest.raises(
        AuthorityFormatError,
        match="unexpected fields",
    ):
        sign_approval_artifact(
            artifact,
            SigningKey.generate(),
        )
