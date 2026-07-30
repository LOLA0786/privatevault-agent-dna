"""Execution-time approval verification acceptance tests."""

from __future__ import annotations

import copy

from nacl.signing import SigningKey

import agent_dna.approval_v01 as approval_module
from agent_dna.approval_v01 import (
    APPROVAL_ARTIFACT_SPEC,
    APPROVAL_REQUEST_SPEC,
    approval_request_digest,
    sign_approval_artifact,
    verify_approval_for_execution,
)
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    COMPOSITION_PROFILE,
    GRANT_SPEC,
    RECEIPT_SPEC,
    TRUST_SPEC,
    DecisionConformance,
    EvidenceState,
    VerificationReport,
    encode_public_key,
    receipt_digest,
    sha256_digest,
    sign_grant,
    sign_receipt,
)

ZERO_DIGEST = "sha256:" + ("0" * 64)
ONE_DIGEST = "sha256:" + ("1" * 64)
EXECUTION_TIME = "2026-07-30T12:02:00Z"


def _context():
    reviewer_key = SigningKey.generate()

    bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": "store.example",
        "bundle_version": 1,
        "pinned_at": "2026-07-30T00:00:00Z",
        "keys": [
            {
                "key_id": "reviewer-01",
                "principal": "reviewer@store.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(
                    reviewer_key
                ),
                "usages": ["approval_signer"],
            }
        ],
    }

    action = {
        "subject_principal": "refund-agent@store.example",
        "subject_key_id": "refund-agent-01",
        "action": "payments.refund",
        "resource": "account:4471",
        "parameters": {
            "amount": {
                "minor_units": 400000,
                "currency": "INR",
            }
        },
    }

    request = {
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

    request_digest = approval_request_digest(request)

    authority_receipt = {
        "organisation_id": "store.example",
        "request_id": request["approval_request_id"],
        "decision_timestamp": "2026-07-30T12:00:30Z",
        "decision_input_digest": request_digest,
        "requested": {
            "subject_principal": "reviewer@store.example",
            "subject_key_id": "reviewer-01",
            "action": "approval.decide",
            "resource": (
                "approval_request:"
                + request["approval_request_id"]
            ),
        },
        "final_verdict": "ALLOW",
    }

    artifact = sign_approval_artifact(
        {
            "spec": APPROVAL_ARTIFACT_SPEC,
            "canonicalization": CANONICALIZATION,
            "approval_id": "approval-001",
            "approval_request_id": (
                request["approval_request_id"]
            ),
            "approval_request_digest": request_digest,
            "organisation_id": request["organisation_id"],
            "request_id": request["request_id"],
            "decision_input_digest": (
                request["decision_input_digest"]
            ),
            "action_digest": request["action_digest"],
            "evidence_manifest_digest": (
                request["evidence_manifest_digest"]
            ),
            "presentation_digest": (
                request["presentation_digest"]
            ),
            "approval_requirement_digest": (
                request["approval_requirement_digest"]
            ),
            "approver_principal": (
                "reviewer@store.example"
            ),
            "approver_key_id": "reviewer-01",
            "approver_authority_digest": receipt_digest(
                authority_receipt
            ),
            "decision": "APPROVE",
            "decided_at": "2026-07-30T12:01:00Z",
            "expires_at": "2026-07-30T12:05:00Z",
        },
        reviewer_key,
    )

    return {
        "reviewer_key": reviewer_key,
        "bundle": bundle,
        "request": request,
        "authority_receipt": authority_receipt,
        "artifact": artifact,
    }


def _trust_authority(monkeypatch):
    report = VerificationReport(
        EvidenceState.VERIFIED,
        DecisionConformance.CONFORMANT,
        accountable_principal="owner@store.example",
    )
    monkeypatch.setattr(
        approval_module,
        "verify_receipt",
        lambda *_args, **_kwargs: report,
    )


def _verify(context, **overrides):
    return verify_approval_for_execution(
        overrides.get("request", context["request"]),
        overrides.get("artifact", context["artifact"]),
        overrides.get("bundle", context["bundle"]),
        overrides.get(
            "authority_receipt",
            context["authority_receipt"],
        ),
        at_time=overrides.get(
            "at_time",
            EXECUTION_TIME,
        ),
    )


def _resign(context, artifact):
    return sign_approval_artifact(
        artifact,
        context["reviewer_key"],
    )


def test_valid_approval_is_executable(monkeypatch):
    context = _context()
    _trust_authority(monkeypatch)

    report = _verify(context)

    assert report.ok
    assert report.evidence_state is EvidenceState.VERIFIED
    assert (
        report.decision_conformance
        is DecisionConformance.CONFORMANT
    )


def test_forged_signature_is_invalid(monkeypatch):
    context = _context()
    _trust_authority(monkeypatch)

    forged = sign_approval_artifact(
        copy.deepcopy(context["artifact"]),
        SigningKey.generate(),
    )

    report = _verify(
        context,
        artifact=forged,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "APPROVAL_SIGNATURE_INVALID"


def test_key_without_approval_usage_is_invalid(
    monkeypatch,
):
    context = _context()
    _trust_authority(monkeypatch)

    bundle = copy.deepcopy(context["bundle"])
    bundle["keys"][0]["usages"] = ["subject"]

    report = _verify(
        context,
        bundle=bundle,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "KEY_USAGE_INVALID"


def test_changed_request_is_non_conformant(
    monkeypatch,
):
    context = _context()
    _trust_authority(monkeypatch)

    changed_request = copy.deepcopy(context["request"])
    changed_request["presentation_digest"] = ONE_DIGEST

    report = _verify(
        context,
        request=changed_request,
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert (
        report.decision_conformance
        is DecisionConformance.NON_CONFORMANT
    )
    assert any(
        "presentation_digest" in failure
        for failure in report.failures
    )


def test_denied_artifact_is_not_executable(
    monkeypatch,
):
    context = _context()
    _trust_authority(monkeypatch)

    denied = copy.deepcopy(context["artifact"])
    denied["decision"] = "DENY"
    denied = _resign(context, denied)

    report = _verify(
        context,
        artifact=denied,
    )

    assert not report.ok
    assert any(
        "not APPROVE" in failure
        for failure in report.failures
    )


def test_expired_artifact_is_not_executable(
    monkeypatch,
):
    context = _context()
    _trust_authority(monkeypatch)

    report = _verify(
        context,
        at_time="2026-07-30T12:05:00Z",
    )

    assert not report.ok
    assert any(
        "not valid at execution time" in failure
        for failure in report.failures
    )


def test_artifact_cannot_outlive_request(
    monkeypatch,
):
    context = _context()
    _trust_authority(monkeypatch)

    artifact = copy.deepcopy(context["artifact"])
    artifact["expires_at"] = "2026-07-30T12:11:00Z"
    artifact = _resign(context, artifact)

    report = _verify(
        context,
        artifact=artifact,
    )

    assert not report.ok
    assert any(
        "outlives" in failure
        for failure in report.failures
    )


def test_missing_authority_receipt_is_absent():
    context = _context()

    report = _verify(
        context,
        authority_receipt=None,
    )

    assert report.evidence_state is EvidenceState.ABSENT
    assert report.reason_code == "APPROVER_AUTHORITY_ABSENT"


def test_wrong_authority_digest_is_non_conformant(
    monkeypatch,
):
    context = _context()
    _trust_authority(monkeypatch)

    artifact = copy.deepcopy(context["artifact"])
    artifact["approver_authority_digest"] = ONE_DIGEST
    artifact = _resign(context, artifact)

    report = _verify(
        context,
        artifact=artifact,
    )

    assert not report.ok
    assert any(
        "approver_authority_digest" in failure
        for failure in report.failures
    )


def test_authority_must_target_exact_request(
    monkeypatch,
):
    context = _context()
    _trust_authority(monkeypatch)

    authority_receipt = copy.deepcopy(
        context["authority_receipt"]
    )
    authority_receipt["requested"]["resource"] = (
        "approval_request:another-request"
    )

    artifact = copy.deepcopy(context["artifact"])
    artifact["approver_authority_digest"] = receipt_digest(
        authority_receipt
    )
    artifact = _resign(context, artifact)

    report = _verify(
        context,
        artifact=artifact,
        authority_receipt=authority_receipt,
    )

    assert not report.ok
    assert any(
        "does not target" in failure
        for failure in report.failures
    )


def test_authority_cannot_be_established_after_decision(
    monkeypatch,
):
    context = _context()
    _trust_authority(monkeypatch)

    authority_receipt = copy.deepcopy(
        context["authority_receipt"]
    )
    authority_receipt["decision_timestamp"] = (
        "2026-07-30T12:02:00Z"
    )

    artifact = copy.deepcopy(context["artifact"])
    artifact["approver_authority_digest"] = receipt_digest(
        authority_receipt
    )
    artifact = _resign(context, artifact)

    report = _verify(
        context,
        artifact=artifact,
        authority_receipt=authority_receipt,
    )

    assert not report.ok
    assert any(
        "established after" in failure
        for failure in report.failures
    )



def _real_authority_context():
    context = _context()
    root_key = SigningKey.generate()
    runtime_key = SigningKey.generate()

    reviewer_entry = next(
        item
        for item in context["bundle"]["keys"]
        if item["key_id"] == "reviewer-01"
    )
    reviewer_entry["usages"] = [
        "subject",
        "approval_signer",
    ]

    context["bundle"]["keys"].extend(
        [
            {
                "key_id": "owner-root-2026",
                "principal": "owner@store.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(root_key),
                "usages": [
                    "root_authority",
                    "grant_issuer",
                ],
            },
            {
                "key_id": "pv-runtime-01",
                "principal": (
                    "privatevault-runtime@store.example"
                ),
                "algorithm": "ed25519",
                "public_key": encode_public_key(
                    runtime_key
                ),
                "usages": ["receipt_signer"],
            },
        ]
    )

    request = context["request"]
    request_digest = approval_request_digest(request)

    grant = sign_grant(
        {
            "spec": GRANT_SPEC,
            "canonicalization": CANONICALIZATION,
            "grant_id": "approval-grant-001",
            "organisation_id": "store.example",
            "issuer_principal": "owner@store.example",
            "issuer_key_id": "owner-root-2026",
            "subject_principal": (
                "reviewer@store.example"
            ),
            "subject_key_id": "reviewer-01",
            "parent_grant_digest": None,
            "capabilities": [
                {
                    "action": "approval.decide",
                    "resource": "approval_request:*",
                    "constraints": [],
                    "obligations": [],
                }
            ],
            "can_delegate": False,
            "remaining_depth": 0,
            "valid_from": "2020-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z",
        },
        root_key,
    )

    authority_receipt = sign_receipt(
        {
            "spec": RECEIPT_SPEC,
            "canonicalization": CANONICALIZATION,
            "receipt_id": "approval-authority-001",
            "organisation_id": "store.example",
            "previous_receipt_hash": None,
            "request_id": request["approval_request_id"],
            "decision_timestamp": (
                "2026-07-30T12:00:30Z"
            ),
            "decision_input_digest": request_digest,
            "grant_chain": [grant],
            "requested": {
                "subject_principal": (
                    "reviewer@store.example"
                ),
                "subject_key_id": "reviewer-01",
                "action": "approval.decide",
                "resource": (
                    "approval_request:"
                    + request["approval_request_id"]
                ),
                "facts": {},
            },
            "authority_result": {
                "verdict": "ALLOW",
                "reason_code": "AUTHORITY_GRANTED",
            },
            "policy_result": {
                "verdict": "ALLOW",
                "policy_id": "APPROVAL-001",
                "policy_version": "1.0",
                "policy_digest": ZERO_DIGEST,
            },
            "composition_profile": COMPOSITION_PROFILE,
            "final_verdict": "ALLOW",
            "signer_key_id": "pv-runtime-01",
        },
        runtime_key,
    )

    artifact = copy.deepcopy(context["artifact"])
    artifact["approver_authority_digest"] = receipt_digest(
        authority_receipt
    )
    artifact = _resign(context, artifact)

    context["authority_receipt"] = authority_receipt
    context["artifact"] = artifact
    return context


def test_real_authority_receipt_composes():
    context = _real_authority_context()

    report = _verify(context)

    assert report.ok
    assert report.evidence_state is EvidenceState.VERIFIED
    assert (
        report.decision_conformance
        is DecisionConformance.CONFORMANT
    )


def test_tampered_real_authority_receipt_is_invalid():
    context = _real_authority_context()
    authority_receipt = copy.deepcopy(
        context["authority_receipt"]
    )
    authority_receipt["requested"]["resource"] = (
        "approval_request:tampered"
    )

    report = _verify(
        context,
        authority_receipt=authority_receipt,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code is not None
    assert report.reason_code.startswith(
        "APPROVER_AUTHORITY_"
    )
