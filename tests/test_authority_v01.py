"""Authority Provenance v0.1-experimental acceptance suite."""

from __future__ import annotations

import copy

import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    COMPOSITION_PROFILE,
    GRANT_SPEC,
    RECEIPT_SPEC,
    TRUST_SPEC,
    AuthorityFormatError,
    DecisionConformance,
    EvidenceState,
    encode_public_key,
    grant_digest,
    sign_grant,
    sign_receipt,
    strict_json_loads,
    verify_receipt,
)

T0 = "2020-01-01T00:00:00Z"
T1 = "2030-01-01T00:00:00Z"
DECISION_TIME = "2026-07-28T09:07:31.442Z"
ZERO_DIGEST = "sha256:" + ("0" * 64)


@pytest.fixture
def artifacts():
    keys = {
        "root": SigningKey.generate(),
        "delegate": SigningKey.generate(),
        "subject": SigningKey.generate(),
        "runtime": SigningKey.generate(),
        "replacement": SigningKey.generate(),
    }

    bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": "store.example",
        "bundle_version": 1,
        "pinned_at": "2026-07-28T00:00:00Z",
        "keys": [
            {
                "key_id": "owner-root-2026",
                "principal": "owner@store.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(keys["root"]),
                "usages": [
                    "root_authority",
                    "grant_issuer",
                ],
            },
            {
                "key_id": "delegate-01",
                "principal": "delegate@store.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(keys["delegate"]),
                "usages": ["grant_issuer"],
            },
            {
                "key_id": "merch-agent-01",
                "principal": "merch-agent-01@store.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(keys["subject"]),
                "usages": ["subject"],
            },
            {
                "key_id": "pv-runtime-01",
                "principal": ("privatevault-runtime@store.example"),
                "algorithm": "ed25519",
                "public_key": encode_public_key(keys["runtime"]),
                "usages": ["receipt_signer"],
            },
            {
                "key_id": "delegate-replacement",
                "principal": "delegate@store.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(keys["replacement"]),
                "usages": ["grant_issuer"],
            },
        ],
    }

    capability = {
        "action": "payments.initiate",
        "resource": "account:*",
        "constraints": [
            {
                "field": "amount",
                "operator": "lte",
                "value": {
                    "minor_units": 500000,
                    "currency": "INR",
                },
            },
            {
                "field": "approval_count",
                "operator": "gte",
                "value": 2,
            },
            {
                "field": "country",
                "operator": "in",
                "value": ["IN"],
            },
        ],
        "obligations": [
            {"kind": "dual_approval"},
        ],
    }

    root = sign_grant(
        {
            "spec": GRANT_SPEC,
            "canonicalization": CANONICALIZATION,
            "grant_id": "g-root",
            "organisation_id": "store.example",
            "issuer_principal": "owner@store.example",
            "issuer_key_id": "owner-root-2026",
            "subject_principal": "delegate@store.example",
            "subject_key_id": "delegate-01",
            "parent_grant_digest": None,
            "capabilities": [copy.deepcopy(capability)],
            "can_delegate": True,
            "remaining_depth": 2,
            "valid_from": T0,
            "expires_at": T1,
        },
        keys["root"],
    )

    child = sign_grant(
        {
            "spec": GRANT_SPEC,
            "canonicalization": CANONICALIZATION,
            "grant_id": "g-child",
            "organisation_id": "store.example",
            "issuer_principal": "delegate@store.example",
            "issuer_key_id": "delegate-01",
            "subject_principal": ("merch-agent-01@store.example"),
            "subject_key_id": "merch-agent-01",
            "parent_grant_digest": grant_digest(root),
            "capabilities": [copy.deepcopy(capability)],
            "can_delegate": False,
            "remaining_depth": 1,
            "valid_from": T0,
            "expires_at": T1,
        },
        keys["delegate"],
    )

    receipt = sign_receipt(
        {
            "spec": RECEIPT_SPEC,
            "canonicalization": CANONICALIZATION,
            "receipt_id": "r-001",
            "organisation_id": "store.example",
            "previous_receipt_hash": None,
            "request_id": "req-001",
            "decision_timestamp": DECISION_TIME,
            "decision_input_digest": ZERO_DIGEST,
            "grant_chain": [root, child],
            "requested": {
                "subject_principal": ("merch-agent-01@store.example"),
                "subject_key_id": "merch-agent-01",
                "action": "payments.initiate",
                "resource": "account:4471",
                "facts": {
                    "amount": {
                        "minor_units": 400000,
                        "currency": "INR",
                    },
                    "approval_count": 2,
                    "country": "IN",
                },
            },
            "authority_result": {
                "verdict": "ALLOW",
                "reason_code": "AUTHORITY_GRANTED",
            },
            "policy_result": {
                "verdict": "ALLOW",
                "policy_id": "PAYMENTS-002",
                "policy_version": "2.1",
                "policy_digest": ZERO_DIGEST,
            },
            "composition_profile": COMPOSITION_PROFILE,
            "final_verdict": "ALLOW",
            "signer_key_id": "pv-runtime-01",
        },
        keys["runtime"],
    )

    return {
        "keys": keys,
        "bundle": bundle,
        "receipt": receipt,
    }


def _resign_grant(grant, key):
    return sign_grant(grant, key)


def _replace_root(artifacts, mutate):
    receipt = copy.deepcopy(artifacts["receipt"])
    root = receipt["grant_chain"][0]

    mutate(root)

    root = _resign_grant(
        root,
        artifacts["keys"]["root"],
    )

    child = receipt["grant_chain"][1]
    child["parent_grant_digest"] = grant_digest(root)

    child = _resign_grant(
        child,
        artifacts["keys"]["delegate"],
    )

    receipt["grant_chain"] = [root, child]

    return sign_receipt(
        receipt,
        artifacts["keys"]["runtime"],
    )


def _replace_child(
    artifacts,
    mutate,
    signing_key="delegate",
):
    receipt = copy.deepcopy(artifacts["receipt"])
    child = receipt["grant_chain"][1]

    mutate(child)

    receipt["grant_chain"][1] = _resign_grant(
        child,
        artifacts["keys"][signing_key],
    )

    return sign_receipt(
        receipt,
        artifacts["keys"]["runtime"],
    )


def _replace_receipt(
    artifacts,
    mutate,
    signing_key="runtime",
):
    receipt = copy.deepcopy(artifacts["receipt"])

    mutate(receipt)

    return sign_receipt(
        receipt,
        artifacts["keys"][signing_key],
    )


def _report(
    artifacts,
    receipt=None,
    bundle=None,
):
    return verify_receipt(
        receipt or artifacts["receipt"],
        (artifacts["bundle"] if bundle is None else bundle),
    )


# --- forgery and trust -------------------------------------------------


def test_chain_without_issuer_signatures_rejected(
    artifacts,
):
    receipt = copy.deepcopy(artifacts["receipt"])
    receipt["grant_chain"][0].pop("issuer_signature")

    receipt = sign_receipt(
        receipt,
        artifacts["keys"]["runtime"],
    )

    report = _report(artifacts, receipt)

    assert report.evidence_state is EvidenceState.INVALID


def test_trust_root_asserted_in_record_is_ignored(
    artifacts,
):
    receipt = copy.deepcopy(artifacts["receipt"])
    receipt["accountable_principal"] = "attacker@example.net"

    receipt = sign_receipt(
        receipt,
        artifacts["keys"]["runtime"],
    )

    report = _report(artifacts, receipt)

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "SCHEMA_INVALID"


def test_receipt_signed_by_subject_key_rejected(
    artifacts,
):
    receipt = _replace_receipt(
        artifacts,
        lambda value: value.update(signer_key_id="merch-agent-01"),
        signing_key="subject",
    )

    assert _report(artifacts, receipt).reason_code == "KEY_USAGE_INVALID"


def test_root_grant_by_non_root_authority_key_rejected(
    artifacts,
):
    receipt = copy.deepcopy(artifacts["receipt"])

    root = receipt["grant_chain"][0]
    root["issuer_principal"] = "delegate@store.example"
    root["issuer_key_id"] = "delegate-01"

    root = sign_grant(
        root,
        artifacts["keys"]["delegate"],
    )

    child = receipt["grant_chain"][1]
    child["parent_grant_digest"] = grant_digest(root)

    child = sign_grant(
        child,
        artifacts["keys"]["delegate"],
    )

    receipt["grant_chain"] = [root, child]

    receipt = sign_receipt(
        receipt,
        artifacts["keys"]["runtime"],
    )

    assert _report(artifacts, receipt).reason_code == "KEY_USAGE_INVALID"


# --- identity continuity ----------------------------------------------


def test_principal_matches_but_key_differs_rejected(
    artifacts,
):
    receipt = _replace_child(
        artifacts,
        lambda child: child.update(issuer_key_id="delegate-replacement"),
        signing_key="replacement",
    )

    assert _report(artifacts, receipt).reason_code == "KEY_CONTINUITY_BROKEN"


def test_leaf_subject_differs_from_requested_actor_rejected(
    artifacts,
):
    receipt = _replace_receipt(
        artifacts,
        lambda value: value["requested"].update(
            subject_principal=("other-agent@store.example")
        ),
    )

    assert _report(artifacts, receipt).reason_code == "KEY_CONTINUITY_BROKEN"


# --- attenuation -------------------------------------------------------


def test_identical_scope_permitted(artifacts):
    report = _report(artifacts)

    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.CONFORMANT


def test_cross_product_escalation_rejected(artifacts):
    receipt = copy.deepcopy(artifacts["receipt"])
    root = receipt["grant_chain"][0]

    root["capabilities"] = [
        {
            "action": "payments.pay",
            "resource": "account:X",
            "constraints": [],
            "obligations": [],
        },
        {
            "action": "payments.approve",
            "resource": "account:Y",
            "constraints": [],
            "obligations": [],
        },
    ]

    root = sign_grant(
        root,
        artifacts["keys"]["root"],
    )

    child = receipt["grant_chain"][1]
    child["parent_grant_digest"] = grant_digest(root)

    # No single parent capability grants approve@X.
    child["capabilities"] = [
        {
            "action": "payments.approve",
            "resource": "account:X",
            "constraints": [],
            "obligations": [],
        }
    ]

    child = sign_grant(
        child,
        artifacts["keys"]["delegate"],
    )

    receipt["grant_chain"] = [root, child]

    receipt = sign_receipt(
        receipt,
        artifacts["keys"]["runtime"],
    )

    assert _report(artifacts, receipt).reason_code == "GRANT_EXCEEDS_PARENT_AUTHORITY"


def test_constant_depth_rejected(artifacts):
    receipt = _replace_child(
        artifacts,
        lambda child: child.update(remaining_depth=2),
    )

    assert _report(artifacts, receipt).reason_code == "DELEGATION_DEPTH_EXCEEDED"


def test_non_delegable_parent_cannot_issue_child(
    artifacts,
):
    receipt = _replace_root(
        artifacts,
        lambda root: root.update(can_delegate=False),
    )

    assert _report(artifacts, receipt).reason_code == "DELEGATION_NOT_PERMITTED"


def test_obligation_cannot_be_shed(artifacts):
    receipt = _replace_child(
        artifacts,
        lambda child: child["capabilities"][0].update(obligations=[]),
    )

    assert _report(artifacts, receipt).reason_code == "GRANT_EXCEEDS_PARENT_AUTHORITY"


def test_missing_constraint_field_is_violation_not_default(
    artifacts,
):
    receipt = _replace_child(
        artifacts,
        lambda child: child["capabilities"][0]["constraints"].pop(),
    )

    assert _report(artifacts, receipt).reason_code == "GRANT_EXCEEDS_PARENT_AUTHORITY"


def test_operator_mismatch_rejected(artifacts):
    def mutate(child):
        child["capabilities"][0]["constraints"][0]["operator"] = "gte"

    receipt = _replace_child(
        artifacts,
        mutate,
    )

    assert _report(artifacts, receipt).reason_code == "GRANT_EXCEEDS_PARENT_AUTHORITY"


def test_gte_constraint_narrows_upward(artifacts):
    def mutate(child):
        child["capabilities"][0]["constraints"][1]["value"] = 3

    receipt = _replace_child(
        artifacts,
        mutate,
    )

    receipt = copy.deepcopy(receipt)
    receipt["requested"]["facts"]["approval_count"] = 3

    receipt = sign_receipt(
        receipt,
        artifacts["keys"]["runtime"],
    )

    assert _report(artifacts, receipt).ok


def test_cycle_detected(artifacts):
    def mutate(child):
        child["subject_principal"] = "owner@store.example"
        child["subject_key_id"] = "owner-root-2026"

    receipt = _replace_child(
        artifacts,
        mutate,
    )

    receipt = copy.deepcopy(receipt)
    receipt["requested"]["subject_principal"] = "owner@store.example"
    receipt["requested"]["subject_key_id"] = "owner-root-2026"

    receipt = sign_receipt(
        receipt,
        artifacts["keys"]["runtime"],
    )

    assert _report(artifacts, receipt).reason_code == "CHAIN_DISCONTINUOUS"


# --- time --------------------------------------------------------------


def test_expired_at_decision_time_not_verification_time(
    artifacts,
):
    receipt = copy.deepcopy(artifacts["receipt"])

    root = receipt["grant_chain"][0]
    root["valid_from"] = "2019-01-01T00:00:00Z"
    root["expires_at"] = "2021-01-01T00:00:00Z"

    root = sign_grant(
        root,
        artifacts["keys"]["root"],
    )

    child = receipt["grant_chain"][1]
    child["valid_from"] = "2019-01-01T00:00:00Z"
    child["expires_at"] = "2021-01-01T00:00:00Z"
    child["parent_grant_digest"] = grant_digest(root)

    child = sign_grant(
        child,
        artifacts["keys"]["delegate"],
    )

    receipt["grant_chain"] = [root, child]
    receipt["decision_timestamp"] = "2020-06-01T00:00:00Z"

    receipt = sign_receipt(
        receipt,
        artifacts["keys"]["runtime"],
    )

    # Grants are expired today but were valid at decision_timestamp.
    assert _report(artifacts, receipt).ok


def test_half_open_interval_boundary(artifacts):
    boundary = artifacts["receipt"]["decision_timestamp"]

    receipt = _replace_root(
        artifacts,
        lambda root: root.update(expires_at=boundary),
    )

    assert _report(artifacts, receipt).reason_code == "GRANT_NOT_VALID_AT_DECISION_TIME"


# --- decision semantics ------------------------------------------------


def test_correct_deny_is_verified_and_conformant(
    artifacts,
):
    def mutate(receipt):
        receipt["requested"]["action"] = "payments.delete"
        receipt["authority_result"] = {
            "verdict": "DENY",
            "reason_code": ("ACTION_OUTSIDE_DELEGATED_AUTHORITY"),
        }
        receipt["final_verdict"] = "DENY"

    report = _report(
        artifacts,
        _replace_receipt(artifacts, mutate),
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.CONFORMANT


def test_allow_outside_scope_is_verified_and_nonconformant(
    artifacts,
):
    receipt = _replace_receipt(
        artifacts,
        lambda value: value["requested"].update(action="payments.delete"),
    )

    report = _report(artifacts, receipt)

    # The signatures and chain are sound.
    assert report.evidence_state is EvidenceState.VERIFIED

    # But the grant does not authorize payments.delete.
    assert report.decision_conformance is DecisionConformance.NON_CONFORMANT

    # This is the scanner's highest-value row.
    assert receipt["final_verdict"] == "ALLOW"


def test_policy_denies_despite_sufficient_authority(
    artifacts,
):
    def mutate(receipt):
        receipt["policy_result"]["verdict"] = "DENY"
        receipt["final_verdict"] = "DENY"

    report = _report(
        artifacts,
        _replace_receipt(artifacts, mutate),
    )

    assert report.ok


def test_missing_policy_result_composes_to_deny(
    artifacts,
):
    def mutate(receipt):
        receipt["policy_result"] = None
        receipt["final_verdict"] = "DENY"

    report = _report(
        artifacts,
        _replace_receipt(artifacts, mutate),
    )

    assert report.ok


def test_recorded_final_verdict_contradicting_profile_is_nonconformant(
    artifacts,
):
    def mutate(receipt):
        receipt["policy_result"]["verdict"] = "DENY"
        receipt["final_verdict"] = "ALLOW"

    report = _report(
        artifacts,
        _replace_receipt(artifacts, mutate),
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.NON_CONFORMANT


# --- hygiene -----------------------------------------------------------


def test_duplicate_json_keys_rejected():
    with pytest.raises(
        AuthorityFormatError,
        match="duplicate JSON key",
    ):
        strict_json_loads('{"spec":"a","spec":"b"}')


def test_unknown_algorithm_rejected(artifacts):
    bundle = copy.deepcopy(artifacts["bundle"])
    bundle["keys"][3]["algorithm"] = "rsa"

    report = _report(
        artifacts,
        bundle=bundle,
    )

    assert report.evidence_state is EvidenceState.INVALID
    assert report.reason_code == "SCHEMA_INVALID"


def test_malformed_timestamp_rejected(artifacts):
    receipt = _replace_receipt(
        artifacts,
        lambda value: value.update(decision_timestamp="not-a-time"),
    )

    assert _report(artifacts, receipt).reason_code == "SCHEMA_INVALID"


def test_currency_mismatch_rejected(artifacts):
    def mutate(receipt):
        receipt["requested"]["facts"]["amount"]["currency"] = "USD"

        receipt["authority_result"] = {
            "verdict": "DENY",
            "reason_code": "CONSTRAINT_NOT_SATISFIED",
        }

        receipt["final_verdict"] = "DENY"

    report = _report(
        artifacts,
        _replace_receipt(artifacts, mutate),
    )

    assert report.evidence_state is EvidenceState.VERIFIED
    assert report.decision_conformance is DecisionConformance.CONFORMANT
