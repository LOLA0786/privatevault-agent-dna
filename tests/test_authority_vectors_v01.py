"""Customer-facing Authority Provenance derivation vectors."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from agent_dna.authority_v01 import (
    DecisionConformance,
    EvidenceState,
    canonicalize,
    scan_authority_records,
    verify_receipt,
)

VECTORS = Path("spec/authority-v01/vectors")


def load_vector(name: str) -> dict:
    path = VECTORS / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_business_checks_pass_but_action_is_denied() -> None:
    vector = load_vector(
        "denied-outside-authority.json"
    )

    assert set(
        vector["business_checks"].values()
    ) == {"PASS"}

    report = verify_receipt(
        vector["receipt"],
        vector["trust_bundle"],
    )

    assert (
        report.evidence_state
        is EvidenceState.VERIFIED
    )
    assert (
        report.decision_conformance
        is DecisionConformance.CONFORMANT
    )
    assert vector["receipt"]["authority_result"] == {
        "verdict": "DENY",
        "reason_code": (
            "ACTION_OUTSIDE_DELEGATED_AUTHORITY"
        ),
    }
    assert vector["receipt"]["policy_result"]["verdict"] == (
        "ALLOW"
    )
    assert vector["receipt"]["final_verdict"] == "DENY"


def test_injected_wrapper_cannot_change_authority_derivation() -> None:
    denied = load_vector(
        "denied-outside-authority.json"
    )
    injected = load_vector("injected-variant.json")

    assert denied["raw_input"] != injected["raw_input"]

    assert (
        denied["receipt"]["decision_input_digest"]
        != injected["receipt"]["decision_input_digest"]
    )

    assert (
        denied["receipt"]["requested"]
        == injected["receipt"]["requested"]
    )

    denied_result = denied["receipt"]["authority_result"]
    injected_result = (
        injected["receipt"]["authority_result"]
    )

    assert canonicalize(denied_result) == canonicalize(
        injected_result
    )

    report = verify_receipt(
        injected["receipt"],
        injected["trust_bundle"],
    )
    assert report.ok


def test_verified_nonconformant_allow_is_scanner_critical() -> None:
    vector = load_vector(
        "allowed-outside-authority.json"
    )

    report = verify_receipt(
        vector["receipt"],
        vector["trust_bundle"],
    )

    assert (
        report.evidence_state
        is EvidenceState.VERIFIED
    )
    assert (
        report.decision_conformance
        is DecisionConformance.NON_CONFORMANT
    )

    scan = scan_authority_records(
        [vector["receipt"]],
        vector["trust_bundle"],
    )

    assert scan["critical_findings"][0]["finding"] == (
        "VERIFIED_NON_CONFORMANT_ALLOW"
    )


def test_case_scoped_grant_allows_same_action_for_ten_minutes() -> None:
    before = load_vector(
        "denied-outside-authority.json"
    )
    after = load_vector("after-grant.json")

    assert (
        before["receipt"]["requested"]
        == after["receipt"]["requested"]
    )

    report = verify_receipt(
        after["receipt"],
        after["trust_bundle"],
    )
    assert report.ok

    grant = after["receipt"]["grant_chain"][-1]

    assert grant["grant_id"] == (
        "grant-refund-issue-RF-1042-10m"
    )
    assert grant["issuer_principal"] == (
        "refund-owner@example.com"
    )
    assert grant["valid_from"] == (
        "2026-07-28T12:00:00Z"
    )
    assert grant["expires_at"] == (
        "2026-07-28T12:10:00Z"
    )
    assert after["receipt"]["final_verdict"] == (
        "ALLOW"
    )


def test_vectors_validate_against_published_schemas() -> None:
    schema_dir = Path("spec/authority-v01")

    schemas = {
        name: json.loads(
            (schema_dir / name).read_text(
                encoding="utf-8"
            )
        )
        for name in (
            "trust-bundle.schema.json",
            "grant.schema.json",
            "receipt.schema.json",
        )
    }

    registry = Registry().with_resources(
        [
            (
                schema["$id"],
                Resource.from_contents(schema),
            )
            for schema in schemas.values()
        ]
    )

    trust_validator = Draft202012Validator(
        schemas["trust-bundle.schema.json"],
        registry=registry,
    )
    grant_validator = Draft202012Validator(
        schemas["grant.schema.json"],
        registry=registry,
    )
    receipt_validator = Draft202012Validator(
        schemas["receipt.schema.json"],
        registry=registry,
    )

    for path in sorted(VECTORS.glob("*.json")):
        vector = json.loads(
            path.read_text(encoding="utf-8")
        )

        trust_validator.validate(
            vector["trust_bundle"]
        )

        for grant in vector["receipt"]["grant_chain"]:
            grant_validator.validate(grant)

        receipt_validator.validate(vector["receipt"])


def test_vector_generator_is_deterministic() -> None:
    before = {
        path.name: path.read_bytes()
        for path in sorted(VECTORS.glob("*.json"))
    }

    result = subprocess.run(
        [
            sys.executable,
            "tools/generate_authority_vectors.py",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, (
        result.stdout + result.stderr
    )

    after = {
        path.name: path.read_bytes()
        for path in sorted(VECTORS.glob("*.json"))
    }

    assert after == before


def test_customer_demo_shows_authority_derivation() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "examples/authority_derivation_demo.py",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, (
        result.stdout + result.stderr
    )

    output = result.stdout

    required_proof = (
        "BUSINESS CHECKS PASS, AUTHORITY DENIES",
        "ACTION_OUTSIDE_DELEGATED_AUTHORITY",
        "INJECTED VARIANT — AUTHORITY RESULT IS UNCHANGED",
        "evidence              VERIFIED",
        "conformance           NON_CONFORMANT",
        "VERIFIED_NON_CONFORMANT_ALLOW",
        "AFTER CASE-SCOPED 10-MINUTE GRANT",
        "grant-refund-issue-RF-1042-10m",
        "Before grant : policy ALLOW + authority DENY => final DENY",
        "After grant  : policy ALLOW + authority ALLOW => final ALLOW",
    )

    for expected in required_proof:
        assert expected in output
