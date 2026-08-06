"""Authority scanner, schema, sequence and CLI integration tests."""

# ruff: noqa: F811 - imported pytest fixture names are injected parameters

from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from agent_dna.authority_v01 import (
    DecisionConformance,
    EvidenceState,
    receipt_digest,
    scan_authority_records,
    sign_receipt,
    verify_receipt_sequence,
)
from tests.test_authority_v01 import (
    artifacts as _artifacts_fixture,  # noqa: F401
)

TOOL = Path("tools/pv_authority_cli.py")


def test_no_bundle_is_unverifiable_not_invalid(
    _artifacts_fixture,
):
    report = scan_authority_records(
        [_artifacts_fixture["receipt"]],
        None,
    )

    assert report["evidence_state"]["UNVERIFIABLE"] == 1
    assert report["evidence_state"]["INVALID"] == 0


def test_absent_evidence_dominates_first_scan(
    _artifacts_fixture,
):
    records = [
        {"action": "a"},
        {"action": "b"},
        {"action": "c"},
    ]

    report = scan_authority_records(
        records,
        _artifacts_fixture["bundle"],
    )

    assert report["actions_analysed"] == 3
    assert report["evidence_state"]["ABSENT"] == 3
    assert report["decision_conformance"]["NOT_ASSESSABLE"] == 3


def test_verified_nonconformant_allow_is_critical_finding(
    _artifacts_fixture,
):
    receipt = copy.deepcopy(_artifacts_fixture["receipt"])

    receipt["requested"]["action"] = "payments.delete"

    receipt = sign_receipt(
        receipt,
        _artifacts_fixture["keys"]["runtime"],
    )

    report = scan_authority_records(
        [receipt],
        _artifacts_fixture["bundle"],
    )

    assert report["evidence_state"]["VERIFIED"] == 1
    assert report["decision_conformance"]["NON_CONFORMANT"] == 1

    finding = report["critical_findings"][0]

    assert finding["finding"] == "VERIFIED_NON_CONFORMANT_ALLOW"
    assert finding["accountable_principal"] == "owner@store.example"


def test_receipt_sequence_linkage_is_checked(
    _artifacts_fixture,
):
    first = _artifacts_fixture["receipt"]
    second = copy.deepcopy(first)

    second["receipt_id"] = "r-002"
    second["request_id"] = "req-002"
    second["previous_receipt_hash"] = receipt_digest(first)

    second = sign_receipt(
        second,
        _artifacts_fixture["keys"]["runtime"],
    )

    reports = verify_receipt_sequence(
        [first, second],
        _artifacts_fixture["bundle"],
    )

    assert all(report.ok for report in reports)

    broken = copy.deepcopy(second)
    broken["previous_receipt_hash"] = "sha256:" + ("f" * 64)

    broken = sign_receipt(
        broken,
        _artifacts_fixture["keys"]["runtime"],
    )

    broken_report = verify_receipt_sequence(
        [first, broken],
        _artifacts_fixture["bundle"],
    )[1]

    assert broken_report.evidence_state is EvidenceState.INVALID
    assert broken_report.decision_conformance is DecisionConformance.NOT_ASSESSABLE
    assert broken_report.reason_code == "CHAIN_DISCONTINUOUS"


def test_authority_cli_accepts_valid_receipt(
    tmp_path,
    _artifacts_fixture,
):
    receipt_path = tmp_path / "receipt.json"
    bundle_path = tmp_path / "trust-bundle.json"

    receipt_path.write_text(
        json.dumps(_artifacts_fixture["receipt"]),
        encoding="utf-8",
    )

    bundle_path.write_text(
        json.dumps(_artifacts_fixture["bundle"]),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "verify",
            str(receipt_path),
            str(bundle_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "evidence_state       VERIFIED" in result.stdout
    assert "decision_conformance CONFORMANT" in result.stdout
    assert "accountable_principal owner@store.example" in result.stdout


def test_pv_authority_scan_reports_absent_evidence(
    tmp_path,
):
    records = tmp_path / "records.jsonl"

    records.write_text(
        '{"action":"a"}\n{"action":"b"}\n',
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_dna.cli",
            "authority",
            "scan",
            "--input",
            str(records),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "AUTHORISATION READINESS ASSESSMENT" in result.stdout
    assert "ABSENT 2" in result.stdout
    assert "industry norm" in result.stdout


def test_authority_scan_accepts_float_fields_outside_receipt(
    tmp_path,
):
    records = tmp_path / "records.jsonl"
    records.write_text(
        '{"action":"a","drift_score":0.9}\n',
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_dna.cli",
            "authority",
            "scan",
            "--input",
            str(records),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "ABSENT 1" in result.stdout
    assert "NOT_ASSESSABLE 1" in result.stdout


def test_authority_scan_rejects_duplicate_wrapper_keys(
    tmp_path,
):
    records = tmp_path / "records.jsonl"
    records.write_text(
        '{"action":"a","action":"b"}\n',
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_dna.cli",
            "authority",
            "scan",
            "--input",
            str(records),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "duplicate JSON key: action" in result.stderr


def test_authority_scan_reads_privatevault_sqlite_history(
    tmp_path,
):
    path = tmp_path / "history.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE records (seq INTEGER PRIMARY KEY, body TEXT NOT NULL)"
    )
    connection.executemany(
        "INSERT INTO records(seq, body) VALUES (?, ?)",
        [
            (1, json.dumps({"action": "a", "drift_score": 0.0})),
            (2, json.dumps({"action": "b", "drift_score": 0.9})),
        ],
    )
    connection.commit()
    connection.close()

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_dna.cli",
            "authority",
            "scan",
            "--input",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Actions analysed   2" in result.stdout
    assert "ABSENT 2" in result.stdout


def test_human_scan_surfaces_nonconformant_allow_and_fails(
    tmp_path,
    _artifacts_fixture,
):
    receipt = copy.deepcopy(_artifacts_fixture["receipt"])
    receipt["requested"]["action"] = "payments.delete"
    receipt = sign_receipt(
        receipt,
        _artifacts_fixture["keys"]["runtime"],
    )

    records = tmp_path / "records.jsonl"
    bundle = tmp_path / "bundle.json"
    records.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    bundle.write_text(
        json.dumps(_artifacts_fixture["bundle"]),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_dna.cli",
            "authority",
            "scan",
            "--input",
            str(records),
            "--trust-bundle",
            str(bundle),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "NON_CONFORMANT 1" in result.stdout
    assert "VERIFIED_NON_CONFORMANT_ALLOW" in result.stdout
    assert "owner@store.example" in result.stdout


def test_published_json_schemas_accept_valid_artifacts(
    _artifacts_fixture,
):
    schema_dir = Path("spec/authority-v01")

    schemas = {
        name: json.loads((schema_dir / name).read_text(encoding="utf-8"))
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

    Draft202012Validator(
        schemas["trust-bundle.schema.json"],
        registry=registry,
    ).validate(_artifacts_fixture["bundle"])

    Draft202012Validator(
        schemas["grant.schema.json"],
        registry=registry,
    ).validate(_artifacts_fixture["receipt"]["grant_chain"][0])

    Draft202012Validator(
        schemas["receipt.schema.json"],
        registry=registry,
    ).validate(_artifacts_fixture["receipt"])


def test_duplicate_request_is_detected_within_supplied_scan(
    _artifacts_fixture,
):
    report = scan_authority_records(
        [
            _artifacts_fixture["receipt"],
            _artifacts_fixture["receipt"],
        ],
        _artifacts_fixture["bundle"],
    )

    assert report["evidence_state"]["VERIFIED"] == 1
    assert report["evidence_state"]["INVALID"] == 1


def test_action_wildcards_and_loose_timestamps_are_rejected(
    _artifacts_fixture,
):
    receipt = copy.deepcopy(_artifacts_fixture["receipt"])

    receipt["grant_chain"][1]["capabilities"][0]["action"] = "payments.*"

    receipt = sign_receipt(
        receipt,
        _artifacts_fixture["keys"]["runtime"],
    )

    report = scan_authority_records(
        [receipt],
        _artifacts_fixture["bundle"],
    )

    assert report["evidence_state"]["INVALID"] == 1

    receipt = copy.deepcopy(_artifacts_fixture["receipt"])
    receipt["decision_timestamp"] = "2026-07-28Z"

    receipt = sign_receipt(
        receipt,
        _artifacts_fixture["keys"]["runtime"],
    )

    report = scan_authority_records(
        [receipt],
        _artifacts_fixture["bundle"],
    )

    assert report["evidence_state"]["INVALID"] == 1
