"""Runtime-coupled verification of signed coding-evaluation reports."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import fields
from typing import Any

from agent_dna.decision_record import (
    GENESIS_HASH,
    DecisionRecord,
)
from agent_dna.signer import verify_trusted_envelope

from .harness import REPORT_SPEC, canonical_hash


class VerificationError(ValueError):
    """A signed evaluation report failed closed verification."""


def _mapping(
    value: Any,
    path: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise VerificationError(f"{path}: expected object")
    return value


def _sequence(
    value: Any,
    path: str,
) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(
        value,
        (str, bytes),
    ):
        raise VerificationError(f"{path}: expected array")
    return value


def _exact(
    value: Mapping[str, Any],
    expected: set[str],
    path: str,
) -> None:
    if set(value) != expected:
        raise VerificationError(f"{path}: invalid fields")


def _decision_record(
    value: Mapping[str, Any],
    path: str,
) -> DecisionRecord:
    record_fields = fields(DecisionRecord)

    _exact(
        value,
        {item.name for item in record_fields},
        path,
    )

    if value["kind"] != "decision" or value["protocol_version"] != "drp/0.1":
        raise VerificationError(f"{path}: unsupported record contract")

    kwargs = {item.name: value[item.name] for item in record_fields if item.init}

    try:
        return DecisionRecord(**kwargs)
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"{path}: malformed record") from exc


def _verify_report_seal(
    report: Mapping[str, Any],
    trusted_public_key: str,
) -> None:
    unsigned = {
        key: value
        for key, value in report.items()
        if key
        not in {
            "report_hash",
            "report_signature",
        }
    }

    report_hash = report["report_hash"]

    if not isinstance(report_hash, str) or canonical_hash(unsigned) != report_hash:
        raise VerificationError("report: hash mismatch")

    signature = _mapping(
        report["report_signature"],
        "report.report_signature",
    )

    if not verify_trusted_envelope(
        dict(signature),
        report_hash,
        trusted_keys={trusted_public_key},
    ):
        raise VerificationError("report: untrusted or invalid signature")


def _verify_link(
    record: DecisionRecord,
    previous: DecisionRecord | None,
    path: str,
) -> None:
    if previous is None:
        if record.prev_hash != GENESIS_HASH or record.parent_decision is not None:
            raise VerificationError(f"{path}: invalid genesis linkage")
    elif (
        record.prev_hash != previous.record_hash
        or record.parent_decision != previous.decision_id
    ):
        raise VerificationError(f"{path}: chain linkage mismatch")


def _verify_result(
    raw_item: Any,
    index: int,
    previous: DecisionRecord | None,
    trusted_public_key: str,
) -> tuple[DecisionRecord, bool]:
    path = f"report.results[{index}]"
    item = _mapping(raw_item, path)

    _exact(
        item,
        {
            "name",
            "description",
            "passed",
            "decision",
            "record",
            "signature",
            "signature_valid",
        },
        path,
    )

    record = _decision_record(
        _mapping(
            item["record"],
            f"{path}.record",
        ),
        f"{path}.record",
    )

    if not record.verify():
        raise VerificationError(f"{path}: record hash mismatch")

    _verify_link(record, previous, path)

    decision = _mapping(
        item["decision"],
        f"{path}.decision",
    )

    if (
        decision.get("decision") != record.decision
        or decision.get("triggered_by") != record.triggered_by
    ):
        raise VerificationError(f"{path}: decision/record mismatch")

    signature = _mapping(
        item["signature"],
        f"{path}.signature",
    )

    if not verify_trusted_envelope(
        dict(signature),
        record.record_hash,
        trusted_keys={trusted_public_key},
    ):
        raise VerificationError(f"{path}: untrusted or invalid signature")

    if item["signature_valid"] is not True:
        raise VerificationError(f"{path}: stored signature verdict is false")

    return record, item["passed"] is True


def _verify_summary(
    report: Mapping[str, Any],
    scenarios_run: int,
    passed_count: int,
) -> None:
    failed_count = scenarios_run - passed_count

    if (
        report["scenarios_run"] != scenarios_run
        or report["scenarios_passed"] != passed_count
        or report["scenarios_failed"] != failed_count
        or report["passed"] is not (failed_count == 0)
    ):
        raise VerificationError("report: summary mismatch")


def verify_report(
    report: Mapping[str, Any],
    *,
    trusted_public_key: str,
) -> dict[str, Any]:
    """Verify seal, hashes, chain and trusted signatures."""

    expected = {
        "spec",
        "runtime_package",
        "runtime_version",
        "suite",
        "scenarios_run",
        "scenarios_passed",
        "scenarios_failed",
        "passed",
        "results",
        "report_hash",
        "report_signature",
    }

    _exact(report, expected, "report")

    if report["spec"] != REPORT_SPEC:
        raise VerificationError("report: unsupported specification")

    if (
        report["runtime_package"] != "privatevault-agent-dna"
        or report["runtime_version"] != "0.3.0"
    ):
        raise VerificationError("report: unexpected runtime")

    _verify_report_seal(
        report,
        trusted_public_key,
    )

    results = _sequence(
        report["results"],
        "report.results",
    )

    previous: DecisionRecord | None = None
    passed_count = 0

    for index, raw_item in enumerate(results):
        previous, passed = _verify_result(
            raw_item,
            index,
            previous,
            trusted_public_key,
        )
        passed_count += int(passed)

    scenarios_run = len(results)

    _verify_summary(
        report,
        scenarios_run,
        passed_count,
    )

    return {
        "valid": True,
        "suite": report["suite"],
        "scenarios_verified": scenarios_run,
        "trusted_public_key": trusted_public_key,
    }
