"""Thin coding-agent scenario harness over actual agent_dna components."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agent_dna.decision_record import (
    GENESIS_HASH,
    DecisionRecord,
    build_record,
)
from agent_dna.signer import (
    ReceiptSigner,
    generate_keypair,
    verify_trusted_envelope,
)

from .runtime import actual_decision_engine
from .scenario import Scenario

REPORT_SPEC = "pv-coding-agent-runtime-evaluation/0.1"


def canonical_hash(value: Mapping[str, Any]) -> str:
    """Hash a float-safe canonical JSON object for report sealing."""

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()

    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    description: str
    passed: bool
    decision: Mapping[str, Any]
    record: Mapping[str, Any]
    signature: Mapping[str, Any]
    signature_valid: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "passed": self.passed,
            "decision": dict(self.decision),
            "record": dict(self.record),
            "signature": dict(self.signature),
            "signature_valid": self.signature_valid,
        }


def run_scenario(
    scenario: Scenario,
    *,
    signer: ReceiptSigner,
    parent_decision: str | None = None,
    prev_hash: str = GENESIS_HASH,
) -> tuple[ScenarioResult, DecisionRecord]:
    """Run one scenario through the real runtime, recorder, and signer."""

    result = actual_decision_engine(
        grants=scenario.grants,
        policy=scenario.policy,
        consensus_enabled=scenario.consensus_enabled,
    ).decide(
        scenario.action,
        prev_capability=scenario.previous_capability,
        evidence=scenario.action.evidence,
    )

    record = build_record(
        scenario.action,
        result,
        parent_decision=parent_decision,
        prev_hash=prev_hash,
        request_id=scenario.action.request_id,
    )

    envelope = signer.sign_record(record)
    envelope_dict = envelope.to_dict()

    signature_valid = verify_trusted_envelope(
        envelope_dict,
        record.record_hash,
        trusted_keys={signer.public_key},
    )

    passed = (
        result.decision.value == scenario.expected_decision
        and result.triggered_by == scenario.expected_trigger
        and record.verify()
        and signature_valid
    )

    return (
        ScenarioResult(
            name=scenario.name,
            description=scenario.description,
            passed=passed,
            decision=result.to_dict(),
            record=record.to_dict(),
            signature=envelope_dict,
            signature_valid=signature_valid,
        ),
        record,
    )


def run_suite(
    name: str,
    scenarios: Sequence[Scenario],
) -> tuple[dict[str, Any], str]:
    """Run scenarios and produce signed, hash-chained records."""

    keys = generate_keypair()
    signer = ReceiptSigner(
        keys["signing_key"],
        key_id="coding-eval-01",
    )

    results: list[ScenarioResult] = []
    parent: str | None = None
    previous_hash = GENESIS_HASH

    for scenario in scenarios:
        result, record = run_scenario(
            scenario,
            signer=signer,
            parent_decision=parent,
            prev_hash=previous_hash,
        )
        results.append(result)
        parent = record.decision_id
        previous_hash = record.record_hash

    passed = sum(item.passed for item in results)

    report = {
        "spec": REPORT_SPEC,
        "runtime_package": "privatevault-agent-dna",
        "runtime_version": "0.3.0",
        "suite": name,
        "scenarios_run": len(results),
        "scenarios_passed": passed,
        "scenarios_failed": len(results) - passed,
        "passed": passed == len(results),
        "results": [item.to_dict() for item in results],
    }

    report_hash = canonical_hash(report)
    report["report_hash"] = report_hash
    report["report_signature"] = signer.sign_hash(report_hash).to_dict()

    return report, signer.public_key
