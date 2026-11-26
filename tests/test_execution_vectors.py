"""execution-v01 conformance vectors: current, and decided as recorded.

spec/execution-v01/vectors/ exists for other implementations: a receiver in
another language, an egress gateway on a DPU, hardware logic driven by
cocotb. These tests hold PrivateVault itself to the same file. The file must
be exactly what the generator writes today, and replaying every recorded
input through PrivateVault's verifiers must give the recorded outcome. The
replay here is written independently of the generator's own helpers.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_dna.authority_v01 import canonicalize
from agent_dna.dispatch_v01 import verify_dispatch_witness
from agent_dna.execution_v01 import (
    execution_authorization_digest,
    verify_execution_authorization,
)
from agent_dna.presenter_identity import presenter_identity_digest
from agent_dna.receiver.gate import ReceiverGate, _RefusalError
from agent_dna.wire_serialization_v01 import wire_action_binding_reason

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "spec" / "execution-v01" / "vectors" / "execution-v01.json"
GENERATOR = ROOT / "tools" / "gen_execution_vectors.py"
DATA = json.loads(VECTORS.read_text(encoding="utf-8"))
PERMITS = {case["id"]: case["authorization"] for case in DATA["authorization_cases"]}


def _bytes(text: str | None) -> bytes | None:
    return None if text is None else base64.b64decode(text, validate=True)


def _outcome(report) -> dict:
    return {
        "evidence_state": report.evidence_state.value,
        "decision_conformance": report.decision_conformance.value,
        "reason_code": report.reason_code,
        "failures": list(report.failures),
        "accountable_principal": report.accountable_principal,
    }


class _Ledger:
    def __init__(self, held: set[tuple[str, str]]) -> None:
        self.held = held

    def try_consume_execution_authorization(
        self, authorization_id, *, organisation_id, consumed_at
    ):
        if (organisation_id, authorization_id) in self.held:
            return False
        self.held.add((organisation_id, authorization_id))
        return True


def test_the_file_is_what_the_generator_writes_today():
    spec = importlib.util.spec_from_file_location("gen_execution_vectors", GENERATOR)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    assert VECTORS.read_text(encoding="utf-8") == generator.render(), (
        "stale vectors: run uv run python tools/gen_execution_vectors.py"
    )


def test_case_ids_are_unique_and_every_section_admits_and_refuses():
    sections = (
        "authorization_cases",
        "presenter_cases",
        "witness_cases",
        "wire_binding_cases",
    )
    ids = [case["id"] for section in sections for case in DATA[section]]
    assert len(ids) == len(set(ids))
    for section in sections:
        reasons = [case["expect"]["reason_code"] for case in DATA[section]]
        assert None in reasons, f"{section} has no accepting case"
        assert any(reasons), f"{section} has no refusing case"


def test_fixtures_pin_the_bytes_an_implementation_must_reproduce():
    fixtures = DATA["fixtures"]
    ea01 = PERMITS["EA-01"]
    unsigned = {key: value for key, value in ea01.items() if key != "signature"}
    assert canonicalize(unsigned) == _bytes(fixtures["ea01_signing_input_b64"])
    assert execution_authorization_digest(ea01) == fixtures["ea01_authorization_digest"]
    spki_digest = (
        "sha256:"
        + hashlib.sha256(_bytes(fixtures["presenter_spki_der_b64"])).hexdigest()
    )
    certificate_digest = presenter_identity_digest(
        _bytes(fixtures["presenter_certificate_der_b64"])
    )
    assert certificate_digest == spki_digest == fixtures["presenter_identity_digest"]
    assert PERMITS["EA-02"]["expected_presenter_identity_digest"] == spki_digest


@pytest.mark.parametrize(
    "case", DATA["authorization_cases"], ids=lambda case: case["id"]
)
def test_authorization_case(case):
    context = case["context"]
    permit = case["authorization"]
    held = (
        {(permit["organisation_id"], permit["execution_authorization_id"])}
        if context["ledger_already_holds_id"]
        else set()
    )
    bundle = (
        DATA["trust_bundles"][case["trust_bundle"]] if case["trust_bundle"] else None
    )
    report = verify_execution_authorization(
        permit,
        bundle,
        expected_request_id=context["expected_request_id"],
        expected_action=context["expected_action"],
        expected_dispatch=context["expected_dispatch"],
        expected_decision_receipt_digest=context["expected_decision_receipt_digest"],
        expected_authority_receipt_digest=context["expected_authority_receipt_digest"],
        expected_approval_artifact_digest=context["expected_approval_artifact_digest"],
        expected_state_snapshot_digest=context["expected_state_snapshot_digest"],
        expected_policy_bundle_digest=context["expected_policy_bundle_digest"],
        expected_obligations_digest=context["expected_obligations_digest"],
        expected_wire_bytes=_bytes(context["expected_wire_bytes_b64"]),
        expected_peer_identity_bytes=_bytes(context["expected_peer_identity_b64"]),
        at_time=context["at_time"],
        already_consumed=context["already_consumed"],
        consume_ledger=_Ledger(held),
    )
    assert _outcome(report) == case["expect"]


@pytest.mark.parametrize("case", DATA["presenter_cases"], ids=lambda case: case["id"])
def test_presenter_case(case):
    gate = SimpleNamespace(require_presenter=case["gate_requires_presenter"])
    try:
        ReceiverGate._verify_presenter(
            gate,
            PERMITS[case["authorization_case"]],
            _bytes(case["client_certificate_der_b64"]),
        )
        outcome = {"admitted": True, "reason_code": None}
    except _RefusalError as refusal:
        outcome = {"admitted": False, "reason_code": refusal.reason_code}
    assert outcome == case["expect"]


@pytest.mark.parametrize("case", DATA["witness_cases"], ids=lambda case: case["id"])
def test_witness_case(case):
    observed = case["observed"]
    report = verify_dispatch_witness(
        case["witness"],
        PERMITS[case["authorization_case"]],
        DATA["trust_bundles"][case["trust_bundle"]],
        observed_action=observed["action"],
        observed_dispatch=observed["dispatch"],
        wire_bytes=_bytes(observed["wire_bytes_b64"]),
        peer_identity_bytes=_bytes(observed["peer_identity_b64"]),
    )
    assert _outcome(report) == case["expect"]


@pytest.mark.parametrize(
    "case", DATA["wire_binding_cases"], ids=lambda case: case["id"]
)
def test_wire_binding_case(case):
    reason = wire_action_binding_reason(
        action=case["action"],
        serialization=case["serialization"],
        expected_wire_bytes_digest=case["expected_wire_bytes_digest"],
        expected_wire_bytes_length=case["expected_wire_bytes_length"],
    )
    assert {"reason_code": reason} == case["expect"]
