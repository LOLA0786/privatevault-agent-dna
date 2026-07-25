"""Detached signature envelopes are exported reproducibly."""

import json
import time

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.signer import ReceiptSigner, generate_keypair
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction


class _Scorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def _populate(path, signer=None):
    store = SQLiteDecisionStore(path)
    recorder = DecisionRecorder(store=store, signer=signer)
    engine = DecisionEngine(scorer=_Scorer())

    for index in range(3):
        action = AgentAction(
            agent_id="export-agent",
            capability=f"storage.read.{index}",
            timestamp=time.time() + index,
        )
        recorder.record(action, engine.decide(action))

    return store


def test_envelope_export_is_deterministic_and_ordered(tmp_path):
    keys = generate_keypair()
    signer = ReceiptSigner(seed_hex=keys["signing_key"])
    store = _populate(tmp_path / "signed.db", signer=signer)

    first = store.export_envelopes_jsonl(tmp_path / "first.jsonl")
    second = store.export_envelopes_jsonl(tmp_path / "second.jsonl")

    assert first.read_bytes() == second.read_bytes()

    envelopes = [
        json.loads(line) for line in first.read_text(encoding="utf-8").splitlines()
    ]
    decisions = list(store.iter_decisions())

    assert [item["signed_hash"] for item in envelopes] == [
        item["record_hash"] for item in decisions
    ]
    assert {item["public_key"] for item in envelopes} == {keys["public_key"]}
    assert first.read_text(encoding="utf-8").endswith("\n")

    store.close()


def test_unsigned_store_exports_empty_envelope_file(tmp_path):
    store = _populate(tmp_path / "unsigned.db")

    exported = store.export_envelopes_jsonl(tmp_path / "unsigned-envelopes.jsonl")

    assert exported.read_bytes() == b""

    store.close()
