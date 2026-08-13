"""Executor feedback: anchored events, outcome queries, divergence
detection in-memory and from the file alone."""

import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.decision_store import DecisionStore
from agent_dna.execution_record import build_execution_event
from agent_dna.trace import AgentAction

VERIFIER = Path(__file__).resolve().parent.parent / "tools" / "verify_records.py"


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


class StubInvariants:
    def validate(self, capability, previous):
        class R:
            pass

        r = R()
        r.violated = capability == "wire.drain"
        r.message = "forbidden" if r.violated else ""
        return r


def _pipeline(store_path=None):
    store = DecisionStore(store_path) if store_path else None
    recorder = DecisionRecorder(store=store)
    engine = DecisionEngine(scorer=StubScorer(), invariants=StubInvariants())
    return engine, recorder


def _decide_and_record(engine, recorder, cap, prev=None):
    a = AgentAction(agent_id="agent-1", capability=cap, timestamp=time.time())
    r = engine.decide(a, prev)
    rec = recorder.record(a, r)
    return rec, r


def test_outcome_roundtrip():
    engine, recorder = _pipeline()
    rec, _ = _decide_and_record(engine, recorder, "crm.read")
    assert recorder.graph.outcome_of(rec.decision_id) == "pending"
    recorder.report_outcome(rec.decision_id, "ok", detail="200")
    assert recorder.graph.outcome_of(rec.decision_id) == "ok"


def test_event_anchored_to_decision_hash():
    engine, recorder = _pipeline()
    rec, _ = _decide_and_record(engine, recorder, "crm.read")
    ev = recorder.report_outcome(rec.decision_id, "ok")
    assert ev.prev_hash == rec.record_hash
    assert ev.edges == [{"type": "resulted_in", "target": rec.decision_id}]
    assert ev.verify()


def test_duplicate_execution_rejected():
    engine, recorder = _pipeline()
    rec, _ = _decide_and_record(engine, recorder, "crm.read")
    recorder.report_outcome(rec.decision_id, "ok")
    with pytest.raises(ValueError):
        recorder.report_outcome(rec.decision_id, "error")


def test_anchor_mismatch_rejected():
    engine, recorder = _pipeline()
    rec, _ = _decide_and_record(engine, recorder, "crm.read")
    forged = build_execution_event(
        agent_id="agent-1",
        decision_id=rec.decision_id,
        decision_hash="f" * 64,  # wrong anchor
        status="ok",
    )
    with pytest.raises(ValueError):
        recorder.graph.add_execution(forged)


def test_find_divergent_flags_executed_block():
    engine, recorder = _pipeline()
    blocked, result = _decide_and_record(engine, recorder, "wire.drain")
    assert result.decision == Decision.BLOCK

    recorder.report_outcome(blocked.decision_id, "ok")  # world says it ran
    divergent = recorder.graph.find_divergent()
    assert len(divergent) == 1
    assert divergent[0].capability == "wire.drain"


def test_honest_refusal_is_not_divergent():
    engine, recorder = _pipeline()
    blocked, _ = _decide_and_record(engine, recorder, "wire.drain")
    recorder.report_outcome(blocked.decision_id, "refused")
    assert recorder.graph.find_divergent() == []


def test_indeterminate_is_not_ok_and_not_divergence():
    engine, recorder = _pipeline()
    rec, _ = _decide_and_record(engine, recorder, "crm.read")
    digest = "sha256:" + ("ab" * 32)
    ev = recorder.report_outcome(
        rec.decision_id,
        "indeterminate",
        "timeout after write",
        response_digest=digest,
    )
    assert ev.status == "indeterminate"
    assert ev.status != "ok"
    assert ev.response_digest == digest
    assert recorder.graph.find_divergent() == []
    assert recorder.graph.outcome_of(rec.decision_id) == "indeterminate"


def test_mixed_file_roundtrip_and_verifier(tmp_path):
    path = tmp_path / "decisions.jsonl"
    engine, recorder = _pipeline(path)

    r1, _ = _decide_and_record(engine, recorder, "crm.read")
    recorder.report_outcome(r1.decision_id, "ok")
    r2, _ = _decide_and_record(engine, recorder, "wire.drain", prev="crm.read")
    recorder.report_outcome(r2.decision_id, "refused")

    # reload
    store = DecisionStore(path)
    g = store.load_graph()
    assert g.outcome_of(r1.decision_id) == "ok"
    assert g.outcome_of(r2.decision_id) == "refused"
    assert g.find_divergent() == []

    # independent verifier passes
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(path)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout
    assert "VERDICT: PASS" in proc.stdout


def test_verifier_flags_divergence_from_file_alone(tmp_path):
    path = tmp_path / "decisions.jsonl"
    engine, recorder = _pipeline(path)
    blocked, _ = _decide_and_record(engine, recorder, "wire.drain")
    recorder.report_outcome(blocked.decision_id, "ok")  # divergence

    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(path)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "ENFORCEMENT DIVERGENCE" in proc.stdout
