"""SQLite store: same contract as JSONL store, plus verifier-clean export."""

import subprocess
import sys
import time
from pathlib import Path

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.sqlite_store import SQLiteDecisionStore
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


def _populate(db_path):
    store = SQLiteDecisionStore(db_path)
    recorder = DecisionRecorder(store=store)
    engine = DecisionEngine(scorer=StubScorer(), invariants=StubInvariants())
    prev = None
    for cap in ("crm.read", "wire.drain", "email.send"):
        a = AgentAction(agent_id="agent-1", capability=cap, timestamp=time.time())
        r = engine.decide(a, prev)
        rec = recorder.record(a, r)
        status = "ok" if r.decision == Decision.ALLOW else "refused"
        recorder.report_outcome(rec.decision_id, status)
        if r.decision == Decision.ALLOW:
            prev = cap
    return store, recorder


def test_roundtrip_graph_from_sqlite(tmp_path):
    store, _ = _populate(tmp_path / "pv.db")
    g = store.load_graph()
    assert len(g) == 3
    assert len(g.find_blocked()) == 1
    assert g.verify_all() == {"agent-1": True}
    assert g.outcome_of(g.find_blocked()[0].decision_id) == "refused"
    store.close()


def test_export_passes_independent_verifier(tmp_path):
    store, _ = _populate(tmp_path / "pv.db")
    out = store.export_jsonl(tmp_path / "export.jsonl")
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(out)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout
    assert "VERDICT: PASS" in proc.stdout
    store.close()


def test_sqlite_refuses_unsealed(tmp_path):
    import pytest

    from agent_dna.decision_record import build_record

    engine = DecisionEngine(scorer=StubScorer())
    a = AgentAction(agent_id="a", capability="crm.read", timestamp=time.time())
    rec = build_record(a, engine.decide(a))
    rec.record_hash = ""
    with pytest.raises(ValueError):
        SQLiteDecisionStore(tmp_path / "x.db").append(rec)
