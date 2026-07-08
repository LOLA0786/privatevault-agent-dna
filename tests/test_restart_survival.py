"""P2: chain state must survive process restarts.

The failure mode these prevent: recorder chain heads lived only in
memory, so a restart chained the next record from GENESIS — breaking
the agent's hash chain in the runtime's own audit trail. Simulated
restart = construct a fresh recorder over the same store.
"""

import subprocess
import sys
import time
from pathlib import Path

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.decision_store import DecisionStore
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


def _engine():
    return DecisionEngine(scorer=StubScorer())


def _act(cap):
    return AgentAction(agent_id="agent-1", capability=cap, timestamp=time.time())


def _run(recorder, engine, caps):
    for cap in caps:
        rec = recorder.record(_act(cap), engine.decide(_act(cap)))
        recorder.report_outcome(rec.decision_id, "ok")


def _restart_scenario(store_factory, tmp_path):
    engine = _engine()

    # session 1
    r1 = DecisionRecorder(store=store_factory())
    _run(r1, engine, ["crm.read", "email.send"])

    # "process restart": brand-new recorder over the same store
    r2 = DecisionRecorder(store=store_factory())
    assert len(r2.graph) == 2, "graph not restored from store"

    _run(r2, engine, ["crm.update"])

    # the third record must chain off the second, NOT genesis
    recs = r2.graph.find_by_agent("agent-1")
    assert len(recs) == 3
    assert recs[2].prev_hash == recs[1].record_hash, (
        "restart chained from GENESIS — chain break in our own audit trail"
    )
    assert r2.graph.verify_chain("agent-1")
    return r2


def test_restart_jsonl(tmp_path):
    path = tmp_path / "d.jsonl"
    r = _restart_scenario(lambda: DecisionStore(path), tmp_path)

    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(path)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout
    assert "VERDICT: PASS" in proc.stdout


def test_restart_sqlite(tmp_path):
    db = tmp_path / "d.db"
    r = _restart_scenario(lambda: SQLiteDecisionStore(db), tmp_path)

    export = tmp_path / "export.jsonl"
    SQLiteDecisionStore(db).export_jsonl(export)
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(export)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout
    assert "VERDICT: PASS" in proc.stdout


def test_double_restart_multiple_agents(tmp_path):
    db = tmp_path / "m.db"
    engine = _engine()

    def act(agent, cap):
        return AgentAction(agent_id=agent, capability=cap, timestamp=time.time())

    r1 = DecisionRecorder(store=SQLiteDecisionStore(db))
    for agent in ("agent-1", "agent-2"):
        r1.record(act(agent, "crm.read"), engine.decide(act(agent, "crm.read")))

    r2 = DecisionRecorder(store=SQLiteDecisionStore(db))
    r2.record(act("agent-1", "email.send"), engine.decide(act("agent-1", "email.send")))

    r3 = DecisionRecorder(store=SQLiteDecisionStore(db))
    r3.record(act("agent-2", "email.send"), engine.decide(act("agent-2", "email.send")))

    assert r3.graph.verify_all() == {"agent-1": True, "agent-2": True}


def test_signer_survives_restart(tmp_path):
    """New envelopes after restart must still verify; pre-restart
    envelopes are in the pre-restart process's memory only — envelope
    persistence is the parked design item, restated here as a claim
    boundary, not silently assumed."""
    from agent_dna.signer import ReceiptSigner, generate_keypair, verify_envelope

    keys = generate_keypair()
    db = tmp_path / "s.db"
    engine = _engine()

    r1 = DecisionRecorder(
        store=SQLiteDecisionStore(db),
        signer=ReceiptSigner(seed_hex=keys["signing_key"]),
    )
    r1.record(_act("crm.read"), engine.decide(_act("crm.read")))

    r2 = DecisionRecorder(
        store=SQLiteDecisionStore(db),
        signer=ReceiptSigner(seed_hex=keys["signing_key"]),
    )
    rec = r2.record(_act("email.send"), engine.decide(_act("email.send")))
    assert verify_envelope(r2.envelopes[rec.record_hash], rec.record_hash)
    assert r2.graph.verify_chain("agent-1")
