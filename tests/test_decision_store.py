"""Persistence round-trip + independent verifier (run via subprocess
to prove it needs nothing from the package)."""

import json
import subprocess
import sys
import time
from pathlib import Path

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.decision_store import DecisionStore
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


def _populate(store_path, caps=("crm.read", "wire.drain", "email.send")):
    store = DecisionStore(store_path)
    recorder = DecisionRecorder(store=store)
    engine = DecisionEngine(scorer=StubScorer(), invariants=StubInvariants())
    prev = None
    for cap in caps:
        a = AgentAction(
            agent_id="agent-1",
            capability=cap,
            timestamp=time.time(),
        )
        r = engine.decide(a, prev)
        recorder.record(a, r)
        if r.decision == Decision.ALLOW:
            prev = cap
    return store, recorder


def _run_verifier(path):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(path)],
        capture_output=True,
        text=True,
    )


def test_round_trip_reloads_verified_graph(tmp_path):
    path = tmp_path / "decisions.jsonl"
    store, recorder = _populate(path)

    g = store.load_graph()
    assert len(g) == 3
    assert len(g.find_blocked()) == 1
    assert g.verify_all() == {"agent-1": True}

    # lineage survives the round trip
    last = list(g)[-1]
    assert [r.capability for r in g.lineage(last.decision_id)] == [
        "crm.read", "wire.drain", "email.send",
    ]


def test_follows_edges_on_disk(tmp_path):
    path = tmp_path / "decisions.jsonl"
    _populate(path)
    lines = [json.loads(l) for l in path.read_text().splitlines()]
    assert lines[0]["edges"] == []
    assert lines[1]["edges"] == [
        {"type": "follows", "target": lines[0]["decision_id"]}
    ]


def test_independent_verifier_passes_clean_file(tmp_path):
    path = tmp_path / "decisions.jsonl"
    _populate(path)
    proc = _run_verifier(path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "VERDICT: PASS" in proc.stdout


def test_independent_verifier_detects_tampered_field(tmp_path):
    path = tmp_path / "decisions.jsonl"
    _populate(path)

    lines = path.read_text().splitlines()
    doctored = json.loads(lines[1])
    doctored["decision"] = "allow"          # flip the BLOCK to ALLOW
    lines[1] = json.dumps(doctored, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    proc = _run_verifier(path)
    assert proc.returncode == 1
    assert "record_hash mismatch" in proc.stdout
    assert "VERDICT: FAIL" in proc.stdout


def test_independent_verifier_detects_deleted_record(tmp_path):
    path = tmp_path / "decisions.jsonl"
    _populate(path)

    lines = path.read_text().splitlines()
    del lines[1]                            # silently drop the BLOCK
    path.write_text("\n".join(lines) + "\n")

    proc = _run_verifier(path)
    assert proc.returncode == 1
    assert "chain break" in proc.stdout


def test_store_refuses_unsealed_record(tmp_path):
    import pytest
    from agent_dna.decision_record import build_record

    engine = DecisionEngine(scorer=StubScorer())
    a = AgentAction(agent_id="a", capability="crm.read", timestamp=time.time())
    rec = build_record(a, engine.decide(a))
    rec.record_hash = ""
    with pytest.raises(ValueError):
        DecisionStore(tmp_path / "x.jsonl").append(rec)
