"""Audit set 4: record + envelope + outcome persistence is
transactional, restart-safe, and store-authoritative."""

import hashlib
import sqlite3
import time

import pytest

from agent_dna.decision import Decision, DecisionResult, Severity
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.signer_python import ReceiptSigner
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction

SEED = hashlib.sha256(b"txn-persistence-seed").hexdigest()


def _act(agent="txn-agent", cap="crm.read_contact"):
    return AgentAction(agent_id=agent, capability=cap, timestamp=time.time())


def _res(action, decision=Decision.ALLOW):
    return DecisionResult(
        decision=decision,
        triggered_by="baseline",
        reason="test",
        capability=action.capability,
        agent_id=action.agent_id,
        drift_score=0.0,
        severity=list(Severity)[0],
    )


def test_envelope_persists_with_record_and_survives_restart(tmp_path):
    db = tmp_path / "pv.db"
    signer = ReceiptSigner(seed_hex=SEED)

    rec = DecisionRecorder(store=SQLiteDecisionStore(db), signer=signer).record(
        _act(), _res(_act())
    )
    h = rec.record_hash

    # fresh process: store + recorder rebuilt from disk
    store2 = SQLiteDecisionStore(db)
    assert store2.get_envelope(h) is not None
    rec2 = DecisionRecorder(store=store2)
    env = rec2.envelopes.get(h)
    assert env is not None and env["signed_hash"] == h


def test_record_and_envelope_are_one_transaction(tmp_path):
    """A failing envelope write must roll back the record: the state
    'record committed, envelope lost' is unrepresentable."""
    db = tmp_path / "pv.db"
    store = SQLiteDecisionStore(db)
    signer = ReceiptSigner(seed_hex=SEED)
    recorder = DecisionRecorder(store=store, signer=signer)

    class PoisonEnvelope:
        def to_dict(self):
            return {"signed_hash": {1, 2}}  # sets are not JSON

    original = signer.sign_record
    signer.sign_record = lambda r: PoisonEnvelope()
    try:
        with pytest.raises(TypeError):
            recorder.record(_act(), _res(_act()))
    finally:
        signer.sign_record = original

    conn = sqlite3.connect(db)
    (n,) = conn.execute("SELECT COUNT(*) FROM records").fetchone()
    (e,) = conn.execute("SELECT COUNT(*) FROM envelopes").fetchone()
    assert (n, e) == (0, 0), "partial commit leaked through the txn"
    # in-memory chain head untouched -> next record chains from genesis
    good = recorder.record(_act(), _res(_act()))
    assert good.prev_hash == "0" * 64


def test_no_signed_decision_without_envelope(tmp_path):
    db = tmp_path / "pv.db"
    recorder = DecisionRecorder(
        store=SQLiteDecisionStore(db),
        signer=ReceiptSigner(seed_hex=SEED),
    )
    for _ in range(5):
        recorder.record(_act(), _res(_act()))
    conn = sqlite3.connect(db)
    (orphans,) = conn.execute(
        "SELECT COUNT(*) FROM records r LEFT JOIN envelopes e "
        "ON r.record_hash = e.record_hash "
        "WHERE r.kind = 'decision' AND e.record_hash IS NULL"
    ).fetchone()
    assert orphans == 0


def test_one_execution_per_decision_enforced_by_database(tmp_path):
    """Cross-process duplicate outcomes: the second recorder instance
    has its own memory; only the DB constraint can catch it."""
    db = tmp_path / "pv.db"
    r1 = DecisionRecorder(store=SQLiteDecisionStore(db))
    rec = r1.record(_act(), _res(_act()))
    r1.report_outcome(rec.decision_id, "ok")

    r2 = DecisionRecorder(store=SQLiteDecisionStore(db))  # "other process"
    with pytest.raises(ValueError, match="duplicate execution"):
        r2.report_outcome(rec.decision_id, "ok")

    conn = sqlite3.connect(db)
    (n,) = conn.execute(
        "SELECT COUNT(*) FROM records WHERE kind='execution'"
    ).fetchone()
    assert n == 1


def test_multi_writer_outcome_resolves_via_store(tmp_path):
    """report_outcome previously resolved through self.graph, which
    multi-writer mode deliberately never populates -- outcomes crashed
    exactly when multi-writer was on."""
    db = tmp_path / "pv.db"
    recorder = DecisionRecorder(store=SQLiteDecisionStore(db), multi_writer_safe=True)
    rec = recorder.record(_act(), _res(_act()))
    event = recorder.report_outcome(rec.decision_id, "ok")
    assert event.decision_ref == rec.decision_id
    assert event.prev_hash == rec.record_hash
    with pytest.raises(KeyError):
        recorder.report_outcome("no-such-decision", "ok")


def test_multi_writer_envelope_in_same_atomic_append(tmp_path):
    db = tmp_path / "pv.db"
    recorder = DecisionRecorder(
        store=SQLiteDecisionStore(db),
        signer=ReceiptSigner(seed_hex=SEED),
        multi_writer_safe=True,
    )
    rec = recorder.record(_act(), _res(_act()))
    assert SQLiteDecisionStore(db).get_envelope(rec.record_hash)


def test_append_atomic_raises_on_duplicate_id_not_false(tmp_path):
    """Only a genuine (agent_id, prev_hash) chain race returns False;
    a duplicate decision_id is corruption and must raise -- the old
    blanket IntegrityError catch retried it 20 times as a 'race'."""
    from agent_dna.decision_record import build_record

    db = tmp_path / "pv.db"
    store = SQLiteDecisionStore(db)
    a = _act()
    r1 = build_record(a, _res(a), parent_decision=None, prev_hash="0" * 64)
    assert store.append_atomic(r1)

    dup = build_record(
        a, _res(a), parent_decision=r1.decision_id, prev_hash=r1.record_hash
    )
    dup.decision_id = r1.decision_id  # forge duplicate id
    dup.seal()
    with pytest.raises(ValueError, match="duplicate record id"):
        store.append_atomic(dup)
