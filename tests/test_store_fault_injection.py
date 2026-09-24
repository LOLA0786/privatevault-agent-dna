"""Fault injection at the evidence store's transaction boundaries.

A failure part-way through a write must (1) propagate, (2) roll back so
no partial row can ever be committed later, and (3) leave the store
usable. The connection proxy raises on one chosen SQL statement.
"""

import sqlite3

import pytest

from agent_dna.advisory import Severity
from agent_dna.decision import Decision, DecisionResult
from agent_dna.decision_record import GENESIS_HASH, build_record
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction

ENVELOPE = {"alg": "ed25519", "sig": "00"}
TS = "2026-09-24T00:00:00Z"


class FaultyConn:
    """Delegates to a real connection; raises once on a statement containing `fail_on`."""

    def __init__(self, real, fail_on, *, rollback_enabled=True):
        self.real, self.fail_on, self.rollback_enabled = real, fail_on, rollback_enabled
        self.rollbacks, self.fired = 0, False

    def execute(self, sql, *args):
        if not self.fired and self.fail_on in sql:
            self.fired = True
            raise sqlite3.OperationalError("injected: disk I/O error")
        return self.real.execute(sql, *args)

    def rollback(self):
        self.rollbacks += 1
        if self.rollback_enabled:
            self.real.rollback()

    def __getattr__(self, name):
        return getattr(self.real, name)


def _inject(store, fail_on, **kw):
    real = store._conn
    faulty = FaultyConn(real, fail_on, **kw)
    store._local.conn = faulty
    return real, faulty


def _record(agent="agent-1"):
    action = AgentAction(
        agent_id=agent,
        capability="payments.transfer",
        timestamp=1000.0,
        arguments={"amount": 10},
        context={},
    )
    result = DecisionResult(
        decision=Decision.ALLOW,
        triggered_by="baseline",
        reason="ok",
        capability="payments.transfer",
        agent_id=agent,
        drift_score=0.0,
        severity=Severity.INFO,
    )
    rec = build_record(
        action,
        result,
        parent_decision=None,
        prev_hash=GENESIS_HASH,
        anchor_hash=None,
        request_id=None,
    )
    return rec, rec.to_dict()


def test_envelope_insert_failure_rolls_back_the_record(tmp_path):
    path = tmp_path / "s.db"
    store = SQLiteDecisionStore(path)
    rec, d = _record()
    real, faulty = _inject(store, "INSERT INTO envelopes")
    with pytest.raises(sqlite3.OperationalError, match="injected"):
        store.append(rec, ENVELOPE)
    assert faulty.rollbacks == 1
    real.commit()  # a later commit on the same connection must not resurrect the half-write
    fresh = SQLiteDecisionStore(path)
    assert fresh.get_decision(d["decision_id"]) is None
    assert fresh.get_envelope(d["record_hash"]) is None
    store._local.conn = real
    store.append(rec, ENVELOPE)  # usable: no transaction left open
    assert SQLiteDecisionStore(path).get_envelope(d["record_hash"]) is not None


def test_negative_control_without_rollback_a_half_write_survives(tmp_path):
    path = tmp_path / "s.db"
    store = SQLiteDecisionStore(path)
    rec, d = _record()
    real, _ = _inject(store, "INSERT INTO envelopes", rollback_enabled=False)
    with pytest.raises(sqlite3.OperationalError):
        store.append(rec, ENVELOPE)
    real.commit()
    fresh = SQLiteDecisionStore(path)
    assert fresh.get_decision(d["decision_id"]) is not None  # record persisted...
    assert fresh.get_envelope(d["record_hash"]) is None  # ...without its signature


def test_consume_failure_does_not_burn_the_authorization(tmp_path):
    store = SQLiteDecisionStore(tmp_path / "s.db")
    real, faulty = _inject(store, "INSERT INTO execution_authorization_consume")
    with pytest.raises(sqlite3.OperationalError, match="injected"):
        store.try_consume_execution_authorization(
            "ea-1", organisation_id="org", consumed_at=TS
        )
    assert faulty.rollbacks == 1
    store._local.conn = real
    assert store.is_execution_authorization_consumed("ea-1") is False
    assert (
        store.try_consume_execution_authorization(
            "ea-1", organisation_id="org", consumed_at=TS
        )
        is True
    )
    assert (
        store.try_consume_execution_authorization(
            "ea-1", organisation_id="org", consumed_at=TS
        )
        is False
    )
