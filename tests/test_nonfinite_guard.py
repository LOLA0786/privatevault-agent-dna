"""Non-finite floats must not seal -- Python mirror of the Rust guard.

Before this guard, json.dumps happily emitted a bare NaN token: the
record verified inside Python but was invalid JSON to every strict
parser (Rust runtime, jq, external auditors) -- silent audit-trail
corruption. Now sealing raises, and inside decide() that exception
lands in the existing fail-closed path => deterministic BLOCK.
"""

import math

import pytest

from agent_dna.decision_record import DRP_V01, DecisionRecord
from agent_dna.execution_record import ExecutionEvent


def _record(drift):
    return DecisionRecord(
        protocol_version=DRP_V01,
        decision_id="d-nan",
        parent_decision=None,
        agent_id="a",
        capability="x",
        decision="allow",
        triggered_by="drift",
        reason="",
        severity="none",
        drift_score=drift,
        evidence=[],
        evidence_strength=0.0,
        arguments_digest="",
        outcome="pending",
    )


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_decision_record_nonfinite_drift_cannot_seal(bad):
    with pytest.raises(ValueError):
        _record(bad).seal()


def test_finite_record_still_seals_and_verifies():
    rec = _record(0.9).seal()
    assert rec.verify()


def test_execution_event_nonfinite_timestamp_cannot_seal():
    ev = ExecutionEvent(
        event_id="e-nan",
        agent_id="a",
        decision_ref="d-1",
        status="ok",
        detail="",
        edges=[],
        timestamp=math.inf,
        prev_hash="0" * 64,
    )
    with pytest.raises(ValueError):
        ev.seal()
