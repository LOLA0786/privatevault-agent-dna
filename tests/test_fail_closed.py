"""Fail-closed hardening: any exception inside decide() must produce
a deterministic BLOCK, never propagate and never silently ALLOW.

Motivation: a buggy scorer, invariant checker, authorizer, or UAAL
evidence source should not be able to crash the request (denial of
enforcement) or, worse, let an action through by accident.
"""

import time

from agent_dna.decision import Decision, DecisionEngine
from agent_dna.trace import AgentAction


class RaisingScorer:
    def score(self, action, prev_capability=None):
        raise RuntimeError("scorer blew up")


class RaisingInvariants:
    def validate(self, capability, previous):
        raise ValueError("invariant checker blew up")


class RaisingAuthorizer:
    def is_authorized(self, agent_id, capability):
        raise KeyError("authorizer blew up")


class RaisingUAAL:
    def check(self, action, evidence):
        raise TypeError("uaal checker blew up")


def _act():
    return AgentAction(agent_id="a1", capability="crm.read", timestamp=time.time())


def test_raising_scorer_fails_closed():
    engine = DecisionEngine(scorer=RaisingScorer())
    result = engine.decide(_act())
    assert result.decision == Decision.BLOCK
    assert result.triggered_by == "engine_fault"
    assert "scorer blew up" in result.reason


def test_raising_invariants_fails_closed():
    from agent_dna.advisory import AdvisorySignal, Severity

    class OKScorer:
        def score(self, action, prev_capability=None):
            return AdvisorySignal(
                agent_id=action.agent_id,
                capability=action.capability,
                drift_score=0.0,
                severity=Severity.INFO,
                reasons=[],
            )

    engine = DecisionEngine(scorer=OKScorer(), invariants=RaisingInvariants())
    result = engine.decide(_act())
    assert result.decision == Decision.BLOCK
    assert result.triggered_by == "engine_fault"


def test_raising_authorizer_fails_closed():
    from agent_dna.advisory import AdvisorySignal, Severity

    class OKScorer:
        def score(self, action, prev_capability=None):
            return AdvisorySignal(
                agent_id=action.agent_id,
                capability=action.capability,
                drift_score=0.0,
                severity=Severity.INFO,
                reasons=[],
            )

    engine = DecisionEngine(scorer=OKScorer(), authorizer=RaisingAuthorizer())
    result = engine.decide(_act())
    assert result.decision == Decision.BLOCK
    assert result.triggered_by == "engine_fault"


def test_raising_uaal_fails_closed():
    from agent_dna.advisory import AdvisorySignal, Severity

    class OKScorer:
        def score(self, action, prev_capability=None):
            return AdvisorySignal(
                agent_id=action.agent_id,
                capability=action.capability,
                drift_score=0.0,
                severity=Severity.INFO,
                reasons=[],
            )

    engine = DecisionEngine(scorer=OKScorer(), uaal=RaisingUAAL())
    result = engine.decide(_act())
    assert result.decision == Decision.BLOCK
    assert result.triggered_by == "engine_fault"


def test_fault_result_is_still_a_valid_sealable_record():
    """A fault-path result must serialize and seal exactly like any
    other decision — the audit trail doesn't get a special case."""
    from agent_dna.decision_record import build_record

    engine = DecisionEngine(scorer=RaisingScorer())
    result = engine.decide(_act())
    rec = build_record(_act(), result)
    assert rec.verify()
    assert rec.decision == "block"
