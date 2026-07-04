"""
Enforcement wiring tests for the streaming runtime.

These exist because of a prior incident where refusal receipts showed
executed:True — the enforcement and evidence layers had come apart.
The streaming monitor must be an enforcing path, not an advisory one.
"""

import time

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.runtime import RuntimeMonitor
from agent_dna.trace import AgentAction


class StubScorer:
    """Returns a fixed drift score."""

    def __init__(self, drift: float = 0.0):
        self.drift = drift

    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=self.drift,
            severity=Severity.INFO,
            reasons=[],
        )


class StubInvariants:
    """Violates only for a named capability."""

    def __init__(self, forbidden: str):
        self.forbidden = forbidden

    def validate(self, capability, previous):
        class R:
            pass
        r = R()
        r.violated = capability == self.forbidden
        r.message = (
            f"invariant: {capability} forbidden"
            if r.violated else ""
        )
        return r


class StubAuthorizer:
    def __init__(self, granted: set):
        self.granted = granted

    def is_authorized(self, agent_id, capability):
        return capability in self.granted


def _action(cap: str) -> AgentAction:
    return AgentAction(
        agent_id="agent-1",
        capability=cap,
        timestamp=time.time(),
    )


def _monitor(drift=0.0, forbidden="wire.drain", granted=None):
    granted = granted if granted is not None else {"crm.read", "email.send"}
    engine = DecisionEngine(
        scorer=StubScorer(drift),
        invariants=StubInvariants(forbidden),
        authorizer=StubAuthorizer(granted),
        drift_threshold=0.50,
    )
    return RuntimeMonitor(engine)


def test_streaming_path_blocks_invariant_violation():
    m = _monitor()
    result = m.process(_action("wire.drain"))
    assert result.decision == Decision.BLOCK
    assert result.triggered_by == "invariant"
    assert len(m.blocked_events()) == 1


def test_streaming_path_requires_approval_for_ungranted_capability():
    m = _monitor()
    result = m.process(_action("payments.initiate"))
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "authorization"


def test_streaming_path_requires_approval_on_drift():
    m = _monitor(drift=0.80)
    result = m.process(_action("crm.read"))
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "drift"


def test_streaming_path_allows_normal_behavior():
    m = _monitor()
    result = m.process(_action("crm.read"))
    assert result.decision == Decision.ALLOW
    assert result.triggered_by == "baseline"


def test_blocked_action_does_not_advance_behavioral_state():
    """A rejected probe must not shift the baseline."""
    m = _monitor()

    m.process(_action("crm.read"))          # ALLOW
    assert m.previous_capability == "crm.read"

    m.process(_action("wire.drain"))         # BLOCK
    assert m.previous_capability == "crm.read", (
        "BLOCKed action advanced previous_capability — "
        "rejected probes can walk the invariant chain"
    )

    m.process(_action("payments.initiate"))  # REQUIRE_APPROVAL
    assert m.previous_capability == "crm.read"


def test_every_event_carries_a_decision():
    m = _monitor()
    m.process(_action("crm.read"))
    m.process(_action("wire.drain"))
    for e in m.events:
        assert e.decision is not None
        assert e.decision.decision in (
            Decision.ALLOW,
            Decision.BLOCK,
            Decision.REQUIRE_APPROVAL,
        )
