"""
Streaming Runtime Monitor.

Processes actions one at a time through the DecisionEngine and maintains
behavioral state for a live agent.

Enforcement invariants:
* Every processed action receives a DecisionResult (not just an advisory).
* Behavioral state (previous_capability) advances ONLY on ALLOW.
  Blocked / approval-pending actions never executed, so they must not
  shift the baseline — otherwise rejected probes could walk the
  invariant chain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .advisory import AdvisorySignal
from .decision import Decision, DecisionEngine, DecisionResult
from .trace import AgentAction


@dataclass
class RuntimeEvent:
    action: AgentAction
    advisory: AdvisorySignal
    decision: DecisionResult


class RuntimeMonitor:
    """Owns the DecisionEngine. The streaming path IS the enforcing path."""

    def __init__(self, engine: DecisionEngine, recorder=None) -> None:
        if engine.scorer is None:
            raise ValueError(
                "RuntimeMonitor requires a DecisionEngine with a scorer"
            )
        self.engine = engine
        self.recorder = recorder     # optional DecisionRecorder; never required
        self.previous_capability: Optional[str] = None
        self.events: List[RuntimeEvent] = []

    def process(
        self,
        action: AgentAction,
        evidence: dict | None = None,
    ) -> DecisionResult:
        result = self.engine.decide(
            action, self.previous_capability, evidence=evidence
        )

        # decide() already scored internally; rebuild the advisory once for
        # the event record so downstream consumers see what the engine saw.
        signal = self.engine.scorer.score(action, self.previous_capability)

        self.events.append(
            RuntimeEvent(
                action=action,
                advisory=signal,
                decision=result,
            )
        )

        if self.recorder is not None:
            self.recorder.record(action, result)

        # Behavioral state advances only when the action was allowed
        # to execute.
        if result.decision == Decision.ALLOW:
            self.previous_capability = action.capability

        return result

    def reset(self) -> None:
        self.previous_capability = None
        self.events.clear()

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def latest(self) -> RuntimeEvent | None:
        if not self.events:
            return None
        return self.events[-1]

    def blocked_events(self) -> List[RuntimeEvent]:
        return [
            e for e in self.events
            if e.decision.decision == Decision.BLOCK
        ]

    def approval_events(self) -> List[RuntimeEvent]:
        return [
            e for e in self.events
            if e.decision.decision == Decision.REQUIRE_APPROVAL
        ]

    def critical_events(self) -> List[RuntimeEvent]:
        return [
            e for e in self.events
            if e.advisory.severity.value == "critical"
        ]
