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
* That state can live outside the process (``state=``, e.g. PostgreSQL),
  so every API instance scores an agent against the same baseline.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Protocol

from .advisory import AdvisorySignal
from .circuit_breaker import GuardedEngine
from .decision import Decision, DecisionEngine, DecisionResult
from .observability.metrics import MetricsExporter
from .shell_guard import (
    attach_shell_evidence,
    attach_shell_record_item,
    escalate_with_shell,
)
from .trace import AgentAction


@dataclass
class RuntimeEvent:
    action: AgentAction
    advisory: AdvisorySignal
    decision: DecisionResult


class AgentState(Protocol):
    """Where one agent's behavioural baseline is kept."""

    def get(self) -> str | None:
        """The last capability this agent was allowed to run, if any."""

    def set(self, capability: str | None) -> None:
        """Record the new baseline (called only after an ALLOW)."""


class _LocalState:
    def __init__(self) -> None:
        self._value: str | None = None

    def get(self) -> str | None:
        return self._value

    def set(self, capability: str | None) -> None:
        self._value = capability


class RuntimeMonitor:
    """Owns the DecisionEngine. The streaming path IS the enforcing path.

    ``state`` keeps the agent's baseline (default: this object's memory).
    ``max_events`` bounds the in-memory event history; a long-running
    server must set it, or the history grows with every decision.
    """

    def __init__(
        self,
        engine: DecisionEngine | GuardedEngine,
        recorder=None,
        *,
        state: AgentState | None = None,
        max_events: int | None = None,
    ) -> None:
        if engine.scorer is None:
            raise ValueError("RuntimeMonitor requires a DecisionEngine with a scorer")
        self.engine = engine
        self.recorder = recorder  # optional DecisionRecorder; never required
        self.metrics = MetricsExporter()
        self._state: AgentState = state if state is not None else _LocalState()
        self.events: deque[RuntimeEvent] = deque(maxlen=max_events)

    @property
    def previous_capability(self) -> str | None:
        return self._state.get()

    @previous_capability.setter
    def previous_capability(self, capability: str | None) -> None:
        self._state.set(capability)

    def process(
        self,
        action: AgentAction,
        evidence: dict | None = None,
        *,
        approval: object = None,
        approval_context: object = None,
    ) -> DecisionResult:
        # ADR 0020 keywords travel only when an approval is presented, so an
        # engine with the plain .decide contract keeps working.
        extra: dict[str, object] = (
            {"approval": approval, "approval_context": approval_context}
            if approval is not None
            else {}
        )
        # Shell guard: evidence.shell is derived here from the action's own
        # arguments (never caller-authored), then any finding escalates.
        evidence = attach_shell_evidence(action.capability, action.arguments, evidence)
        previous = self.previous_capability  # read once: one baseline per decision
        result = self.engine.decide(action, previous, evidence=evidence, **extra)
        result = escalate_with_shell(result, (evidence or {}).get("shell"))
        result = attach_shell_record_item(result, (evidence or {}).get("shell"))

        # decide() already scored internally and is itself fail-closed.
        # Rebuild the advisory for the event record too, but never let
        # a second, redundant scoring call bypass fail-closed behavior
        # that decide() already enforced.
        try:
            signal = self.engine.scorer.score(action, previous)
        except Exception:
            # decide() already produced the authoritative (fault-closed)
            # result above; the advisory rebuild is best-effort only.
            signal = AdvisorySignal(
                agent_id=action.agent_id,
                capability=action.capability,
                drift_score=result.drift_score,
                severity=result.severity,
                reasons=list(result.advisory_reasons),
            )

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

        self.metrics.record(result.decision.value, result.drift_score, result.reason)

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

    def blocked_events(self) -> list[RuntimeEvent]:
        return [e for e in self.events if e.decision.decision == Decision.BLOCK]

    def approval_events(self) -> list[RuntimeEvent]:
        return [
            e for e in self.events if e.decision.decision == Decision.REQUIRE_APPROVAL
        ]

    def critical_events(self) -> list[RuntimeEvent]:
        return [e for e in self.events if e.advisory.severity.value == "critical"]
