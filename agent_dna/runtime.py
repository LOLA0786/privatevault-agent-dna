"""
Streaming Runtime Monitor.

Scores actions one at a time and maintains behavioral state for a live agent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .advisory import AdvisorySignal
from .scorer import DriftScorer
from .trace import AgentAction


@dataclass
class RuntimeEvent:
    action: AgentAction
    advisory: AdvisorySignal


class RuntimeMonitor:

    def __init__(self, scorer: DriftScorer) -> None:
        self.scorer = scorer
        self.previous_capability: Optional[str] = None
        self.events: List[RuntimeEvent] = []

    def process(
        self,
        action: AgentAction,
    ) -> AdvisorySignal:

        signal = self.scorer.score(
            action,
            self.previous_capability,
        )

        self.events.append(
            RuntimeEvent(
                action=action,
                advisory=signal,
            )
        )

        self.previous_capability = action.capability

        return signal

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

    def critical_events(self) -> List[RuntimeEvent]:
        return [
            e
            for e in self.events
            if e.advisory.severity.value == "critical"
        ]
