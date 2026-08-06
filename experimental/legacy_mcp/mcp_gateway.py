"""
MCP-facing gateway over the composed decision line.

Contains the actual logic — testable directly, no MCP transport
needed. agent_dna/mcp_server.py wraps these methods as MCP tools via
FastMCP; it decorates, it does not duplicate.

One RuntimeMonitor per agent_id (same pattern as api/server.py),
so behavioral baselines and precedence state stay isolated per agent.
"""

from __future__ import annotations

import time
from typing import Any

from .decision import DecisionEngine
from .decision_recorder import DecisionRecorder
from .runtime import RuntimeMonitor
from .trace import AgentAction


class MCPGateway:
    def __init__(self, engine: DecisionEngine, recorder: DecisionRecorder) -> None:
        self.engine = engine
        self.recorder = recorder
        self._monitors: dict[str, RuntimeMonitor] = {}

    def _monitor_for(self, agent_id: str) -> RuntimeMonitor:
        if agent_id not in self._monitors:
            self._monitors[agent_id] = RuntimeMonitor(
                self.engine, recorder=self.recorder
            )
        return self._monitors[agent_id]

    def decide(
        self,
        agent_id: str,
        capability: str,
        arguments: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
        timestamp: float | None = None,
    ) -> dict[str, Any]:
        action = AgentAction(
            agent_id=agent_id,
            capability=capability,
            timestamp=timestamp if timestamp is not None else time.time(),
            arguments=arguments or {},
        )
        monitor = self._monitor_for(agent_id)
        result = monitor.process(action, evidence=evidence)
        rec = self.recorder.graph.find_by_agent(agent_id)[-1]
        return {
            "decision": result.decision.value,
            "triggered_by": result.triggered_by,
            "reason": result.reason,
            "decision_id": rec.decision_id,
            "record_hash": rec.record_hash,
        }

    def report_outcome(
        self, decision_id: str, status: str, detail: str = ""
    ) -> dict[str, Any]:
        event = self.recorder.report_outcome(decision_id, status, detail)
        return event.to_dict()

    def verify(self) -> dict[str, bool]:
        return self.recorder.graph.verify_all()

    def lineage(self, decision_id: str) -> list[dict[str, Any]]:
        path = self.recorder.graph.lineage(decision_id)
        return [r.to_dict() for r in path]

    def blocked(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.recorder.graph.find_blocked()]

    def divergent(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.recorder.graph.find_divergent()]
