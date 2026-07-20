"""
ConnectorMiddleware — the single enforcement path for every harness.

    adapter -> ToolCallRequest
        -> identity (ApiKeyRegistry, scope must satisfy "full";
           an audit-scoped key must NEVER exercise enforcement)
        -> AgentAction
        -> RuntimeMonitor.process (GuardedEngine: breaker pre-gate,
           then the L0..L6 precedence line; recorded + signed)
        -> ToolCallVerdict carrying the chain record_hash

Fail-closed at every layer:
  * missing/invalid/audit-scoped key  -> BLOCK, trigger=identity
  * any exception in the connector    -> BLOCK, trigger=connector_fault
  * engine faults already BLOCK inside decide() (engine_fault)

Identity refusals are deliberately NOT written to the decision
chain: there is no authenticated agent to attribute them to, and
unauthenticated traffic must not be able to write to the evidence
store. They surface in the returned verdict only.
"""

from __future__ import annotations

import threading
from typing import Dict, Optional

from ..apikeys import ApiKeyRegistry
from ..decision import Decision, DecisionResult, Severity
from ..multi_agent import Verdict as CabiVerdict
from ..runtime import RuntimeMonitor
from ..trace import AgentAction
from .models import ToolCallRequest, ToolCallVerdict

import time


class ConnectorMiddleware:
    def __init__(self, engine, recorder, keys: ApiKeyRegistry,
                 cross_agent=None, shadow=None) -> None:
        """engine: GuardedEngine (or DecisionEngine-compatible).
        recorder: DecisionRecorder — required, the verdict must carry
        a chain record_hash. keys: ApiKeyRegistry with enabled=True;
        a disabled registry is refused loudly rather than silently
        open."""
        if recorder is None:
            raise ValueError("ConnectorMiddleware requires a recorder")
        if not keys.enabled:
            raise ValueError(
                "ConnectorMiddleware requires an enabled ApiKeyRegistry "
                "(set PV_API_KEYS_FILE); refusing to run open"
            )
        self.engine = engine
        self.recorder = recorder
        self.keys = keys
        self.cross_agent = cross_agent   # optional CrossAgentEnforcer
        self.shadow = shadow
        self._monitors: Dict[str, RuntimeMonitor] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._registry_lock = threading.Lock()

    # -- per-agent monitor: mirrors api/server.py _monitor_for --------

    def _monitor_for(self, agent_id: str) -> tuple:
        with self._registry_lock:
            if agent_id not in self._monitors:
                # recorder=None: the middleware records explicitly below
                # and needs record()'s return value (the DecisionRecord).
                # Letting the monitor record would discard it, forcing a
                # fragile graph lookup that BREAKS under multi_writer_safe
                # recorders (the in-memory graph is not populated there;
                # the store is the truth). Found by
                # tests/connector/test_multi_agent_isolation.py.
                self._monitors[agent_id] = RuntimeMonitor(
                    self.engine, recorder=None
                )
                self._locks[agent_id] = threading.Lock()
            return self._monitors[agent_id], self._locks[agent_id]

    # -- the one path --------------------------------------------------

    def handle(self, request: ToolCallRequest) -> ToolCallVerdict:
        try:
            return self._handle_unsafe(request)
        except Exception as exc:
            return ToolCallVerdict(
                decision="block",
                triggered_by="connector_fault",
                reason=f"{type(exc).__name__}: {exc}",
                agent_id=None,
                record_hash=None,
            )

    def _handle_unsafe(self, request: ToolCallRequest) -> ToolCallVerdict:
        agent_id = self.keys.verify_scope(request.api_key, "full")
        if agent_id is None:
            return ToolCallVerdict(
                decision="block",
                triggered_by="identity",
                reason=(
                    "no valid full-scope API key presented; "
                    "audit-scoped keys cannot exercise enforcement"
                ),
                agent_id=None,
                record_hash=None,
            )

        action = AgentAction(
            agent_id=agent_id,
            capability=request.tool,
            timestamp=time.time(),
            arguments=dict(request.arguments),
            context={"adapter": request.adapter, **request.context},
        )

        monitor, lock = self._monitor_for(agent_id)
        with lock:
            result = monitor.process(action, evidence=request.evidence)
            result = self._cross_agent_escalate(request, agent_id, result)
            rec = self.recorder.record(action, result)
            if self.shadow is not None:
                try:
                    self.shadow.observe(action, result, request.evidence)
                except Exception:
                    pass  # shadow is diagnostic; cannot break enforcement

        return ToolCallVerdict(
            decision=result.decision.value,
            triggered_by=result.triggered_by,
            reason=result.reason,
            agent_id=agent_id,
            record_hash=rec.record_hash,
            signed=rec.record_hash in self.recorder.envelopes,
        )

    # -- cross-agent invariants: escalation-only ------------------------

    _ESCALATION_RANK = {"allow": 0, "require_approval": 1, "block": 2}

    def _cross_agent_escalate(self, request, agent_id, result):
        """CABI can only escalate a verdict, never relax one. Calls
        without a declared execution_id are not evaluated (documented
        scope: cross-agent invariants require declared correlation).
        Attempted-but-blocked calls still enter the window."""
        if self.cross_agent is None:
            return result
        execution_id = (request.context or {}).get("execution_id")
        if not execution_id:
            return result
        engine_verdict = self.cross_agent.observe(
            execution_id, agent_id, request.tool
        )
        if engine_verdict.verdict is CabiVerdict.ALLOW:
            return result
        target = (
            Decision.BLOCK
            if engine_verdict.verdict is CabiVerdict.BLOCK
            else Decision.REQUIRE_APPROVAL
        )
        if (self._ESCALATION_RANK[target.value]
                <= self._ESCALATION_RANK[result.decision.value]):
            return result                # never relax
        return DecisionResult(
            decision=target,
            triggered_by="cross_agent_invariant",
            reason="; ".join(engine_verdict.reasons)
                   or f"cross-agent invariant verdict "
                      f"{engine_verdict.verdict.value} "
                      f"(score={engine_verdict.score:.3f})",
            capability=request.tool,
            agent_id=agent_id,
            drift_score=result.drift_score,
            severity=(Severity.CRITICAL if target is Decision.BLOCK
                      else result.severity),
            advisory_reasons=list(result.advisory_reasons),
        )
