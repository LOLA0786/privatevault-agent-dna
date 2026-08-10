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
import time

from ..apikeys import ApiKeyRegistry
from ..authority_v01 import AuthorityFormatError, canonicalize
from ..runtime import RuntimeMonitor
from ..trace import AgentAction
from .models import ToolCallRequest, ToolCallVerdict


def _authority_safe_parameters(arguments: dict) -> dict:
    """Project tool arguments into authority-canonicalizable parameters.

    Integer-valued floats become ints (JSON number ambiguity). Other
    floats refuse minting — floating point is forbidden in authority
    artifacts. Engine/UAAL still see the original ``AgentAction.arguments``.
    """

    def convert(value):
        if isinstance(value, float):
            if value.is_integer() and abs(value) <= 2**53:
                return int(value)
            raise AuthorityFormatError(
                "parameters: floating point is forbidden in authority artifacts"
            )
        if isinstance(value, dict):
            return {str(k): convert(v) for k, v in value.items()}
        if isinstance(value, list):
            return [convert(v) for v in value]
        return value

    out = convert(dict(arguments))
    canonicalize(out)
    return out


class ConnectorMiddleware:
    def __init__(
        self, engine, recorder, keys: ApiKeyRegistry, cross_agent=None, shadow=None
    ) -> None:
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
        self.cross_agent = cross_agent  # optional CrossAgentEnforcer
        self.shadow = shadow
        self._monitors: dict[str, RuntimeMonitor] = {}
        self._locks: dict[str, threading.Lock] = {}
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
                self._monitors[agent_id] = RuntimeMonitor(self.engine, recorder=None)
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

        ctx = dict(request.context or {})
        action = AgentAction(
            agent_id=agent_id,
            capability=request.tool,
            timestamp=time.time(),
            arguments=dict(request.arguments),
            context={"adapter": request.adapter, **ctx},
        )
        # Mintable DRP 0.2 binding for connector decisions.
        execution_action = {
            "subject_principal": str(ctx.get("subject_principal") or agent_id),
            "subject_key_id": agent_id,
            "action": request.tool,
            "resource": str(ctx.get("resource") or request.tool),
            "parameters": _authority_safe_parameters(dict(request.arguments)),
        }
        dispatch_context = {
            "adapter": request.adapter,
            "transport": str(ctx.get("transport") or request.adapter),
            "operation": request.tool,
            "destination": str(ctx.get("destination") or "local"),
            "wire_content_type": str(
                ctx.get("wire_content_type") or "application/json"
            ),
        }

        monitor, lock = self._monitor_for(agent_id)
        with lock:
            result = monitor.process(action, evidence=request.evidence)
            result = self._cross_agent_escalate(request, agent_id, result)
            from ..control_posture import (
                attach_control_posture,
                authorization_mode_of,
            )

            execution_id = (request.context or {}).get("execution_id")
            enforcer = self.cross_agent
            attach_control_posture(
                result,
                {
                    "authorization_mode": authorization_mode_of(
                        getattr(self.engine, "authorizer", None)
                    ),
                    "cross_agent_attached": enforcer is not None,
                    "cross_agent_require_execution_id": bool(
                        enforcer is not None
                        and getattr(enforcer, "require_execution_id", False)
                    ),
                    "cross_agent_correlated": bool(execution_id)
                    and enforcer is not None,
                },
            )

            rec = self.recorder.record(
                action,
                result,
                execution_action=execution_action,
                dispatch_context=dispatch_context,
            )
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

    def _cross_agent_escalate(self, request, agent_id, result):
        """CABI can only escalate a verdict, never relax one. Calls
        without a declared execution_id are not evaluated (documented
        scope: cross-agent invariants require declared correlation).
        Attempted-but-blocked calls still enter the window."""
        from .cross_agent import escalate_with_cross_agent

        return escalate_with_cross_agent(
            self.cross_agent,
            execution_id=(request.context or {}).get("execution_id"),
            agent_id=agent_id,
            capability=request.tool,
            result=result,
        )
