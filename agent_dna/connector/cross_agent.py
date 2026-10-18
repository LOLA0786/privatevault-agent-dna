"""
Cross-agent invariant enforcement (CABI) for the connector and HTTP API.

Escalation-only post-decision check: after the precedence line
produces a verdict, declared-execution interaction windows are
validated against the InvariantEngine. A violating window can
ESCALATE the verdict (allow -> block/require_approval,
require_approval -> block) and can never relax one — identical
escalation semantics to drift.

Scope, stated honestly:
  * Correlation is DECLARED: calls must carry context["execution_id"]
    to participate. Uncorrelated calls get no cross-agent evaluation
    (they still get the full precedence line + breakers).
  * Roles and tool targets are DECLARED config, not inferred.
  * Attempted-but-blocked calls enter the window: an attempted
    forbidden interaction is signal, not noise.
  * Production default attaches definitional dual-control + structural
    approval invariants (no corpus required).
  * Windows live in this process by default; a ``window_store`` (e.g.
    PostgreSQL) shares them across every API instance with the same
    bounds (events per execution, LRU executions).
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Protocol

from agent_dna.identity import fold_agent_id

from ..advisory import Severity
from ..control_posture import CROSS_AGENT_EXECUTION_ID_REQUIRED
from ..decision import Decision, DecisionResult
from ..multi_agent import InteractionEvent
from ..multi_agent.base import Verdict as CabiVerdict
from ..multi_agent.dual_control import is_approve_intent, is_initiate_intent
from ..multi_agent.invariant_engine import EngineVerdict
from ..multi_agent.runtime_validator import RuntimeValidator, definitional_engine


@dataclass(frozen=True)
class CrossAgentConfig:
    agent_roles: dict[str, str] = field(default_factory=dict)
    # capability (exact or prefix before '.') -> (target, target_role)
    tool_targets: dict[str, tuple[str, str]] = field(default_factory=dict)
    max_window_events: int = 500  # per execution, memory bound
    max_executions: int = 1000  # LRU-evicted beyond this


_DEFAULT_TOOL_TARGETS: dict[str, tuple[str, str]] = {
    "payments": ("payment_rail", "rail"),
    "treasury": ("payment_rail", "rail"),
    "crm": ("crm", "system"),
    "email": ("email", "system"),
}


class WindowStore(Protocol):
    """Execution windows: the recent interaction events per execution."""

    def window(self, execution_id: str) -> list[InteractionEvent]:
        """The current window of one execution, oldest first."""

    def append(
        self,
        event: InteractionEvent,
        *,
        max_window_events: int,
        max_executions: int,
    ) -> list[InteractionEvent]:
        """Append, apply both bounds, return the window after appending."""


class InMemoryWindows:
    def __init__(self) -> None:
        self._windows: OrderedDict[str, list[InteractionEvent]] = OrderedDict()
        self._lock = threading.Lock()  # executions span agents; the
        # per-agent middleware locks cannot protect a shared window

    def window(self, execution_id: str) -> list[InteractionEvent]:
        with self._lock:
            return list(self._windows.get(execution_id, []))

    def append(
        self,
        event: InteractionEvent,
        *,
        max_window_events: int,
        max_executions: int,
    ) -> list[InteractionEvent]:
        with self._lock:
            window = self._windows.setdefault(event.execution_id, [])
            window.append(event)
            if len(window) > max_window_events:
                del window[0]
            self._windows.move_to_end(event.execution_id)
            while len(self._windows) > max_executions:
                self._windows.popitem(last=False)
            return list(window)


def production_cross_agent(
    config: CrossAgentConfig | None = None,
    *,
    require_execution_id: bool = False,
    window_store: WindowStore | None = None,
) -> CrossAgentEnforcer:
    """Definitional CABI attached by default in production composition."""
    cfg = config or CrossAgentConfig(tool_targets=dict(_DEFAULT_TOOL_TARGETS))
    if not cfg.tool_targets:
        cfg = CrossAgentConfig(
            agent_roles=cfg.agent_roles,
            tool_targets=dict(_DEFAULT_TOOL_TARGETS),
            max_window_events=cfg.max_window_events,
            max_executions=cfg.max_executions,
        )
    return CrossAgentEnforcer(
        RuntimeValidator(definitional_engine()),
        config=cfg,
        require_execution_id=require_execution_id,
        window_store=window_store,
    )


class CrossAgentEnforcer:
    def __init__(
        self,
        validator: RuntimeValidator,
        config: CrossAgentConfig | None = None,
        *,
        require_execution_id: bool = False,
        window_store: WindowStore | None = None,
    ) -> None:
        self.validator = validator
        self.config = config or CrossAgentConfig()
        self.require_execution_id = require_execution_id
        self.windows: WindowStore = (
            window_store if window_store is not None else InMemoryWindows()
        )

    def requires_execution_id_for(self, capability: str) -> bool:
        """True when operator require-mode is on and capability is in
        declared tool_targets (exact or configured prefix key)."""
        if not self.require_execution_id:
            return False
        tt = self.config.tool_targets
        if capability in tt:
            return True
        prefix = capability.split(".", 1)[0]
        return prefix in tt

    def _target_for(self, capability: str) -> tuple[str, str]:
        tt = self.config.tool_targets
        if capability in tt:
            return tt[capability]
        prefix = capability.split(".", 1)[0]
        if prefix in tt:
            return tt[prefix]
        return (prefix or "unknown", "unknown")

    def observe(
        self, execution_id: str, agent_id: str, capability: str
    ) -> EngineVerdict | None:
        """Append this call's interaction event to its execution
        window and validate the window. Returns the EngineVerdict
        (never raises into the caller's decision path — the
        middleware's fault handler owns exceptions)."""
        # One identity per agent regardless of case or Unicode form, so
        # "Maker" cannot approve what "maker" initiated.
        raw_agent_id = agent_id
        agent_id = fold_agent_id(agent_id)
        target, target_role = self._target_for(capability)
        approval = is_approve_intent(capability)
        if approval:
            prior = self.windows.window(execution_id)
            self_initiated = any(
                e.source == agent_id and is_initiate_intent(e.intent) for e in prior
            )
            other_initiators = [
                e.source
                for e in prior
                if e.source != agent_id and is_initiate_intent(e.intent)
            ]
            if self_initiated:
                target = agent_id
                target_role = self.config.agent_roles.get(raw_agent_id, "unknown")
            elif other_initiators:
                target = other_initiators[-1]
                target_role = self.config.agent_roles.get(target, target_role)

        event = InteractionEvent(
            execution_id=execution_id,
            source=agent_id,
            target=target,
            source_role=self.config.agent_roles.get(raw_agent_id, "unknown"),
            target_role=target_role,
            timestamp=time.time(),
            intent=capability,
            approval=approval,
            metadata={"is_signoff": True} if approval else {},
        )
        snapshot = self.windows.append(
            event,
            max_window_events=self.config.max_window_events,
            max_executions=self.config.max_executions,
        )
        return self.validator.validate_events(snapshot)


_ESCALATION_RANK = {"allow": 0, "require_approval": 1, "block": 2}


def escalate_with_cross_agent(
    enforcer: CrossAgentEnforcer | None,
    *,
    execution_id: str | None,
    agent_id: str,
    capability: str,
    result: DecisionResult,
) -> DecisionResult:
    """Shared CABI escalate for HTTP and connector. Never relaxes.

    When the operator enables require-execution-id mode, a missing
    execution_id for a declared tool-target capability fails closed.
    Callers cannot disable that mode.
    """
    if enforcer is not None and enforcer.requires_execution_id_for(capability):
        if not execution_id:
            return DecisionResult(
                decision=Decision.BLOCK,
                triggered_by="cross_agent_correlation",
                reason=(
                    f"{CROSS_AGENT_EXECUTION_ID_REQUIRED}: capability "
                    f"{capability!r} requires a declared execution_id "
                    f"(PV_CROSS_AGENT_REQUIRE_EXECUTION_ID)"
                ),
                capability=capability,
                agent_id=agent_id,
                drift_score=result.drift_score,
                severity=Severity.CRITICAL,
                advisory_reasons=list(result.advisory_reasons),
                evidence=result.evidence,
                grant_id=result.grant_id,
            )

    if enforcer is None or not execution_id:
        return result
    engine_verdict = enforcer.observe(execution_id, agent_id, capability)
    if engine_verdict is None or engine_verdict.verdict is CabiVerdict.ALLOW:
        return result
    target = (
        Decision.BLOCK
        if engine_verdict.verdict is CabiVerdict.BLOCK
        else Decision.REQUIRE_APPROVAL
    )
    if _ESCALATION_RANK[target.value] <= _ESCALATION_RANK[result.decision.value]:
        return result
    return DecisionResult(
        decision=target,
        triggered_by="cross_agent_invariant",
        reason="; ".join(engine_verdict.reasons)
        or (
            f"cross-agent invariant verdict {engine_verdict.verdict.value} "
            f"(score={engine_verdict.score:.3f})"
        ),
        capability=capability,
        agent_id=agent_id,
        drift_score=result.drift_score,
        severity=(Severity.CRITICAL if target is Decision.BLOCK else result.severity),
        advisory_reasons=list(result.advisory_reasons),
        evidence=result.evidence,
        grant_id=result.grant_id,
    )
