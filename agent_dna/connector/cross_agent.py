"""
Cross-agent invariant enforcement (CABI) for the connector.

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
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from ..multi_agent import InteractionEvent
from ..multi_agent.runtime_validator import RuntimeValidator


@dataclass(frozen=True)
class CrossAgentConfig:
    agent_roles: dict[str, str] = field(default_factory=dict)
    # capability (exact or prefix before '.') -> (target, target_role)
    tool_targets: dict[str, tuple[str, str]] = field(default_factory=dict)
    max_window_events: int = 500  # per execution, memory bound
    max_executions: int = 1000  # LRU-evicted beyond this


class CrossAgentEnforcer:
    def __init__(
        self,
        validator: RuntimeValidator,
        config: CrossAgentConfig | None = None,
    ) -> None:
        self.validator = validator
        self.config = config or CrossAgentConfig()
        self._windows: OrderedDict[str, list[InteractionEvent]] = OrderedDict()
        self._lock = threading.Lock()  # executions span agents; the
        # per-agent middleware locks
        # cannot protect a shared window

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
    ) -> object | None:
        """Append this call's interaction event to its execution
        window and validate the window. Returns the EngineVerdict
        (never raises into the caller's decision path — the
        middleware's fault handler owns exceptions)."""
        target, target_role = self._target_for(capability)
        event = InteractionEvent(
            execution_id=execution_id,
            source=agent_id,
            target=target,
            source_role=self.config.agent_roles.get(agent_id, "unknown"),
            target_role=target_role,
            timestamp=time.time(),
            intent=capability,
        )
        with self._lock:
            window = self._windows.setdefault(execution_id, [])
            window.append(event)
            if len(window) > self.config.max_window_events:
                del window[0]
            self._windows.move_to_end(execution_id)
            while len(self._windows) > self.config.max_executions:
                self._windows.popitem(last=False)
            snapshot = list(window)
        return self.validator.validate_events(snapshot)
