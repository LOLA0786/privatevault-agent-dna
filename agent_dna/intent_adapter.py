"""
AgentIntent <-> AgentAction adapter.

UAAL's SDKs and gate express actions as AgentIntent(actor_id, verb,
target, parameters, confidence). The composed decision line consumes
AgentAction. Mapping:

    actor_id             -> agent_id
    target.type + verb   -> capability ("payment.spend_money" style)
    parameters (+target) -> arguments
    confidence           -> context["confidence"]
"""

from __future__ import annotations

from typing import Any

from .trace import AgentAction


def intent_to_action(
    *,
    actor_id: str,
    verb: str,
    target: dict[str, Any] | None = None,
    parameters: dict[str, Any] | None = None,
    confidence: float | None = None,
    timestamp: float = 0.0,
) -> AgentAction:
    target = target or {}
    parameters = dict(parameters or {})
    namespace = target.get("type", "action")
    if "target" not in parameters and target.get("id") is not None:
        parameters["target"] = target["id"]
    context: dict[str, Any] = {}
    if confidence is not None:
        context["confidence"] = confidence
    return AgentAction(
        agent_id=actor_id,
        capability=f"{namespace}.{verb}",
        timestamp=timestamp,
        arguments=parameters,
        context=context,
    )
