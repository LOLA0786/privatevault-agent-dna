"""Shared DRP 0.2 decide bindings for API tests.

Mintable decisions require derive-only ``execution_action`` and
``dispatch_context``. Digests are computed server-side; callers must not
supply them.
"""

from __future__ import annotations

import time
from typing import Any

DEFAULT_DISPATCH_CONTEXT: dict[str, str] = {
    "adapter": "https",
    "transport": "https",
    "operation": "GET /v1/resource",
    "destination": "example.test",
    "wire_content_type": "application/json",
}


def execution_action_for(
    agent_id: str,
    capability: str,
    arguments: dict[str, Any] | None = None,
    *,
    resource: str = "resource:default",
    org: str = "test.example",
    subject_principal: str | None = None,
) -> dict[str, Any]:
    return {
        "subject_principal": subject_principal or f"{agent_id}@{org}",
        "subject_key_id": agent_id,
        "action": capability,
        "resource": resource,
        "parameters": dict(arguments or {}),
    }


def dispatch_context_for(**overrides: str) -> dict[str, str]:
    ctx = dict(DEFAULT_DISPATCH_CONTEXT)
    ctx.update(overrides)
    return ctx


def decide_json(
    agent_id: str,
    capability: str,
    *,
    arguments: dict[str, Any] | None = None,
    timestamp: float | None = None,
    resource: str = "resource:default",
    org: str = "test.example",
    dispatch_context: dict[str, str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build a complete ``POST /v1/decide`` JSON body."""
    args = dict(arguments or {})
    body: dict[str, Any] = {
        "agent_id": agent_id,
        "capability": capability,
        "timestamp": time.time() if timestamp is None else timestamp,
        "arguments": args,
        "execution_action": execution_action_for(
            agent_id,
            capability,
            args,
            resource=resource,
            org=org,
        ),
        "dispatch_context": (
            dict(dispatch_context)
            if dispatch_context is not None
            else dispatch_context_for()
        ),
    }
    body.update(extra)
    return body
