"""Tools and the clearance rule.

A tool declares its risk class. ``READ`` tools run locally without a
decision. ``EXTERNAL`` tools run locally only with a single-use clearance the
gate issues after an ALLOW for exactly these arguments. ``MONEY`` tools never
run locally at all: their effect is the sidecar dispatch of the permitted
bytes to a receiver gate, so ``execute`` is refused by construction.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RiskClass(StrEnum):
    READ = "read"
    EXTERNAL = "external"
    MONEY = "money"


class ClearanceRequiredError(PermissionError):
    """Executing a gated tool without a matching, unused clearance."""


@dataclass(frozen=True)
class ReceiverSpec:
    """Where a money tool's bytes go: the receiver gate's identity."""

    receiver_id: str
    destination: str
    operation: str
    tool_id: str

    @property
    def credential_audience(self) -> str:
        return self.receiver_id

    @property
    def method(self) -> str:
        return self.operation.split(None, 1)[0].upper()

    @property
    def path(self) -> str:
        return self.operation.split(None, 1)[1]


@dataclass
class Tool:
    name: str
    description: str
    capability: str
    risk: RiskClass
    # Local effect for READ and EXTERNAL tools. None for MONEY tools.
    execute: Callable[[dict[str, Any]], Any] | None = None
    # Enrich or normalise the model's arguments before they are decided and
    # sealed (for example resolve an invoice id into amount and payee). The
    # returned mapping is what PrivateVault decides on and what is dispatched.
    prepare: Callable[[dict[str, Any]], dict[str, Any]] | None = None
    resource: Callable[[dict[str, Any]], str] | None = None
    receiver: ReceiverSpec | None = None
    # name -> (json type, description), for the model's tool schema
    parameters: dict[str, tuple[str, str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.risk is RiskClass.MONEY and self.receiver is None:
            raise ValueError(f"money tool {self.name!r} needs a receiver")
        if self.risk is RiskClass.MONEY and self.execute is not None:
            raise ValueError(
                f"money tool {self.name!r} must not execute locally; "
                "its effect is the sidecar dispatch"
            )

    def arguments_for(self, raw: dict[str, Any]) -> dict[str, Any]:
        return dict(self.prepare(raw)) if self.prepare is not None else dict(raw)

    def resource_for(self, arguments: dict[str, Any]) -> str:
        if self.resource is not None:
            return self.resource(arguments)
        return f"{self.capability}:default"

    def execution_action(
        self, agent_id: str, organisation_id: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "subject_principal": f"{agent_id}@{organisation_id}",
            "subject_key_id": agent_id,
            "action": self.capability,
            "resource": self.resource_for(arguments),
            "parameters": dict(arguments),
        }


def arguments_digest(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(
        arguments, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class Clearance:
    """Issued by the gate after an ALLOW; good for one execution of one
    tool with exactly these arguments."""

    tool: str
    arguments_digest: str
    decision_id: str
    used: bool = False


class ToolRegistry:
    def __init__(self, tools: Iterable[Tool]) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools:
            if tool.name in self._tools:
                raise ValueError(f"duplicate tool {tool.name!r}")
            self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        try:
            return self._tools[name]
        except KeyError:
            raise KeyError(f"unknown tool {name!r}") from None

    @property
    def tools(self) -> list[Tool]:
        return list(self._tools.values())

    def clearance_for(
        self, name: str, arguments: dict[str, Any], *, decision_id: str
    ) -> Clearance:
        self.get(name)
        return Clearance(name, arguments_digest(arguments), decision_id)

    def execute(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        clearance: Clearance | None = None,
    ) -> Any:
        tool = self.get(name)
        if tool.risk is RiskClass.READ:
            assert tool.execute is not None
            return tool.execute(dict(arguments))
        if tool.risk is RiskClass.MONEY:
            raise ClearanceRequiredError(
                f"{name} is a money tool; it executes only through the sidecar dispatch"
            )
        if (
            clearance is None
            or clearance.used
            or clearance.tool != name
            or clearance.arguments_digest != arguments_digest(arguments)
        ):
            raise ClearanceRequiredError(
                f"{name} needs an unused clearance for exactly these arguments"
            )
        clearance.used = True
        assert tool.execute is not None
        return tool.execute(dict(arguments))
