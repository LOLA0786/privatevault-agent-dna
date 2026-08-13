"""Minimal dispatch-adapter conformance contract.

Any adapter that can produce an external effect must satisfy:

  C1. Refusal produces no side effect.
  C2. On success, the payload that leaves is exactly the payload that was
      checked (bytes for exact-byte egress; tool args for MCP).
  C3. A second attempt with the same consumed authorization / blocked
      path does not produce a new side effect.

Adapters plug into ``tests/test_adapter_conformance.py`` via a harness
that implements ``AdapterConformanceHarness``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class SideEffect:
    """One observed external effect produced by an adapter under test."""

    kind: str
    payload: bytes | dict[str, Any]


@dataclass
class ConformanceOutcome:
    refused: bool
    reason_code: str | None = None
    detail: str | None = None


@runtime_checkable
class AdapterConformanceHarness(Protocol):
    """Plug-in surface for the shared conformance suite."""

    name: str

    def reset(self) -> None:
        """Clear recorded side effects and restore a fresh allow path."""

    def configure_refuse(self) -> None:
        """Arrange the next attempt so enforcement must refuse."""

    def configure_allow(self) -> None:
        """Arrange the next attempt so enforcement may allow."""

    def attempt(self) -> ConformanceOutcome:
        """Invoke the adapter once."""

    @property
    def side_effects(self) -> list[SideEffect]:
        """Side effects observed since the last ``reset``."""

    def checked_payload(self) -> bytes | dict[str, Any]:
        """The payload enforcement checked for the last successful allow."""


@dataclass
class HarnessBase:
    """Optional helper base; harnesses may implement the Protocol directly."""

    name: str
    effects: list[SideEffect] = field(default_factory=list)

    def reset(self) -> None:
        self.effects.clear()

    @property
    def side_effects(self) -> list[SideEffect]:
        return list(self.effects)
