"""The model is a proposer. It never holds credentials and never executes.

``Model.next_step`` looks at the run so far and either proposes one tool
call or finishes. ``ScriptedModel`` replays a fixed script and is what the
tests and demos use. ``AnthropicModel`` is the opt-in real model, selected
with ``PV_AGENT_MODEL=anthropic``; it is never imported by tests.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from agents.core.tools import Tool

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5-5"
MODEL_NAME_ENV = "PV_AGENT_MODEL_NAME"  # for example claude-opus-5-5


def anthropic_model_name() -> str:
    """Sonnet 5.5 by default; Opus (or any model) opt-in via the env var."""
    import os

    return os.environ.get(MODEL_NAME_ENV, "").strip() or DEFAULT_ANTHROPIC_MODEL


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Final:
    text: str


Step = ToolCall | Final


class Model(Protocol):
    def next_step(self, history: list[dict[str, Any]], tools: Sequence[Tool]) -> Step:
        """Propose the next tool call, or finish."""


class ScriptedModel:
    """Deterministic: replays ``steps`` in order, one per call."""

    def __init__(self, steps: Sequence[Step]) -> None:
        self._steps = list(steps)
        self._index = 0

    def next_step(self, history: list[dict[str, Any]], tools: Sequence[Tool]) -> Step:
        if self._index >= len(self._steps):
            raise RuntimeError("script exhausted: the scripted model has no more steps")
        step = self._steps[self._index]
        self._index += 1
        return step


def _tool_definition(tool: Tool) -> dict[str, Any]:
    properties = {
        name: {"type": kind, "description": desc}
        for name, (kind, desc) in tool.parameters.items()
    }
    return {
        "name": tool.name,
        "description": f"{tool.description} (risk: {tool.risk.value}; "
        f"capability {tool.capability}; decided by PrivateVault)",
        "input_schema": {
            "type": "object",
            "properties": properties,
            "required": sorted(properties),
            "additionalProperties": False,
        },
        "strict": True,
    }


class AnthropicModel:
    """Real model, opt-in. One Messages API call per step, tools as strict
    JSON-schema tools, adaptive thinking, server-side refusal fallback on.

    The model only proposes: a ``tool_use`` block becomes a ``ToolCall`` that
    the runner takes to PrivateVault. Tool results, including refusals, go
    back as ``tool_result`` blocks so the model sees what was and was not
    allowed.
    """

    def __init__(self, system: str, *, model: str | None = None) -> None:
        # Opt-in dependency (``uv sync --extra live``); typed as Any so the
        # gate passes with or without the SDK installed.
        import anthropic  # type: ignore[import-not-found, unused-ignore]

        self._client: Any = anthropic.Anthropic()
        self._model = model or anthropic_model_name()
        self._system = system
        self._messages: list[dict[str, Any]] = []
        self._pending_tool_use_id: str | None = None

    def next_step(self, history: list[dict[str, Any]], tools: Sequence[Tool]) -> Step:
        if not self._messages:
            goal = history[0]["goal"] if history and "goal" in history[0] else "Begin."
            self._messages.append({"role": "user", "content": goal})
        elif self._pending_tool_use_id is not None and history:
            last = history[-1]
            self._messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": self._pending_tool_use_id,
                            "content": json.dumps(last, sort_keys=True, default=str),
                        }
                    ],
                }
            )
            self._pending_tool_use_id = None
        response = self._client.beta.messages.create(
            model=self._model,
            max_tokens=16000,
            system=self._system,
            thinking={"type": "adaptive"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            tools=[_tool_definition(t) for t in tools],
            tool_choice={"type": "auto", "disable_parallel_tool_use": True},
            messages=self._messages,
        )
        if response.stop_reason == "refusal":
            return Final("the model declined to continue")
        self._messages.append({"role": "assistant", "content": response.content})
        for block in response.content:
            if block.type == "tool_use":
                self._pending_tool_use_id = block.id
                arguments = block.input if isinstance(block.input, dict) else {}
                return ToolCall(block.name, dict(arguments))
        text = " ".join(b.text for b in response.content if b.type == "text")
        return Final(text or "done")
