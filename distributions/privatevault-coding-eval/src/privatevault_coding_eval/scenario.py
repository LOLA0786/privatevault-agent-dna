"""Portable scenario inputs reduced to the actual AgentAction contract."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_dna import AgentAction


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    action: AgentAction
    previous_capability: str | None
    grants: tuple[Mapping[str, Any], ...]
    policy: Mapping[str, Any]
    consensus_enabled: bool
    expected_decision: str
    expected_trigger: str


def _require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{path} must be an object")
    return value


def _require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path} must be a non-empty string")
    return value


def _require_exact_fields(
    value: Mapping[str, Any],
    required: set[str],
    path: str,
) -> None:
    if set(value) != required:
        missing = sorted(required - set(value))
        unknown = sorted(set(value) - required)
        raise ValueError(
            f"{path} fields invalid: missing={missing}, unknown={unknown}"
        )


def load_scenario(path: Path) -> Scenario:
    """Load external JSON and reduce it to actual runtime types."""

    raw = _require_mapping(
        json.loads(path.read_text(encoding="utf-8")),
        "scenario",
    )
    required = {
        "name",
        "description",
        "action",
        "previous_capability",
        "grants",
        "policy",
        "consensus_enabled",
        "expected_decision",
        "expected_trigger",
    }
    _require_exact_fields(raw, required, "scenario")

    action_raw = _require_mapping(raw["action"], "scenario.action")
    action_required = {
        "agent_id",
        "capability",
        "timestamp",
        "arguments",
        "evidence",
        "request_id",
    }
    _require_exact_fields(action_raw, action_required, "scenario.action")

    grants = raw["grants"]
    if not isinstance(grants, list) or not all(
        isinstance(item, Mapping) for item in grants
    ):
        raise ValueError("scenario.grants must be a list of objects")

    policy = _require_mapping(raw["policy"], "scenario.policy")
    evidence = _require_mapping(
        action_raw["evidence"],
        "scenario.action.evidence",
    )
    arguments = _require_mapping(
        action_raw["arguments"],
        "scenario.action.arguments",
    )

    previous = raw["previous_capability"]
    if previous is not None and not isinstance(previous, str):
        raise ValueError("previous_capability must be string or null")

    if not isinstance(raw["consensus_enabled"], bool):
        raise ValueError("consensus_enabled must be boolean")

    timestamp = action_raw["timestamp"]
    if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
        raise ValueError("action.timestamp must be numeric")

    return Scenario(
        name=_require_string(raw["name"], "scenario.name"),
        description=_require_string(
            raw["description"],
            "scenario.description",
        ),
        action=AgentAction(
            agent_id=_require_string(
                action_raw["agent_id"],
                "scenario.action.agent_id",
            ),
            capability=_require_string(
                action_raw["capability"],
                "scenario.action.capability",
            ),
            timestamp=float(timestamp),
            arguments=dict(arguments),
            evidence=dict(evidence),
            request_id=_require_string(
                action_raw["request_id"],
                "scenario.action.request_id",
            ),
        ),
        previous_capability=previous,
        grants=tuple(grants),
        policy=policy,
        consensus_enabled=raw["consensus_enabled"],
        expected_decision=_require_string(
            raw["expected_decision"],
            "scenario.expected_decision",
        ),
        expected_trigger=_require_string(
            raw["expected_trigger"],
            "scenario.expected_trigger",
        ),
    )
