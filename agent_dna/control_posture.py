"""Operator-controlled enforcement posture recorded into decision evidence.

Controls may be configured off by the operator; callers cannot disable them.
Active/inactive state is written into the sealed DecisionRecord evidence so
an auditor can distinguish correlated from uncorrelated decisions.
"""

from __future__ import annotations

import json
from typing import Any

from agent_dna.decision import DecisionResult
from agent_dna.evidence import EvidenceItem, EvidenceReport

# Distinct reason codes — auditors must not collapse failure modes.
AUTHORIZATION_NOT_CONFIGURED = "AUTHORIZATION_NOT_CONFIGURED"
CROSS_AGENT_EXECUTION_ID_REQUIRED = "CROSS_AGENT_EXECUTION_ID_REQUIRED"
AUTHORIZE_LOOP_EVENTS_REQUIRED = "AUTHORIZE_LOOP_EVENTS_REQUIRED"

CONTROL_POSTURE_EVIDENCE_NAME = "enforcement_control_posture"


def authorization_mode_of(authorizer: Any) -> str:
    mode = getattr(authorizer, "authorization_mode", None)
    if isinstance(mode, str) and mode:
        return mode
    if authorizer is None:
        return "absent"
    return "attached"


def attach_control_posture(
    result: DecisionResult,
    posture: dict[str, Any],
) -> DecisionResult:
    """Append a hashed evidence item describing operator control state."""
    payload = json.dumps(posture, sort_keys=True, separators=(",", ":"), default=str)
    item = EvidenceItem(
        name=CONTROL_POSTURE_EVIDENCE_NAME,
        score=1.0,
        confidence=1.0,
        summary=payload,
    )
    if result.evidence is None:
        result.evidence = EvidenceReport(items=[item])
    else:
        # Replace prior posture item if present (idempotent re-stamp).
        result.evidence.items = [
            existing
            for existing in result.evidence.items
            if existing.name != CONTROL_POSTURE_EVIDENCE_NAME
        ]
        result.evidence.add(item)
    return result


def posture_from_evidence(
    evidence: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    if not evidence:
        return None
    for item in evidence:
        if item.get("name") == CONTROL_POSTURE_EVIDENCE_NAME:
            summary = item.get("summary")
            if isinstance(summary, str) and summary:
                try:
                    parsed = json.loads(summary)
                except json.JSONDecodeError:
                    return None
                if isinstance(parsed, dict):
                    return parsed
    return None
