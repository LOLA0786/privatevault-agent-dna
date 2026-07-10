"""
Policy rule schema — the data shape a customer's policy file must
follow. Deliberately minimal: a rule matches on capability (required)
and optionally agent_id, then either always fires or evaluates one
condition against the action's arguments or supplied evidence.

Evidence-honesty rule, same as every other precedence level: if a
rule's condition references a field that isn't present, that rule is
SKIPPED -- never treated as passed or failed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

VALID_OPERATORS = {">", ">=", "<", "<=", "==", "!=", "in", "not_in"}
VALID_OUTCOMES = {"block", "require_approval"}


@dataclass
class PolicyCondition:
    field: str          # dotted path, e.g. "arguments.amount"
    operator: str
    value: Any

    def __post_init__(self):
        if self.operator not in VALID_OPERATORS:
            raise ValueError(
                f"invalid operator {self.operator!r}, must be one of "
                f"{sorted(VALID_OPERATORS)}"
            )


@dataclass
class PolicyRule:
    id: str
    capability: str          # exact match; "*" matches any capability
    outcome: str              # "block" or "require_approval"
    reason: str
    agent_id: Optional[str] = None     # None = applies to all agents
    condition: Optional[PolicyCondition] = None  # None = always fires
                                                   # when capability/agent match

    def __post_init__(self):
        if self.outcome not in VALID_OUTCOMES:
            raise ValueError(
                f"invalid outcome {self.outcome!r} for rule {self.id!r}, "
                f"must be one of {sorted(VALID_OUTCOMES)}"
            )


@dataclass
class PolicyDocument:
    policies: List[PolicyRule] = field(default_factory=list)
    version: str = "1.0"

    def validate_ids_unique(self) -> None:
        ids = [p.id for p in self.policies]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate policy IDs: {sorted(dupes)}")


def parse_policy_dict(raw: Dict[str, Any]) -> PolicyDocument:
    """Parse a raw dict (loaded from YAML/JSON) into a validated
    PolicyDocument. Raises ValueError with a specific message on any
    malformed rule -- fails loudly at load time, never silently."""
    rules = []
    for i, p in enumerate(raw.get("policies", [])):
        if "id" not in p:
            raise ValueError(f"policy at index {i} missing required field 'id'")
        if "capability" not in p:
            raise ValueError(f"policy {p.get('id', f'#{i}')} missing 'capability'")
        if "outcome" not in p:
            raise ValueError(f"policy {p['id']} missing 'outcome'")
        if "reason" not in p:
            raise ValueError(f"policy {p['id']} missing 'reason'")

        condition = None
        if "condition" in p and p["condition"] is not None:
            c = p["condition"]
            for req in ("field", "operator", "value"):
                if req not in c:
                    raise ValueError(
                        f"policy {p['id']}'s condition missing '{req}'"
                    )
            condition = PolicyCondition(
                field=c["field"], operator=c["operator"], value=c["value"]
            )

        rules.append(PolicyRule(
            id=p["id"],
            capability=p["capability"],
            outcome=p["outcome"],
            reason=p["reason"],
            agent_id=p.get("agent_id"),
            condition=condition,
        ))

    doc = PolicyDocument(policies=rules, version=raw.get("version", "1.0"))
    doc.validate_ids_unique()
    return doc
