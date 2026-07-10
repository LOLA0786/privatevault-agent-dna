"""
PolicyChecker — evaluates an action against a customer-supplied
PolicyDocument. Same evidence-honesty discipline as every other
precedence level: a rule whose condition field is missing is SKIPPED,
never silently passed or failed.

Rules are evaluated in document order; the FIRST matching, firing
rule wins (not all matching rules -- first match, same short-circuit
philosophy as the main precedence chain). A rule's own declared
outcome (block or require_approval) is returned -- this is the one
level in the engine whose outcome is data-driven, not fixed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .schema import PolicyDocument, PolicyRule


def _get_field(obj: Dict[str, Any], dotted_path: str):
    """Walk a dotted path like 'arguments.amount' through nested
    dicts. Returns a sentinel-free None-means-absent result via a
    tuple (found: bool, value: Any) so 'field exists but is None'
    is distinguishable from 'field does not exist' -- evidence
    honesty requires this distinction."""
    parts = dotted_path.split(".")
    current = obj
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _evaluate_condition(cond, context: Dict[str, Any]) -> Optional[bool]:
    """Returns True/False if evaluable, None if the field is absent
    (meaning: skip this rule, evidence-honest)."""
    found, actual = _get_field(context, cond.field)
    if not found:
        return None

    op = cond.operator
    val = cond.value
    try:
        if op == ">":
            return actual > val
        if op == ">=":
            return actual >= val
        if op == "<":
            return actual < val
        if op == "<=":
            return actual <= val
        if op == "==":
            return actual == val
        if op == "!=":
            return actual != val
        if op == "in":
            return actual in val
        if op == "not_in":
            return actual not in val
    except TypeError:
        # incomparable types (e.g. comparing str > int) -- treat as
        # unevaluable, not as a match. Never silently coerce.
        return None
    return None


@dataclass
class PolicyCheckResult:
    fired: bool
    matched_rule_id: Optional[str] = None
    outcome: Optional[str] = None   # "block" | "require_approval"
    reason: str = ""
    rules_evaluated: List[str] = field(default_factory=list)
    rules_skipped: List[str] = field(default_factory=list)
    rules_not_matched: List[str] = field(default_factory=list)
    # rules_not_matched: capability/agent matched, condition was
    # evaluable, but evaluated False -- the rule was genuinely
    # considered and did not apply. Distinct from rules_skipped
    # (evidence was missing, rule could not be evaluated at all).
    # Exists so nothing goes silently unconsidered: every rule in the
    # policy document ends up in exactly one of rules_evaluated
    # (fired or checked), rules_skipped, or -- for rules whose
    # capability/agent_id didn't even match this action -- none of
    # the three, which is itself correct (irrelevant rules are not
    # "checked" in any meaningful sense).


class PolicyChecker:
    def __init__(self, document: PolicyDocument):
        self.document = document

    def check(
        self,
        agent_id: str,
        capability: str,
        arguments: Optional[Dict[str, Any]] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> PolicyCheckResult:
        context = {
            "arguments": arguments or {},
            "evidence": evidence or {},
        }
        evaluated: List[str] = []
        skipped: List[str] = []
        not_matched: List[str] = []

        for rule in self.document.policies:
            if rule.capability != "*" and rule.capability != capability:
                continue
            if rule.agent_id is not None and rule.agent_id != agent_id:
                continue

            if rule.condition is None:
                evaluated.append(rule.id)
                return PolicyCheckResult(
                    fired=True, matched_rule_id=rule.id,
                    outcome=rule.outcome, reason=rule.reason,
                    rules_evaluated=evaluated, rules_skipped=skipped,
                    rules_not_matched=not_matched,
                )

            result = _evaluate_condition(rule.condition, context)
            if result is None:
                skipped.append(rule.id)
                continue

            evaluated.append(rule.id)
            if result:
                return PolicyCheckResult(
                    fired=True, matched_rule_id=rule.id,
                    outcome=rule.outcome, reason=rule.reason,
                    rules_evaluated=evaluated, rules_skipped=skipped,
                    rules_not_matched=not_matched,
                )
            else:
                not_matched.append(rule.id)

        return PolicyCheckResult(
            fired=False, rules_evaluated=evaluated, rules_skipped=skipped,
            rules_not_matched=not_matched,
        )
