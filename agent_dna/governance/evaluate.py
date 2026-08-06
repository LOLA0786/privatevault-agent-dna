"""Deterministic evaluation of governance controls.

The evaluator deliberately separates:

    proposed_result
        What the assertion would decide if the control were active.

    result
        What PrivateVault is permitted to enforce.

Only ACTIVE controls bind. Draft, source-verified, expert-mapped,
customer-approved and signed-but-not-activated controls remain REVIEW,
regardless of whether their proposed result is PASS or BLOCK.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .pack import (
    Control,
    DeploymentProfile,
    Lifecycle,
    Mode,
    Pack,
    Result,
    most_restrictive,
)


class AssertionError(ValueError):
    """The control assertion is unsupported or malformed."""


class MissingFactError(KeyError):
    """The assertion referenced a fact that was not supplied."""


@dataclass(frozen=True)
class ControlEvaluation:
    control_id: str
    title: str
    mode: Mode
    lifecycle: Lifecycle
    proposed_result: Result
    result: Result
    binding: bool
    detail: str
    assertion: str = ""
    mapped_requirements: tuple[str, ...] = ()
    interpretation_owner: str = ""
    approved_by: str = ""


@dataclass(frozen=True)
class GovernanceEvaluation:
    pack_id: str
    pack_version: str
    jurisdiction: str
    bundle_hash: str
    controls: tuple[ControlEvaluation, ...]
    result: Result
    enforced_result: Result

    @property
    def blocking_controls(self) -> tuple[ControlEvaluation, ...]:
        return tuple(item for item in self.controls if item.result is Result.BLOCK)

    @property
    def review_controls(self) -> tuple[ControlEvaluation, ...]:
        return tuple(item for item in self.controls if item.result is Result.REVIEW)


def _compare(op: ast.cmpop, left: Any, right: Any) -> bool:
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    if isinstance(op, ast.Lt):
        return left < right
    if isinstance(op, ast.LtE):
        return left <= right
    if isinstance(op, ast.Gt):
        return left > right
    if isinstance(op, ast.GtE):
        return left >= right
    if isinstance(op, ast.In):
        return left in right
    if isinstance(op, ast.NotIn):
        return left not in right
    raise AssertionError(f"unsupported comparison: {type(op).__name__}")


def _evaluate_node(  # noqa: C901
    node: ast.AST,
    facts: dict[str, Any],
) -> Any:
    if isinstance(node, ast.Expression):
        return _evaluate_node(node.body, facts)

    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.Name):
        if node.id not in facts:
            raise MissingFactError(node.id)
        return facts[node.id]

    if isinstance(node, ast.List):
        return [_evaluate_node(item, facts) for item in node.elts]

    if isinstance(node, ast.Tuple):
        return tuple(_evaluate_node(item, facts) for item in node.elts)

    if isinstance(node, ast.Set):
        return {_evaluate_node(item, facts) for item in node.elts}

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not bool(_evaluate_node(node.operand, facts))

    if isinstance(node, ast.BoolOp):
        values = node.values
        if isinstance(node.op, ast.And):
            return all(bool(_evaluate_node(item, facts)) for item in values)
        if isinstance(node.op, ast.Or):
            return any(bool(_evaluate_node(item, facts)) for item in values)
        raise AssertionError(f"unsupported boolean operator: {type(node.op).__name__}")

    if isinstance(node, ast.Compare):
        left = _evaluate_node(node.left, facts)
        for operator, comparator in zip(node.ops, node.comparators, strict=True):
            right = _evaluate_node(comparator, facts)
            if not _compare(operator, left, right):
                return False
            left = right
        return True

    raise AssertionError(f"unsupported expression node: {type(node).__name__}")


def evaluate_assertion(expression: str, facts: dict[str, Any]) -> bool:
    """Evaluate a small, non-executable assertion language.

    Function calls, attribute access, subscripting, imports and arbitrary
    Python execution are intentionally unsupported.
    """
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise AssertionError(f"invalid assertion syntax: {exc.msg}") from exc

    return bool(_evaluate_node(tree, facts))


def _proposed_result(
    control: Control,
    facts: dict[str, Any],
) -> tuple[Result, str]:
    if control.mode is Mode.ASSESSMENT:
        return (
            Result.NOT_APPLICABLE,
            "assessment control: answered per organisation, not per action",
        )

    if control.mode is Mode.HUMAN_REVIEW:
        return (
            Result.REVIEW,
            "requires legal, compliance or professional judgement",
        )

    if control.mode is Mode.EVIDENCE:
        missing = [
            name
            for name in control.evidence_required
            if name not in facts or facts[name] in (None, "")
        ]
        if missing:
            return (
                Result.REVIEW,
                "evidence not captured: " + ", ".join(missing),
            )
        return Result.PASS, "required evidence captured"

    missing_required = [
        name
        for name in control.required_facts
        if name not in facts or facts[name] is None
    ]
    if missing_required:
        return (
            control.missing_fact_result,
            "required facts missing: " + ", ".join(missing_required),
        )

    try:
        passed = evaluate_assertion(control.assertion, facts)
    except MissingFactError as exc:
        return (
            control.missing_fact_result,
            f"assertion fact missing: {exc.args[0]}",
        )
    except (AssertionError, TypeError, ValueError) as exc:
        # A broken ACTIVE policy must not silently allow a consequential action.
        return Result.BLOCK, f"assertion evaluation failed closed: {exc}"

    if passed:
        return Result.PASS, f"assertion passed: {control.assertion}"

    return (
        control.failed_control_result,
        f"assertion failed: {control.assertion}",
    )


def _gate(
    control: Control,
    proposed_result: Result,
    detail: str,
) -> tuple[Result, bool, str]:
    if control.mode is Mode.ASSESSMENT:
        return Result.NOT_APPLICABLE, False, detail

    if not control.lifecycle.enforceable:
        return (
            Result.REVIEW,
            False,
            f"proposal only; lifecycle={control.lifecycle.value}; "
            f"proposed={proposed_result.value}; {detail}",
        )

    return proposed_result, True, detail


def evaluate_control(
    control: Control,
    facts: dict[str, Any],
) -> ControlEvaluation:
    proposed, proposed_detail = _proposed_result(control, facts)
    result, binding, detail = _gate(control, proposed, proposed_detail)

    return ControlEvaluation(
        control_id=control.control_id,
        title=control.title,
        mode=control.mode,
        lifecycle=control.lifecycle,
        proposed_result=proposed,
        result=result,
        binding=binding,
        detail=detail,
        assertion=control.assertion,
        mapped_requirements=control.mapped_requirements,
        interpretation_owner=control.interpretation_owner,
        approved_by=control.approved_by,
    )


def evaluate_pack(
    pack: Pack,
    profile: DeploymentProfile,
    action_class: str,
    risk_tier: str,
    facts: dict[str, Any],
) -> GovernanceEvaluation:
    applicable = pack.applicable(
        entity_type=profile.entity_type,
        action_class=action_class,
        risk_tier=risk_tier,
    )

    evaluations = tuple(evaluate_control(control, facts) for control in applicable)

    results = [
        item.result for item in evaluations if item.result is not Result.NOT_APPLICABLE
    ]

    # `result` is the readiness/display result. It deliberately shows
    # REVIEW for mappings that are not active, so their unresolved status
    # remains visible.
    result = most_restrictive(results)

    # `enforced_result` contains only controls authorized to bind.
    # A draft or expert mapping may propose BLOCK, but it cannot alter the
    # execution decision until it is ACTIVE.
    binding_results = [
        item.result
        for item in evaluations
        if item.binding and item.result is not Result.NOT_APPLICABLE
    ]
    enforced_result = most_restrictive(binding_results)

    return GovernanceEvaluation(
        pack_id=pack.pack_id,
        pack_version=pack.version,
        jurisdiction=pack.jurisdiction,
        bundle_hash=pack.bundle_hash(),
        controls=evaluations,
        result=result,
        enforced_result=enforced_result,
    )


def combine_evaluations(
    evaluations: Iterable[GovernanceEvaluation],
) -> Result:
    """Combine only binding pack results using most-restrictive-wins.

    Readiness findings remain visible through `evaluation.result`, but
    non-binding mappings cannot change an execution verdict.
    """
    results = [
        evaluation.enforced_result
        for evaluation in evaluations
        if evaluation.enforced_result is not Result.NOT_APPLICABLE
    ]
    return most_restrictive(results)
