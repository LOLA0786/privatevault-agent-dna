"""
UAAL Layer (L0) — enterprise deterministic constraints, evaluated
before everything else in the precedence order:

    0. UAAL/EAV constraints  (enterprise deterministic)   -> BLOCK
    1. behavioral invariants (deterministic contract)     -> BLOCK
    2. capability grants     (deterministic authz)        -> REQUIRE_APPROVAL
    3. learned drift         (probabilistic advisory)     -> REQUIRE_APPROVAL
    4. baseline                                           -> ALLOW

Evidence honesty: EAV invariants evaluate against caller-supplied
evidence (user_request, planner, approvals, enterprise_state). This
layer evaluates ONLY the invariants whose evidence is present —
absent evidence means "not checkable here", never "pass" and never
"fail". The result says which checks ran.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .eav import InvariantEngine
from .trace import AgentAction


@dataclass
class _CEA:
    """Canonical Enterprise Action — the shape EAV evaluates."""
    verb: str
    object_id: Optional[str]
    amount: Optional[float]
    capability: str
    # P0-7: distinguishes MALFORMED (present but not a number ->
    # fail closed) from ABSENT (None -> skip honestly)
    amount_malformed: bool = False


@dataclass
class UAALResult:
    violated: bool
    message: str
    checks_run: List[str] = field(default_factory=list)
    checks_skipped: List[str] = field(default_factory=list)
    detail: List[Dict[str, Any]] = field(default_factory=list)


# evidence key each EAV invariant requires to be meaningful
_EVIDENCE_REQ = {
    "identity_preservation": ("user_request", "planner"),
    "authority_preservation": ("approvals",),
    "monetary_conservation": ("enterprise_state",),
    "enterprise_state": ("enterprise_state",),
    "capability_preservation": (),          # needs only the action itself
}


class UAALConstraintChecker:
    def __init__(self) -> None:
        self.engine = InvariantEngine()

    @staticmethod
    def _to_cea(action: AgentAction) -> _CEA:
        args = action.arguments or {}
        raw_amount = args.get("amount")
        amount = None
        amount_malformed = False
        if raw_amount is not None:
            try:
                amount = float(raw_amount)
            except (TypeError, ValueError):
                # P0-7: previously coerced to None, which the monetary
                # invariant then counted as "amount conserved" --
                # garbage laundered into a passed check. Malformed is
                # now its own state and fails closed downstream.
                amount_malformed = True
        return _CEA(
            verb=action.capability.split(".")[-1],
            object_id=args.get("target") or args.get("object_id"),
            amount=amount,
            capability=action.capability,
            amount_malformed=amount_malformed,
        )

    def check(
        self,
        action: AgentAction,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> UAALResult:
        evidence = evidence if evidence is not None else {}
        raw = self.engine.evaluate(self._to_cea(action), evidence)

        run: List[str] = []
        skipped: List[str] = []
        failures: List[str] = []
        detail: List[Dict[str, Any]] = []

        for r in raw["results"]:
            name = r["name"]
            needed = _EVIDENCE_REQ.get(name, ())
            if needed and not all(k in evidence for k in needed):
                skipped.append(name)
                continue
            if r["passed"] is None:
                # evaluable evidence key was present but incomplete/
                # absent at field level -- honestly skipped, reason
                # preserved in detail
                skipped.append(name)
                detail.append(r)
                continue
            run.append(name)
            detail.append(r)
            if r["passed"] is False:
                failures.append(f"{name}: {r['reason']}")

        return UAALResult(
            violated=bool(failures),
            message="; ".join(failures) if failures else (
                f"uaal: {len(run)} checks passed"
                + (f", {len(skipped)} skipped (no evidence)" if skipped else "")
            ),
            checks_run=run,
            checks_skipped=skipped,
            detail=detail,
        )
