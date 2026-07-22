"""
UAAL Layer (L0) — enterprise deterministic constraints, evaluated
before everything else in the precedence order:

    0. UAAL/EAV constraints  (enterprise deterministic)   -> BLOCK
    1. behavioral invariants (deterministic contract)     -> BLOCK
    2. capability grants     (deterministic authz)        -> REQUIRE_APPROVAL
    3. learned drift         (probabilistic advisory)     -> REQUIRE_APPROVAL
    4. baseline                                           -> ALLOW

Evidence honesty is THREE-state, not two:

    present            -> evaluate the invariant
    absent + optional  -> SKIP, recorded (not checkable, not a pass)
    absent + MANDATORY -> BLOCK (missing_required_evidence)

For SENSITIVE capability classes (credentials, infra exec, external
egress, role assumption), identity_preservation and
authority_preservation are mandatory -- an agent reaching for a
credential with no declared goal is the eval-escape signature, and a
hostile caller would omit the evidence. Ordinary actions with no
identity claim skip honestly, so L0 does not force every benign call
to carry planner evidence. This closes a fail-open in which an
attacker suppressing evidence delivery defeated the identity check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .eav import InvariantEngine
from .trace import AgentAction


@dataclass
class _CEA:
    """Canonical Enterprise Action — the shape EAV evaluates."""
    verb: str
    object_id: str | None
    amount: float | None
    capability: str
    # P0-7: distinguishes MALFORMED (present but not a number ->
    # fail closed) from ABSENT (None -> skip honestly)
    amount_malformed: bool = False


@dataclass
class UAALResult:
    violated: bool
    message: str
    checks_run: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)
    detail: list[dict[str, Any]] = field(default_factory=list)


# evidence key each EAV invariant requires to be meaningful
_EVIDENCE_REQ = {
    "identity_preservation": ("user_request", "planner"),
    "authority_preservation": ("approvals",),
    "monetary_conservation": ("enterprise_state",),
    "enterprise_state": ("enterprise_state",),
    "capability_preservation": (),          # needs only the action itself
}

# Fail-open fix (scoped). Missing identity/authority evidence blocks
# ONLY when the action touches a sensitive capability class -- there,
# an unstated intent is itself the anomaly (an agent reaching for a
# credential or moving laterally with no declared goal is exactly the
# eval-escape signature, and a hostile caller would omit the
# evidence). For ordinary actions a missing identity claim is not
# suspicious and still skips honestly, so L0 does not force every
# benign call to carry planner evidence.
_SENSITIVE_PREFIXES = (
    "secrets.", "infra.", "network.egress", "cloud.assume_role",
    "iam.", "admin.", "security.",
)
_MANDATORY_FOR_SENSITIVE = frozenset({
    "identity_preservation",
    "authority_preservation",
})


def _is_sensitive(capability: str) -> bool:
    return any(capability.startswith(p) or f".{p.rstrip('.')}" in capability
              for p in _SENSITIVE_PREFIXES)


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
        evidence: dict[str, Any] | None = None,
    ) -> UAALResult:
        evidence = evidence if evidence is not None else {}
        raw = self.engine.evaluate(self._to_cea(action), evidence)

        run: list[str] = []
        skipped: list[str] = []
        failures: list[str] = []
        detail: list[dict[str, Any]] = []

        for r in raw["results"]:
            name = r["name"]
            needed = _EVIDENCE_REQ.get(name, ())
            if needed and not all(k in evidence for k in needed):
                sensitive = (
                    name in _MANDATORY_FOR_SENSITIVE
                    and _is_sensitive(action.capability)
                )
                if sensitive:
                    # fail closed: a sensitive action with no declared
                    # identity/authority is the eval-escape signature;
                    # missing evidence there is a block, not a skip
                    missing = [k for k in needed if k not in evidence]
                    failures.append(
                        f"{name}: missing_required_evidence "
                        f"({', '.join(missing)})")
                    run.append(name)
                    detail.append({"name": name, "passed": False,
                                   "reason": "missing_required_evidence",
                                   "missing_evidence": missing})
                else:
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
