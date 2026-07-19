from dataclasses import dataclass
from typing import Optional


@dataclass
class Invariant:
    """passed is tri-state (P0-7):
        True  -- evaluated, held
        False -- evaluated, VIOLATED (or evidence was malformed:
                 garbage never counts as a held invariant)
        None  -- not evaluable: required fields absent/incomplete.
                 Reported as SKIPPED upstream, never as a pass."""
    name: str
    passed: Optional[bool]
    reason: str


class InvariantEngine:

    def evaluate(self, cea, evidence):

        results = []

        # I001 Identity Preservation
        user = evidence.get("user_request", {})
        planner = evidence.get("planner", {})
        tool = {
            "target": cea.object_id,
            "verb": cea.verb,
            "amount": cea.amount,
        }

        if (
            user.get("canonical_target") is None
            or planner.get("canonical_target") is None
        ):
            results.append(
                Invariant(
                    "identity_preservation",
                    None,
                    "identity not checkable: canonical_target missing "
                    "from user_request/planner evidence",
                )
            )
        elif (
            user.get("canonical_target") == planner.get("canonical_target")
            == tool.get("target")
        ):
            results.append(
                Invariant(
                    "identity_preservation",
                    True,
                    "canonical identity preserved",
                )
            )
        else:
            results.append(
                Invariant(
                    "identity_preservation",
                    False,
                    "enterprise identity drift",
                )
            )

        # I002 Authority Preservation
        approvals = evidence.get("approvals", {})

        if approvals.get("required", False):
            ok = approvals.get("token_present", False)
            results.append(
                Invariant(
                    "authority_preservation",
                    ok,
                    "approval token verified" if ok else "missing approval token",
                )
            )

        # I003 Monetary Conservation (P0-7 tri-state):
        #   MALFORMED action amount        -> False (fail closed)
        #   MALFORMED invoice amount       -> False (fail closed)
        #   ABSENT either amount           -> None  (skip honestly)
        #   both VALID                     -> compare
        invoice = evidence.get("enterprise_state", {})

        if getattr(cea, "amount_malformed", False):
            results.append(Invariant(
                "monetary_conservation", False,
                "malformed action amount: not a number (fail-closed)",
            ))
        elif invoice.get("invoice_amount") is None or cea.amount is None:
            results.append(Invariant(
                "monetary_conservation", None,
                "amount not checkable: action or invoice amount absent",
            ))
        else:
            try:
                invoice_amount = float(invoice["invoice_amount"])
            except (TypeError, ValueError):
                results.append(Invariant(
                    "monetary_conservation", False,
                    "malformed invoice_amount in enterprise_state "
                    "evidence (fail-closed)",
                ))
            else:
                conserved = invoice_amount == float(cea.amount)
                results.append(Invariant(
                    "monetary_conservation", conserved,
                    "amount conserved" if conserved else "amount mismatch",
                ))

        # I004 Enterprise State Preservation (P0-7): every required
        # field must be PRESENT to evaluate. An empty or partial
        # enterprise_state used to default to open/verified/
        # non-duplicate -- absence of evidence evaluated as evidence
        # of validity. Now: incomplete -> None (skipped honestly).
        _state_fields = ("invoice_open", "target_verified", "duplicate")
        _missing = [f for f in _state_fields if f not in invoice]
        if _missing:
            results.append(Invariant(
                "enterprise_state", None,
                "enterprise state not checkable: missing field(s) "
                + ", ".join(_missing),
            ))
        else:
            state_ok = (
                invoice["invoice_open"]
                and invoice["target_verified"]
                and not invoice["duplicate"]
            )
            results.append(Invariant(
                "enterprise_state", state_ok,
                "state valid" if state_ok else "enterprise state violation",
            ))

        # I005 Capability Preservation
        capability_ok = cea.capability is not None

        results.append(
            Invariant(
                "capability_preservation",
                capability_ok,
                "capability present" if capability_ok else "missing capability",
            )
        )

        passed = all(r.passed is not False for r in results)

        return {
            "passed": passed,
            "score": sum(r.passed is True for r in results) / len(results),
            "results": [vars(r) for r in results],
        }
