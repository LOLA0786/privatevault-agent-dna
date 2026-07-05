from dataclasses import dataclass


@dataclass
class Invariant:
    name: str
    passed: bool
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

        # I003 Monetary Conservation
        invoice = evidence.get("enterprise_state", {})

        if (
            invoice.get("invoice_amount") is None
            or cea.amount is None
            or float(invoice["invoice_amount"]) == float(cea.amount)
        ):
            results.append(
                Invariant(
                    "monetary_conservation",
                    True,
                    "amount conserved",
                )
            )
        else:
            results.append(
                Invariant(
                    "monetary_conservation",
                    False,
                    "amount mismatch",
                )
            )

        # I004 Enterprise State Preservation
        state_ok = (
            invoice.get("invoice_open", True)
            and invoice.get("target_verified", True)
            and not invoice.get("duplicate", False)
        )

        results.append(
            Invariant(
                "enterprise_state",
                state_ok,
                "state valid" if state_ok else "enterprise state violation",
            )
        )

        # I005 Capability Preservation
        capability_ok = cea.capability is not None

        results.append(
            Invariant(
                "capability_preservation",
                capability_ok,
                "capability present" if capability_ok else "missing capability",
            )
        )

        passed = all(r.passed for r in results)

        return {
            "passed": passed,
            "score": sum(r.passed for r in results) / len(results),
            "results": [vars(r) for r in results],
        }
