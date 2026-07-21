#!/usr/bin/env python3
"""
Run the adversarial corpus against the composed decision line and
report PASS/FAIL per scenario.

Designed to be run BY A REVIEWER WHO DID NOT WRITE THE DEFENSES.
Edit spec/adversarial/attack_corpus.py freely to add your own
scenarios before running — that is the intended use.

Usage: python3 tools/run_adversarial.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "spec" / "adversarial"))

from attack_corpus import build_corpus  # noqa: E402

from agent_dna.decision import DecisionEngine  # noqa: E402
from agent_dna.grants import GrantRegistry  # noqa: E402
from agent_dna.uaal_layer import UAALConstraintChecker  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))
from runtime_demo import train  # noqa: E402

# The deployer's declared behavioral contract. Everything here is a
# capability this agent may never exercise regardless of stated intent,
# task context or evidence quality. The eval-boundary escape family
# tests exactly this: a benign, well-evidenced goal does not soften a
# declared boundary.
FORBIDDEN_CAPABILITIES = frozenset({
    "storage.bulk_export",       # bulk customer data extraction
    "secrets.read",              # credential / token discovery
    "infra.exec_remote",         # lateral movement to other hosts
    "network.egress_external",   # egress beyond the declared scope
})


class Invariants:
    def validate(self, capability, previous):
        class R:
            pass
        r = R()
        r.violated = capability in FORBIDDEN_CAPABILITIES
        r.message = f"forbidden capability: {capability}" if r.violated else ""
        return r


def main():
    grants = GrantRegistry()
    grants.grant(
        agent_id="adversary-agent",
        capability="payment.pay_invoice",
        granted_by="benchmark-setup",
    )
    grants.grant(
        agent_id="adversary-agent",
        capability="crm.read_contact",
        granted_by="benchmark-setup",
    )
    engine = DecisionEngine(
        scorer=train(),
        invariants=Invariants(),
        authorizer=grants,
        uaal=UAALConstraintChecker(),
    )

    corpus = build_corpus()
    passed = 0
    failed = 0

    print(f"Running {len(corpus)} adversarial scenarios\n" + "=" * 70)

    for sc in corpus:
        result = engine.decide(sc.action, evidence=sc.evidence)

        if sc.expected_decision is None:
            # scenario checks skip-behavior, not a verdict
            ok = True
            note = "(verdict-agnostic scenario — inspect manually)"
        else:
            decision_ok = result.decision == sc.expected_decision
            trigger_ok = (
                sc.expected_trigger is None
                or result.triggered_by == sc.expected_trigger
            )
            ok = decision_ok and trigger_ok
            note = ""

        status = "PASS" if ok else "FAIL"
        passed += ok
        failed += not ok

        print(f"[{status}] {sc.name}")
        print(f"       verdict={result.decision.value} trigger={result.triggered_by}")
        if sc.regulatory_note:
            print(f"       note: {sc.regulatory_note}")
        if note:
            print(f"       {note}")
        if not ok:
            print(f"       EXPECTED decision={sc.expected_decision} "
                  f"trigger={sc.expected_trigger}")
        print()

    print("=" * 70)
    print(f"RESULT: {passed} passed, {failed} failed, {len(corpus)} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
