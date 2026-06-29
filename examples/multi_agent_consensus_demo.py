"""CABI consensus demo: multi-party sign-off before a consequential action.

Sanctioned society:  planner -> risk -> finance -> approval -> payment
with a sign-off gate: risk, finance, and approval must each emit approval=True
BEFORE the payment role fires.

This is the case a per-agent monitor cannot catch: each approver is behaving
normally in isolation, but the *collective* sign-off required before payment
was never reached.

Run:  python -m examples.multi_agent_consensus_demo
"""
from __future__ import annotations

import random

from agent_dna.multi_agent import InteractionEvent, RuntimeValidator, Verdict

ROLE_OF = {
    "planner": "planning", "risk": "risk", "finance": "finance",
    "approval": "approval", "payment": "payment",
}

# approver agent ids and the role each casts a sign-off as
SIGNOFFS = [("risk_agent", "risk"),
            ("finance_agent", "finance"),
            ("approval_agent", "approval")]


def step(exec_id, src, dst, src_role, dst_role, t, **kw):
    return InteractionEvent(
        execution_id=exec_id, source=src, target=dst,
        source_role=src_role, target_role=dst_role, timestamp=t, **kw)


def signoff(exec_id, agent, role, t, approve=True, confidence=0.95):
    return InteractionEvent(
        execution_id=exec_id, source=agent, target="consensus_ledger",
        source_role=role, target_role="ledger", timestamp=t,
        approval=approve, confidence=confidence, intent="sign_off",
        metadata={"is_signoff": True})


def good_execution(exec_id, *, skip=None, dissent=None, early_payment=False):
    """A sanctioned execution. Optional knobs synthesize the attacks:
      skip:           role name whose sign-off is omitted
      dissent:        role name that signs off with approval=False
      early_payment:  payment fires before any sign-off
    """
    ev = []
    ev.append(step(exec_id, "planner", "risk", "planning", "risk", 1.0))
    ev.append(step(exec_id, "risk", "finance", "risk", "finance", 2.0))
    ev.append(step(exec_id, "finance", "approval", "finance", "approval", 3.0))

    if early_payment:
        ev.append(step(exec_id, "approval", "payment", "approval", "payment", 2.5))

    # sign-offs cluster just before payment
    t = 3.2
    for agent, role in SIGNOFFS:
        if skip and role == skip:
            t += 0.2
            continue
        if dissent and role == dissent:
            ev.append(signoff(exec_id, agent, role, t, approve=False))
        else:
            ev.append(signoff(exec_id, agent, role, t, approve=True))
        t += 0.2

    if not early_payment:
        ev.append(step(exec_id, "approval", "payment", "approval", "payment", 4.0))
    return ev


def build_corpus(n=300):
    corpus = []
    for i in range(n):
        corpus.extend(good_execution(f"train-{i}"))
    return corpus


def run():
    random.seed(11)
    validator = RuntimeValidator.from_corpus(build_corpus())

    import json
    consensus = next(i for i in validator.engine.invariants
                    if i.name == "consensus")
    print("Learned consensus requirements:")
    print(json.dumps(consensus.describe(), indent=2))
    print("=" * 64)

    cases = [
        ("known-good (all sign off)", good_execution("live-ok"), Verdict.ALLOW),
        ("finance silent (no sign-off)",
        good_execution("atk-silent", skip="finance"), Verdict.BLOCK),
        ("risk dissents (approval=False)",
        good_execution("atk-dissent", dissent="risk"), Verdict.BLOCK),
        ("payment before any sign-off",
        good_execution("atk-early", early_payment=True), Verdict.BLOCK),
    ]

    all_ok = True
    for label, events, want in cases:
        v = validator.validate_events(events)
        ok = v.verdict is want
        all_ok &= ok
        print(f"\n### {label}  ->  {v.verdict.value}  "
            f"[{'as expected' if ok else 'UNEXPECTED'}]")
        print(v.explain())

    print("\n" + "=" * 64)
    print("DEMO RESULT:", "ALL VERDICTS AS EXPECTED" if all_ok else "MISMATCH")
    return all_ok


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
