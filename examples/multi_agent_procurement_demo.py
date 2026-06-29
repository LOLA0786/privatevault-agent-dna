"""End-to-end CABI demo on a procurement workflow.

Normal society:  planner -> risk -> finance -> approval -> payment

We synthesize many known-good executions, learn the organizational DNA, then
throw four adversarial executions at the runtime validator and watch it return
ALLOW / REVIEW / BLOCK with explanations.

Run:  python -m examples.multi_agent_procurement_demo
"""
from __future__ import annotations

import random

from agent_dna.multi_agent import InteractionEvent, RuntimeValidator, Verdict

ROLE_OF = {
    "planner": "planning",
    "risk": "risk",
    "finance": "finance",
    "approval": "approval",
    "payment": "payment",
}

# the sanctioned chain of hand-offs
CHAIN = ["planner", "risk", "finance", "approval", "payment"]


def make_event(exec_id, src, dst, t):
    return InteractionEvent(
        execution_id=exec_id,
        source=src, target=dst,
        source_role=ROLE_OF.get(src, "unknown"),
        target_role=ROLE_OF.get(dst, "unknown"),
        timestamp=t,
        trust=round(random.uniform(0.8, 1.0), 3),
        tool=f"{dst}.handle",
        intent="procure_vendor",
        approval=(dst == "approval"),
    )


def good_execution(exec_id: str) -> list[InteractionEvent]:
    events, t = [], 0.0
    for src, dst in zip(CHAIN, CHAIN[1:]):
        t += random.uniform(1.0, 3.0)        # jittered but monotonic
        events.append(make_event(exec_id, src, dst, t))
    return events


def build_corpus(n: int = 400) -> list[InteractionEvent]:
    corpus: list[InteractionEvent] = []
    for i in range(n):
        corpus.extend(good_execution(f"train-{i}"))
    return corpus


# ---- adversarial executions ----------------------------------------------
def attack_topology_skip(exec_id="atk-topo"):
    # planner jumps straight to payment, skipping every control
    return [make_event(exec_id, "planner", "payment", 1.0)]


def attack_temporal_reorder(exec_id="atk-temporal"):
    # payment fires before finance approves
    ev = []
    ev.append(make_event(exec_id, "planner", "risk", 1.0))
    ev.append(make_event(exec_id, "risk", "payment", 2.0))   # pay early
    ev.append(make_event(exec_id, "payment", "finance", 3.0))  # finance after
    ev.append(make_event(exec_id, "finance", "approval", 4.0))
    return ev


def attack_authority(exec_id="atk-authority"):
    # a rogue marketing agent drives the payment agent
    ev = good_execution(exec_id)
    ev.append(InteractionEvent(
        execution_id=exec_id, source="marketing_bot", target="payment",
        source_role="marketing", target_role="payment",
        timestamp=99.0, tool="payment.handle", intent="promo_payout",
    ))
    return ev


def benign_novelty(exec_id="atk-novel"):
    # finance also pings a (new) audit agent -- unusual but not a breach
    ev = good_execution(exec_id)
    ev.append(make_event(exec_id, "finance", "audit", 2.5))
    return ev


def run():
    random.seed(7)
    validator = RuntimeValidator.from_corpus(build_corpus())

    print("Learned organizational DNA:")
    import json
    print(json.dumps(validator.engine.describe(), indent=2))
    print("=" * 64)

    cases = [
        ("known-good execution", good_execution("live-ok")),
        ("topology skip (planner->payment)", attack_topology_skip()),
        ("temporal reorder (pay before finance)", attack_temporal_reorder()),
        ("authority breach (marketing->payment)", attack_authority()),
        ("benign novelty (finance->audit)", benign_novelty()),
    ]

    expected = {
        "known-good execution": Verdict.ALLOW,
        "topology skip (planner->payment)": Verdict.BLOCK,
        "temporal reorder (pay before finance)": Verdict.BLOCK,
        "authority breach (marketing->payment)": Verdict.BLOCK,
        "benign novelty (finance->audit)": Verdict.REVIEW,
    }

    all_ok = True
    for label, events in cases:
        v = validator.validate_events(events)
        ok = v.verdict is expected[label]
        all_ok &= ok
        print(f"\n### {label}  ->  {v.verdict.value}  "
            f"[{'as expected' if ok else 'UNEXPECTED'}]")
        print(v.explain())

    print("\n" + "=" * 64)
    print("DEMO RESULT:", "ALL VERDICTS AS EXPECTED" if all_ok else "MISMATCH")
    return all_ok


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
