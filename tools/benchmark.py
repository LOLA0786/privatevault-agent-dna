#!/usr/bin/env python3
"""
Reproducible decision-engine benchmark.

Methodology (stated so results can be falsified, not just cited):
  - N decisions run through DecisionEngine.decide() in-process
  - Engine configured with: trained synthetic scorer, invariant
    checker, grant authorizer, UAAL constraint checker — i.e. the
    FULL composed line, not a stripped-down fast path
  - Each run alternates across 5 representative capabilities (the
    same ones from composed_line_demo.py) so no single cheap branch
    dominates the average
  - Wall-clock only (time.perf_counter), single process, no
    concurrency — this measures engine throughput, NOT API/network
    latency, which is a separate, larger number
  - Machine spec is printed with the result so numbers are
    comparable across environments, not treated as universal

Run: python3 tools/benchmark.py [N]   (default N=10000)
"""

import platform
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_dna.decision import DecisionEngine  # noqa: E402
from agent_dna.grants import GrantRegistry  # noqa: E402
from agent_dna.trace import AgentAction  # noqa: E402
from agent_dna.uaal_layer import UAALConstraintChecker  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))
from runtime_demo import train  # noqa: E402


class Invariants:
    def validate(self, capability, previous):
        class R:
            pass

        r = R()
        r.violated = capability == "storage.bulk_export"
        r.message = "forbidden" if r.violated else ""
        return r


CAPS = [
    "crm.read_contact",
    "payment.pay_invoice",
    "storage.bulk_export",
    "payments.initiate_wire",
    "email.send",
]


def build_engine():
    reg = GrantRegistry()
    reg.grant(agent_id="bench-agent", capability="crm.read_contact", granted_by="bench")
    reg.grant(agent_id="bench-agent", capability="email.send", granted_by="bench")
    return DecisionEngine(
        scorer=train(),
        invariants=Invariants(),
        authorizer=reg,
        uaal=UAALConstraintChecker(),
    )


def run(n: int):
    engine = build_engine()
    actions = [
        AgentAction(
            agent_id="bench-agent",
            capability=CAPS[i % len(CAPS)],
            timestamp=0.0,
        )
        for i in range(n)
    ]

    # warmup — exclude JIT/cache effects from the measured window
    for a in actions[: min(100, n)]:
        engine.decide(a)

    start = time.perf_counter()
    for a in actions:
        engine.decide(a)
    elapsed = time.perf_counter() - start

    return elapsed, n


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10_000
    elapsed, n = run(n)

    per_decision_ms = (elapsed / n) * 1000
    per_second = n / elapsed

    print("PrivateVault decision-engine benchmark")
    print("=" * 50)
    print(f"python          : {platform.python_version()}")
    print(f"platform        : {platform.platform()}")
    print(f"processor       : {platform.processor() or 'unknown'}")
    print(f"decisions       : {n}")
    print(f"total time      : {elapsed:.3f}s")
    print(f"mean latency    : {per_decision_ms:.4f} ms/decision")
    print(f"throughput      : {per_second:,.0f} decisions/sec")
    print("=" * 50)
    print("Scope: full composed engine (scorer + invariants + grants +")
    print("UAAL L0), in-process, single-threaded. Excludes HTTP/network")
    print("overhead, persistence, and signing — those are measured")
    print("separately (see benchmark_api.py for the HTTP-inclusive figure).")


if __name__ == "__main__":
    main()
