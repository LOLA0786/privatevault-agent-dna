"""Latency of the PrivateVault approval-binding check in the LangGraph HITL flow.

Two arms, identical graph shape / checkpointer / interrupt():
  baseline  : build_plain_graph  (no PrivateVault)
  treatment : build_graph        (decide + record + bind + mint + verify + consume + outcome)

Each iteration = one full tool call: invoke (propose, approve->interrupt) then
programmatic Command(resume=...) (approve-after-resume, execute).  No human wait
is in the loop.  Arm order is randomised per iteration; a warm-up runs first.
Measured with perf_counter_ns around the two graph calls.

Usage:
  uv run --no-sync python examples/langgraph_hitl/bench_latency.py [--n 600] [--sleep-n 100]
"""

from __future__ import annotations

import argparse
import platform
import random
import sqlite3
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import agent as A  # noqa: E402, N812
from langgraph.types import Command  # noqa: E402

CALL = {
    "id": "c1",
    "name": "send_payment",
    "args": {"to": "acct-1", "amount": 5000, "currency": "USD"},
}


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def summarize(name, xs):
    m = statistics.fmean(xs)
    sd = statistics.stdev(xs) if len(xs) > 1 else 0.0
    ci = 1.96 * sd / (len(xs) ** 0.5)
    return (
        f"{name:<12} n={len(xs):<5} p50={pct(xs, 50):8.3f}  p95={pct(xs, 95):8.3f}  "
        f"p99={pct(xs, 99):8.3f}  mean={m:8.3f} +/-{ci:.3f} ms"
    )


def one_call(graph, tid, *, blocked=False):
    cfg = {"configurable": {"thread_id": tid}}
    t0 = time.perf_counter_ns()
    out = graph.invoke({"incoming": [CALL], "calls": {}, "results": []}, cfg)
    d = out["__interrupt__"][0].value["action_digest"]
    graph.invoke(
        Command(
            resume={
                "decision": "approve",
                "action_digest": d,
                "reviewer": "reviewer:alice",
            }
        ),
        cfg,
    )
    return (time.perf_counter_ns() - t0) / 1e6


def blocked_call(gate, graph, tid):
    """Approve, pause before execute, edit args, resume => verify fails + block + burn."""
    cfg = {"configurable": {"thread_id": tid}}
    graph.invoke({"incoming": [CALL], "calls": {}, "results": []}, cfg)
    d = graph.get_state(cfg).interrupts[0].value["action_digest"]
    graph.invoke(
        Command(
            resume={
                "decision": "approve",
                "action_digest": d,
                "reviewer": "reviewer:alice",
            }
        ),
        cfg,
    )
    graph.update_state(
        cfg, {"calls": {"c1": {"args": {**CALL["args"], "amount": 50000}}}}
    )
    t0 = time.perf_counter_ns()
    graph.invoke(None, cfg)
    return (time.perf_counter_ns() - t0) / 1e6


def run(n, warm, tool, tmpdir, label):
    A.SENT.clear()
    timings: dict[str, list[float]] = {}
    gate = A.PVGate(Path(tmpdir) / f"pv_{label}.db", timings=timings)
    base = A.build_plain_graph(tool=tool)
    treat = A.build_graph(gate, tool=tool)
    for i in range(warm):
        one_call(base, f"w-b-{i}")
        one_call(treat, f"w-t-{i}")
    for k in timings:
        timings[k].clear()
    res = {"baseline": [], "treatment": []}
    for i in range(n):
        arms = [("baseline", base), ("treatment", treat)]
        random.shuffle(arms)
        for name, g in arms:
            res[name].append(one_call(g, f"{name}-{i}"))
    return res, timings, gate


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=600)
    ap.add_argument("--warm", type=int, default=100)
    ap.add_argument("--sleep-n", type=int, default=100)
    ap.add_argument("--sleep-ms", type=float, default=100.0)
    args = ap.parse_args()
    random.seed(1)

    print(
        f"python {platform.python_version()} | {platform.platform()} | {platform.processor()}"
    )
    print(f"sqlite {sqlite3.sqlite_version}")

    with tempfile.TemporaryDirectory(
        prefix="pvbench_", ignore_cleanup_errors=True
    ) as tmp:
        t0 = time.perf_counter()
        A.PVGate(Path(tmp) / "once.db")
        print(
            f"one-time gate setup (key gen, store, engine): {(time.perf_counter() - t0) * 1e3:.1f} ms\n"
        )

        def zero_tool(**kw):
            return "ok"

        res, timings, gate = run(args.n, args.warm, zero_tool, tmp, "zero")
        print(
            f"== Arm comparison, zero-latency mock tool (worst-case relative overhead), N={args.n}/arm =="
        )
        print(summarize("baseline", res["baseline"]))
        print(summarize("treatment", res["treatment"]))
        d50 = pct(res["treatment"], 50) - pct(res["baseline"], 50)
        dm = statistics.fmean(res["treatment"]) - statistics.fmean(res["baseline"])
        print(
            f"added by check: p50 +{d50:.3f} ms, mean +{dm:.3f} ms "
            f"({dm / statistics.fmean(res['baseline']) * 100:.0f}% of baseline mean)\n"
        )

        print(
            "== Treatment per-stage breakdown (ms per tool call, summed over calls in that stage) =="
        )
        for stage in ("decide", "record", "bind", "mint", "verify", "outcome"):
            xs = timings.get(stage, [])
            if xs:
                print(
                    f"  {stage:<8} calls={len(xs):<6} mean={statistics.fmean(xs):7.3f} "
                    f"p50={pct(xs, 50):7.3f} p95={pct(xs, 95):7.3f} p99={pct(xs, 99):7.3f}"
                )
        print(
            "  (decide/record occur twice per call: propose + approval re-decide;"
            " consume is inside 'verify' via consume_ledger)\n"
        )

        # blocked path
        bgate = A.PVGate(Path(tmp) / "pv_blocked.db")
        bg = A.build_graph(bgate, interrupt_before=["execute"])
        for i in range(args.warm):
            blocked_call(bgate, bg, f"bw-{i}")
        bx = [blocked_call(bgate, bg, f"b-{i}") for i in range(min(args.n, 300))]
        A.SENT.clear()
        print(
            "== Blocked path (execute node only: verify fail + block record + burn), "
            f"N={len(bx)} =="
        )
        print(summarize("blocked", bx))
        ok_gate = A.PVGate(Path(tmp) / "pv_okexec.db")
        og = A.build_graph(ok_gate, interrupt_before=["execute"])
        ox = []
        for i in range(args.warm + min(args.n, 300)):
            cfg = {"configurable": {"thread_id": f"o-{i}"}}
            og.invoke({"incoming": [CALL], "calls": {}, "results": []}, cfg)
            d = og.get_state(cfg).interrupts[0].value["action_digest"]
            og.invoke(
                Command(
                    resume={
                        "decision": "approve",
                        "action_digest": d,
                        "reviewer": "reviewer:alice",
                    }
                ),
                cfg,
            )
            t0 = time.perf_counter_ns()
            og.invoke(None, cfg)
            if i >= args.warm:
                ox.append((time.perf_counter_ns() - t0) / 1e6)
        print(summarize("happy exec", ox))
        print("  (both: execute node only, for comparison)\n")

        # realistic I/O
        def slow_tool(**kw):
            time.sleep(args.sleep_ms / 1000)
            return "ok"

        res2, _, _ = run(args.sleep_n, 20, slow_tool, tmp, "slow")
        print(
            f"== Arm comparison, mock tool sleeping {args.sleep_ms:.0f} ms, N={args.sleep_n}/arm =="
        )
        print(summarize("baseline", res2["baseline"]))
        print(summarize("treatment", res2["treatment"]))
        dm2 = statistics.fmean(res2["treatment"]) - statistics.fmean(res2["baseline"])
        print(
            f"added by check: mean +{dm2:.3f} ms = {dm2 / args.sleep_ms * 100:.1f}% of the {args.sleep_ms:.0f} ms tool call"
        )
        print(
            "\nCaveats: single machine, one filesystem (see platform line), InMemorySaver for both arms, "
            "treatment DB on the temp dir's disk (fsync cost included, no tmpfs run), "
            "treatment resume includes digest echo by the reviewer stub."
        )


if __name__ == "__main__":
    main()
