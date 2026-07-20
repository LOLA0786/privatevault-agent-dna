"""
pv — PrivateVault command line.

Subcommands are deliberately few and CI-shaped: each prints a human
report to stdout, optionally writes machine-readable JSON, and exits
with a contract:

    0  gate passed / verification passed
    1  gate failed (assertions or divergence budget) / verification failed
    2  usage or configuration error

`pv policy check` is the policy-change gate: run it in a pull request
and a rule change becomes reviewable evidence instead of a leap.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import List, Optional

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def _print_report(result, rule_path: str) -> None:
    print(f"\npolicy gate: {rule_path}")
    print("=" * 64)

    if result.assertions:
        print("\nassertions (policy states its own intent):")
        for a in result.assertions:
            mark = "PASS" if a.passed else "FAIL"
            rule = f"  [rule {a.rule_id}]" if a.rule_id else ""
            print(f"  [{mark}] {a.name}: expected {a.expected}, "
                  f"got {a.actual}{rule}")
    else:
        print("\nassertions: none declared "
              "(consider adding them -- a rule that cannot state its "
              "intent is hard to review)")

    cf = result.counterfactual
    if cf is None:
        print("\ncounterfactual: skipped (no history source given)")
    elif cf.get("status") == "unavailable":
        print(f"\ncounterfactual: unavailable — {cf.get('reason')}")
    else:
        print(f"\ncounterfactual vs {cf['source']}:")
        print(f"  decisions replayed   : {cf['replayed']}")
        print(f"  would newly BLOCK    : {cf['would_newly_block']}")
        print(f"  would newly ALLOW    : {cf['would_newly_allow']}")
        print(f"  unchanged            : {cf['unchanged']}")
        if cf.get("candidate_errors"):
            print(f"  candidate errors     : {cf['candidate_errors']}")
        if cf.get("newly_blocked_by_capability"):
            print("  newly blocked by capability:")
            for cap, n in cf["newly_blocked_by_capability"].items():
                print(f"    {cap:<40} {n}")
        if cf.get("sample_newly_blocked"):
            # Honest labelling: fixture rows are a committed corpus and
            # carry no record_hash; only store-mode samples are
            # traceable to sealed records.
            traceable = any(s.get("record_hash")
                            for s in cf["sample_newly_blocked"])
            print("  sample (traceable to sealed records):" if traceable
                  else "  sample (from the committed corpus):")
            for s in cf["sample_newly_blocked"][:5]:
                rh = s.get("record_hash", "")
                suffix = f"  {rh}" if rh else ""
                print(f"    {s.get('decision_id', '?'):<38} "
                      f"{s['capability']:<28} {s['live']} -> {s['shadow']}"
                      f"{suffix}")

    print("\n" + "=" * 64)
    if result.passed:
        print("GATE: PASS — safe to merge on this evidence.")
    else:
        print("GATE: FAIL")
        for v in result.violations:
            print(f"  - {v}")


def cmd_policy_check(args) -> int:
    from .policy_gate import (
        GateResult, counterfactual_from_fixture, counterfactual_from_store,
        evaluate_budget, load_candidate, run_assertions,
    )

    try:
        checker, assertions = load_candidate(args.rule)
    except Exception as e:  # noqa: BLE001
        print(f"error: cannot load rule {args.rule}: {e}", file=sys.stderr)
        return EXIT_USAGE

    result = GateResult(assertions=run_assertions(checker, assertions))

    if args.fixture:
        try:
            result.counterfactual = counterfactual_from_fixture(
                checker, args.fixture)
        except Exception as e:  # noqa: BLE001
            print(f"error: cannot read fixture {args.fixture}: {e}",
                  file=sys.stderr)
            return EXIT_USAGE
    elif args.history_db:
        if not args.replay_fields:
            print("error: --replay-fields is required with --history-db "
                  "(retrospective replay is field-scoped and opt-in; "
                  "see docs/POLICY-REPLAY.md)", file=sys.stderr)
            return EXIT_USAGE
        since = (time.time() - args.since_days * 86400.0
                 if args.since_days else None)
        try:
            result.counterfactual = counterfactual_from_store(
                checker, args.history_db,
                args.replay_db or f"{args.history_db}.replay.db",
                [f.strip() for f in args.replay_fields.split(",") if f.strip()],
                since_ts=since, limit=args.limit)
        except Exception as e:  # noqa: BLE001
            print(f"error: replay failed: {e}", file=sys.stderr)
            return EXIT_USAGE

    result = evaluate_budget(
        result, max_new_blocks=args.max_new_blocks,
        max_new_allows=args.max_new_allows)

    _print_report(result, args.rule)

    if args.json:
        from pathlib import Path
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2))
        print(f"\nmachine-readable report: {args.json}")

    return EXIT_OK if result.passed else EXIT_FAIL


def cmd_policy_suggest(args) -> int:
    from .policy_miner import mine
    from .sqlite_store import SQLiteDecisionStore

    store = SQLiteDecisionStore(args.history_db)
    replay = None
    if args.replay_db or args.replay_fields:
        if not args.replay_fields:
            print("error: --replay-fields is required to mine numeric "
                  "thresholds (field-scoped, opt-in; see "
                  "docs/POLICY-REPLAY.md)", file=sys.stderr)
            return EXIT_USAGE
        from .policy_replay import ReplayInputStore
        replay = ReplayInputStore(
            path=args.replay_db or f"{args.history_db}.replay.db",
            retain_fields=[f.strip() for f in args.replay_fields.split(",")
                           if f.strip()])

    since = (time.time() - args.since_days * 86400.0
             if args.since_days else None)
    candidates = mine(store, replay, since_ts=since,
                      min_support=args.min_support,
                      numeric_field=args.field)

    print(f"\npolicy suggestions from sealed history: {args.history_db}")
    print("=" * 64)
    if not candidates:
        print("\nNo candidates above the support threshold "
              f"(--min-support {args.min_support}). This means the history "
              "shows no repeated pattern the runtime is missing -- not "
              "that none exists.")
    for c in candidates:
        tag = {"policy": "RULE", "grant": "GRANT",
               "advisory": "ADVISORY"}[c.kind]
        print(f"\n[{c.severity}] {tag}  {c.capability}")
        print(f"  {c.rationale}")
        print(f"  backed by {c.support} sealed decision(s)")
        for s in c.evidence.get("sample", c.evidence.get(
                "sample_refused", []))[:3]:
            print(f"    {json.dumps(s)}")
        if c.note:
            print(f"  note: {c.note}")
        if args.out:
            written = c.write(args.out)
            if written:
                print(f"  -> {written}")
                print(f"     gate it:  pv policy check --rule {written} "
                      f"--history-db {args.history_db} "
                      f"--replay-fields {args.field}")

    print("\n" + "=" * 64)
    n_rules = sum(1 for c in candidates if c.kind == "policy")
    print(f"{len(candidates)} candidate(s): {n_rules} gate-ready rule(s), "
          f"{sum(1 for c in candidates if c.kind == 'grant')} grant(s), "
          f"{sum(1 for c in candidates if c.kind == 'advisory')} advisory.")
    print("Nothing here is applied. Every suggestion is a pull request "
          "waiting to be gated and acknowledged by a named human.")

    if args.json:
        from pathlib import Path as _P
        _P(args.json).write_text(json.dumps(
            [c.to_dict() for c in candidates], indent=2))
        print(f"machine-readable: {args.json}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pv", description="PrivateVault decision-security runtime")
    sub = p.add_subparsers(dest="group", required=True)

    policy = sub.add_parser("policy", help="policy tooling")
    psub = policy.add_subparsers(dest="action", required=True)

    check = psub.add_parser(
        "check",
        help="gate a policy change: assertions + counterfactual replay",
        description="Exit 0 = safe to merge, 1 = gate failed, 2 = usage.")
    check.add_argument("--rule", required=True,
                       help="candidate policy document (JSON)")
    check.add_argument("--fixture",
                       help="committed decision corpus (JSONL) — CI mode, "
                            "no production data required")
    check.add_argument("--history-db",
                       help="sealed decision store for retrospective replay")
    check.add_argument("--replay-db",
                       help="replay input sidecar (default: <history-db>.replay.db)")
    check.add_argument("--replay-fields",
                       help="comma-separated retained field allowlist "
                            "(required with --history-db)")
    check.add_argument("--since-days", type=float, default=30.0,
                       help="replay window in days (default 30)")
    check.add_argument("--limit", type=int,
                       help="max decisions to replay")
    check.add_argument("--max-new-blocks", type=int, default=0,
                       help="how many previously-allowed decisions this rule "
                            "may newly block (default 0 — you must "
                            "acknowledge the number)")
    check.add_argument("--max-new-allows", type=int, default=0,
                       help="how many previously-refused decisions this rule "
                            "may newly allow (default 0)")
    check.add_argument("--json", help="write the report as JSON")
    check.set_defaults(func=cmd_policy_check)

    suggest = psub.add_parser(
        "suggest",
        help="mine sealed history for controls that should exist",
        description="Reads the decision log and proposes candidate rules, "
                    "each traced to the records that motivated it. Nothing "
                    "is applied; gate every suggestion with `pv policy "
                    "check` before it ships.")
    suggest.add_argument("--history-db", required=True,
                         help="sealed decision store")
    suggest.add_argument("--replay-db",
                         help="replay input sidecar (default: "
                              "<history-db>.replay.db)")
    suggest.add_argument("--replay-fields",
                         help="retained field allowlist; required to mine "
                              "numeric thresholds")
    suggest.add_argument("--field", default="amount",
                         help="numeric field to mine thresholds on "
                              "(default: amount)")
    suggest.add_argument("--since-days", type=float, default=90.0,
                         help="history window in days (default 90)")
    suggest.add_argument("--min-support", type=int, default=5,
                         help="minimum decisions backing a suggestion "
                              "(default 5)")
    suggest.add_argument("--out",
                         help="directory to write gate-ready policy files")
    suggest.add_argument("--json", help="write all candidates as JSON")
    suggest.set_defaults(func=cmd_policy_suggest)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
