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
from pathlib import Path

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def _authority_json(path: str):
    from .authority_v01 import (
        AuthorityFormatError,
        strict_json_loads,
    )

    try:
        return strict_json_loads(Path(path).read_bytes())
    except OSError as exc:
        raise AuthorityFormatError(f"cannot read {path}: {exc}") from exc


def _scan_json_object(
    line: str,
    path: str,
    line_number: int,
) -> dict[str, object]:
    """Parse an outer history row without weakening receipt validation."""
    from .authority_v01 import AuthorityFormatError

    def no_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise AuthorityFormatError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    def reject_constant(token: str) -> None:
        raise AuthorityFormatError(f"non-finite JSON number: {token}")

    try:
        value = json.loads(
            line,
            object_pairs_hook=no_duplicate_keys,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise AuthorityFormatError(
            f"{path} line {line_number}: invalid JSON: {exc}"
        ) from exc
    except AuthorityFormatError as exc:
        raise AuthorityFormatError(f"{path} line {line_number}: {exc}") from exc

    if not isinstance(value, dict):
        raise AuthorityFormatError(f"{path} line {line_number}: expected JSON object")
    return value


def _authority_jsonl(path: str):
    from .authority_v01 import (
        AuthorityFormatError,
    )

    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AuthorityFormatError(f"cannot read {path}: {exc}") from exc

    records = []

    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue

        records.append(
            _scan_json_object(
                line,
                path,
                line_number,
            )
        )

    return records


def _authority_sqlite(path: str):
    """Read PrivateVault decision bodies from SQLite in read-only mode."""
    import sqlite3

    from .authority_v01 import AuthorityFormatError

    db_path = Path(path)
    try:
        connection = sqlite3.connect(
            f"file:{db_path.resolve()}?mode=ro",
            uri=True,
        )
    except sqlite3.Error as exc:
        raise AuthorityFormatError(f"cannot open {path} read-only: {exc}") from exc

    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if "records" not in tables:
            raise AuthorityFormatError(f"{path}: SQLite history has no records table")

        records = []
        for sequence, body in connection.execute(
            "SELECT seq, body FROM records ORDER BY seq"
        ):
            try:
                value = json.loads(body)
            except (TypeError, json.JSONDecodeError) as exc:
                raise AuthorityFormatError(
                    f"{path} record {sequence}: invalid body JSON: {exc}"
                ) from exc
            if not isinstance(value, dict):
                raise AuthorityFormatError(
                    f"{path} record {sequence}: expected JSON object"
                )
            records.append(value)
        return records
    except sqlite3.Error as exc:
        raise AuthorityFormatError(f"cannot read {path}: {exc}") from exc
    finally:
        connection.close()


def _authority_records(path: str):
    suffix = Path(path).suffix.lower()
    if suffix in {".db", ".sqlite", ".sqlite3"}:
        return _authority_sqlite(path)
    return _authority_jsonl(path)


def cmd_authority_verify(args) -> int:
    from .authority_v01 import (
        AuthorityFormatError,
        verify_receipt,
    )

    try:
        receipt = _authority_json(args.receipt)
        bundle = _authority_json(args.trust_bundle)

        if not isinstance(receipt, dict) or not isinstance(bundle, dict):
            raise AuthorityFormatError("receipt and trust bundle must be JSON objects")

        report = verify_receipt(
            receipt,
            bundle,
        )

    except AuthorityFormatError as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    print(f"evidence_state       {report.evidence_state.value}")
    print(f"decision_conformance {report.decision_conformance.value}")

    if report.accountable_principal:
        print(f"accountable_principal {report.accountable_principal}")

    if report.reason_code:
        print(f"reason_code          {report.reason_code}")

    for failure in report.failures:
        print(f"failure              {failure}")

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                report.to_dict(),
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    return EXIT_OK if report.ok else EXIT_FAIL


def cmd_authority_scan(args) -> int:
    from .authority_v01 import (
        AuthorityFormatError,
        scan_authority_records,
    )

    try:
        records = _authority_records(args.input)

        bundle = _authority_json(args.trust_bundle) if args.trust_bundle else None

        if bundle is not None and not isinstance(bundle, dict):
            raise AuthorityFormatError("trust bundle must be a JSON object")

        report = scan_authority_records(
            records,
            bundle,
        )

    except AuthorityFormatError as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    evidence = report["evidence_state"]
    conformance = report["decision_conformance"]

    print("\npv authority scan - AUTHORISATION READINESS ASSESSMENT")
    print("=" * 64)

    print(f"Actions analysed   {report['actions_analysed']}")

    print(
        "Evidence           "
        f"VERIFIED {evidence['VERIFIED']}   "
        f"INVALID {evidence['INVALID']}   "
        f"UNVERIFIABLE {evidence['UNVERIFIABLE']}   "
        f"ABSENT {evidence['ABSENT']}"
    )
    print(
        "Conformance        "
        f"CONFORMANT {conformance['CONFORMANT']}   "
        f"NON_CONFORMANT {conformance['NON_CONFORMANT']}   "
        f"NOT_ASSESSABLE {conformance['NOT_ASSESSABLE']}"
    )

    if report["critical_findings"]:
        print("\nCRITICAL FINDINGS")
        for finding in report["critical_findings"]:
            print(f"row {finding['row']}  {finding['finding']}")
            if finding.get("accountable_principal"):
                print(f"  accountable_principal {finding['accountable_principal']}")
            for failure in finding.get("failures", []):
                print(f"  failure {failure}")

    if evidence["ABSENT"]:
        print("\nFINDING")
        print("Your agent infrastructure does not currently emit authority evidence.")
        print("This is the industry norm; the result measures instrumentation.")

    if args.json:
        Path(args.json).write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )

    failed = evidence["INVALID"] > 0 or conformance["NON_CONFORMANT"] > 0
    return EXIT_FAIL if failed else EXIT_OK


def cmd_loop_discover(args: argparse.Namespace) -> int:
    """Discover security-relevant loops in strict JSONL telemetry."""
    from .authority_v01 import AuthorityFormatError
    from .security.loop_discovery import (
        LoopDecision,
        LoopFormatError,
        discover_loops,
    )

    try:
        report = discover_loops(_authority_jsonl(args.input))
    except (AuthorityFormatError, LoopFormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print("\npv loop discover - AGENT SECURITY LOOP ASSESSMENT")
    print("=" * 64)
    print(f"Decision          {report.decision.value}")
    print(f"Events analyzed   {report.events_analyzed}")
    print(f"Traces analyzed   {report.traces_analyzed}")
    print(f"Report ID         {report.report_id}")

    for finding in report.findings:
        print(
            f"\n[{finding.disposition.value}] {finding.reason_code} "
            f"({finding.severity.value})"
        )
        print(f"  trace   {finding.trace_id}")
        if finding.agent_ids:
            print(f"  agents  {', '.join(finding.agent_ids)}")
        if finding.event_ids:
            print(f"  events  {', '.join(finding.event_ids)}")
        print(f"  detail  {finding.detail}")

    if args.json:
        Path(args.json).write_text(
            json.dumps(report.to_dict(), indent=2) + "\n",
            encoding="utf-8",
        )

    return EXIT_OK if report.decision is LoopDecision.ALLOW else EXIT_FAIL


def _print_report(result, rule_path: str) -> None:  # noqa: C901
    print(f"\npolicy gate: {rule_path}")
    print("=" * 64)

    if result.assertions:
        print("\nassertions (policy states its own intent):")
        for a in result.assertions:
            mark = "PASS" if a.passed else "FAIL"
            rule = f"  [rule {a.rule_id}]" if a.rule_id else ""
            print(f"  [{mark}] {a.name}: expected {a.expected}, got {a.actual}{rule}")
    else:
        print(
            "\nassertions: none declared "
            "(consider adding them -- a rule that cannot state its "
            "intent is hard to review)"
        )

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
            traceable = any(s.get("record_hash") for s in cf["sample_newly_blocked"])
            print(
                "  sample (traceable to sealed records):"
                if traceable
                else "  sample (from the committed corpus):"
            )
            for s in cf["sample_newly_blocked"][:5]:
                rh = s.get("record_hash", "")
                suffix = f"  {rh}" if rh else ""
                print(
                    f"    {s.get('decision_id', '?'):<38} "
                    f"{s['capability']:<28} {s['live']} -> {s['shadow']}"
                    f"{suffix}"
                )

    print("\n" + "=" * 64)
    if result.passed:
        print("GATE: PASS — safe to merge on this evidence.")
    else:
        print("GATE: FAIL")
        for v in result.violations:
            print(f"  - {v}")


def cmd_policy_check(args) -> int:
    from .policy_gate import (
        GateResult,
        counterfactual_from_fixture,
        counterfactual_from_store,
        evaluate_budget,
        load_candidate,
        run_assertions,
    )

    try:
        checker, assertions = load_candidate(args.rule)
    except Exception as e:  # noqa: BLE001
        print(f"error: cannot load rule {args.rule}: {e}", file=sys.stderr)
        return EXIT_USAGE

    result = GateResult(assertions=run_assertions(checker, assertions))

    if args.fixture:
        try:
            result.counterfactual = counterfactual_from_fixture(checker, args.fixture)
        except Exception as e:  # noqa: BLE001
            print(f"error: cannot read fixture {args.fixture}: {e}", file=sys.stderr)
            return EXIT_USAGE
    elif args.history_db:
        if not args.replay_fields:
            print(
                "error: --replay-fields is required with --history-db "
                "(retrospective replay is field-scoped and opt-in; "
                "see docs/POLICY-REPLAY.md)",
                file=sys.stderr,
            )
            return EXIT_USAGE
        since = time.time() - args.since_days * 86400.0 if args.since_days else None
        try:
            result.counterfactual = counterfactual_from_store(
                checker,
                args.history_db,
                args.replay_db or f"{args.history_db}.replay.db",
                [f.strip() for f in args.replay_fields.split(",") if f.strip()],
                since_ts=since,
                limit=args.limit,
            )
        except Exception as e:  # noqa: BLE001
            print(f"error: replay failed: {e}", file=sys.stderr)
            return EXIT_USAGE

    result = evaluate_budget(
        result, max_new_blocks=args.max_new_blocks, max_new_allows=args.max_new_allows
    )

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
            print(
                "error: --replay-fields is required to mine numeric "
                "thresholds (field-scoped, opt-in; see "
                "docs/POLICY-REPLAY.md)",
                file=sys.stderr,
            )
            return EXIT_USAGE
        from .policy_replay import ReplayInputStore

        replay = ReplayInputStore(
            path=args.replay_db or f"{args.history_db}.replay.db",
            retain_fields=[
                f.strip() for f in args.replay_fields.split(",") if f.strip()
            ],
        )

    since = time.time() - args.since_days * 86400.0 if args.since_days else None
    candidates = mine(
        store,
        replay,
        since_ts=since,
        min_support=args.min_support,
        numeric_field=args.field,
    )

    print(f"\npolicy suggestions from sealed history: {args.history_db}")
    print("=" * 64)
    if not candidates:
        print(
            "\nNo candidates above the support threshold "
            f"(--min-support {args.min_support}). This means the history "
            "shows no repeated pattern the runtime is missing -- not "
            "that none exists."
        )
    for c in candidates:
        tag = {"policy": "RULE", "grant": "GRANT", "advisory": "ADVISORY"}[c.kind]
        print(f"\n[{c.severity}] {tag}  {c.capability}")
        print(f"  {c.rationale}")
        print(f"  backed by {c.support} sealed decision(s)")
        for s in c.evidence.get("sample", c.evidence.get("sample_refused", []))[:3]:
            print(f"    {json.dumps(s)}")
        if c.note:
            print(f"  note: {c.note}")
        if args.out:
            written = c.write(args.out)
            if written:
                print(f"  -> {written}")
                print(
                    f"     gate it:  pv policy check --rule {written} "
                    f"--history-db {args.history_db} "
                    f"--replay-fields {args.field}"
                )

    print("\n" + "=" * 64)
    n_rules = sum(1 for c in candidates if c.kind == "policy")
    print(
        f"{len(candidates)} candidate(s): {n_rules} gate-ready rule(s), "
        f"{sum(1 for c in candidates if c.kind == 'grant')} grant(s), "
        f"{sum(1 for c in candidates if c.kind == 'advisory')} advisory."
    )
    print(
        "Nothing here is applied. Every suggestion is a pull request "
        "waiting to be gated and acknowledged by a named human."
    )

    if args.json:
        Path(args.json).write_text(
            json.dumps([c.to_dict() for c in candidates], indent=2)
        )
        print(f"machine-readable: {args.json}")
    return EXIT_OK


def cmd_discovery_run(args: argparse.Namespace) -> int:  # noqa: C901
    """Run one offline proposal-only discovery cycle."""
    from .authority_v01 import AuthorityFormatError
    from .discovery import (
        DiscoveryConfig,
        DiscoveryInputError,
        DiscoveryStatus,
        load_adversarial_fixture,
        run_discovery,
    )
    from .policy_replay import ReplayInputStore
    from .security.loop_discovery import LoopFormatError
    from .sqlite_store import SQLiteDecisionStore

    history_path = Path(args.history_db)
    if not history_path.is_file():
        print(
            f"error: history database does not exist: {history_path}", file=sys.stderr
        )
        return EXIT_USAGE
    if args.since_days is not None and args.since_days < 0:
        print("error: --since-days must be non-negative", file=sys.stderr)
        return EXIT_USAGE
    if args.replay_db and not args.replay_fields:
        print("error: --replay-fields is required with --replay-db", file=sys.stderr)
        return EXIT_USAGE

    store = None
    replay = None
    try:
        store = SQLiteDecisionStore(history_path)
        if args.replay_fields:
            replay_path = Path(args.replay_db or f"{args.history_db}.replay.db")
            if not replay_path.is_file():
                raise DiscoveryInputError(
                    f"replay database does not exist: {replay_path}"
                )
            fields = [field.strip() for field in args.replay_fields.split(",")]
            fields = [field for field in fields if field]
            if not fields:
                raise DiscoveryInputError("--replay-fields cannot be empty")
            replay = ReplayInputStore(str(replay_path), fields)

        since_ts = time.time() - args.since_days * 86400.0 if args.since_days else None
        adversarial = (
            load_adversarial_fixture(args.adversarial_fixture)
            if args.adversarial_fixture
            else None
        )
        loop_events = _authority_jsonl(args.loop_events) if args.loop_events else None
        validation = (
            _authority_json(args.validation_report) if args.validation_report else None
        )
        if validation is not None and not isinstance(validation, dict):
            raise DiscoveryInputError("validation report must be a JSON object")

        result = run_discovery(
            store,
            replay,
            adversarial_rows=adversarial,
            loop_events=loop_events,
            validation_envelope=validation,
            config=DiscoveryConfig(
                min_support=args.min_support,
                numeric_field=args.field,
                since_ts=since_ts,
                max_new_blocks=args.max_new_blocks,
                max_candidates=args.max_candidates,
                max_history_records=args.max_history_records,
                max_adversarial_rows=args.max_adversarial_rows,
                as_of=float(int(time.time())),
            ),
        )
    except (
        DiscoveryInputError,
        AuthorityFormatError,
        LoopFormatError,
        ValueError,
    ) as exc:
        print(f"error: discovery run refused unsafe input: {exc}", file=sys.stderr)
        return EXIT_USAGE
    finally:
        if replay is not None:
            replay.close()
        if store is not None:
            store.close()

    body = result.envelope["body"]
    counts = body["disposition_counts"]
    print("\npv discover run - PRIVATEVAULT DISCOVERY LOOP")
    print("=" * 64)
    print(f"Status             {body['status']}")
    print(f"Sealed decisions   {body['source_counts']['sealed_decisions']}")
    print(f"Candidates         {body['source_counts']['candidates']}")
    print(
        "Disposition        "
        f"PROPOSE {counts['PROPOSE']}   REVIEW {counts['REVIEW']}   "
        f"REJECT {counts['REJECT']}   ADVISORY {counts['ADVISORY']}"
    )
    print(f"Report hash        {result.report_hash}")

    if args.out_dir:
        paths = result.write_proposals(args.out_dir)
        print(f"Proposal files     {len(paths)} written under {args.out_dir}")
    if args.json:
        Path(args.json).write_text(
            json.dumps(result.envelope, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Report             {args.json}")

    print("Nothing was applied. PROPOSE means ready for a human-reviewed PR.")
    return EXIT_FAIL if result.status is DiscoveryStatus.STRUCTURAL_BLOCK else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pv", description="PrivateVault decision-security runtime"
    )
    sub = p.add_subparsers(dest="group", required=True)

    policy = sub.add_parser("policy", help="policy tooling")
    psub = policy.add_subparsers(dest="action", required=True)

    check = psub.add_parser(
        "check",
        help="gate a policy change: assertions + counterfactual replay",
        description="Exit 0 = safe to merge, 1 = gate failed, 2 = usage.",
    )
    check.add_argument("--rule", required=True, help="candidate policy document (JSON)")
    check.add_argument(
        "--fixture",
        help="committed decision corpus (JSONL) — CI mode, no production data required",
    )
    check.add_argument(
        "--history-db", help="sealed decision store for retrospective replay"
    )
    check.add_argument(
        "--replay-db", help="replay input sidecar (default: <history-db>.replay.db)"
    )
    check.add_argument(
        "--replay-fields",
        help="comma-separated retained field allowlist (required with --history-db)",
    )
    check.add_argument(
        "--since-days",
        type=float,
        default=30.0,
        help="replay window in days (default 30)",
    )
    check.add_argument("--limit", type=int, help="max decisions to replay")
    check.add_argument(
        "--max-new-blocks",
        type=int,
        default=0,
        help="how many previously-allowed decisions this rule "
        "may newly block (default 0 — you must "
        "acknowledge the number)",
    )
    check.add_argument(
        "--max-new-allows",
        type=int,
        default=0,
        help="how many previously-refused decisions this rule "
        "may newly allow (default 0)",
    )
    check.add_argument("--json", help="write the report as JSON")
    check.set_defaults(func=cmd_policy_check)

    suggest = psub.add_parser(
        "suggest",
        help="mine sealed history for controls that should exist",
        description="Reads the decision log and proposes candidate rules, "
        "each traced to the records that motivated it. Nothing "
        "is applied; gate every suggestion with `pv policy "
        "check` before it ships.",
    )
    suggest.add_argument("--history-db", required=True, help="sealed decision store")
    suggest.add_argument(
        "--replay-db", help="replay input sidecar (default: <history-db>.replay.db)"
    )
    suggest.add_argument(
        "--replay-fields",
        help="retained field allowlist; required to mine numeric thresholds",
    )
    suggest.add_argument(
        "--field",
        default="amount",
        help="numeric field to mine thresholds on (default: amount)",
    )
    suggest.add_argument(
        "--since-days",
        type=float,
        default=90.0,
        help="history window in days (default 90)",
    )
    suggest.add_argument(
        "--min-support",
        type=int,
        default=5,
        help="minimum decisions backing a suggestion (default 5)",
    )
    suggest.add_argument("--out", help="directory to write gate-ready policy files")
    suggest.add_argument("--json", help="write all candidates as JSON")
    suggest.set_defaults(func=cmd_policy_suggest)

    authority = sub.add_parser(
        "authority",
        help=("authority provenance verification and readiness scan"),
    )

    asub = authority.add_subparsers(
        dest="action",
        required=True,
    )

    verify = asub.add_parser(
        "verify",
        help=("verify one v0.1-experimental authority receipt"),
    )
    verify.add_argument(
        "--receipt",
        required=True,
    )
    verify.add_argument(
        "--trust-bundle",
        required=True,
    )
    verify.add_argument(
        "--json",
        help="write machine-readable result",
    )
    verify.set_defaults(func=cmd_authority_verify)

    scan = asub.add_parser(
        "scan",
        help=(
            "assess authority-evidence readiness "
            "in JSONL records or PrivateVault SQLite history"
        ),
    )
    scan.add_argument(
        "--input",
        required=True,
    )
    scan.add_argument("--trust-bundle")
    scan.add_argument(
        "--json",
        help="write machine-readable report",
    )
    scan.set_defaults(func=cmd_authority_scan)

    loop = sub.add_parser(
        "loop",
        help="deterministic cross-agent loop discovery",
    )
    lsub = loop.add_subparsers(dest="action", required=True)
    discover = lsub.add_parser(
        "discover",
        help="analyze strict agent-security event JSONL",
        description=(
            "Exit 0 = no loop finding, 1 = review or block finding, "
            "2 = malformed or unsafe input."
        ),
    )
    discover.add_argument("--input", required=True, help="event JSONL")
    discover.add_argument("--json", help="write machine-readable report")
    discover.set_defaults(func=cmd_loop_discover)

    discovery = sub.add_parser(
        "discover",
        help="run the offline proposal/evaluate/iterate discovery loop",
    )
    dsub = discovery.add_subparsers(dest="action", required=True)
    run = dsub.add_parser(
        "run",
        help="mine and evaluate policy candidates without applying them",
        description=(
            "Verify sealed history, mine candidates, replay them additively, "
            "run optional security probes, and emit a sealed proposal report."
        ),
    )
    run.add_argument("--history-db", required=True, help="sealed decision store")
    run.add_argument("--replay-db", help="opt-in replay-input sidecar")
    run.add_argument(
        "--replay-fields",
        help="comma-separated retained argument fields (required with replay DB)",
    )
    run.add_argument(
        "--adversarial-fixture",
        help="committed pv-discovery-adversarial-row/1.0 JSONL corpus",
    )
    run.add_argument("--loop-events", help="strict agent-security event JSONL")
    run.add_argument("--validation-report", help="sealed pv-validation/1 report")
    run.add_argument("--field", default="amount", help="numeric field to mine")
    run.add_argument("--since-days", type=float, default=90.0)
    run.add_argument("--min-support", type=int, default=5)
    run.add_argument("--max-new-blocks", type=int, default=0)
    run.add_argument("--max-candidates", type=int, default=100)
    run.add_argument("--max-history-records", type=int, default=100_000)
    run.add_argument("--max-adversarial-rows", type=int, default=10_000)
    run.add_argument("--out-dir", help="write PR-ready policies and review notes")
    run.add_argument("--json", help="write sealed discovery report")
    run.set_defaults(func=cmd_discovery_run)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
