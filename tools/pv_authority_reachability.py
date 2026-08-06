#!/usr/bin/env python3
"""Offline CLI for Authority Reachability v0.1-experimental.

The CLI is runtime-coupled to the experimental Python implementation. It is
not an independently implemented verifier.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Permit direct execution from a source checkout.
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1]),
)

from agent_dna.authority_v01 import strict_json_loads  # noqa: E402
from experimental.authority_reachability_v01 import (  # noqa: E402
    AuthorityGraph,
    MappedCompanyGraphAdapter,
    ProtectedSink,
    analyze_change,
    analyze_reachability,
)


def _json(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def _load_graph(
    source_path: Path,
    mapping_path: Path,
) -> AuthorityGraph:
    source = _json(source_path)
    mapping = _json(mapping_path)
    adapter = mapping["adapter"]

    sinks = tuple(
        ProtectedSink.from_dict(
            item,
            f"mapping.protected_sinks[{index}]",
        )
        for index, item in enumerate(mapping["protected_sinks"])
    )

    return MappedCompanyGraphAdapter(
        source,
        source_system=adapter["source_system"],
        adapter_version=adapter["adapter_version"],
        node_mapping=mapping["node_mapping"],
        edge_mapping=mapping["edge_mapping"],
        protected_sinks=sinks,
    ).load()


def _context(
    path: Path | None,
) -> dict[str, Any]:
    return _json(path) if path is not None else {}


def _write_json(
    value: dict[str, Any],
    destination: str | None,
) -> None:
    encoded = (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    if destination == "-":
        print(encoded, end="")
    elif destination:
        Path(destination).write_text(
            encoded,
            encoding="utf-8",
        )


def _print_report(
    report: dict[str, Any],
) -> None:
    print("PRIVATEVAULT AUTHORITY REACHABILITY")
    print("=" * 68)
    print(f"Graph              {report['graph_id']}")
    print(f"Source             {report['source_node_id']}")
    print(f"Graph hash         {report['graph_hash']}")

    for finding in report["findings"]:
        print()
        print(f"Sink               {finding['sink_node_id']}")
        print(f"Severity           {finding['severity']}")
        print(f"State              {finding['state']}")
        print("Reason             " + ", ".join(finding["reason_codes"]))

        witness = finding["witness"]
        if witness:
            print(f"Hops               {witness['hop_count']}")
            print("Path               " + " -> ".join(witness["node_ids"]))
            print(
                "Evidence           "
                + ", ".join(
                    f"{key}={count}" for key, count in witness["evidence"].items()
                )
            )


def _analyze(
    args: argparse.Namespace,
) -> int:
    graph = _load_graph(
        args.graph,
        args.mapping,
    )

    report = analyze_reachability(
        graph,
        source_node_id=args.source,
        context=_context(args.context),
    ).to_dict()

    if args.json != "-":
        _print_report(report)

    _write_json(
        report,
        args.json,
    )

    return 1 if report["summary"]["PROHIBITED_REACHABLE"] else 0


def _simulate(
    args: argparse.Namespace,
) -> int:
    before = _load_graph(
        args.before,
        args.mapping,
    )
    after = _load_graph(
        args.after,
        args.mapping,
    )

    change = analyze_change(
        before,
        after,
        source_node_id=args.source,
        context=_context(args.context),
    ).to_dict()

    if args.json != "-":
        _print_report(change["after"])
        print()
        print("PROPOSED CHANGE")
        print("=" * 68)
        print(
            "New reachable      "
            + (", ".join(change["newly_reachable_sinks"]) or "none")
        )
        print(
            "New prohibited     "
            + (", ".join(change["newly_prohibited_sinks"]) or "none")
        )
        print(f"Decision           {change['decision']}")

    _write_json(
        change,
        args.json,
    )

    return 1 if change["decision"] == "BLOCK_PROPOSED_CHANGE" else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pv-authority-reachability",
        description=("deterministic blast-radius analysis over authority graphs"),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    analyze = subparsers.add_parser(
        "analyze",
        help="analyze one graph snapshot",
    )
    analyze.add_argument(
        "graph",
        type=Path,
    )
    analyze.add_argument(
        "mapping",
        type=Path,
    )
    analyze.add_argument(
        "--source",
        required=True,
    )
    analyze.add_argument(
        "--context",
        type=Path,
    )
    analyze.add_argument(
        "--json",
        metavar="PATH",
        help="write JSON; use - for stdout",
    )
    analyze.set_defaults(
        handler=_analyze,
    )

    simulate = subparsers.add_parser(
        "simulate",
        help=("compare graph snapshots before a proposed change"),
    )
    simulate.add_argument(
        "before",
        type=Path,
    )
    simulate.add_argument(
        "after",
        type=Path,
    )
    simulate.add_argument(
        "mapping",
        type=Path,
    )
    simulate.add_argument(
        "--source",
        required=True,
    )
    simulate.add_argument(
        "--context",
        type=Path,
    )
    simulate.add_argument(
        "--json",
        metavar="PATH",
        help="write JSON; use - for stdout",
    )
    simulate.set_defaults(
        handler=_simulate,
    )

    return parser


def main(
    argv: list[str] | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return int(args.handler(args))
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        parser.exit(
            2,
            f"error: {exc}\n",
        )


if __name__ == "__main__":
    raise SystemExit(main())
