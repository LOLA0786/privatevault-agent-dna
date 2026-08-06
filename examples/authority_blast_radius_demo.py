#!/usr/bin/env python3
"""CTO demonstration of deterministic identity blast-radius analysis."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experimental.authority_reachability_v01 import (  # noqa: E402
    AuthorityGraph,
    MappedCompanyGraphAdapter,
    ProtectedSink,
    analyze_change,
)

VECTORS = Path("spec/authority-reachability-v01/vectors")
PAYMENT_SINK = "sink:payment-execute"


def _load(name: str) -> dict[str, Any]:
    value: Any = json.loads((VECTORS / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{name}: expected JSON object")
    return value


def _graph(name: str) -> AuthorityGraph:
    mapping = _load("adapter-mapping.json")
    adapter = mapping["adapter"]
    sinks = tuple(
        ProtectedSink.from_dict(item, f"protected_sinks[{index}]")
        for index, item in enumerate(mapping["protected_sinks"])
    )

    return MappedCompanyGraphAdapter(
        _load(name),
        source_system=adapter["source_system"],
        adapter_version=adapter["adapter_version"],
        node_mapping=mapping["node_mapping"],
        edge_mapping=mapping["edge_mapping"],
        protected_sinks=sinks,
    ).load()


def _payment_finding(report):
    return next(
        finding for finding in report.findings if finding.sink_node_id == PAYMENT_SINK
    )


def main() -> None:
    result = analyze_change(
        _graph("company-graph-before.json"),
        _graph("company-graph-after.json"),
        source_node_id="agent:refund",
        context={"environment": "production"},
    )

    before = _payment_finding(result.before)
    after = _payment_finding(result.after)

    if after.witness is None:
        raise RuntimeError("expected a payment.execute witness path")

    print("IDENTITY BLAST-RADIUS DEMO")
    print("=" * 72)
    print("Source              Synthetic Agentforce / knowledge-graph export")
    print("Proposed change     RefundAgent may assume RefundAutomation identity")
    print()
    print("BEFORE")
    print("-" * 72)
    print(f"payment.execute     {before.state.value}")
    print()
    print("AFTER")
    print("-" * 72)
    print(f"payment.execute     {after.state.value}")
    print(f"Severity            {after.severity.value}")
    print(f"Shortest path       {after.witness.hop_count} hops")
    print()
    print("Witness path")

    for index, node_id in enumerate(after.witness.node_ids):
        prefix = "  " if index == 0 else "  -> "
        print(f"{prefix}{node_id}")

    evidence = "  |  ".join(
        f"{name}: {count}" for name, count in sorted(after.witness.evidence.items())
    )

    print()
    print(f"Evidence            {evidence}")
    print("Grant issuer        " + ", ".join(after.witness.grant_issuers))
    print()
    print("Violations")

    for reason_code in after.reason_codes:
        print(f"  - {reason_code}")

    print()
    print("PRE-ISSUANCE DECISION")
    print("-" * 72)
    print(result.to_dict()["decision"])
    print()
    print("Reason: The proposed identity binding creates a prohibited deterministic")
    print("path from RefundAgent to the irreversible payment.execute action.")


if __name__ == "__main__":
    main()
