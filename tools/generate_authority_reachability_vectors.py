#!/usr/bin/env python3
"""Generate deterministic customer-graph reachability vectors."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Permit direct execution from a source checkout.
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1]),
)

from agent_dna.authority_v01 import canonicalize

OUT = Path("spec/authority-reachability-v01/vectors")
SNAPSHOT_TIME = "2026-07-28T12:30:00Z"


def _snapshot_hash(value: dict[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "snapshot_hash"}
    return "sha256:" + hashlib.sha256(canonicalize(payload)).hexdigest()


def _write(
    name: str,
    value: Any,
) -> None:
    OUT.mkdir(
        parents=True,
        exist_ok=True,
    )
    (OUT / name).write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"GENERATED: {OUT / name}")


def _node(
    node_id: str,
    node_type: str,
    label: str,
    **attributes: Any,
) -> dict[str, Any]:
    return {
        "id": node_id,
        "type": node_type,
        "label": label,
        "attributes": attributes,
    }


def _edge(
    edge_id: str,
    source: str,
    target: str,
    edge_type: str,
    *,
    conditions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": edge_id,
        "source": source,
        "target": target,
        "type": edge_type,
        "conditions": conditions or [],
    }


def main() -> None:
    nodes = [
        _node(
            "agent:refund",
            "Agent",
            "Agentforce Refund Agent",
        ),
        _node(
            "grant:refund-recommend",
            "SignedGrant",
            "Refund recommendation grant",
            grant_id="grant-refund-recommend",
            issuer_principal="refund-owner@example.com",
            delegation_depth=0,
        ),
        _node(
            "capability:refund-recommend",
            "Capability",
            "refund.recommend",
        ),
        _node(
            "action:refund-recommend",
            "Action",
            "Recommend refund",
        ),
        _node(
            "identity:refund-automation",
            "ServiceIdentity",
            "Refund automation service identity",
        ),
        _node(
            "grant:payment-execute",
            "SignedGrant",
            "Payment execution service grant",
            grant_id="grant-payment-execute",
            issuer_principal="payments-platform@example.com",
            delegation_depth=1,
        ),
        _node(
            "capability:payment-execute",
            "Capability",
            "payment.execute",
        ),
        _node(
            "sink:payment-execute",
            "IrreversibleAction",
            "Execute customer payment",
        ),
        _node(
            "sink:customer-bulk-export",
            "IrreversibleAction",
            "Bulk export customer records",
        ),
    ]

    base_edges = [
        _edge(
            "edge:agent-holds-refund-grant",
            "agent:refund",
            "grant:refund-recommend",
            "holdsSignedGrant",
        ),
        _edge(
            "edge:refund-grant-capability",
            "grant:refund-recommend",
            "capability:refund-recommend",
            "grantsSignedCapability",
        ),
        _edge(
            "edge:refund-capability-action",
            "capability:refund-recommend",
            "action:refund-recommend",
            "authorizesAction",
        ),
        _edge(
            "edge:identity-holds-payment-grant",
            "identity:refund-automation",
            "grant:payment-execute",
            "holdsSignedGrant",
        ),
        _edge(
            "edge:payment-grant-capability",
            "grant:payment-execute",
            "capability:payment-execute",
            "grantsSignedCapability",
        ),
        _edge(
            "edge:payment-capability-action",
            "capability:payment-execute",
            "sink:payment-execute",
            "authorizesAction",
        ),
    ]

    proposed_edge = _edge(
        "edge:agent-assumes-refund-automation",
        "agent:refund",
        "identity:refund-automation",
        "canAssumeIdentity",
        conditions=[
            {
                "field": "environment",
                "operator": "eq",
                "value": "production",
            }
        ],
    )

    before: dict[str, Any] = {
        "graph_id": "agentforce-refund-before",
        "organisation_id": "salesforce-demo.example",
        "snapshot_time": SNAPSHOT_TIME,
        "snapshot_hash": "",
        "nodes": nodes,
        "edges": base_edges,
    }
    before["snapshot_hash"] = _snapshot_hash(before)

    after: dict[str, Any] = copy.deepcopy(before)
    after["graph_id"] = "agentforce-refund-after"
    after["edges"].append(proposed_edge)
    after["snapshot_hash"] = _snapshot_hash(after)

    mapping: dict[str, Any] = {
        "adapter": {
            "source_system": "salesforce-agentforce-synthetic",
            "adapter_version": "agentforce-graph/0.1-experimental",
        },
        "node_mapping": {
            "Action": "ACTION",
            "Agent": "AGENT",
            "Capability": "CAPABILITY",
            "IrreversibleAction": "IRREVERSIBLE_SINK",
            "ServiceIdentity": "IDENTITY",
            "SignedGrant": "GRANT",
        },
        "edge_mapping": {
            "authorizesAction": {
                "kind": "AUTHORIZES",
                "traversable": True,
                "evidence_state": "DECLARED",
            },
            "canAssumeIdentity": {
                "kind": "CAN_ASSUME",
                "traversable": True,
                "evidence_state": "DISCOVERED",
            },
            "grantsSignedCapability": {
                "kind": "GRANTS",
                "traversable": True,
                "evidence_state": "DECLARED",
            },
            "holdsSignedGrant": {
                "kind": "HOLDS_GRANT",
                "traversable": True,
                "evidence_state": "DECLARED",
            },
        },
        "protected_sinks": [
            {
                "node_id": "sink:payment-execute",
                "severity": "CRITICAL",
                "direct_grant_required": True,
                "delegation_forbidden": False,
                "maximum_delegation_depth": 0,
                "allowed_issuers": ["treasury-owner@example.com"],
            },
            {
                "node_id": "sink:customer-bulk-export",
                "severity": "CRITICAL",
                "direct_grant_required": True,
                "delegation_forbidden": True,
                "maximum_delegation_depth": 0,
                "allowed_issuers": ["data-owner@example.com"],
            },
        ],
    }

    expected: dict[str, Any] = {
        "source_node_id": "agent:refund",
        "context": {"environment": "production"},
        "before": {
            "sink:payment-execute": "UNREACHABLE",
            "sink:customer-bulk-export": "UNREACHABLE",
        },
        "after": {
            "sink:payment-execute": "PROHIBITED_REACHABLE",
            "sink:customer-bulk-export": "UNREACHABLE",
        },
        "newly_reachable_sinks": ["sink:payment-execute"],
        "newly_prohibited_sinks": ["sink:payment-execute"],
        "decision": "BLOCK_PROPOSED_CHANGE",
        "reason_codes": [
            "DIRECT_GRANT_REQUIRED",
            "MAXIMUM_DELEGATION_DEPTH_EXCEEDED",
            "ISSUER_NOT_ALLOWED",
        ],
    }

    _write(
        "company-graph-before.json",
        before,
    )
    _write(
        "company-graph-after.json",
        after,
    )
    _write(
        "adapter-mapping.json",
        mapping,
    )
    _write(
        "analysis-context.json",
        {"environment": "production"},
    )
    _write(
        "expected-analysis.json",
        expected,
    )

    print("PASS: deterministic reachability vectors generated")


if __name__ == "__main__":
    main()
