"""Adapter boundary between customer graphs and the canonical authority graph."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from agent_dna.authority_v01 import strict_json_loads

from .model import (
    GRAPH_SPEC,
    AuthorityGraph,
    EdgeKind,
    EvidenceClass,
    GraphFormatError,
    NodeKind,
    ProtectedSink,
    require_exact_fields,
    require_mapping,
    require_string,
)


class GraphAdapter(ABC):
    """Read-only adapter contract.

    Adapters normalize source topology and preserve provenance. They do not
    upgrade discovered or declared relationships to verified authority.
    """

    @abstractmethod
    def load(self) -> AuthorityGraph:
        """Return one immutable canonical graph snapshot."""


class GenericJSONGraphAdapter(GraphAdapter):
    """Load the portable PrivateVault graph contract from strict JSON."""

    def __init__(self, source: str | bytes | Path | Mapping[str, Any]):
        self._source = source

    def load(self) -> AuthorityGraph:
        if isinstance(self._source, Path):
            raw = strict_json_loads(self._source.read_bytes())
        elif isinstance(self._source, bytes):
            raw = strict_json_loads(self._source)
        elif isinstance(self._source, str):
            raw = strict_json_loads(self._source)
        elif isinstance(self._source, Mapping):
            # Round-trip prevents non-JSON Python objects and duplicate-like
            # key surprises from bypassing the portable contract.
            raw = strict_json_loads(
                json.dumps(self._source, separators=(",", ":"), ensure_ascii=False)
            )
        else:
            raise GraphFormatError("adapter source must be JSON, path, or mapping")
        graph = AuthorityGraph.from_dict(raw)
        if any(edge.evidence_state is EvidenceClass.VERIFIED for edge in graph.edges):
            raise GraphFormatError(
                "generic JSON cannot assert VERIFIED evidence; "
                "use a cryptographic authority adapter"
            )
        return graph


class MappedCompanyGraphAdapter(GraphAdapter):
    """Normalize a simple company graph export through explicit mappings.

    This is the portable design-partner adapter. Neo4j, Agentforce, IAM, and
    internal knowledge-graph connectors can export this narrow shape while
    keeping their platform-specific discovery code outside the analyzer.
    """

    def __init__(
        self,
        source: Mapping[str, Any],
        *,
        source_system: str,
        adapter_version: str,
        node_mapping: Mapping[str, str],
        edge_mapping: Mapping[str, Mapping[str, Any]],
        protected_sinks: Sequence[ProtectedSink],
    ):
        self._source = source
        self._source_system = source_system
        self._adapter_version = adapter_version
        self._node_mapping = node_mapping
        self._edge_mapping = edge_mapping
        self._protected_sinks = protected_sinks

    def load(self) -> AuthorityGraph:  # noqa: C901
        raw = require_mapping(self._source, "company_graph")
        require_exact_fields(
            raw,
            required={
                "graph_id",
                "organisation_id",
                "snapshot_time",
                "snapshot_hash",
                "nodes",
                "edges",
            },
            path="company_graph",
        )
        nodes = raw["nodes"]
        edges = raw["edges"]
        if not isinstance(nodes, list) or not nodes:
            raise GraphFormatError("company_graph.nodes: expected non-empty list")
        if not isinstance(edges, list):
            raise GraphFormatError("company_graph.edges: expected list")

        normalized_nodes: list[dict[str, Any]] = []
        for index, item in enumerate(nodes):
            path = f"company_graph.nodes[{index}]"
            node = require_mapping(item, path)
            require_exact_fields(
                node,
                required={"id", "type", "label", "attributes"},
                path=path,
            )
            external_type = require_string(node["type"], f"{path}.type")
            mapped = self._node_mapping.get(external_type)
            if mapped is None:
                raise GraphFormatError(f"{path}.type: no mapping for {external_type!r}")
            try:
                node_kind = NodeKind(mapped)
            except ValueError as exc:
                raise GraphFormatError(
                    f"{path}.type: invalid mapped kind {mapped!r}"
                ) from exc

            normalized_nodes.append(
                {
                    "node_id": require_string(node["id"], f"{path}.id"),
                    "kind": node_kind.value,
                    "label": require_string(node["label"], f"{path}.label"),
                    "attributes": dict(
                        require_mapping(node["attributes"], f"{path}.attributes")
                    ),
                }
            )

        snapshot_hash = require_string(
            raw["snapshot_hash"], "company_graph.snapshot_hash"
        )
        observed_at = require_string(
            raw["snapshot_time"], "company_graph.snapshot_time"
        )

        normalized_edges: list[dict[str, Any]] = []
        for index, item in enumerate(edges):
            path = f"company_graph.edges[{index}]"
            edge = require_mapping(item, path)
            require_exact_fields(
                edge,
                required={
                    "id",
                    "source",
                    "target",
                    "type",
                    "conditions",
                },
                path=path,
            )
            external_type = require_string(edge["type"], f"{path}.type")
            mapping = self._edge_mapping.get(external_type)
            if mapping is None:
                raise GraphFormatError(f"{path}.type: no mapping for {external_type!r}")
            require_exact_fields(
                mapping,
                required={"kind", "traversable", "evidence_state"},
                path=f"edge_mapping.{external_type}",
            )
            try:
                edge_kind = EdgeKind(mapping["kind"])
                evidence = EvidenceClass(mapping["evidence_state"])
            except ValueError as exc:
                raise GraphFormatError(
                    f"edge_mapping.{external_type}: invalid enum value"
                ) from exc

            if evidence is EvidenceClass.VERIFIED:
                raise GraphFormatError(
                    f"edge_mapping.{external_type}: mapped company "
                    "edges cannot assert VERIFIED"
                )

            if not isinstance(mapping["traversable"], bool):
                raise GraphFormatError(
                    f"edge_mapping.{external_type}.traversable: expected boolean"
                )
            conditions = edge["conditions"]
            if not isinstance(conditions, list):
                raise GraphFormatError(f"{path}.conditions: expected list")

            edge_id = require_string(edge["id"], f"{path}.id")
            normalized_edges.append(
                {
                    "edge_id": edge_id,
                    "source": require_string(edge["source"], f"{path}.source"),
                    "target": require_string(edge["target"], f"{path}.target"),
                    "kind": edge_kind.value,
                    "traversable": mapping["traversable"],
                    "evidence_state": evidence.value,
                    "conditions": conditions,
                    "provenance": {
                        "source_system": self._source_system,
                        "source_object_id": edge_id,
                        "source_snapshot": snapshot_hash,
                        "adapter_version": self._adapter_version,
                        "observed_at": observed_at,
                    },
                }
            )

        return AuthorityGraph.from_dict(
            {
                "spec": GRAPH_SPEC,
                "graph_id": require_string(raw["graph_id"], "company_graph.graph_id"),
                "organisation_id": require_string(
                    raw["organisation_id"], "company_graph.organisation_id"
                ),
                "snapshot_time": observed_at,
                "source_snapshots": [snapshot_hash],
                "nodes": normalized_nodes,
                "edges": normalized_edges,
                "protected_sinks": [sink.to_dict() for sink in self._protected_sinks],
            }
        )


def merge_graphs(
    graphs: Sequence[AuthorityGraph],
    *,
    graph_id: str,
    snapshot_time: str,
) -> AuthorityGraph:
    """Merge adapter snapshots without silently resolving collisions."""

    if not graphs:
        raise GraphFormatError("at least one graph is required")

    organisation = graphs[0].organisation_id
    if any(graph.organisation_id != organisation for graph in graphs):
        raise GraphFormatError("cannot merge graphs from different organisations")

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    sinks: dict[str, dict[str, Any]] = {}
    snapshots: set[str] = set()

    for graph in graphs:
        snapshots.update(graph.source_snapshots)

        for node in graph.nodes:
            encoded = node.to_dict()
            existing = nodes.setdefault(node.node_id, encoded)
            if existing != encoded:
                raise GraphFormatError(f"conflicting node {node.node_id!r}")

        for edge in graph.edges:
            encoded = edge.to_dict()
            existing = edges.setdefault(edge.edge_id, encoded)
            if existing != encoded:
                raise GraphFormatError(f"conflicting edge {edge.edge_id!r}")

        for sink in graph.protected_sinks:
            encoded = sink.to_dict()
            existing = sinks.setdefault(sink.node_id, encoded)
            if existing != encoded:
                raise GraphFormatError(f"conflicting protected sink {sink.node_id!r}")

    return AuthorityGraph.from_dict(
        {
            "spec": GRAPH_SPEC,
            "graph_id": graph_id,
            "organisation_id": organisation,
            "snapshot_time": snapshot_time,
            "source_snapshots": sorted(snapshots),
            "nodes": [nodes[key] for key in sorted(nodes)],
            "edges": [edges[key] for key in sorted(edges)],
            "protected_sinks": [sinks[key] for key in sorted(sinks)],
        }
    )
