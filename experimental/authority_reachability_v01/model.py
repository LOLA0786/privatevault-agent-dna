"""Strict data model for deterministic authority-graph reachability."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from agent_dna.authority_v01 import canonicalize

GRAPH_SPEC = "pv-authority-graph/0.1-experimental"
REPORT_SPEC = "pv-authority-reachability-report/0.1-experimental"
SIGNED_REPORT_SPEC = "pv-signed-authority-reachability-report/0.1-experimental"

RFC3339_UTC_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z"
)
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONDITION_OPERATORS = frozenset({"eq", "in", "not_in", "lte", "gte"})


class GraphFormatError(ValueError):
    """The graph cannot be interpreted without guessing."""


class NodeKind(StrEnum):
    PRINCIPAL = "PRINCIPAL"
    AGENT = "AGENT"
    IDENTITY = "IDENTITY"
    GRANT = "GRANT"
    CAPABILITY = "CAPABILITY"
    ACTION = "ACTION"
    TOOL = "TOOL"
    RESOURCE = "RESOURCE"
    SERVICE = "SERVICE"
    IRREVERSIBLE_SINK = "IRREVERSIBLE_SINK"


class EdgeKind(StrEnum):
    ISSUED = "ISSUED"
    HOLDS_GRANT = "HOLDS_GRANT"
    DELEGATED_TO = "DELEGATED_TO"
    GRANTS = "GRANTS"
    AUTHORIZES = "AUTHORIZES"
    CAN_ASSUME = "CAN_ASSUME"
    CAN_INVOKE = "CAN_INVOKE"
    EXPOSES = "EXPOSES"
    ENABLES = "ENABLES"
    READS = "READS"
    WRITES = "WRITES"
    SCOPED_TO = "SCOPED_TO"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


class EvidenceClass(StrEnum):
    VERIFIED = "VERIFIED"
    DECLARED = "DECLARED"
    DISCOVERED = "DISCOVERED"
    OBSERVED = "OBSERVED"
    UNVERIFIABLE = "UNVERIFIABLE"
    INVALID = "INVALID"


class ReachabilityState(StrEnum):
    UNREACHABLE = "UNREACHABLE"
    REACHABLE = "REACHABLE"
    PROHIBITED_REACHABLE = "PROHIBITED_REACHABLE"
    CONDITIONAL = "CONDITIONAL"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def parse_timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not RFC3339_UTC_RE.fullmatch(value):
        raise GraphFormatError(f"{path}: expected RFC 3339 UTC timestamp")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GraphFormatError(f"{path}: malformed timestamp") from exc


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise GraphFormatError(f"{path}: expected non-empty string")
    return value


def require_exact_fields(
    value: Mapping[str, Any],
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
    path: str,
) -> None:
    required_set = frozenset(required)
    allowed = required_set | frozenset(optional)
    actual = frozenset(value)
    missing = required_set - actual
    unknown = actual - allowed
    if missing:
        raise GraphFormatError(f"{path}: missing fields {sorted(missing)}")
    if unknown:
        raise GraphFormatError(f"{path}: unknown fields {sorted(unknown)}")


def require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GraphFormatError(f"{path}: expected object")
    return value


def require_json(value: Any, path: str) -> Any:
    try:
        canonicalize(value)
    except ValueError as exc:
        raise GraphFormatError(f"{path}: {exc}") from exc
    return value


def enum_value(enum_type: type[StrEnum], value: Any, path: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise GraphFormatError(f"{path}: unsupported value {value!r}") from exc


@dataclass(frozen=True)
class Condition:
    field: str
    operator: str
    value: Any

    @classmethod
    def from_dict(cls, raw: Any, path: str) -> Condition:
        value = require_mapping(raw, path)
        require_exact_fields(
            value,
            required={"field", "operator", "value"},
            path=path,
        )
        field = require_string(value["field"], f"{path}.field")
        operator = value["operator"]
        if operator not in CONDITION_OPERATORS:
            raise GraphFormatError(f"{path}.operator: unsupported operator")
        declared = require_json(value["value"], f"{path}.value")
        if operator in {"in", "not_in"} and (
            not isinstance(declared, list) or not declared
        ):
            raise GraphFormatError(f"{path}.value: expected non-empty list")
        if operator in {"lte", "gte"} and (
            isinstance(declared, bool) or not isinstance(declared, int)
        ):
            raise GraphFormatError(f"{path}.value: expected integer")
        return cls(field, operator, declared)

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "operator": self.operator,
            "value": self.value,
        }


@dataclass(frozen=True)
class EdgeProvenance:
    source_system: str
    source_object_id: str
    source_snapshot: str
    adapter_version: str
    observed_at: str
    signer_key_id: str | None = None

    @classmethod
    def from_dict(cls, raw: Any, path: str) -> EdgeProvenance:
        value = require_mapping(raw, path)
        require_exact_fields(
            value,
            required={
                "source_system",
                "source_object_id",
                "source_snapshot",
                "adapter_version",
                "observed_at",
            },
            optional={"signer_key_id"},
            path=path,
        )
        snapshot = require_string(
            value["source_snapshot"], f"{path}.source_snapshot"
        )
        if not SHA256_RE.fullmatch(snapshot):
            raise GraphFormatError(f"{path}.source_snapshot: malformed digest")
        observed_at = require_string(value["observed_at"], f"{path}.observed_at")
        parse_timestamp(observed_at, f"{path}.observed_at")
        signer = value.get("signer_key_id")
        if signer is not None:
            signer = require_string(signer, f"{path}.signer_key_id")
        return cls(
            require_string(value["source_system"], f"{path}.source_system"),
            require_string(value["source_object_id"], f"{path}.source_object_id"),
            snapshot,
            require_string(value["adapter_version"], f"{path}.adapter_version"),
            observed_at,
            signer,
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "source_system": self.source_system,
            "source_object_id": self.source_object_id,
            "source_snapshot": self.source_snapshot,
            "adapter_version": self.adapter_version,
            "observed_at": self.observed_at,
        }
        if self.signer_key_id is not None:
            result["signer_key_id"] = self.signer_key_id
        return result


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    kind: NodeKind
    label: str
    attributes: Mapping[str, Any]

    @classmethod
    def from_dict(cls, raw: Any, path: str) -> GraphNode:
        value = require_mapping(raw, path)
        require_exact_fields(
            value,
            required={"node_id", "kind", "label", "attributes"},
            path=path,
        )
        attributes = require_mapping(value["attributes"], f"{path}.attributes")
        require_json(attributes, f"{path}.attributes")
        return cls(
            require_string(value["node_id"], f"{path}.node_id"),
            NodeKind(enum_value(NodeKind, value["kind"], f"{path}.kind")),
            require_string(value["label"], f"{path}.label"),
            dict(attributes),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "label": self.label,
            "attributes": dict(self.attributes),
        }

@dataclass(frozen=True)
class GraphEdge:
    edge_id: str
    source: str
    target: str
    kind: EdgeKind
    traversable: bool
    evidence_state: EvidenceClass
    conditions: tuple[Condition, ...]
    provenance: EdgeProvenance

    @classmethod
    def from_dict(cls, raw: Any, path: str) -> GraphEdge:
        value = require_mapping(raw, path)
        require_exact_fields(
            value,
            required={
                "edge_id",
                "source",
                "target",
                "kind",
                "traversable",
                "evidence_state",
                "conditions",
                "provenance",
            },
            path=path,
        )
        if not isinstance(value["traversable"], bool):
            raise GraphFormatError(f"{path}.traversable: expected boolean")
        if not isinstance(value["conditions"], list):
            raise GraphFormatError(f"{path}.conditions: expected list")
        conditions = tuple(
            Condition.from_dict(item, f"{path}.conditions[{index}]")
            for index, item in enumerate(value["conditions"])
        )
        fields = [condition.field for condition in conditions]
        if len(fields) != len(set(fields)):
            raise GraphFormatError(f"{path}.conditions: duplicate field")
        return cls(
            require_string(value["edge_id"], f"{path}.edge_id"),
            require_string(value["source"], f"{path}.source"),
            require_string(value["target"], f"{path}.target"),
            EdgeKind(enum_value(EdgeKind, value["kind"], f"{path}.kind")),
            value["traversable"],
            EvidenceClass(
                enum_value(
                    EvidenceClass,
                    value["evidence_state"],
                    f"{path}.evidence_state",
                )
            ),
            conditions,
            EdgeProvenance.from_dict(value["provenance"], f"{path}.provenance"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source": self.source,
            "target": self.target,
            "kind": self.kind.value,
            "traversable": self.traversable,
            "evidence_state": self.evidence_state.value,
            "conditions": [condition.to_dict() for condition in self.conditions],
            "provenance": self.provenance.to_dict(),
        }


@dataclass(frozen=True)
class ProtectedSink:
    node_id: str
    severity: Severity
    direct_grant_required: bool
    delegation_forbidden: bool
    maximum_delegation_depth: int | None
    allowed_issuers: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: Any, path: str) -> ProtectedSink:
        value = require_mapping(raw, path)
        require_exact_fields(
            value,
            required={
                "node_id",
                "severity",
                "direct_grant_required",
                "delegation_forbidden",
                "maximum_delegation_depth",
                "allowed_issuers",
            },
            path=path,
        )
        for field in ("direct_grant_required", "delegation_forbidden"):
            if not isinstance(value[field], bool):
                raise GraphFormatError(f"{path}.{field}: expected boolean")
        depth = value["maximum_delegation_depth"]
        if depth is not None and (
            isinstance(depth, bool) or not isinstance(depth, int) or depth < 0
        ):
            raise GraphFormatError(
                f"{path}.maximum_delegation_depth: expected null or integer >= 0"
            )
        issuers = value["allowed_issuers"]
        if (
            not isinstance(issuers, list)
            or any(not isinstance(item, str) or not item for item in issuers)
            or len(issuers) != len(set(issuers))
        ):
            raise GraphFormatError(f"{path}.allowed_issuers: invalid list")
        return cls(
            require_string(value["node_id"], f"{path}.node_id"),
            Severity(enum_value(Severity, value["severity"], f"{path}.severity")),
            value["direct_grant_required"],
            value["delegation_forbidden"],
            depth,
            tuple(issuers),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "severity": self.severity.value,
            "direct_grant_required": self.direct_grant_required,
            "delegation_forbidden": self.delegation_forbidden,
            "maximum_delegation_depth": self.maximum_delegation_depth,
            "allowed_issuers": list(self.allowed_issuers),
        }


@dataclass(frozen=True)
class AuthorityGraph:
    graph_id: str
    organisation_id: str
    snapshot_time: str
    source_snapshots: tuple[str, ...]
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    protected_sinks: tuple[ProtectedSink, ...]

    @classmethod
    def from_dict(cls, raw: Any) -> AuthorityGraph:  # noqa: C901
        value = require_mapping(raw, "graph")
        require_exact_fields(
            value,
            required={
                "spec",
                "graph_id",
                "organisation_id",
                "snapshot_time",
                "source_snapshots",
                "nodes",
                "edges",
                "protected_sinks",
            },
            path="graph",
        )
        if value["spec"] != GRAPH_SPEC:
            raise GraphFormatError("graph.spec: unsupported spec")
        snapshot_time = require_string(
            value["snapshot_time"], "graph.snapshot_time"
        )
        parse_timestamp(snapshot_time, "graph.snapshot_time")
        snapshots = value["source_snapshots"]
        if (
            not isinstance(snapshots, list)
            or not snapshots
            or any(
                not isinstance(item, str) or not SHA256_RE.fullmatch(item)
                for item in snapshots
            )
            or len(snapshots) != len(set(snapshots))
        ):
            raise GraphFormatError("graph.source_snapshots: invalid digest list")
        if not isinstance(value["nodes"], list) or not value["nodes"]:
            raise GraphFormatError("graph.nodes: expected non-empty list")
        if not isinstance(value["edges"], list):
            raise GraphFormatError("graph.edges: expected list")
        if not isinstance(value["protected_sinks"], list):
            raise GraphFormatError("graph.protected_sinks: expected list")
        nodes = tuple(
            GraphNode.from_dict(item, f"graph.nodes[{index}]")
            for index, item in enumerate(value["nodes"])
        )
        edges = tuple(
            GraphEdge.from_dict(item, f"graph.edges[{index}]")
            for index, item in enumerate(value["edges"])
        )
        sinks = tuple(
            ProtectedSink.from_dict(item, f"graph.protected_sinks[{index}]")
            for index, item in enumerate(value["protected_sinks"])
        )
        node_ids = [node.node_id for node in nodes]
        if len(node_ids) != len(set(node_ids)):
            raise GraphFormatError("graph.nodes: duplicate node_id")
        edge_ids = [edge.edge_id for edge in edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise GraphFormatError("graph.edges: duplicate edge_id")
        known_nodes = set(node_ids)
        for edge in edges:
            if edge.source not in known_nodes or edge.target not in known_nodes:
                raise GraphFormatError(
                    f"graph.edges: {edge.edge_id!r} references unknown node"
                )
        sink_ids = [sink.node_id for sink in sinks]
        if len(sink_ids) != len(set(sink_ids)):
            raise GraphFormatError("graph.protected_sinks: duplicate node_id")
        for sink in sinks:
            if sink.node_id not in known_nodes:
                raise GraphFormatError(
                    f"graph.protected_sinks: unknown node {sink.node_id!r}"
                )
            node = next(node for node in nodes if node.node_id == sink.node_id)
            if node.kind is not NodeKind.IRREVERSIBLE_SINK:
                raise GraphFormatError(
                    f"graph.protected_sinks: {sink.node_id!r} is not a sink node"
                )
        return cls(
            require_string(value["graph_id"], "graph.graph_id"),
            require_string(value["organisation_id"], "graph.organisation_id"),
            snapshot_time,
            tuple(snapshots),
            nodes,
            edges,
            sinks,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec": GRAPH_SPEC,
            "graph_id": self.graph_id,
            "organisation_id": self.organisation_id,
            "snapshot_time": self.snapshot_time,
            "source_snapshots": list(self.source_snapshots),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "protected_sinks": [
                sink.to_dict() for sink in self.protected_sinks
            ],
        }
