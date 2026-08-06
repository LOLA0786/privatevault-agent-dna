"""Deterministic constrained reachability and grant-change simulation."""

from __future__ import annotations

import hashlib
from collections import Counter, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agent_dna.authority_v01 import canonicalize

from .model import (
    REPORT_SPEC,
    AuthorityGraph,
    EdgeKind,
    EvidenceClass,
    GraphEdge,
    GraphFormatError,
    GraphNode,
    ProtectedSink,
    ReachabilityState,
    Severity,
    parse_timestamp,
    require_json,
)


@dataclass(frozen=True)
class _ActiveEdge:
    edge: GraphEdge
    unresolved_fields: tuple[str, ...]

    @property
    def conditional(self) -> bool:
        return bool(self.unresolved_fields)


@dataclass(frozen=True)
class PathWitness:
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    edge_kinds: tuple[str, ...]
    evidence: Mapping[str, int]
    conditional_fields: tuple[str, ...]
    grant_ids: tuple[str, ...]
    grant_issuers: tuple[str, ...]
    maximum_delegation_depth: int

    @property
    def hop_count(self) -> int:
        return len(self.edge_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_ids": list(self.node_ids),
            "edge_ids": list(self.edge_ids),
            "edge_kinds": list(self.edge_kinds),
            "hop_count": self.hop_count,
            "evidence": dict(sorted(self.evidence.items())),
            "conditional_fields": list(self.conditional_fields),
            "grant_ids": list(self.grant_ids),
            "grant_issuers": list(self.grant_issuers),
            "maximum_delegation_depth": self.maximum_delegation_depth,
        }


@dataclass(frozen=True)
class ReachabilityFinding:
    source_node_id: str
    sink_node_id: str
    severity: Severity
    state: ReachabilityState
    reason_codes: tuple[str, ...]
    witness: PathWitness | None
    cut_candidates: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_node_id": self.source_node_id,
            "sink_node_id": self.sink_node_id,
            "severity": self.severity.value,
            "state": self.state.value,
            "reason_codes": list(self.reason_codes),
            "witness": self.witness.to_dict() if self.witness else None,
            "cut_candidates": list(self.cut_candidates),
        }


@dataclass(frozen=True)
class AnalysisReport:
    analysis_id: str
    graph_id: str
    graph_hash: str
    organisation_id: str
    analysis_time: str
    source_node_id: str
    findings: tuple[ReachabilityFinding, ...]

    def to_dict(self) -> dict[str, Any]:
        counts = Counter(finding.state.value for finding in self.findings)
        return {
            "spec": REPORT_SPEC,
            "analysis_id": self.analysis_id,
            "graph_id": self.graph_id,
            "graph_hash": self.graph_hash,
            "organisation_id": self.organisation_id,
            "analysis_time": self.analysis_time,
            "source_node_id": self.source_node_id,
            "summary": {
                state.value: counts.get(state.value, 0) for state in ReachabilityState
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class ChangeAnalysis:
    before: AnalysisReport
    after: AnalysisReport
    newly_reachable_sinks: tuple[str, ...]
    newly_prohibited_sinks: tuple[str, ...]
    removed_reachability: tuple[str, ...]

    @property
    def should_block(self) -> bool:
        return bool(self.newly_prohibited_sinks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec": "pv-authority-reachability-change/0.1-experimental",
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "newly_reachable_sinks": list(self.newly_reachable_sinks),
            "newly_prohibited_sinks": list(self.newly_prohibited_sinks),
            "removed_reachability": list(self.removed_reachability),
            "decision": (
                "BLOCK_PROPOSED_CHANGE" if self.should_block else "ACCEPTABLE"
            ),
        }


def _lookup(context: Mapping[str, Any], dotted: str) -> tuple[bool, Any]:
    current: Any = context
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _condition_result(
    field: str,
    operator: str,
    expected: Any,
    context: Mapping[str, Any],
) -> bool | None:
    present, actual = _lookup(context, field)
    if not present:
        return None
    try:
        if operator == "eq":
            return bool(canonicalize(actual) == canonicalize(expected))
        if operator == "in":
            return any(canonicalize(actual) == canonicalize(item) for item in expected)
        if operator == "not_in":
            return all(canonicalize(actual) != canonicalize(item) for item in expected)
        if (
            isinstance(actual, bool)
            or not isinstance(actual, int)
            or isinstance(expected, bool)
            or not isinstance(expected, int)
        ):
            return False
        return actual <= expected if operator == "lte" else actual >= expected
    except (TypeError, ValueError):
        return False


def _active_edges(
    graph: AuthorityGraph,
    context: Mapping[str, Any],
) -> tuple[_ActiveEdge, ...]:
    result: list[_ActiveEdge] = []

    for edge in graph.edges:
        if not edge.traversable or edge.evidence_state is EvidenceClass.INVALID:
            continue

        unresolved: set[str] = set()
        if edge.evidence_state is EvidenceClass.UNVERIFIABLE:
            unresolved.add(f"edge:{edge.edge_id}")

        excluded = False
        for condition in edge.conditions:
            outcome = _condition_result(
                condition.field,
                condition.operator,
                condition.value,
                context,
            )
            if outcome is False:
                excluded = True
                break
            if outcome is None:
                unresolved.add(condition.field)

        if not excluded:
            result.append(
                _ActiveEdge(
                    edge,
                    tuple(sorted(unresolved)),
                )
            )

    return tuple(result)


def _shortest_path(
    graph: AuthorityGraph,
    *,
    source: str,
    target: str,
    context: Mapping[str, Any],
) -> tuple[tuple[GraphEdge, ...], tuple[str, ...]] | None:
    adjacency: dict[str, list[_ActiveEdge]] = {}

    for active in _active_edges(graph, context):
        adjacency.setdefault(active.edge.source, []).append(active)

    for edges in adjacency.values():
        edges.sort(
            key=lambda item: (
                item.edge.target,
                item.edge.edge_id,
            )
        )

    # Definite and conditional arrival are distinct states. A longer definite
    # path is stronger evidence than a shorter unresolved path.
    queue: deque[
        tuple[
            str,
            bool,
            tuple[GraphEdge, ...],
            tuple[str, ...],
        ]
    ] = deque(
        [
            (
                source,
                False,
                (),
                (),
            )
        ]
    )

    seen: set[tuple[str, bool]] = {(source, False)}
    conditional_result: (
        tuple[
            tuple[GraphEdge, ...],
            tuple[str, ...],
        ]
        | None
    ) = None

    while queue:
        node_id, conditional, path, unresolved = queue.popleft()

        if node_id == target:
            if not conditional:
                return path, ()
            if conditional_result is None:
                conditional_result = (path, unresolved)
            continue

        for active in adjacency.get(node_id, []):
            next_conditional = conditional or active.conditional
            state = (active.edge.target, next_conditional)

            if state in seen:
                continue

            seen.add(state)
            queue.append(
                (
                    active.edge.target,
                    next_conditional,
                    (*path, active.edge),
                    tuple(sorted(set(unresolved) | set(active.unresolved_fields))),
                )
            )

    return conditional_result


def _path_witness(
    source: str,
    path: Sequence[GraphEdge],
    nodes: Mapping[str, GraphNode],
    *,
    unresolved_fields: Sequence[str],
) -> PathWitness:
    node_ids = [source]
    evidence: Counter[str] = Counter()

    for edge in path:
        node_ids.append(edge.target)
        evidence[edge.evidence_state.value] += 1

    grants: list[GraphNode] = [
        nodes[node_id] for node_id in node_ids if nodes[node_id].kind.value == "GRANT"
    ]

    grant_ids = tuple(
        str(node.attributes.get("grant_id", node.node_id)) for node in grants
    )

    issuers = tuple(
        sorted(
            {
                str(node.attributes["issuer_principal"])
                for node in grants
                if isinstance(
                    node.attributes.get("issuer_principal"),
                    str,
                )
            }
        )
    )

    depths = [
        node.attributes.get("delegation_depth", 0)
        for node in grants
        if isinstance(
            node.attributes.get("delegation_depth", 0),
            int,
        )
        and not isinstance(
            node.attributes.get("delegation_depth", 0),
            bool,
        )
    ]

    return PathWitness(
        tuple(node_ids),
        tuple(edge.edge_id for edge in path),
        tuple(edge.kind.value for edge in path),
        dict(evidence),
        tuple(sorted(unresolved_fields)),
        grant_ids,
        issuers,
        max(depths, default=0),
    )


def _direct_grant_path(
    source: str,
    path: Sequence[GraphEdge],
) -> bool:
    if any(edge.kind is EdgeKind.ENABLES for edge in path):
        return False

    holds = [
        edge
        for edge in path
        if edge.kind is EdgeKind.HOLDS_GRANT and edge.source == source
    ]

    return len(holds) == 1 and bool(path) and path[-1].kind is EdgeKind.AUTHORIZES


def _violations(
    sink: ProtectedSink,
    source: str,
    path: Sequence[GraphEdge],
    witness: PathWitness,
) -> tuple[str, ...]:
    reasons: list[str] = []

    if sink.direct_grant_required and not _direct_grant_path(source, path):
        reasons.append("DIRECT_GRANT_REQUIRED")

    if sink.delegation_forbidden and witness.maximum_delegation_depth > 0:
        reasons.append("DELEGATION_FORBIDDEN")

    if (
        sink.maximum_delegation_depth is not None
        and witness.maximum_delegation_depth > sink.maximum_delegation_depth
    ):
        reasons.append("MAXIMUM_DELEGATION_DEPTH_EXCEEDED")

    if sink.allowed_issuers and (
        not witness.grant_issuers
        or not set(witness.grant_issuers) <= set(sink.allowed_issuers)
    ):
        reasons.append("ISSUER_NOT_ALLOWED")

    return tuple(reasons)


def _graph_hash(graph: AuthorityGraph) -> str:
    return "sha256:" + hashlib.sha256(canonicalize(graph.to_dict())).hexdigest()


def analyze_reachability(
    graph: AuthorityGraph,
    *,
    source_node_id: str,
    context: Mapping[str, Any] | None = None,
    analysis_time: str | None = None,
) -> AnalysisReport:
    """Analyze one immutable graph snapshot without probabilistic inference."""

    node_map = {node.node_id: node for node in graph.nodes}

    if source_node_id not in node_map:
        raise GraphFormatError(f"unknown source node {source_node_id!r}")

    effective_time = analysis_time or graph.snapshot_time
    parse_timestamp(effective_time, "analysis_time")

    supplied_context = dict(context or {})
    require_json(supplied_context, "context")
    supplied_context.setdefault(
        "analysis_time",
        effective_time,
    )

    findings: list[ReachabilityFinding] = []

    for sink in sorted(
        graph.protected_sinks,
        key=lambda item: item.node_id,
    ):
        result = _shortest_path(
            graph,
            source=source_node_id,
            target=sink.node_id,
            context=supplied_context,
        )

        if result is None:
            findings.append(
                ReachabilityFinding(
                    source_node_id,
                    sink.node_id,
                    sink.severity,
                    ReachabilityState.UNREACHABLE,
                    ("NO_PATH",),
                    None,
                    (),
                )
            )
            continue

        path, unresolved_fields = result
        conditional = bool(unresolved_fields)

        witness = _path_witness(
            source_node_id,
            path,
            node_map,
            unresolved_fields=unresolved_fields,
        )

        violations = _violations(
            sink,
            source_node_id,
            path,
            witness,
        )

        if conditional:
            state = ReachabilityState.CONDITIONAL
            reasons = (
                "UNRESOLVED_PATH_CONDITIONS",
                *violations,
            )
        elif violations:
            state = ReachabilityState.PROHIBITED_REACHABLE
            reasons = violations
        else:
            state = ReachabilityState.REACHABLE
            reasons = ("VALID_PATH",)

        findings.append(
            ReachabilityFinding(
                source_node_id,
                sink.node_id,
                sink.severity,
                state,
                tuple(reasons),
                witness,
                tuple(
                    edge.edge_id
                    for edge in path
                    if (
                        edge.evidence_state is not EvidenceClass.VERIFIED
                        or edge.kind is EdgeKind.ENABLES
                    )
                ),
            )
        )

    graph_hash = _graph_hash(graph)

    identity_input = {
        "graph_hash": graph_hash,
        "source_node_id": source_node_id,
        "analysis_time": effective_time,
        "context": supplied_context,
    }

    analysis_id = hashlib.sha256(canonicalize(identity_input)).hexdigest()[:24]

    return AnalysisReport(
        f"analysis-{analysis_id}",
        graph.graph_id,
        graph_hash,
        graph.organisation_id,
        effective_time,
        source_node_id,
        tuple(findings),
    )


def analyze_change(
    before_graph: AuthorityGraph,
    after_graph: AuthorityGraph,
    *,
    source_node_id: str,
    context: Mapping[str, Any] | None = None,
    analysis_time: str | None = None,
) -> ChangeAnalysis:
    """Compare immutable before/after snapshots of a proposed graph change."""

    before = analyze_reachability(
        before_graph,
        source_node_id=source_node_id,
        context=context,
        analysis_time=analysis_time,
    )

    after = analyze_reachability(
        after_graph,
        source_node_id=source_node_id,
        context=context,
        analysis_time=analysis_time,
    )

    before_by_sink = {item.sink_node_id: item for item in before.findings}
    after_by_sink = {item.sink_node_id: item for item in after.findings}

    reachable = {
        ReachabilityState.REACHABLE,
        ReachabilityState.PROHIBITED_REACHABLE,
        ReachabilityState.CONDITIONAL,
    }

    newly_reachable: list[str] = []
    newly_prohibited: list[str] = []
    removed: list[str] = []

    for sink_id in sorted(set(before_by_sink) | set(after_by_sink)):
        old = before_by_sink.get(sink_id)
        new = after_by_sink.get(sink_id)

        old_state = old.state if old else ReachabilityState.UNREACHABLE
        new_state = new.state if new else ReachabilityState.UNREACHABLE

        if old_state not in reachable and new_state in reachable:
            newly_reachable.append(sink_id)

        if (
            old_state is not ReachabilityState.PROHIBITED_REACHABLE
            and new_state is ReachabilityState.PROHIBITED_REACHABLE
        ):
            newly_prohibited.append(sink_id)

        if old_state in reachable and new_state not in reachable:
            removed.append(sink_id)

    return ChangeAnalysis(
        before,
        after,
        tuple(newly_reachable),
        tuple(newly_prohibited),
        tuple(removed),
    )
