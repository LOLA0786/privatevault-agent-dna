"""Deterministic loop discovery at the PrivateVault authority boundary.

Agent loops are not one problem:

* a circular approval or delegation graph is an authority contradiction;
* a causal parent cycle is malformed execution provenance;
* reuse of a single-use authorization is an execution-control breach;
* a bidirectional agent workflow may be legitimate, but is reviewable; and
* repeated canonical actions in one causal lineage indicate recursion.

This module keeps those cases separate. It consumes strict, immutable security
events and emits a stable report with witnesses. The algorithm is bounded,
uses no network or model calls, and never treats model output as evidence.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from agent_dna.authority_v01 import canonicalize

LOOP_EVENT_SPEC = "pv-agent-security-event/1.0"
LOOP_REPORT_SPEC = "pv-loop-discovery-report/1.0"

_RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


class LoopFormatError(ValueError):
    """Input cannot be interpreted safely without guessing."""


class Relation(StrEnum):
    """Security meaning of a directed edge."""

    DELEGATES = "DELEGATES"
    APPROVES = "APPROVES"
    INVOKES = "INVOKES"
    DISPATCHES = "DISPATCHES"


class AuthorizationState(StrEnum):
    """Verification state of the event's execution authorization."""

    VERIFIED = "VERIFIED"
    INVALID = "INVALID"
    UNVERIFIABLE = "UNVERIFIABLE"
    ABSENT = "ABSENT"


class LoopDecision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class FindingSeverity(StrEnum):
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def _require_mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise LoopFormatError(f"{path}: expected object with string keys")
    return value


def _require_exact_fields(
    value: Mapping[str, object],
    *,
    required: set[str],
    path: str,
) -> None:
    actual = set(value)
    missing = required - actual
    unknown = actual - required
    if missing:
        raise LoopFormatError(f"{path}: missing fields {sorted(missing)}")
    if unknown:
        raise LoopFormatError(f"{path}: unknown fields {sorted(unknown)}")


def _require_string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise LoopFormatError(f"{path}: expected non-empty string")
    if len(value) > 512:
        raise LoopFormatError(f"{path}: exceeds 512 characters")
    return value


def _optional_string(value: object, path: str) -> str | None:
    if value is None:
        return None
    return _require_string(value, path)


def _timestamp(value: object, path: str) -> str:
    text = _require_string(value, path)
    if not _RFC3339_UTC.fullmatch(text):
        raise LoopFormatError(f"{path}: expected RFC 3339 UTC timestamp")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise LoopFormatError(f"{path}: malformed timestamp") from exc
    return text


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _digest(value: object, path: str) -> str:
    text = _require_string(value, path)
    if not _SHA256.fullmatch(text):
        raise LoopFormatError(f"{path}: expected sha256 digest")
    return text


def _enum_value[T: StrEnum](enum_type: type[T], value: object, path: str) -> T:
    if not isinstance(value, str):
        raise LoopFormatError(f"{path}: expected string enum value")
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise LoopFormatError(f"{path}: unsupported value {value!r}") from exc


def _sha256_json(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonicalize(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class LoopEvent:
    """One authority-bearing or causal agent edge.

    ``action_digest`` binds the immutable ActionIntent or grant bytes. An
    ``authorization_id`` identifies one single-use authorization consumption;
    it is not a model-provided token.
    """

    event_id: str
    trace_id: str
    occurred_at: str
    source_agent_id: str
    target_agent_id: str
    relation: Relation
    action_digest: str
    authorization_id: str | None
    authorization_state: AuthorizationState
    parent_event_id: str | None

    @classmethod
    def from_dict(cls, raw: object, path: str = "event") -> LoopEvent:
        value = _require_mapping(raw, path)
        _require_exact_fields(
            value,
            required={
                "spec",
                "event_id",
                "trace_id",
                "occurred_at",
                "source_agent_id",
                "target_agent_id",
                "relation",
                "action_digest",
                "authorization_id",
                "authorization_state",
                "parent_event_id",
            },
            path=path,
        )
        if value["spec"] != LOOP_EVENT_SPEC:
            raise LoopFormatError(f"{path}.spec: unsupported spec")
        return cls(
            event_id=_require_string(value["event_id"], f"{path}.event_id"),
            trace_id=_require_string(value["trace_id"], f"{path}.trace_id"),
            occurred_at=_timestamp(value["occurred_at"], f"{path}.occurred_at"),
            source_agent_id=_require_string(
                value["source_agent_id"], f"{path}.source_agent_id"
            ),
            target_agent_id=_require_string(
                value["target_agent_id"], f"{path}.target_agent_id"
            ),
            relation=_enum_value(Relation, value["relation"], f"{path}.relation"),
            action_digest=_digest(value["action_digest"], f"{path}.action_digest"),
            authorization_id=_optional_string(
                value["authorization_id"], f"{path}.authorization_id"
            ),
            authorization_state=_enum_value(
                AuthorizationState,
                value["authorization_state"],
                f"{path}.authorization_state",
            ),
            parent_event_id=_optional_string(
                value["parent_event_id"], f"{path}.parent_event_id"
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "spec": LOOP_EVENT_SPEC,
            "event_id": self.event_id,
            "trace_id": self.trace_id,
            "occurred_at": self.occurred_at,
            "source_agent_id": self.source_agent_id,
            "target_agent_id": self.target_agent_id,
            "relation": self.relation.value,
            "action_digest": self.action_digest,
            "authorization_id": self.authorization_id,
            "authorization_state": self.authorization_state.value,
            "parent_event_id": self.parent_event_id,
        }


@dataclass(frozen=True, slots=True)
class LoopPolicy:
    """Resource bounds and enforcement thresholds."""

    max_events: int = 10_000
    max_causal_depth: int = 64
    action_review_occurrences: int = 2
    action_block_occurrences: int = 3
    max_findings: int = 256
    require_complete_lineage: bool = True

    def __post_init__(self) -> None:
        integer_fields = {
            "max_events": self.max_events,
            "max_causal_depth": self.max_causal_depth,
            "action_review_occurrences": self.action_review_occurrences,
            "action_block_occurrences": self.action_block_occurrences,
            "max_findings": self.max_findings,
        }
        for name, value in integer_fields.items():
            if isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be an integer >= 1")
        if self.action_review_occurrences >= self.action_block_occurrences:
            raise ValueError(
                "action_review_occurrences must be below action_block_occurrences"
            )


@dataclass(frozen=True, slots=True)
class LoopFinding:
    reason_code: str
    disposition: LoopDecision
    severity: FindingSeverity
    trace_id: str
    agent_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "reason_code": self.reason_code,
            "disposition": self.disposition.value,
            "severity": self.severity.value,
            "trace_id": self.trace_id,
            "agent_ids": list(self.agent_ids),
            "event_ids": list(self.event_ids),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class LoopDiscoveryReport:
    report_id: str
    input_digest: str
    decision: LoopDecision
    events_analyzed: int
    traces_analyzed: int
    findings: tuple[LoopFinding, ...]

    def to_dict(self) -> dict[str, object]:
        counts = Counter(finding.severity.value for finding in self.findings)
        return {
            "spec": LOOP_REPORT_SPEC,
            "report_id": self.report_id,
            "input_digest": self.input_digest,
            "decision": self.decision.value,
            "events_analyzed": self.events_analyzed,
            "traces_analyzed": self.traces_analyzed,
            "summary": {
                severity.value: counts.get(severity.value, 0)
                for severity in FindingSeverity
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class _CycleWitness:
    agent_ids: tuple[str, ...]
    event_ids: tuple[str, ...]


def _event_order(event: LoopEvent) -> tuple[str, str, str]:
    return (event.trace_id, event.occurred_at, event.event_id)


def _deduplicate(events: Iterable[LoopEvent]) -> tuple[LoopEvent, ...]:
    by_id: dict[str, LoopEvent] = {}
    for event in events:
        previous = by_id.get(event.event_id)
        if previous is not None and previous != event:
            raise LoopFormatError(f"event_id {event.event_id!r} has conflicting bodies")
        by_id[event.event_id] = event
    return tuple(sorted(by_id.values(), key=_event_order))


def _adjacency(
    events: Sequence[LoopEvent],
) -> dict[str, list[tuple[str, LoopEvent]]]:
    graph: dict[str, list[tuple[str, LoopEvent]]] = {}
    for event in events:
        graph.setdefault(event.source_agent_id, []).append(
            (event.target_agent_id, event)
        )
        graph.setdefault(event.target_agent_id, [])
    for outgoing in graph.values():
        outgoing.sort(key=lambda item: (item[0], item[1].event_id))
    return graph


def _finish_order(
    graph: Mapping[str, Sequence[tuple[str, LoopEvent]]],
) -> list[str]:
    seen: set[str] = set()
    finish: list[str] = []
    for root in sorted(graph):
        if root in seen:
            continue
        stack: list[tuple[str, bool]] = [(root, False)]
        while stack:
            node, exiting = stack.pop()
            if exiting:
                finish.append(node)
                continue
            if node in seen:
                continue
            seen.add(node)
            stack.append((node, True))
            neighbors = sorted(
                {target for target, _ in graph.get(node, ())}, reverse=True
            )
            stack.extend((neighbor, False) for neighbor in neighbors)
    return finish


def _reverse_graph(
    graph: Mapping[str, Sequence[tuple[str, LoopEvent]]],
) -> dict[str, set[str]]:
    reverse: dict[str, set[str]] = {node: set() for node in graph}
    for source, outgoing in graph.items():
        for target, _ in outgoing:
            reverse.setdefault(target, set()).add(source)
    return reverse


def _strong_components(
    graph: Mapping[str, Sequence[tuple[str, LoopEvent]]],
) -> tuple[tuple[str, ...], ...]:
    """Kosaraju SCCs with iterative traversals and deterministic ordering."""

    reverse = _reverse_graph(graph)
    assigned: set[str] = set()
    components: list[tuple[str, ...]] = []
    for root in reversed(_finish_order(graph)):
        if root in assigned:
            continue
        component: set[str] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if node in assigned:
                continue
            assigned.add(node)
            component.add(node)
            stack.extend(sorted(reverse.get(node, ()), reverse=True))
        components.append(tuple(sorted(component)))

    return tuple(sorted(components, key=lambda item: (len(item), item)))


def _path_to_target(
    graph: Mapping[str, Sequence[tuple[str, LoopEvent]]],
    *,
    source: str,
    target: str,
    allowed: frozenset[str],
) -> _CycleWitness | None:
    queue: deque[tuple[str, tuple[str, ...], tuple[str, ...]]] = deque(
        [(source, (source,), ())]
    )
    seen = {source}
    while queue:
        node, agents, event_ids = queue.popleft()
        if node == target:
            return _CycleWitness(agents, event_ids)
        for neighbor, event in graph.get(node, ()):
            if neighbor not in allowed or neighbor in seen:
                continue
            seen.add(neighbor)
            queue.append(
                (neighbor, agents + (neighbor,), event_ids + (event.event_id,))
            )
    return None


def _cycle_witness(
    graph: Mapping[str, Sequence[tuple[str, LoopEvent]]],
    component: tuple[str, ...],
) -> _CycleWitness:
    allowed = frozenset(component)
    candidates: list[_CycleWitness] = []
    for start in component:
        for neighbor, event in graph.get(start, ()):
            if neighbor not in allowed:
                continue
            if neighbor == start:
                candidates.append(_CycleWitness((start, start), (event.event_id,)))
                continue
            suffix = _path_to_target(
                graph, source=neighbor, target=start, allowed=allowed
            )
            if suffix is not None:
                candidates.append(
                    _CycleWitness(
                        (start,) + suffix.agent_ids,
                        (event.event_id,) + suffix.event_ids,
                    )
                )
    if not candidates:
        raise AssertionError("strong component did not contain a cycle")
    return min(candidates, key=lambda item: (len(item.event_ids), item.agent_ids))


def _cyclic_components(
    events: Sequence[LoopEvent],
) -> tuple[tuple[tuple[str, ...], _CycleWitness], ...]:
    graph = _adjacency(events)
    result: list[tuple[tuple[str, ...], _CycleWitness]] = []
    for component in _strong_components(graph):
        self_loop = len(component) == 1 and any(
            target == component[0] for target, _ in graph.get(component[0], ())
        )
        if len(component) > 1 or self_loop:
            result.append((component, _cycle_witness(graph, component)))
    return tuple(result)


def _finding_key(finding: LoopFinding) -> tuple[object, ...]:
    return (
        finding.trace_id,
        finding.reason_code,
        finding.agent_ids,
        finding.event_ids,
        finding.detail,
    )


def _parent_integrity_findings(
    events: Sequence[LoopEvent],
    by_id: Mapping[str, LoopEvent],
    policy: LoopPolicy,
) -> list[LoopFinding]:
    findings: list[LoopFinding] = []
    for event in events:
        parent_id = event.parent_event_id
        if parent_id is None:
            continue
        parent = by_id.get(parent_id)
        if parent is None:
            if policy.require_complete_lineage:
                findings.append(
                    LoopFinding(
                        "CAUSAL_PARENT_ABSENT",
                        LoopDecision.BLOCK,
                        FindingSeverity.HIGH,
                        event.trace_id,
                        tuple(sorted({event.source_agent_id, event.target_agent_id})),
                        (event.event_id,),
                        f"parent event {parent_id!r} is absent",
                    )
                )
            continue
        if parent.trace_id != event.trace_id:
            findings.append(
                LoopFinding(
                    "CROSS_TRACE_PARENT",
                    LoopDecision.BLOCK,
                    FindingSeverity.CRITICAL,
                    event.trace_id,
                    tuple(sorted({event.source_agent_id, event.target_agent_id})),
                    tuple(sorted((event.event_id, parent.event_id))),
                    "causal parent belongs to another trace",
                )
            )
        if _timestamp_value(event.occurred_at) < _timestamp_value(parent.occurred_at):
            findings.append(
                LoopFinding(
                    "CAUSAL_TIME_REGRESSION",
                    LoopDecision.BLOCK,
                    FindingSeverity.HIGH,
                    event.trace_id,
                    tuple(sorted({event.source_agent_id, event.target_agent_id})),
                    (parent.event_id, event.event_id),
                    "child event predates its declared parent",
                )
            )
    return findings


def _lineage_findings(
    by_id: Mapping[str, LoopEvent], policy: LoopPolicy
) -> list[LoopFinding]:
    findings: list[LoopFinding] = []

    depths: dict[str, int] = {}
    reported_cycles: set[tuple[str, ...]] = set()
    deepest: tuple[int, LoopEvent] | None = None

    for start in sorted(by_id):
        path: list[str] = []
        positions: dict[str, int] = {}
        current: str | None = start
        while current is not None and current in by_id and current not in depths:
            if current in positions:
                cycle = tuple(path[positions[current] :])
                normalized = min(
                    tuple(cycle[index:] + cycle[:index]) for index in range(len(cycle))
                )
                if normalized not in reported_cycles:
                    reported_cycles.add(normalized)
                    cycle_events = [by_id[event_id] for event_id in normalized]
                    findings.append(
                        LoopFinding(
                            "CAUSAL_LINEAGE_CYCLE",
                            LoopDecision.BLOCK,
                            FindingSeverity.CRITICAL,
                            min(event.trace_id for event in cycle_events),
                            tuple(
                                sorted(
                                    {
                                        agent
                                        for event in cycle_events
                                        for agent in (
                                            event.source_agent_id,
                                            event.target_agent_id,
                                        )
                                    }
                                )
                            ),
                            normalized,
                            "parent_event_id references form a cycle",
                        )
                    )
                break
            positions[current] = len(path)
            path.append(current)
            current = by_id[current].parent_event_id

        base = depths.get(current, 0) if current is not None else 0
        for event_id in reversed(path):
            base += 1
            depths[event_id] = base
            candidate = (base, by_id[event_id])
            if deepest is None or (candidate[0], candidate[1].event_id) > (
                deepest[0],
                deepest[1].event_id,
            ):
                deepest = candidate

    if deepest is not None and deepest[0] > policy.max_causal_depth:
        event = deepest[1]
        findings.append(
            LoopFinding(
                "CAUSAL_DEPTH_EXCEEDED",
                LoopDecision.BLOCK,
                FindingSeverity.HIGH,
                event.trace_id,
                tuple(sorted({event.source_agent_id, event.target_agent_id})),
                (event.event_id,),
                f"causal depth {deepest[0]} exceeds {policy.max_causal_depth}",
            )
        )
    return findings


def _recursive_action_findings(
    events: Sequence[LoopEvent],
    by_id: Mapping[str, LoopEvent],
    policy: LoopPolicy,
) -> list[LoopFinding]:
    findings: list[LoopFinding] = []

    for event in events:
        token = (
            event.source_agent_id,
            event.target_agent_id,
            event.relation,
            event.action_digest,
        )
        occurrences = 1
        lineage = [event.event_id]
        current_id = event.parent_event_id
        steps = 0
        while (
            current_id is not None
            and current_id in by_id
            and steps <= policy.max_causal_depth
        ):
            ancestor = by_id[current_id]
            ancestor_token = (
                ancestor.source_agent_id,
                ancestor.target_agent_id,
                ancestor.relation,
                ancestor.action_digest,
            )
            if ancestor_token == token:
                occurrences += 1
                lineage.append(ancestor.event_id)
            current_id = ancestor.parent_event_id
            steps += 1
        if occurrences >= policy.action_block_occurrences:
            disposition = LoopDecision.BLOCK
            severity = FindingSeverity.CRITICAL
            reason = "RECURSIVE_ACTION_LOOP"
        elif occurrences >= policy.action_review_occurrences:
            disposition = LoopDecision.REVIEW
            severity = FindingSeverity.MEDIUM
            reason = "REPEATED_ACTION_IN_LINEAGE"
        else:
            continue
        findings.append(
            LoopFinding(
                reason,
                disposition,
                severity,
                event.trace_id,
                tuple(sorted({event.source_agent_id, event.target_agent_id})),
                tuple(reversed(lineage)),
                f"identical action edge occurs {occurrences} times in lineage",
            )
        )

    return findings


def _causal_findings(
    events: Sequence[LoopEvent], policy: LoopPolicy
) -> list[LoopFinding]:
    by_id = {event.event_id: event for event in events}
    return (
        _parent_integrity_findings(events, by_id, policy)
        + _lineage_findings(by_id, policy)
        + _recursive_action_findings(events, by_id, policy)
    )


def _authorization_findings(events: Sequence[LoopEvent]) -> list[LoopFinding]:
    findings: list[LoopFinding] = []
    authority_relations = {
        Relation.DELEGATES,
        Relation.APPROVES,
        Relation.DISPATCHES,
    }
    by_authorization: dict[str, list[LoopEvent]] = {}

    for event in events:
        if event.authorization_id is not None:
            by_authorization.setdefault(event.authorization_id, []).append(event)

        if event.authorization_state is AuthorizationState.VERIFIED:
            if event.authorization_id is None:
                findings.append(
                    LoopFinding(
                        "VERIFIED_AUTHORIZATION_ID_ABSENT",
                        LoopDecision.BLOCK,
                        FindingSeverity.CRITICAL,
                        event.trace_id,
                        tuple(sorted({event.source_agent_id, event.target_agent_id})),
                        (event.event_id,),
                        "VERIFIED state requires a single-use authorization_id",
                    )
                )
            continue

        if event.relation in authority_relations:
            disposition = LoopDecision.BLOCK
            severity = FindingSeverity.CRITICAL
        else:
            disposition = LoopDecision.REVIEW
            severity = FindingSeverity.HIGH
        findings.append(
            LoopFinding(
                f"AUTHORIZATION_{event.authorization_state.value}",
                disposition,
                severity,
                event.trace_id,
                tuple(sorted({event.source_agent_id, event.target_agent_id})),
                (event.event_id,),
                "edge lacks verified execution authority",
            )
        )

    for authorization_id, uses in sorted(by_authorization.items()):
        if len(uses) <= 1:
            continue
        findings.append(
            LoopFinding(
                "AUTHORIZATION_REUSE",
                LoopDecision.BLOCK,
                FindingSeverity.CRITICAL,
                min(event.trace_id for event in uses),
                tuple(
                    sorted(
                        {
                            agent
                            for event in uses
                            for agent in (
                                event.source_agent_id,
                                event.target_agent_id,
                            )
                        }
                    )
                ),
                tuple(sorted(event.event_id for event in uses)),
                f"single-use authorization {authorization_id!r} was reused",
            )
        )
    return findings


def _graph_findings(events: Sequence[LoopEvent]) -> list[LoopFinding]:
    findings: list[LoopFinding] = []
    traces = sorted({event.trace_id for event in events})
    authority_relations = {Relation.DELEGATES, Relation.APPROVES}

    for trace_id in traces:
        trace_events = [event for event in events if event.trace_id == trace_id]
        authority_events = [
            event for event in trace_events if event.relation in authority_relations
        ]
        for component, witness in _cyclic_components(authority_events):
            relations = sorted(
                {
                    event.relation.value
                    for event in authority_events
                    if event.event_id in witness.event_ids
                }
            )
            findings.append(
                LoopFinding(
                    "CIRCULAR_AUTHORITY",
                    LoopDecision.BLOCK,
                    FindingSeverity.CRITICAL,
                    trace_id,
                    component,
                    witness.event_ids,
                    "authority-bearing cycle via " + ", ".join(relations),
                )
            )

        invocation_events = [
            event for event in trace_events if event.relation is Relation.INVOKES
        ]
        for component, witness in _cyclic_components(invocation_events):
            findings.append(
                LoopFinding(
                    "AGENT_INVOCATION_CYCLE",
                    LoopDecision.REVIEW,
                    FindingSeverity.MEDIUM,
                    trace_id,
                    component,
                    witness.event_ids,
                    "bidirectional invocation is reviewable; repeated canonical "
                    "actions or causal cycles are blocked separately",
                )
            )
    return findings


def discover_loops(
    events: Iterable[LoopEvent | Mapping[str, object]],
    policy: LoopPolicy | None = None,
) -> LoopDiscoveryReport:
    """Analyze one bounded batch and return a deterministic security report."""

    policy = policy or LoopPolicy()
    parsed = (
        event if isinstance(event, LoopEvent) else LoopEvent.from_dict(event)
        for event in events
    )
    normalized = _deduplicate(parsed)
    if not normalized:
        raise LoopFormatError("at least one event is required")
    if len(normalized) > policy.max_events:
        raise LoopFormatError(
            f"event count {len(normalized)} exceeds limit {policy.max_events}"
        )

    findings = (
        _authorization_findings(normalized)
        + _causal_findings(normalized, policy)
        + _graph_findings(normalized)
    )
    findings = sorted(
        {_finding_key(item): item for item in findings}.values(), key=_finding_key
    )

    if len(findings) > policy.max_findings:
        omitted = len(findings) - policy.max_findings
        findings = findings[: policy.max_findings]
        findings.append(
            LoopFinding(
                "FINDING_LIMIT_EXCEEDED",
                LoopDecision.BLOCK,
                FindingSeverity.HIGH,
                "multiple",
                (),
                (),
                f"{omitted} findings omitted after bounded report limit",
            )
        )

    if any(item.disposition is LoopDecision.BLOCK for item in findings):
        decision = LoopDecision.BLOCK
    elif findings:
        decision = LoopDecision.REVIEW
    else:
        decision = LoopDecision.ALLOW

    input_body = [event.to_dict() for event in normalized]
    input_digest = _sha256_json(input_body)
    report_body: dict[str, object] = {
        "spec": LOOP_REPORT_SPEC,
        "input_digest": input_digest,
        "decision": decision.value,
        "events_analyzed": len(normalized),
        "traces_analyzed": len({event.trace_id for event in normalized}),
        "findings": [finding.to_dict() for finding in findings],
    }
    report_id = _sha256_json(report_body)
    return LoopDiscoveryReport(
        report_id=report_id,
        input_digest=input_digest,
        decision=decision,
        events_analyzed=len(normalized),
        traces_analyzed=len({event.trace_id for event in normalized}),
        findings=tuple(findings),
    )
