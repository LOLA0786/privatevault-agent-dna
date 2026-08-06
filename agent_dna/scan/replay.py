"""Replay a customer's own log through the engine, enforcing nothing.

The scan exists to give an operator a number about their own system
before asking them to change anything. That imposes two constraints the
rest of the runtime does not have:

  * Nothing is persisted. No decision records, no signatures, no
    breaker state, no writes of any kind. A read-only tool that leaves
    a database behind is not read-only, and the first question a bank's
    platform team asks is what this writes.

  * The baseline comes from the customer's own history, not from us.
    A drift score against a synthetic profile says nothing about their
    agents. So each agent's actions are split chronologically: the
    earlier portion trains that agent's profile, the later portion is
    scored against it. "Here is what your agents did that does not look
    like what your agents normally do."

The report is deliberately explicit about which precedence levels were
able to fire. A scan with no policy, grants, or invariants configured
can only exercise drift and baseline -- six of eight levels are inert,
and a report that let someone believe otherwise would be the same
overclaim the composition manifest exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..decision import Decision, DecisionEngine
from ..dynamics import BehaviorDynamics
from ..manifold import CapabilityManifold
from ..scorer import DriftScorer
from ..trace import AgentAction, ExecutionTrace
from .ingest import IngestResult

# Every level DecisionEngine can consult, in precedence order, paired
# with the constructor argument that wires it. Used to report what was
# actually live rather than implying full coverage.
LEVELS: tuple[tuple[str, str], ...] = (
    ("uaal", "enterprise constraint"),
    ("policy", "customer policy"),
    ("invariants", "behavioral invariant"),
    ("consensus", "multi-agent consensus"),
    ("authorizer", "capability grant"),
    ("economics", "cost anomaly"),
    ("scorer", "learned drift"),
)

_MAX_SAMPLES = 20
_ARG_PREVIEW = 120


def action_amount(action: AgentAction) -> float | None:
    """Monetary amount carried by an action, or None.

    Same key convention as the circuit breaker's default amount
    function, kept local so the scan does not depend on a private name
    in the enforcement path.
    """
    amt = getattr(action, "amount", None)
    if amt is None:
        amt = (getattr(action, "arguments", None) or {}).get("amount")
    try:
        return float(amt) if amt is not None else None
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class RefusedSample:
    """One refused action, kept verbatim so the operator can go and
    look it up in their own log."""

    agent_id: str
    capability: str
    timestamp: float
    verdict: str
    triggered_by: str
    reason: str
    amount: float | None
    source_line: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "capability": self.capability,
            "timestamp": self.timestamp,
            "verdict": self.verdict,
            "triggered_by": self.triggered_by,
            "reason": self.reason[:400],
            "amount": self.amount,
            "source_line": self.source_line,
        }


@dataclass
class MoneyAtRisk:
    """Refused actions that carried an amount. Reported because it is a
    literal field in the log, not an inference: no attempt is made to
    classify PII or sensitivity, because that would require guessing
    about data the scan never sees."""

    count: int = 0
    total: float = 0.0
    largest: float = 0.0
    largest_capability: str = ""

    def observe(self, amount: float, capability: str) -> None:
        self.count += 1
        self.total += amount
        if amount > self.largest:
            self.largest = amount
            self.largest_capability = capability

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "total": round(self.total, 2),
            "largest": round(self.largest, 2),
            "largest_capability": self.largest_capability,
        }


@dataclass
class ScanReport:
    source_path: str = ""
    source_format: str = ""
    coverage: float = 0.0
    lines_skipped: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)

    agents: list[str] = field(default_factory=list)
    window: tuple[float, float] | None = None

    baseline_actions: int = 0
    evaluated_actions: int = 0

    allowed: int = 0
    approval: int = 0
    blocked: int = 0
    engine_errors: int = 0

    by_level: dict[str, int] = field(default_factory=dict)
    refused_by_capability: dict[str, int] = field(default_factory=dict)
    refused_by_agent: dict[str, int] = field(default_factory=dict)
    samples: list[RefusedSample] = field(default_factory=list)
    money: MoneyAtRisk = field(default_factory=MoneyAtRisk)

    levels_active: list[str] = field(default_factory=list)
    levels_inert: list[str] = field(default_factory=list)
    drift_threshold: float = 0.0
    baseline_fraction: float = 0.0
    min_baseline_actions: int = 20
    agents_without_baseline: list[str] = field(default_factory=list)

    @property
    def refused(self) -> int:
        return self.approval + self.blocked

    @property
    def refusal_rate(self) -> float:
        return (
            (self.refused / self.evaluated_actions) if self.evaluated_actions else 0.0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": {
                "path": self.source_path,
                "format": self.source_format,
                "coverage": round(self.coverage, 4),
                "lines_skipped": self.lines_skipped,
                "skip_reasons": self.skip_reasons,
            },
            "window": {
                "start": self.window[0] if self.window else None,
                "end": self.window[1] if self.window else None,
            },
            "agents": self.agents,
            "counts": {
                "baseline": self.baseline_actions,
                "evaluated": self.evaluated_actions,
                "allowed": self.allowed,
                "require_approval": self.approval,
                "blocked": self.blocked,
                "engine_errors": self.engine_errors,
            },
            "by_level": self.by_level,
            "refused_by_capability": self.refused_by_capability,
            "refused_by_agent": self.refused_by_agent,
            "money": self.money.to_dict(),
            "samples": [s.to_dict() for s in self.samples],
            "coverage_caveat": {
                "levels_active": self.levels_active,
                "levels_inert": self.levels_inert,
                "drift_threshold": self.drift_threshold,
                "baseline_fraction": self.baseline_fraction,
                "min_baseline_actions": self.min_baseline_actions,
                "agents_without_baseline": self.agents_without_baseline,
            },
        }


def _split_by_agent(
    actions: list[AgentAction],
) -> dict[str, list[AgentAction]]:
    """Group by agent and order by time. Ingest preserves file order;
    scoring needs chronological order, and a log written by several
    concurrent workers is not guaranteed to be either."""
    grouped: dict[str, list[AgentAction]] = {}
    for action in actions:
        grouped.setdefault(action.agent_id, []).append(action)
    for seq in grouped.values():
        seq.sort(key=lambda a: a.timestamp)
    return grouped


def _partition(
    grouped: dict[str, list[AgentAction]],
    baseline_fraction: float,
    min_baseline_actions: int,
) -> tuple[dict[str, list[AgentAction]], list[AgentAction], list[str]]:
    """Split each agent chronologically into profile and evaluation.

    The profile must contain at least min_baseline_actions observations,
    and evaluation must be non-empty.  Capability count is deliberately
    irrelevant: a single-purpose agent can have a legitimate baseline.
    An agent too small to split is named in the report rather than scored
    against somebody else's profile.
    """
    baseline: dict[str, list[AgentAction]] = {}
    evaluate: list[AgentAction] = []
    unsplittable: list[str] = []

    for agent_id, seq in sorted(grouped.items()):
        cut = int(len(seq) * baseline_fraction)
        if cut < min_baseline_actions or cut >= len(seq):
            unsplittable.append(agent_id)
            continue
        baseline[agent_id] = seq[:cut]
        evaluate.extend(seq[cut:])

    return baseline, evaluate, unsplittable


def _fit_baseline(
    baseline: dict[str, list[AgentAction]],
) -> DriftScorer:
    """One profile across all agents, matching how DriftScorer is built
    in composition.py. Each agent contributes its own trace so
    transition dynamics stay per-agent rather than interleaved."""
    traces = [
        ExecutionTrace(agent_id=agent_id, actions=list(seq))
        for agent_id, seq in sorted(baseline.items())
        if seq
    ]
    manifold = CapabilityManifold().fit(traces)
    dynamics = BehaviorDynamics().fit(traces)
    return DriftScorer(manifold, dynamics)


def _describe_levels(engine: DecisionEngine) -> tuple[list[str], list[str]]:
    active: list[str] = []
    inert: list[str] = []
    for attr, label in LEVELS:
        (active if getattr(engine, attr, None) is not None else inert).append(label)
    return active, inert


def replay(
    ingested: IngestResult,
    *,
    baseline_fraction: float = 0.5,
    engine: DecisionEngine | None = None,
    drift_threshold: float = 0.50,
    max_samples: int = _MAX_SAMPLES,
    min_baseline_actions: int = 20,
) -> ScanReport:
    """Score the later portion of a log against the earlier portion.

    baseline_fraction is the share of each agent's actions used to
    learn that agent's normal behaviour. min_baseline_actions is the
    minimum observation count required for that profile. An agent with
    too few actions is reported by name in agents_without_baseline and
    excluded from evaluation rather than scored against a profile built
    from somebody else's traffic.

    Pass `engine` to supply a fully composed DecisionEngine (policy,
    grants, invariants and so on). When omitted, a drift-only engine is
    built from the log itself and the report says so.
    """
    if not 0.0 < baseline_fraction < 1.0:
        raise ValueError("baseline_fraction must be strictly between 0 and 1")
    if min_baseline_actions < 1:
        raise ValueError("min_baseline_actions must be at least 1")

    report = ScanReport(
        source_path=ingested.source_path,
        source_format=ingested.source_format,
        coverage=ingested.coverage,
        lines_skipped=len(ingested.skipped),
        skip_reasons=ingested.skip_reasons(),
        agents=ingested.agents(),
        window=ingested.time_span(),
        baseline_fraction=baseline_fraction,
        min_baseline_actions=min_baseline_actions,
        drift_threshold=drift_threshold,
    )

    baseline, evaluate, unsplittable = _partition(
        _split_by_agent(ingested.actions),
        baseline_fraction,
        min_baseline_actions,
    )
    report.agents_without_baseline = unsplittable
    report.baseline_actions = sum(len(v) for v in baseline.values())
    evaluate.sort(key=lambda a: a.timestamp)

    if engine is None:
        engine = DecisionEngine(
            scorer=_fit_baseline(baseline) if baseline else None,
            drift_threshold=drift_threshold,
        )
    report.levels_active, report.levels_inert = _describe_levels(engine)
    report.drift_threshold = getattr(engine, "drift_threshold", drift_threshold)

    prev_capability: dict[str, str] = {}
    for action in evaluate:
        report.evaluated_actions += 1
        try:
            result = engine.decide(
                action, prev_capability.get(action.agent_id), action.evidence or None
            )
        except Exception:
            # The engine is fail-closed and should not raise, but a scan
            # over somebody else's data must survive anything. Counted,
            # never silently dropped, never treated as an allow.
            report.engine_errors += 1
            continue
        prev_capability[action.agent_id] = action.capability

        trigger = result.triggered_by or "unknown"
        report.by_level[trigger] = report.by_level.get(trigger, 0) + 1

        if result.decision is Decision.ALLOW:
            report.allowed += 1
            continue
        if result.decision is Decision.REQUIRE_APPROVAL:
            report.approval += 1
        else:
            report.blocked += 1

        cap = action.capability
        report.refused_by_capability[cap] = report.refused_by_capability.get(cap, 0) + 1
        report.refused_by_agent[action.agent_id] = (
            report.refused_by_agent.get(action.agent_id, 0) + 1
        )

        amount = action_amount(action)
        if amount is not None and amount > 0:
            report.money.observe(amount, cap)

        if len(report.samples) < max_samples:
            report.samples.append(
                RefusedSample(
                    agent_id=action.agent_id,
                    capability=cap,
                    timestamp=action.timestamp,
                    verdict=result.decision.value,
                    triggered_by=trigger,
                    reason=result.reason or "",
                    amount=amount,
                    source_line=(action.context or {}).get("source_line"),
                )
            )

    report.by_level = dict(sorted(report.by_level.items(), key=lambda kv: -kv[1]))
    report.refused_by_capability = dict(
        sorted(report.refused_by_capability.items(), key=lambda kv: -kv[1])
    )
    report.refused_by_agent = dict(
        sorted(report.refused_by_agent.items(), key=lambda kv: -kv[1])
    )
    return report
