"""
Policy mining — derive the controls that SHOULD exist from the
controls that actually fired.

Rules only catch what a human anticipated. An agent doing something
nobody wrote a rule for falls through to the learned layer, which
escalates but never blocks. That gap is real, and the sealed decision
log is the asset that closes it: every decision the runtime ever made,
with its verdict, its trigger, and (where opted in) the rule-relevant
inputs.

This module reads that history and proposes candidate rules, each one:

  * traced to the exact sealed records that motivated it (record
    hashes), never a vibe;
  * emitted as a VALID policy document with assertions derived from
    observed data, so it feeds straight into `pv policy check` and
    gets counterfactualled before anyone merges it;
  * or, when the current policy schema cannot express the pattern
    (sequences, time-of-day), reported as an ADVISORY that names the
    gap instead of emitting a rule that would silently not work.

Nothing here is auto-applied. A suggestion is a pull request waiting
to be written, reviewed, gated, and acknowledged by a named human.
"""

from __future__ import annotations

import json
import statistics
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HIGH_RISK_TOKENS = (
    "pay",
    "wire",
    "transfer",
    "settle",
    "disburse",
    "export",
    "delete",
    "grant",
)


def _severity(capability: str, support: int) -> str:
    if any(t in capability.lower() for t in HIGH_RISK_TOKENS) or support >= 10:
        return "HIGH"
    return "MEDIUM"


@dataclass
class RuleCandidate:
    id: str
    kind: str  # "policy" | "grant" | "advisory"
    severity: str
    capability: str
    rationale: str
    support: int  # decisions backing this suggestion
    evidence: dict[str, Any] = field(default_factory=dict)
    policy_document: dict[str, Any] | None = None  # gate-ready
    note: str = ""

    def write(self, out_dir: str) -> str | None:
        """Write a gate-ready policy file. Advisories write nothing --
        there is no valid rule to write."""
        if self.policy_document is None:
            return None
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        path = Path(out_dir) / f"{self.id}.json"
        path.write_text(json.dumps(self.policy_document, indent=2))
        return str(path)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in vars(self).items()}


# ---------------------------------------------------------------------
# detectors
# ---------------------------------------------------------------------


def _detect_numeric_cap(
    decisions: dict[str, dict],
    inputs: Iterable[dict],
    numeric_field: str,
    min_support: int,
) -> list[RuleCandidate]:
    """A threshold the organisation is ALREADY enforcing by hand.

    If every allowed amount sits below every escalated/blocked amount,
    the data itself draws the line -- the control exists in humans'
    heads and nowhere in the runtime. Suggest it explicitly, with the
    cap set at the highest amount actually allowed, so the rule blocks
    nothing that was previously approved (counterfactual: zero newly
    blocked, by construction).

    When allowed and refused amounts OVERLAP there is no clean line;
    an advisory says so rather than inventing a percentile.
    """
    per_cap: dict[str, dict[str, list]] = {}
    for row in inputs:
        rec = decisions.get(row["decision_id"])
        if rec is None:
            continue
        value = row["retained"].get(numeric_field)
        if not isinstance(value, (int, float)):
            continue
        bucket = per_cap.setdefault(
            row["capability"], {"allow": [], "refused": [], "hashes": []}
        )
        (bucket["allow"] if rec["decision"] == "allow" else bucket["refused"]).append(
            (float(value), rec)
        )

    out: list[RuleCandidate] = []
    for capability, b in per_cap.items():
        support = len(b["allow"]) + len(b["refused"])
        if support < min_support or not b["refused"] or not b["allow"]:
            continue
        allowed_max = max(v for v, _ in b["allow"])
        refused_min = min(v for v, _ in b["refused"])
        sev = _severity(capability, support)
        slug = capability.replace(".", "-")

        if refused_min <= allowed_max:
            out.append(
                RuleCandidate(
                    id=f"advisory-overlap-{slug}",
                    kind="advisory",
                    severity=sev,
                    capability=capability,
                    rationale=(
                        f"{numeric_field} does not separate approved from "
                        f"refused activity: approved up to {allowed_max:g}, "
                        f"refused from {refused_min:g}. A single cap would "
                        "block previously-approved work."
                    ),
                    support=support,
                    evidence={
                        "allowed_max": allowed_max,
                        "refused_min": refused_min,
                        "allowed_n": len(b["allow"]),
                        "refused_n": len(b["refused"]),
                        "record_hashes": sorted(
                            {r["record_hash"] for _, r in b["allow"] + b["refused"]}
                        ),
                    },
                    note=(
                        "No threshold suggested. Consider an additional "
                        "condition (counterparty, time, agent) that "
                        "explains the overlap."
                    ),
                )
            )
            continue

        rule_id = f"MINED-{slug.upper()}-{numeric_field.upper()}-CAP"
        out.append(
            RuleCandidate(
                id=f"cap-{slug}-{numeric_field}",
                kind="policy",
                severity=sev,
                capability=capability,
                rationale=(
                    f"every approved {capability} had {numeric_field} <= "
                    f"{allowed_max:g}; every refused one had {numeric_field} "
                    f">= {refused_min:g}. The organisation is already "
                    "enforcing this line by hand -- the runtime does not "
                    "know it."
                ),
                support=support,
                evidence={
                    "allowed_max": allowed_max,
                    "refused_min": refused_min,
                    "allowed_n": len(b["allow"]),
                    "refused_n": len(b["refused"]),
                    "record_hashes": sorted(
                        {r["record_hash"] for _, r in b["allow"] + b["refused"]}
                    ),
                    "sample_refused": [
                        {
                            "decision_id": r["decision_id"],
                            numeric_field: v,
                            "verdict": r["decision"],
                            "triggered_by": r["triggered_by"],
                            "record_hash": r["record_hash"],
                        }
                        for v, r in sorted(b["refused"])[:5]
                    ],
                },
                policy_document={
                    "policies": [
                        {
                            "id": rule_id,
                            "capability": capability,
                            "outcome": "block",
                            "reason": (
                                f"{numeric_field} above {allowed_max:g} "
                                "requires manual release (mined from "
                                f"{support} sealed decisions)"
                            ),
                            "condition": {
                                "field": f"arguments.{numeric_field}",
                                "operator": ">",
                                "value": allowed_max,
                            },
                        }
                    ],
                    # assertions derived from OBSERVED data, not invented
                    "assertions": [
                        {
                            "name": f"blocks the smallest refused {numeric_field} "
                            f"({refused_min:g})",
                            "capability": capability,
                            "arguments": {numeric_field: refused_min},
                            "expect": "block",
                        },
                        {
                            "name": f"allows the largest approved {numeric_field} "
                            f"({allowed_max:g})",
                            "capability": capability,
                            "arguments": {numeric_field: allowed_max},
                            "expect": "allow",
                        },
                    ],
                },
            )
        )
    return out


def _detect_always_refused(
    records: list[dict], min_support: int
) -> list[RuleCandidate]:
    """A capability the runtime has NEVER allowed, but only ever
    refused via the learned/authorization path -- i.e. no deterministic
    rule states it. Escalation is not enforcement: make it explicit."""
    per_cap: dict[str, list[dict]] = {}
    for r in records:
        per_cap.setdefault(r["capability"], []).append(r)

    out = []
    for capability, rows in per_cap.items():
        if len(rows) < min_support:
            continue
        if any(r["decision"] == "allow" for r in rows):
            continue
        if any(r["triggered_by"] == "policy" for r in rows):
            continue  # a rule already covers it
        triggers = sorted({r["triggered_by"] for r in rows})
        slug = capability.replace(".", "-")
        out.append(
            RuleCandidate(
                id=f"deny-{slug}",
                kind="policy",
                severity=_severity(capability, len(rows)),
                capability=capability,
                rationale=(
                    f"{capability} was refused {len(rows)}/{len(rows)} times, "
                    f"never by a policy rule (triggers: {', '.join(triggers)}). "
                    "The outcome is consistent but not stated -- a change in "
                    "drift calibration or a new grant would silently permit it."
                ),
                support=len(rows),
                evidence={
                    "refused_n": len(rows),
                    "triggers": triggers,
                    "record_hashes": sorted({r["record_hash"] for r in rows}),
                    "sample": [
                        {
                            "decision_id": r["decision_id"],
                            "verdict": r["decision"],
                            "triggered_by": r["triggered_by"],
                            "record_hash": r["record_hash"],
                        }
                        for r in rows[:5]
                    ],
                },
                policy_document={
                    "policies": [
                        {
                            "id": f"MINED-DENY-{slug.upper()}",
                            "capability": capability,
                            "outcome": "block",
                            "reason": (
                                f"{capability} is not permitted (mined: "
                                f"refused in {len(rows)}/{len(rows)} sealed "
                                "decisions)"
                            ),
                        }
                    ],
                    "assertions": [
                        {
                            "name": f"blocks {capability}",
                            "capability": capability,
                            "arguments": {},
                            "expect": "block",
                        },
                    ],
                },
            )
        )
    return out


def _detect_missing_grant(records: list[dict], min_support: int) -> list[RuleCandidate]:
    """Repeated authorization escalations for the same agent+capability:
    work the business clearly does, with no standing approval recorded.
    Every one of these is an unnamed approval -- an auditor cannot see
    who sanctioned it."""
    per_pair: dict[tuple, list[dict]] = {}
    for r in records:
        if r["triggered_by"] == "authorization":
            per_pair.setdefault((r["agent_id"], r["capability"]), []).append(r)

    out = []
    for (agent_id, capability), rows in per_pair.items():
        if len(rows) < min_support:
            continue
        out.append(
            RuleCandidate(
                id=f"grant-{agent_id}-{capability}".replace(".", "-"),
                kind="grant",
                severity=_severity(capability, len(rows)),
                capability=capability,
                rationale=(
                    f"{agent_id} was escalated for {capability} {len(rows)} "
                    "times with no standing grant. Each escalation is an "
                    "approval nobody is named in -- approval_ref is null on "
                    "all of them."
                ),
                support=len(rows),
                evidence={
                    "agent_id": agent_id,
                    "escalations": len(rows),
                    "record_hashes": sorted({r["record_hash"] for r in rows}),
                    "sample": [
                        {
                            "decision_id": r["decision_id"],
                            "record_hash": r["record_hash"],
                        }
                        for r in rows[:5]
                    ],
                },
                note=(
                    f'Suggested grant: {{"agent_id": "{agent_id}", '
                    f'"capability": "{capability}", "granted_by": '
                    '"<NAMED APPROVER>", "budget": <amount>}. Grants are '
                    "authorization, not policy -- add to your grants file, "
                    "not a rule set."
                ),
            )
        )
    return out


def _detect_rapid_sequence(
    records: list[dict], min_support: int, window_seconds: float = 300.0
) -> list[RuleCandidate]:
    """Same agent performing capability A then B within minutes -- the
    classic self-dealing shape (onboard a vendor, pay the vendor).
    Not expressible as a single-action rule: reported as an advisory
    pointing at cross-agent invariants."""
    by_agent: dict[str, list[dict]] = {}
    for r in records:
        by_agent.setdefault(r["agent_id"], []).append(r)

    pairs: dict[tuple, list[tuple]] = {}
    for agent, rows in by_agent.items():
        rows.sort(key=lambda r: r.get("timestamp", 0.0))
        for a, b in zip(rows, rows[1:], strict=False):
            if a["capability"] == b["capability"]:
                continue
            dt = b.get("timestamp", 0.0) - a.get("timestamp", 0.0)
            if 0 <= dt <= window_seconds:
                pairs.setdefault((a["capability"], b["capability"]), []).append(
                    (agent, a, b)
                )

    out = []
    for (cap_a, cap_b), hits in pairs.items():
        if len(hits) < min_support:
            continue
        out.append(
            RuleCandidate(
                id=f"advisory-sequence-{cap_a}-{cap_b}".replace(".", "-"),
                kind="advisory",
                severity=_severity(cap_b, len(hits)),
                capability=f"{cap_a} -> {cap_b}",
                rationale=(
                    f"the same agent performed {cap_a} then {cap_b} within "
                    f"{int(window_seconds)}s on {len(hits)} occasion(s). "
                    "Single-action rules cannot see this shape."
                ),
                support=len(hits),
                evidence={
                    "agents": sorted({h[0] for h in hits})[:5],
                    "record_hashes": sorted(
                        {
                            record["record_hash"]
                            for hit in hits
                            for record in (hit[1], hit[2])
                        }
                    ),
                    "sample": [
                        {
                            "first": h[1]["decision_id"],
                            "then": h[2]["decision_id"],
                            "gap_seconds": round(
                                h[2].get("timestamp", 0) - h[1].get("timestamp", 0), 1
                            ),
                        }
                        for h in hits[:5]
                    ],
                },
                note=(
                    "Not expressible in the current policy schema (rules "
                    "evaluate one action). Express as a cross-agent "
                    "invariant / dual-control requirement instead."
                ),
            )
        )
    return out


def _detect_off_hours(records: list[dict], min_support: int) -> list[RuleCandidate]:
    """Activity outside the capability's normal operating hours."""
    per_cap: dict[str, list[dict]] = {}
    for r in records:
        if r.get("timestamp"):
            per_cap.setdefault(r["capability"], []).append(r)

    out = []
    for capability, rows in per_cap.items():
        if len(rows) < max(min_support, 10):
            continue
        hours = [datetime.fromtimestamp(r["timestamp"], tz=UTC).hour for r in rows]
        median = statistics.median(hours)
        outliers = [
            row for row, hour in zip(rows, hours, strict=True) if abs(hour - median) > 6
        ]
        if not outliers or len(outliers) > len(rows) * 0.25:
            continue
        out.append(
            RuleCandidate(
                id=f"advisory-offhours-{capability}".replace(".", "-"),
                kind="advisory",
                severity=_severity(capability, len(rows)),
                capability=capability,
                rationale=(
                    f"{len(outliers)} of {len(rows)} {capability} decisions "
                    f"fell far outside the usual hour (~{int(median)}:00 UTC)."
                ),
                support=len(rows),
                evidence={
                    "outlier_n": len(outliers),
                    "median_hour_utc": median,
                    "record_hashes": sorted(
                        {record["record_hash"] for record in outliers}
                    ),
                    "sample": [
                        {
                            "decision_id": r["decision_id"],
                            "hour_utc": datetime.fromtimestamp(
                                r["timestamp"], tz=UTC
                            ).hour,
                        }
                        for r in outliers[:5]
                    ],
                },
                note=(
                    "Not expressible in the current policy schema: rules "
                    "evaluate arguments and evidence, and time-of-day is "
                    "neither. Supply it as evidence (e.g. "
                    "evidence.request_time_utc) to make it rule-able."
                ),
            )
        )
    return out


# ---------------------------------------------------------------------


def mine(
    decision_store,
    replay_store=None,
    *,
    since_ts: float | None = None,
    min_support: int = 5,
    numeric_field: str = "amount",
) -> list[RuleCandidate]:
    records = list(decision_store.iter_decisions(since_ts))
    by_id = {r["decision_id"]: r for r in records}

    candidates: list[RuleCandidate] = []
    if replay_store is not None and getattr(replay_store, "enabled", False):
        candidates += _detect_numeric_cap(
            # The history window is defined by the sealed decision timestamp.
            # Replay rows live in a separate store and may have a slightly
            # different capture timestamp.
            by_id,
            replay_store.iter_inputs(None),
            numeric_field,
            min_support,
        )
    candidates += _detect_always_refused(records, min_support)
    candidates += _detect_missing_grant(records, min_support)
    candidates += _detect_rapid_sequence(records, min_support)
    candidates += _detect_off_hours(records, min_support)

    order = {"HIGH": 0, "MEDIUM": 1}
    kind_order = {"policy": 0, "grant": 1, "advisory": 2}
    candidates.sort(
        key=lambda c: (order.get(c.severity, 9), kind_order.get(c.kind, 9), -c.support)
    )
    return candidates
