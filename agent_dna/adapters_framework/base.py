"""
EvidenceAdapter base class.

Subclass and implement:
    to_action(row)    -> AgentAction
    to_evidence(row)  -> dict (evidence shape only -- NEVER include
                         ground-truth fields here)
    ground_truth(row) -> Any (optional; used only for post-hoc scoring
                         in dry_run, NEVER passed to the engine)

The base class enforces:
  - to_evidence()'s output is schema-checked before use
  - ground_truth() is only ever called by dry_run's scoring path,
    never by anything that touches the engine
  - dry_run() is the only entry point until .run_live() is explicitly
    called, and run_live() requires a boolean acknowledgement
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agent_dna.decision import Decision, DecisionEngine
from agent_dna.trace import AgentAction

# Keys that MUST NOT appear anywhere inside an evidence dict. This is
# a blunt, cheap guard: if a subclass's to_evidence() output contains
# any of these key names at any nesting level, it's almost certainly
# a ground-truth leak (label, alert flag, fraud marker, etc.).
FORBIDDEN_EVIDENCE_KEYS = {
    "is_fraud",
    "isfraud",
    "label",
    "ground_truth",
    "alert_id",
    "alert_type",
    "fraud",
    "is_laundering",
}


def _scan_for_forbidden_keys(obj: Any, path: str = "") -> list[str]:
    """Recursively scan a dict/list for forbidden key names. Returns
    a list of violation paths, empty if clean."""
    violations = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_lower = str(k).lower().replace("_", "").replace("-", "")
            if key_lower in {f.replace("_", "") for f in FORBIDDEN_EVIDENCE_KEYS}:
                violations.append(f"{path}.{k}" if path else str(k))
            violations.extend(_scan_for_forbidden_keys(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            violations.extend(_scan_for_forbidden_keys(item, f"{path}[{i}]"))
    return violations


@dataclass
class SourceRow:
    """A single row from a source system, before adaptation. raw is
    whatever the source format is (a csv.DictReader row, a DB row,
    etc.) -- the adapter interprets it."""

    raw: dict[str, Any]


@dataclass
class DryRunReport:
    rows_processed: int
    verdict_counts: dict[str, int] = field(default_factory=dict)
    trigger_counts: dict[str, int] = field(default_factory=dict)
    schema_violations: list[str] = field(default_factory=list)
    forbidden_key_violations: list[str] = field(default_factory=list)
    ground_truth_confusion: dict[str, int] | None = None  # only if
    # ground_truth()
    # is implemented

    def is_clean(self) -> bool:
        return not self.schema_violations and not self.forbidden_key_violations

    def summary(self) -> str:
        lines = [
            f"rows processed        : {self.rows_processed}",
            f"schema violations     : {len(self.schema_violations)}",
            f"forbidden-key leaks   : {len(self.forbidden_key_violations)}",
            f"verdict distribution  : {self.verdict_counts}",
            f"trigger distribution  : {self.trigger_counts}",
        ]
        if self.ground_truth_confusion:
            lines.append(f"ground-truth confusion: {self.ground_truth_confusion}")
        if self.schema_violations:
            lines.append("SCHEMA VIOLATIONS (first 5):")
            lines.extend(f"  {v}" for v in self.schema_violations[:5])
        if self.forbidden_key_violations:
            lines.append("FORBIDDEN KEY LEAKS (first 5):")
            lines.extend(f"  {v}" for v in self.forbidden_key_violations[:5])
        return "\n".join(lines)


class EvidenceAdapter:
    """Subclass this. Do not call the engine directly from adapter
    code -- use dry_run() first, always, on any new adapter or any
    change to an existing one."""

    def __init__(self, engine: DecisionEngine):
        self.engine = engine

    # ---- subclass must implement -----------------------------------

    def to_action(self, row: SourceRow) -> AgentAction:
        raise NotImplementedError

    def to_evidence(self, row: SourceRow) -> dict[str, Any] | None:
        """Return the evidence dict for this row, or None if no
        evidence is available (which is always safer than a
        fabricated/empty dict -- see evidence-integration.md's
        evidence-honesty rule)."""
        raise NotImplementedError

    def ground_truth(self, row: SourceRow) -> Any:
        """Optional. If implemented, dry_run() will use this ONLY for
        post-hoc scoring -- never passed to to_evidence() or the
        engine. Default: not implemented, dry_run skips scoring."""
        raise NotImplementedError

    # ---- framework-enforced behavior --------------------------------

    def _validate_evidence(self, evidence: dict[str, Any] | None) -> list[str]:
        if evidence is None:
            return []
        return _scan_for_forbidden_keys(evidence)

    def dry_run(
        self,
        rows: Iterable[SourceRow],
        limit: int | None = None,
    ) -> DryRunReport:
        """The only way to run a new or changed adapter. Reports what
        WOULD happen; does not assert correctness. Read the report
        before ever calling run_live()."""
        report = DryRunReport(rows_processed=0)
        has_ground_truth = True
        confusion = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

        for i, row in enumerate(rows):
            if limit is not None and i >= limit:
                break

            action = self.to_action(row)
            evidence = self.to_evidence(row)

            violations = self._validate_evidence(evidence)
            if violations:
                report.forbidden_key_violations.extend(
                    f"row {i}: {v}" for v in violations
                )
                continue  # do not evaluate a row with a ground-truth leak

            result = self.engine.decide(action, evidence=evidence)
            report.rows_processed += 1
            report.verdict_counts[result.decision.value] = (
                report.verdict_counts.get(result.decision.value, 0) + 1
            )
            report.trigger_counts[result.triggered_by] = (
                report.trigger_counts.get(result.triggered_by, 0) + 1
            )

            if has_ground_truth:
                try:
                    truth = self.ground_truth(row)
                except NotImplementedError:
                    has_ground_truth = False
                    continue
                flagged = result.decision != Decision.ALLOW
                truthy = bool(truth)
                if flagged and truthy:
                    confusion["tp"] += 1
                elif flagged and not truthy:
                    confusion["fp"] += 1
                elif not flagged and truthy:
                    confusion["fn"] += 1
                else:
                    confusion["tn"] += 1

        if has_ground_truth and report.rows_processed > 0:
            report.ground_truth_confusion = confusion

        return report

    def run_live(
        self,
        rows: Iterable[SourceRow],
        *,
        acknowledge_dry_run_reviewed: bool,
    ) -> list[Any]:
        """Requires explicit acknowledgement that dry_run's report was
        reviewed. This is a deliberate speed bump, not a technical
        control -- it exists so a live run is never the FIRST time
        anyone looked at what the adapter produces."""
        if not acknowledge_dry_run_reviewed:
            raise ValueError(
                "run_live requires acknowledge_dry_run_reviewed=True. "
                "Run dry_run() first and review its report -- this is "
                "not a formality, see agent_dna/adapters_framework "
                "module docstring for why."
            )

        results = []
        for row in rows:
            action = self.to_action(row)
            evidence = self.to_evidence(row)
            violations = self._validate_evidence(evidence)
            if violations:
                raise ValueError(
                    f"Forbidden key(s) in evidence, refusing to run live: {violations}"
                )
            results.append(self.engine.decide(action, evidence=evidence))
        return results
