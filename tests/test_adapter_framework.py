"""Evidence adapter framework: ground-truth isolation, schema
validation, dry-run-before-live. Built to prevent a repeat of the
AMLSim incident (an adapter silently producing meaningless results
because a misconfiguration wasn't caught before the full run)."""

import time

import pytest

from agent_dna.adapters_framework import EvidenceAdapter, SourceRow
from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.trace import AgentAction


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


class CleanAdapter(EvidenceAdapter):
    """Well-behaved: no ground-truth leak."""

    def to_action(self, row):
        return AgentAction(
            agent_id=row.raw["agent"], capability="crm.read", timestamp=time.time()
        )

    def to_evidence(self, row):
        return {"enterprise_state": {"invoice_open": True}}

    def ground_truth(self, row):
        return row.raw.get("is_fraud", False)


class LeakyAdapter(EvidenceAdapter):
    """Deliberately misbehaved: leaks a ground-truth-shaped key into
    evidence, simulating the class of mistake the framework exists
    to catch."""

    def to_action(self, row):
        return AgentAction(
            agent_id=row.raw["agent"], capability="crm.read", timestamp=time.time()
        )

    def to_evidence(self, row):
        return {
            "enterprise_state": {
                "invoice_open": True,
                "is_fraud": row.raw.get("is_fraud", False),  # LEAK
            }
        }


def _engine():
    return DecisionEngine(scorer=StubScorer())


def _rows(n=5):
    return [SourceRow(raw={"agent": f"a{i}", "is_fraud": i % 2 == 0}) for i in range(n)]


def test_clean_adapter_dry_run_reports_no_violations():
    adapter = CleanAdapter(_engine())
    report = adapter.dry_run(_rows())
    assert report.is_clean()
    assert report.rows_processed == 5
    assert "allow" in report.verdict_counts


def test_leaky_adapter_caught_by_forbidden_key_scan():
    adapter = LeakyAdapter(_engine())
    report = adapter.dry_run(_rows())
    assert not report.is_clean()
    assert len(report.forbidden_key_violations) == 5
    assert "is_fraud" in report.forbidden_key_violations[0]


def test_leaky_rows_are_skipped_not_silently_evaluated():
    """A row with a ground-truth leak must not be evaluated by the
    engine at all -- it should be excluded, not evaluated-with-leak."""
    adapter = LeakyAdapter(_engine())
    report = adapter.dry_run(_rows())
    assert report.rows_processed == 0  # all 5 rejected, none evaluated


def test_ground_truth_confusion_matrix_populated_when_implemented():
    adapter = CleanAdapter(_engine())
    report = adapter.dry_run(_rows())
    assert report.ground_truth_confusion is not None
    total = sum(report.ground_truth_confusion.values())
    assert total == 5


def test_ground_truth_absent_gracefully_skipped():
    class NoGroundTruthAdapter(EvidenceAdapter):
        def to_action(self, row):
            return AgentAction(
                agent_id="a", capability="crm.read", timestamp=time.time()
            )

        def to_evidence(self, row):
            return None

    adapter = NoGroundTruthAdapter(_engine())
    report = adapter.dry_run(_rows(2))
    assert report.ground_truth_confusion is None  # not implemented, skipped
    assert report.rows_processed == 2


def test_run_live_refuses_without_acknowledgement():
    adapter = CleanAdapter(_engine())
    with pytest.raises(ValueError, match="acknowledge_dry_run_reviewed"):
        adapter.run_live(_rows(), acknowledge_dry_run_reviewed=False)


def test_run_live_works_with_acknowledgement():
    adapter = CleanAdapter(_engine())
    results = adapter.run_live(_rows(2), acknowledge_dry_run_reviewed=True)
    assert len(results) == 2


def test_run_live_still_refuses_leaky_evidence_even_with_acknowledgement():
    """Acknowledgement bypasses the SPEED BUMP, never the actual
    safety check -- a leak is refused unconditionally."""
    adapter = LeakyAdapter(_engine())
    with pytest.raises(ValueError, match="Forbidden key"):
        adapter.run_live(_rows(2), acknowledge_dry_run_reviewed=True)


def test_none_evidence_is_valid_not_a_violation():
    """Evidence-honesty: returning None (no evidence available) must
    NOT be flagged as a violation -- it's the correct, safe default."""

    class NoEvidenceAdapter(EvidenceAdapter):
        def to_action(self, row):
            return AgentAction(
                agent_id="a", capability="crm.read", timestamp=time.time()
            )

        def to_evidence(self, row):
            return None

    adapter = NoEvidenceAdapter(_engine())
    report = adapter.dry_run(_rows(3))
    assert report.is_clean()
    assert report.rows_processed == 3
