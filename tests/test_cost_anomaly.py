"""CostAnomalyChecker: evidence-honest cost-ratio and ROI-floor checks.
Never blocks; wired at precedence level 'economics' between
authorization and drift."""

import time

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.economics import CostAnomalyChecker
from agent_dna.trace import AgentAction


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id, capability=action.capability,
            drift_score=0.0, severity=Severity.INFO, reasons=[],
        )


def _engine():
    return DecisionEngine(scorer=StubScorer(), economics=CostAnomalyChecker())


def _act():
    return AgentAction(agent_id="a1", capability="api.call", timestamp=time.time())


def test_no_evidence_skips_both_checks():
    checker = CostAnomalyChecker()
    result = checker.check(evidence=None)
    assert not result.flagged
    assert "cost_ratio_anomaly" in result.checks_skipped
    assert "roi_floor" in result.checks_skipped


def test_normal_cost_ratio_passes():
    checker = CostAnomalyChecker()
    result = checker.check(evidence={"economics": {
        "estimated_cost_usd": 0.02, "historical_avg_cost_usd": 0.015,
    }})
    assert not result.flagged
    assert "cost_ratio_anomaly" in result.checks_run


def test_cost_ratio_anomaly_flags_with_real_ratio_in_message():
    checker = CostAnomalyChecker()
    result = checker.check(evidence={"economics": {
        "estimated_cost_usd": 5.0, "historical_avg_cost_usd": 0.02,
    }})
    assert result.flagged
    assert "250.0x" in result.reasons[0]


def test_roi_floor_flags_cost_exceeding_business_value():
    checker = CostAnomalyChecker()
    result = checker.check(evidence={"economics": {
        "estimated_cost_usd": 10.0, "business_value_usd": 3.0,
    }})
    assert result.flagged
    assert "roi_floor" in result.reasons[0]


def test_roi_floor_passes_when_value_exceeds_cost():
    checker = CostAnomalyChecker()
    result = checker.check(evidence={"economics": {
        "estimated_cost_usd": 1.0, "business_value_usd": 50.0,
    }})
    assert not result.flagged


def test_engine_escalates_on_cost_anomaly_never_blocks():
    engine = _engine()
    result = engine.decide(_act(), evidence={"economics": {
        "estimated_cost_usd": 9000.0, "historical_avg_cost_usd": 0.01,
    }})
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "economics"


def test_engine_falls_through_to_baseline_without_economics_evidence():
    engine = _engine()
    result = engine.decide(_act(), evidence=None)
    assert result.decision == Decision.ALLOW
    assert result.triggered_by == "baseline"


def test_no_economics_checker_means_no_economics_level():
    engine = DecisionEngine(scorer=StubScorer())  # economics=None
    result = engine.decide(_act(), evidence={"economics": {
        "estimated_cost_usd": 9000.0, "historical_avg_cost_usd": 0.01,
    }})
    assert result.triggered_by != "economics"
    assert result.decision == Decision.ALLOW
