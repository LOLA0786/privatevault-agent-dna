"""Replay must be read-only, reproducible, and honest about its reach.

The scan produces a number a customer will act on. Three properties
carry that weight:

  * it writes nothing,
  * it says which levels were actually able to fire,
  * it never scores an agent against a profile built from somebody
    else's traffic.

These tests are weighted accordingly.
"""

from __future__ import annotations

import json

import pytest

from agent_dna.advisory import Severity
from agent_dna.decision import Decision, DecisionEngine, DecisionResult
from agent_dna.scan import ScanReport, ingest, replay
from agent_dna.scan.replay import LEVELS, action_amount
from agent_dna.trace import AgentAction


def _log(tmp_path, rows, name="log.jsonl") -> str:
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return str(p)


def _rows(agent: str, caps, start=1780000000, step=30):
    return [
        {
            "agent_id": agent,
            "capability": cap,
            "timestamp": start + i * step,
            "arguments": args,
        }
        for i, (cap, args) in enumerate(caps)
    ]


def _routine(agent: str, n: int, cap="crm.read", start=1780000000):
    return _rows(agent, [(cap, {}) for _ in range(n)], start=start)


# ------------------------------------------------- baseline behaviour


def test_novel_capability_after_a_routine_baseline_is_refused(
    tmp_path,
) -> None:
    rows = _routine("a1", 40) + _rows(
        "a1",
        [("payments.wire_transfer", {"amount": 340000})],
        start=1780000000 + 40 * 30,
    )
    report = replay(ingest(_log(tmp_path, rows)))

    assert report.evaluated_actions > 0
    assert report.refused >= 1
    caps = report.refused_by_capability
    assert "payments.wire_transfer" in caps


def test_a_uniform_log_produces_few_refusals(tmp_path) -> None:
    """The control. If everything an agent does is what it always does,
    a scan that flags a large share of it is measuring noise."""
    report = replay(ingest(_log(tmp_path, _routine("a1", 200))))

    assert report.evaluated_actions == 100
    assert report.refusal_rate < 0.05


def test_amount_bearing_refusals_are_totalled(tmp_path) -> None:
    rows = _routine("a1", 40) + _rows(
        "a1",
        [("payments.wire", {"amount": 340000}), ("payments.wire", {"amount": 95000})],
        start=1780000000 + 40 * 30,
    )
    report = replay(ingest(_log(tmp_path, rows)))

    assert report.money.count == 2
    assert report.money.total == pytest.approx(435000.0)
    assert report.money.largest == pytest.approx(340000.0)
    assert report.money.largest_capability == "payments.wire"


def test_amount_is_read_only_from_literal_fields() -> None:
    """No inference. An action without an amount has no amount, and a
    non-numeric one is not coerced into a number."""

    def act(args):
        return AgentAction(agent_id="a", capability="c", timestamp=1.0, arguments=args)

    assert action_amount(act({"amount": 12.5})) == 12.5
    assert action_amount(act({"amount": "12.5"})) == 12.5
    assert action_amount(act({})) is None
    assert action_amount(act({"amount": "many"})) is None
    assert action_amount(act({"total": 99})) is None


# --------------------------------------------------------- read-only


def test_replay_writes_nothing_to_disk(tmp_path) -> None:
    """A read-only tool that leaves a database behind is not read-only.
    This is the first question a platform team asks."""
    rows = _routine("a1", 40) + _rows(
        "a1", [("novel.cap", {})], start=1780000000 + 40 * 30
    )
    log = _log(tmp_path, rows)
    before = {p.name for p in tmp_path.iterdir()}

    replay(ingest(log))

    assert {p.name for p in tmp_path.iterdir()} == before


def test_replay_is_deterministic(tmp_path) -> None:
    """Two runs over the same log must produce the same number. A scan
    whose answer moves between runs cannot be quoted to a customer."""
    rows = _routine("a1", 60) + _rows(
        "a1",
        [("novel.a", {}), ("novel.b", {"amount": 500})],
        start=1780000000 + 60 * 30,
    )
    log = _log(tmp_path, rows)

    first = replay(ingest(log)).to_dict()
    second = replay(ingest(log)).to_dict()

    assert first == second


# ------------------------------------------------------- honest reach


def test_a_drift_only_scan_reports_six_inert_levels(tmp_path) -> None:
    """Without policy, grants, or invariants configured, only drift and
    baseline can fire. A report that implied full coverage would be the
    overclaim the composition manifest exists to prevent."""
    report = replay(ingest(_log(tmp_path, _routine("a1", 40))))

    assert report.levels_active == ["learned drift"]
    assert len(report.levels_inert) == len(LEVELS) - 1
    assert "capability grant" in report.levels_inert
    assert "customer policy" in report.levels_inert


def test_a_composed_engine_reports_its_levels_as_active(tmp_path) -> None:
    class _Invariants:
        def check(self, *_a, **_k):
            return None

    engine = DecisionEngine(scorer=None, invariants=_Invariants())
    report = replay(ingest(_log(tmp_path, _routine("a1", 40))), engine=engine)

    assert "behavioral invariant" in report.levels_active
    assert "behavioral invariant" not in report.levels_inert


def test_ingest_coverage_is_carried_into_the_report(tmp_path) -> None:
    """A scan over a log we half understood is worth half as much, and
    the report has to say so rather than quietly reporting on the half
    it managed to read."""
    rows = [
        {"agent_id": "a1", "capability": "c", "timestamp": 1780000000 + i}
        for i in range(20)
    ]
    rows += [{"capability": "c", "timestamp": 1780001000 + i} for i in range(20)]
    report = replay(ingest(_log(tmp_path, rows)))

    assert report.coverage == 0.5
    assert report.lines_skipped == 20
    assert report.skip_reasons == {"no agent identifier": 20}


# ------------------------------------------- refusal to misattribute


def test_an_agent_too_small_to_split_is_named_not_scored(tmp_path) -> None:
    """Scoring a two-action agent against a profile learned from a
    busy one would manufacture drift out of nothing."""
    rows = _routine("busy", 100) + _rows("tiny", [("x", {})])
    report = replay(ingest(_log(tmp_path, rows)))

    assert report.agents_without_baseline == ["tiny"]
    assert all(s.agent_id != "tiny" for s in report.samples)


def test_short_multi_capability_history_is_not_scored(tmp_path) -> None:
    rows = _rows(
        "short",
        [(f"capability.{index}", {}) for index in range(9)],
    )

    report = replay(ingest(_log(tmp_path, rows)))

    assert report.agents_without_baseline == ["short"]
    assert report.baseline_actions == 0
    assert report.evaluated_actions == 0
    assert report.to_dict()["coverage_caveat"]["min_baseline_actions"] == 20


def test_single_capability_history_can_form_a_real_baseline(tmp_path) -> None:
    report = replay(ingest(_log(tmp_path, _routine("a1", 40))))

    assert report.baseline_actions == 20
    assert report.evaluated_actions == 20


def test_baseline_and_evaluation_never_overlap(tmp_path) -> None:
    """An action used to learn normal cannot also be judged against it;
    that would report the training set as compliant and inflate the
    allow count."""
    rows = _routine("a1", 100)
    report = replay(ingest(_log(tmp_path, rows)), baseline_fraction=0.5)

    assert report.baseline_actions == 50
    assert report.evaluated_actions == 50
    assert report.baseline_actions + report.evaluated_actions == len(rows)


def test_each_agent_is_scored_against_its_own_history(tmp_path) -> None:
    """Two agents doing entirely different but internally consistent
    work must not flag each other."""
    rows = _routine("crm-agent", 60, cap="crm.read") + _routine(
        "ops-agent", 60, cap="ops.deploy", start=1780100000
    )
    report = replay(ingest(_log(tmp_path, rows)))

    assert report.evaluated_actions == 60
    assert report.refusal_rate < 0.10


# --------------------------------------------------------- robustness


def test_a_raising_engine_is_counted_never_treated_as_allow(
    tmp_path,
) -> None:
    class _Exploding:
        drift_threshold = 0.5
        scorer = object()
        invariants = authorizer = uaal = economics = consensus = policy = None

        def decide(self, *_a, **_k):
            raise RuntimeError("candidate engine is broken")

    report = replay(ingest(_log(tmp_path, _routine("a1", 40))), engine=_Exploding())

    assert report.engine_errors == report.evaluated_actions
    assert report.allowed == 0


def test_sample_cap_is_respected(tmp_path) -> None:
    rows = _routine("a1", 40) + _rows(
        "a1",
        [(f"novel.{i}", {}) for i in range(30)],
        start=1780000000 + 40 * 30,
    )
    report = replay(ingest(_log(tmp_path, rows)), max_samples=5)

    assert len(report.samples) == 5
    assert report.refused > 5


def test_samples_point_back_into_the_source_log(tmp_path) -> None:
    """An operator has to be able to go and look the action up."""
    rows = _routine("a1", 40) + _rows(
        "a1", [("novel.cap", {})], start=1780000000 + 40 * 30
    )
    report = replay(ingest(_log(tmp_path, rows)))

    assert report.samples
    assert report.samples[0].source_line == 41


def test_empty_log_produces_a_well_formed_empty_report(tmp_path) -> None:
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    report = replay(ingest(str(p)))

    assert isinstance(report, ScanReport)
    assert report.evaluated_actions == 0
    assert report.refusal_rate == 0.0
    assert report.to_dict()["counts"]["evaluated"] == 0


@pytest.mark.parametrize("bad", [0.0, 1.0, -0.5, 1.5])
def test_invalid_baseline_fraction_is_rejected(tmp_path, bad: float) -> None:
    log = _log(tmp_path, _routine("a1", 10))
    with pytest.raises(ValueError, match="baseline_fraction"):
        replay(ingest(log), baseline_fraction=bad)


@pytest.mark.parametrize("bad", [0, -1])
def test_invalid_minimum_baseline_is_rejected(tmp_path, bad: int) -> None:
    log = _log(tmp_path, _routine("a1", 40))
    with pytest.raises(ValueError, match="min_baseline_actions"):
        replay(ingest(log), min_baseline_actions=bad)


def test_report_serializes_to_json(tmp_path) -> None:
    """The report is an artifact a customer keeps. It has to survive
    round-tripping without custom encoders."""
    rows = _routine("a1", 40) + _rows(
        "a1", [("novel.cap", {"amount": 10})], start=1780000000 + 40 * 30
    )
    report = replay(ingest(_log(tmp_path, rows)))

    text = json.dumps(report.to_dict())
    assert json.loads(text)["counts"]["evaluated"] == report.evaluated_actions


def test_counts_add_up(tmp_path) -> None:
    rows = _routine("a1", 60) + _rows(
        "a1",
        [("novel.a", {}), ("novel.b", {})],
        start=1780000000 + 60 * 30,
    )
    report = replay(ingest(_log(tmp_path, rows)))

    assert (
        report.allowed + report.approval + report.blocked + report.engine_errors
        == report.evaluated_actions
    )
    assert report.refused == report.approval + report.blocked


def test_verdict_levels_are_tallied(tmp_path) -> None:
    rows = _routine("a1", 40) + _rows(
        "a1", [("novel.cap", {})], start=1780000000 + 40 * 30
    )
    report = replay(ingest(_log(tmp_path, rows)))

    assert sum(report.by_level.values()) == (
        report.evaluated_actions - report.engine_errors
    )


def test_allow_verdicts_do_not_appear_in_refusal_breakdowns(
    tmp_path,
) -> None:
    class _AlwaysAllow:
        drift_threshold = 0.5
        scorer = object()
        invariants = authorizer = uaal = economics = consensus = policy = None

        def decide(self, action, *_a, **_k):
            return DecisionResult(
                decision=Decision.ALLOW,
                triggered_by="baseline",
                reason="ok",
                capability=action.capability,
                agent_id=action.agent_id,
                drift_score=0.0,
                severity=Severity.INFO,
            )

    report = replay(ingest(_log(tmp_path, _routine("a1", 40))), engine=_AlwaysAllow())

    assert report.refused == 0
    assert report.refused_by_capability == {}
    assert report.money.count == 0
    assert report.samples == []
