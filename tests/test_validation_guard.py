"""ValidationGuard: tighten-only at the drift level, everything else
report-only, and every failure mode leaves enforcement unchanged."""

import json
import time

from agent_dna.validation import ValidationGuard, build_report, seal


def _report(auc_target="high", score_type="probability", ece=None, expired=False):
    import random

    rng = random.Random(9)
    n = 120
    labels = [int(rng.random() < 0.3) for _ in range(n)]
    if auc_target == "high":
        scores = [min(1.0, 0.7 * y + 0.25 * rng.random()) for y in labels]
    else:
        scores = [rng.random() for _ in labels]
    env = build_report(
        score_name="drift_score",
        score_type=score_type,
        scores=scores,
        labels=labels,
        agents=[f"a{i % 3}" for i in range(n)],
        capabilities=["c1" if i % 2 else "c2" for i in range(n)],
        label_source="independent",
        label_source_note="risk ops",
        now=time.time() - (100 * 24 * 3600 if expired else 0),
    )
    if ece is not None:
        body = env["body"]
        body["calibration"]["ece"] = ece
        env = seal(body)
    return env


def _write(tmp_path, env, name="r.json"):
    f = tmp_path / name
    f.write_text(json.dumps(env))
    return str(f)


def test_healthy_report_leaves_threshold_unchanged(tmp_path):
    g = ValidationGuard(report_path=_write(tmp_path, _report("high")))
    assert g.loaded
    assert g.effective_drift_threshold(0.5) == 0.5


def test_weak_auc_tightens_threshold_never_loosens(tmp_path):
    g = ValidationGuard(report_path=_write(tmp_path, _report("weak")))
    assert g.loaded
    eff = g.effective_drift_threshold(0.5)
    assert eff < 0.5
    assert eff == min(0.5, eff)


def test_tampered_report_rejected_threshold_unchanged(tmp_path):
    env = _report("weak")
    env["body"]["global"]["auc"] = 0.99
    g = ValidationGuard(report_path=_write(tmp_path, env))
    assert not g.loaded
    assert g.effective_drift_threshold(0.5) == 0.5
    assert any("hash mismatch" in w for w in g.warnings())


def test_missing_report_env_unset_is_status_quo(monkeypatch):
    monkeypatch.delenv("PV_VALIDATION_REPORT", raising=False)
    g = ValidationGuard()
    assert not g.loaded
    assert g.effective_drift_threshold(0.42) == 0.42


def test_env_var_wiring(tmp_path, monkeypatch):
    path = _write(tmp_path, _report("high"))
    monkeypatch.setenv("PV_VALIDATION_REPORT", path)
    g = ValidationGuard()
    assert g.loaded


def test_expired_report_ignored(tmp_path):
    g = ValidationGuard(report_path=_write(tmp_path, _report(expired=True)))
    assert not g.loaded
    assert any("EXPIRED" in w for w in g.warnings())


def test_calibration_warning_is_report_only(tmp_path):
    g = ValidationGuard(report_path=_write(tmp_path, _report("high", ece=0.25)))
    assert g.loaded
    assert any("report-only" in w for w in g.warnings())
    assert g.effective_drift_threshold(0.5) == 0.5


def test_guard_has_no_deterministic_level_surface():
    """The tighten-only drift hook is the guard's ONLY runtime effect;
    nothing on the API mentions or reaches L0-L4."""
    api = [a for a in dir(ValidationGuard) if not a.startswith("_")]
    assert set(api) == {
        "effective_drift_threshold",
        "warnings",
        "loaded",
        "report_path",
    }
