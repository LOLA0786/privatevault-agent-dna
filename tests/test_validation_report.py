"""pv-validation/1 report: sealing, honesty enforcement, schema
conformance, and stdlib verifier round-trip (incl. tamper detection)."""

import json
import random
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from agent_dna.validation import (
    LabelSourceError,
    ScoreTypeError,
    build_report,
    calibration_metrics_for,
)

SCHEMA = json.loads(
    Path("spec/validation/pv-validation-1.schema.json").read_text())
VERIFIER = Path("tools/verify_validation.py")


def _dataset(n=120, seed=5):
    rng = random.Random(seed)
    labels = [int(rng.random() < 0.3) for _ in range(n)]
    scores = [min(1.0, max(0.0, 0.65 * y + 0.3 * rng.random()))
              for y in labels]
    agents = [f"agent-{i % 3}" for i in range(n)]
    caps = ["payments.transfer" if i % 2 else "crm.read" for i in range(n)]
    return scores, labels, agents, caps


def _build(score_type="probability", **kw):
    scores, labels, agents, caps = _dataset()
    return build_report(
        score_name="drift_score", score_type=score_type,
        scores=scores, labels=labels, agents=agents, capabilities=caps,
        label_source="independent",
        label_source_note="incident tickets labelled by risk ops, not the agent",
        now=1_700_000_000.0, **kw)


def test_report_conforms_to_schema_probability_and_ranking():
    for stype in ("probability", "ranking"):
        env = _build(stype)
        jsonschema.validate(env, SCHEMA)


def test_hash_is_stable_and_deterministic():
    assert _build()["report_hash"] == _build()["report_hash"]


def test_ranking_scores_never_carry_calibration():
    env = _build("ranking")
    assert env["body"]["calibration"] is None


def test_probability_scores_carry_calibration():
    cal = _build("probability")["body"]["calibration"]
    assert set(cal) == {"brier", "log_loss", "ece", "n_bins"}


def test_calibration_gate_refuses_ranking():
    with pytest.raises(ScoreTypeError):
        calibration_metrics_for("ranking", [0.5], [1])


def test_undeclared_score_type_refused():
    with pytest.raises(ScoreTypeError):
        _build("vibes")


def test_self_labelled_ground_truth_refused():
    scores, labels, agents, caps = _dataset()
    with pytest.raises(LabelSourceError):
        build_report(score_name="s", score_type="ranking", scores=scores,
                     labels=labels, agents=agents, capabilities=caps,
                     label_source="self", label_source_note="agent said so")
    with pytest.raises(LabelSourceError):
        build_report(score_name="s", score_type="ranking", scores=scores,
                     labels=labels, agents=agents, capabilities=caps,
                     label_source="independent", label_source_note="   ")


def test_decomposition_identity_present_in_report():
    g = _build()["body"]["global"]
    assert abs(g["auc"] - (g["auc_within_contribution"]
                           + g["auc_between_contribution"])) < 1e-9


def test_drift_section_populated_from_reference():
    scores, labels, agents, caps = _dataset()
    ref_scores, ref_labels, _, _ = _dataset(seed=11)
    env = build_report(
        score_name="drift_score", score_type="ranking",
        scores=scores, labels=labels, agents=agents, capabilities=caps,
        label_source="independent", label_source_note="risk ops tickets",
        reference=(ref_scores, ref_labels), now=1_700_000_000.0)
    assert env["body"]["drift"]["verdict"] in (
        "no_drift", "label_shift_only", "concept_drift", "insufficient_data")


def _run_verifier(path):
    return subprocess.run([sys.executable, str(VERIFIER), str(path)],
                          capture_output=True, text=True)


def test_verifier_passes_valid_report(tmp_path):
    env = _build()
    f = tmp_path / "report.json"
    f.write_text(json.dumps(env))
    proc = _run_verifier(f)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout


def test_verifier_catches_tampered_metric(tmp_path):
    env = _build()
    env["body"]["global"]["auc"] = 0.99
    f = tmp_path / "tampered.json"
    f.write_text(json.dumps(env))
    proc = _run_verifier(f)
    assert proc.returncode == 1
    assert "hash mismatch" in proc.stdout


def test_verifier_catches_calibration_on_ranking_even_if_resealed(tmp_path):
    from agent_dna.validation import seal
    env = _build("ranking")
    body = env["body"]
    body["calibration"] = {"brier": 0.1, "log_loss": 0.3, "ece": 0.02,
                           "n_bins": 10}
    f = tmp_path / "resealed.json"
    f.write_text(json.dumps(seal(body)))
    proc = _run_verifier(f)
    assert proc.returncode == 1
    assert "honesty" in proc.stdout


def test_verifier_catches_safeguard_violation_even_if_resealed(tmp_path):
    from agent_dna.validation import seal
    env = _build()
    body = env["body"]
    body["segments"]["by_agent"].append({
        "key": "sneaky", "n": 3, "n_pos": 1, "prevalence": 0.33,
        "prevalence_ci": [0.0, 1.0], "auc": 0.9,
        "status": "insufficient_samples"})
    body["dataset"]["n"] += 3
    body["dataset"]["n_neg"] += 3
    for t in ("by_capability", "by_agent_capability"):
        body["segments"][t][0]["n"] += 3
    f = tmp_path / "small_n.json"
    f.write_text(json.dumps(seal(body)))
    proc = _run_verifier(f)
    assert proc.returncode == 1
    assert "safeguards" in proc.stdout
