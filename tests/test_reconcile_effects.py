"""drp-observer/1 reconciliation: the theorem side of complete
mediation.

    ObservedEffect => exists! PriorValidAllow    (verified here)
    Effect => Observed                            (TCB assumption; NOT
                                                   provable, by design)
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path("tools").resolve()))
import reconcile_effects as re  # noqa: E402

VEC = Path("spec/observer/vectors")


def _h(rec):
    rec["record_hash"] = re.compute_hash(rec)
    return rec


def _decision(did, cap, verdict, ts=1000.0):
    return _h(
        {
            "kind": "decision",
            "decision_id": did,
            "agent_id": "a1",
            "capability": cap,
            "decision": verdict,
            "timestamp": ts,
            "reason": "t",
            "prev_hash": "0" * 64,
            "triggered_by": "x",
        }
    )


def _effect(obs, seq, dref, etype, ts=1002.0, epoch="ep-1"):
    return _h(
        {
            "kind": "effect",
            "observer_id": obs,
            "seq": seq,
            "decision_ref": dref,
            "effect_type": etype,
            "target": etype,
            "timestamp": ts,
            "epoch_id": epoch,
            "observer_sig": "ed25519:sig",
        }
    )


def _epoch(obs, s0, s1, eid="ep-1"):
    return _h(
        {
            "kind": "coverage_epoch",
            "observer_id": obs,
            "epoch_id": eid,
            "seq_start": s0,
            "seq_end": s1,
            "window_start": 0.0,
            "window_end": 9e9,
            "observer_sig": "ed25519:sig",
        }
    )


def test_clean_reconciliation_passes():
    decs = [_decision("d1", "payments.transfer", "allow")]
    effs = [_epoch("obs-A", 1, 1), _effect("obs-A", 1, "d1", "payments.transfer")]
    rep = re.reconcile(decs, effs)
    assert rep.ok, [f.detail for f in rep.findings]


def test_unauthorized_effect_no_matching_decision():
    effs = [_epoch("obs-A", 1, 1), _effect("obs-A", 1, "missing", "x")]
    rep = re.reconcile([], effs)
    assert any(f.kind == "UNAUTHORIZED_EFFECT" for f in rep.findings)


def test_unauthorized_effect_decision_was_not_allow():
    decs = [_decision("d1", "storage.bulk_export", "block")]
    effs = [_epoch("obs-A", 1, 1), _effect("obs-A", 1, "d1", "storage.bulk_export")]
    rep = re.reconcile(decs, effs)
    kinds = {f.kind for f in rep.findings}
    assert "UNAUTHORIZED_EFFECT" in kinds
    assert "BLOCK_EXECUTED" in kinds


def test_orphan_effect_no_decision_ref():
    effs = [_epoch("obs-A", 1, 1), _effect("obs-A", 1, None, "network.egress")]
    rep = re.reconcile([], effs)
    assert any(f.kind == "ORPHAN_EFFECT" for f in rep.findings)


def test_observer_gap_missing_seq_in_asserted_epoch():
    decs = [_decision("d1", "c", "allow"), _decision("d2", "c", "allow")]
    effs = [
        _epoch("obs-A", 1, 3),
        _effect("obs-A", 1, "d1", "c"),
        _effect("obs-A", 3, "d2", "c"),
    ]
    rep = re.reconcile(decs, effs)
    assert any(f.kind == "OBSERVER_GAP" for f in rep.findings)


def test_effects_without_any_epoch_is_a_gap():
    decs = [_decision("d1", "c", "allow")]
    effs = [_effect("obs-A", 1, "d1", "c")]
    rep = re.reconcile(decs, effs)
    assert any(f.kind == "OBSERVER_GAP" for f in rep.findings)


def test_stale_effect_is_unauthorized():
    decs = [_decision("d1", "c", "allow", ts=1000.0)]
    effs = [_epoch("obs-A", 1, 1), _effect("obs-A", 1, "d1", "c", ts=1000.0 + 600)]
    rep = re.reconcile(decs, effs)
    assert any(
        f.kind == "UNAUTHORIZED_EFFECT" and "fresh" in f.detail for f in rep.findings
    )


def test_unsigned_observation_flagged():
    decs = [_decision("d1", "c", "allow")]
    e = _effect("obs-A", 1, "d1", "c")
    e["observer_sig"] = ""
    e = _h(e)
    rep = re.reconcile(decs, [_epoch("obs-A", 1, 1), e])
    assert any(f.kind == "UNSIGNED_OBSERVATION" for f in rep.findings)


def test_tampered_effect_record_detected():
    decs = [_decision("d1", "c", "allow")]
    e = _effect("obs-A", 1, "d1", "c")
    e["target"] = "somewhere-else"
    rep = re.reconcile(decs, [_epoch("obs-A", 1, 1), e])
    assert any(f.kind == "RECORD_TAMPERED" for f in rep.findings)


def test_second_observer_catches_what_first_omitted():
    decs = [_decision("d1", "c", "allow")]
    effs = [
        _epoch("obs-A", 1, 1),
        _effect("obs-A", 1, "d1", "c"),
        _epoch("obs-B", 1, 1),
        _effect("obs-B", 1, "no-such-allow", "exfil"),
    ]
    rep = re.reconcile(decs, effs)
    assert len(rep.observers) == 2
    assert any(
        f.kind == "UNAUTHORIZED_EFFECT" and "obs-B" in f.detail for f in rep.findings
    )


def _cli(*paths):
    return subprocess.run(
        [sys.executable, "tools/reconcile_effects.py", *paths],
        capture_output=True,
        text=True,
    )


def test_canonical_clean_vector_passes():
    p = _cli(str(VEC / "clean_decisions.jsonl"), str(VEC / "clean_effects.jsonl"))
    assert p.returncode == 0, p.stdout
    assert "PASS" in p.stdout


def test_canonical_failure_vectors_fail_with_named_verdicts():
    for dec, eff, verdict in (
        ("unauthorized_decisions", "unauthorized_effects", "UNAUTHORIZED_EFFECT"),
        ("orphan_decisions", "orphan_effects", "ORPHAN_EFFECT"),
        ("gap_decisions", "gap_effects", "OBSERVER_GAP"),
    ):
        p = _cli(str(VEC / f"{dec}.jsonl"), str(VEC / f"{eff}.jsonl"))
        assert p.returncode == 1, p.stdout
        assert verdict in p.stdout
