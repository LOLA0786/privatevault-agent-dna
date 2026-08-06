"""Key rotation is a governed, audited action.

Regression context: rotate_key produced a correct rotation envelope
that nothing consumed, so rotations left no trace in the chain -- a
verifier could not distinguish an authorised rotation from a key
compromise.
"""

import pytest

from agent_dna.advisory import Severity
from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.decision import Decision, DecisionResult
from agent_dna.key_lifecycle import (
    ROTATION_CAPABILITY,
    RotationRefused,
    rotate_and_record,
)
from agent_dna.signer import generate_keypair


class _Ladder:
    """Stand-in engine returning a real DecisionResult with an
    explicit verdict, so the recorder seals a genuine record."""

    def __init__(self, decision):
        self._decision = decision

    def decide(self, action, previous=None, evidence=None):
        return DecisionResult(
            decision=self._decision,
            triggered_by="policy",
            reason="security-officer rotation policy",
            capability=action.capability,
            agent_id=action.agent_id,
            drift_score=0.0,
            severity=Severity.INFO,
        )


def _runtime(tmp):
    return build_production_runtime(RuntimeConfig(db_path=str(tmp / "pv.db")))


def test_allowed_rotation_is_sealed_into_the_chain(tmp_path):
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    out = rotate_and_record(
        engine=_Ladder(Decision.ALLOW),
        recorder=rt.recorder,
        agent_id="sec-officer-01",
        old_seed_hex=old,
        reason="scheduled 90-day rotation",
    )
    assert out["new_public_key"]
    assert out["decision_id"]

    export = rt.store.export_jsonl(tmp_path / "audit.jsonl")
    lines = export.read_text().splitlines()
    assert any(ROTATION_CAPABILITY in ln for ln in lines), (
        "rotation left no record in the chain"
    )
    assert any(out["new_public_key"] in ln for ln in lines), (
        "new public key not anchored in the execution outcome"
    )
    rt.store.close()


def test_refused_rotation_raises_and_is_still_recorded(tmp_path):
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    with pytest.raises(RotationRefused, match="block"):
        rotate_and_record(
            engine=_Ladder(Decision.BLOCK),
            recorder=rt.recorder,
            agent_id="unauthorised-agent",
            old_seed_hex=old,
        )
    export = rt.store.export_jsonl(tmp_path / "audit.jsonl")
    assert ROTATION_CAPABILITY in export.read_text(), (
        "a denied rotation attempt must still be auditable"
    )
    rt.store.close()


def test_rotation_is_capability_gated_not_a_side_door(tmp_path):
    """require_approval is not allow: only an explicit ALLOW rotates."""
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    with pytest.raises(RotationRefused):
        rotate_and_record(
            engine=_Ladder(Decision.REQUIRE_APPROVAL),
            recorder=rt.recorder,
            agent_id="sec-officer-01",
            old_seed_hex=old,
        )
    rt.store.close()


def test_rotated_chain_still_verifies(tmp_path):
    """The audit file containing a rotation must pass the independent
    verifier unchanged -- rotation adds no new record kind."""
    import subprocess
    import sys

    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    rotate_and_record(
        engine=_Ladder(Decision.ALLOW),
        recorder=rt.recorder,
        agent_id="sec-officer-01",
        old_seed_hex=old,
        reason="rotation",
    )
    export = rt.store.export_jsonl(tmp_path / "audit.jsonl")
    rt.store.close()
    proc = subprocess.run(
        [sys.executable, "tools/verify_records.py", str(export)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
