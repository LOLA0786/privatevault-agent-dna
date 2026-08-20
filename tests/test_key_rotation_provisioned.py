"""PV-07: key rotation requires a caller-provisioned seed and a usable signer."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey

from agent_dna.advisory import Severity
from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.decision import Decision, DecisionResult
from agent_dna.key_lifecycle import ROTATION_CAPABILITY, rotate_and_record
from agent_dna.signer import generate_keypair, rotate_key


class _Ladder:
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


def _runtime(tmp: Path):
    return build_production_runtime(RuntimeConfig(db_path=str(tmp / "pv.db")))


def test_omitted_new_seed_fails_before_rotation_record(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    with pytest.raises((TypeError, ValueError)):
        rotate_and_record(
            engine=_Ladder(Decision.ALLOW),
            recorder=rt.recorder,
            agent_id="sec-officer-01",
            old_seed_hex=old,
        )
    export = rt.store.export_jsonl(tmp_path / "audit.jsonl")
    text = export.read_text()
    assert ROTATION_CAPABILITY not in text
    rt.store.close()


def test_omitted_new_seed_on_rotate_key_fails_closed() -> None:
    old = generate_keypair()["signing_key"]
    with pytest.raises((TypeError, ValueError)):
        rotate_key(old)


def test_invalid_new_seed_fails_closed_without_success_record(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    with pytest.raises(ValueError):
        rotate_and_record(
            engine=_Ladder(Decision.ALLOW),
            recorder=rt.recorder,
            agent_id="sec-officer-01",
            old_seed_hex=old,
            new_seed_hex="not-a-seed",
        )
    export = rt.store.export_jsonl(tmp_path / "audit.jsonl")
    text = export.read_text()
    assert '"outcome": "ok"' not in text or ROTATION_CAPABILITY not in text
    assert "new_public_key=" not in text
    rt.store.close()


def test_provisioned_rotation_returns_public_metadata_only(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    new = generate_keypair()["signing_key"]
    out = rotate_and_record(
        engine=_Ladder(Decision.ALLOW),
        recorder=rt.recorder,
        agent_id="sec-officer-01",
        old_seed_hex=old,
        new_seed_hex=new,
        reason="scheduled",
    )
    assert "new_seed" not in out
    assert "new_seed_hex" not in out
    assert "new_seed_hint" not in out
    dumped = json_safe(out)
    assert new.lower() not in dumped.lower()
    assert out["new_public_key"]
    assert out["key_id"]
    assert out["rotation_envelope"]["public_key"]
    assert out["decision_id"]
    rt.store.close()


def json_safe(value) -> str:
    import json

    return json.dumps(value)


def test_post_rotation_sign_verify_with_provisioned_seed(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    new = generate_keypair()["signing_key"]
    out = rotate_and_record(
        engine=_Ladder(Decision.ALLOW),
        recorder=rt.recorder,
        agent_id="sec-officer-01",
        old_seed_hex=old,
        new_seed_hex=new,
    )
    challenge = b"privatevault-key-rotation-v1:" + bytes.fromhex(out["new_public_key"])
    sig = SigningKey(new.encode("ascii"), encoder=HexEncoder).sign(challenge).signature
    VerifyKey(out["new_public_key"], encoder=HexEncoder).verify(challenge, sig)
    assert out.get("challenge_verified") is True
    rt.store.close()


def test_rotation_does_not_log_seed(tmp_path: Path, caplog) -> None:
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    new = generate_keypair()["signing_key"]
    with caplog.at_level(logging.DEBUG):
        rotate_and_record(
            engine=_Ladder(Decision.ALLOW),
            recorder=rt.recorder,
            agent_id="sec-officer-01",
            old_seed_hex=old,
            new_seed_hex=new,
        )
    blob = caplog.text
    export = rt.store.export_jsonl(tmp_path / "audit.jsonl")
    blob += export.read_text()
    assert new not in blob
    assert old not in blob
    rt.store.close()


def test_challenge_verify_failure_does_not_record_success(
    tmp_path: Path, monkeypatch
) -> None:
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    new = generate_keypair()["signing_key"]

    def _boom(*args, **kwargs):
        raise ValueError("challenge verify failed")

    monkeypatch.setattr(
        "agent_dna.key_lifecycle.rotate_key",
        _boom,
    )
    with pytest.raises(ValueError, match="challenge verify failed"):
        rotate_and_record(
            engine=_Ladder(Decision.ALLOW),
            recorder=rt.recorder,
            agent_id="sec-officer-01",
            old_seed_hex=old,
            new_seed_hex=new,
        )
    export = rt.store.export_jsonl(tmp_path / "audit.jsonl")
    text = export.read_text()
    assert "new_public_key=" not in text
    rt.store.close()
