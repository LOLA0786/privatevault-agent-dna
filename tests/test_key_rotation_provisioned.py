"""PV-07: key rotation requires a caller-provisioned seed and a usable signer."""

from __future__ import annotations

import json
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
        self.actions = []

    def decide(self, action, previous=None, evidence=None):
        self.actions.append(action)
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


def _jsonl_records(path: Path) -> list[dict]:
    records = []
    for line in path.read_text().splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _rotation_decisions(records: list[dict]) -> list[dict]:
    return [
        record
        for record in records
        if record.get("kind") == "decision"
        and record.get("capability") == ROTATION_CAPABILITY
    ]


def _rotation_executions(records: list[dict]) -> list[dict]:
    decision_ids = {record["decision_id"] for record in _rotation_decisions(records)}
    return [
        record
        for record in records
        if record.get("kind") == "execution"
        and record.get("decision_ref") in decision_ids
    ]


def _public_key(seed_hex: str) -> str:
    return (
        SigningKey(seed_hex.encode("ascii"), encoder=HexEncoder)
        .verify_key.encode(encoder=HexEncoder)
        .decode()
    )


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
    records = _jsonl_records(export)
    assert _rotation_decisions(records) == []
    assert _rotation_executions(records) == []
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
    records = _jsonl_records(export)
    assert all(event.get("status") != "ok" for event in _rotation_executions(records))
    assert all(record.get("outcome") != "ok" for record in _rotation_decisions(records))
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
    records = _jsonl_records(export)
    executions = _rotation_executions(records)
    assert executions
    assert any(event.get("status") == "error" for event in executions)
    assert all(event.get("status") != "ok" for event in executions)
    rt.store.close()


def test_rotation_action_binds_new_public_key_not_seed(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    new = generate_keypair()["signing_key"]
    ladder = _Ladder(Decision.ALLOW)
    out = rotate_and_record(
        engine=ladder,
        recorder=rt.recorder,
        agent_id="sec-officer-01",
        old_seed_hex=old,
        new_seed_hex=new,
        reason="scheduled",
    )
    action = ladder.actions[0]
    assert action.arguments["new_public_key"] == out["new_public_key"]
    assert action.arguments["new_public_key"] == _public_key(new)
    assert "new_seed_hex" not in action.arguments
    assert new not in json.dumps(action.arguments)
    export = rt.store.export_jsonl(tmp_path / "audit.jsonl")
    records = _jsonl_records(export)
    decisions = _rotation_decisions(records)
    assert len(decisions) == 1
    assert decisions[0]["decision_id"] == out["decision_id"]
    executions = _rotation_executions(records)
    assert any(event.get("status") == "ok" for event in executions)
    blob = export.read_text()
    assert new not in blob
    assert old not in blob
    rt.store.close()


def test_changing_target_key_changes_authorized_action_binding(
    tmp_path: Path,
) -> None:
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    new_a = generate_keypair()["signing_key"]
    new_b = generate_keypair()["signing_key"]
    first = rotate_and_record(
        engine=_Ladder(Decision.ALLOW),
        recorder=rt.recorder,
        agent_id="sec-officer-01",
        old_seed_hex=old,
        new_seed_hex=new_a,
    )
    second = rotate_and_record(
        engine=_Ladder(Decision.ALLOW),
        recorder=rt.recorder,
        agent_id="sec-officer-01",
        old_seed_hex=old,
        new_seed_hex=new_b,
    )
    assert first["decision_id"] != second["decision_id"]
    assert first["new_public_key"] != second["new_public_key"]
    export = rt.store.export_jsonl(tmp_path / "audit.jsonl")
    records = _jsonl_records(export)
    decisions = _rotation_decisions(records)
    assert len(decisions) == 2
    digests = {record["arguments_digest"] for record in decisions}
    assert len(digests) == 2
    rt.store.close()


def test_returned_public_key_must_match_authorized_key(
    tmp_path: Path, monkeypatch
) -> None:
    rt = _runtime(tmp_path)
    old = generate_keypair()["signing_key"]
    new = generate_keypair()["signing_key"]
    other = generate_keypair()

    def _wrong_key(old_seed_hex, new_seed_hex=None):
        return {
            "rotation_envelope": {
                "envelope_id": "rotate-wrong",
                "algorithm": "Ed25519-key-rotation",
                "signed_hash": "00",
                "signature": "00",
                "public_key": _public_key(old_seed_hex),
                "key_id": "rotated-to-wrong",
            },
            "new_public_key": other["public_key"],
            "key_id": "rotated-to-wrong",
            "challenge_verified": True,
        }

    monkeypatch.setattr("agent_dna.key_lifecycle.rotate_key", _wrong_key)
    with pytest.raises(ValueError):
        rotate_and_record(
            engine=_Ladder(Decision.ALLOW),
            recorder=rt.recorder,
            agent_id="sec-officer-01",
            old_seed_hex=old,
            new_seed_hex=new,
        )
    export = rt.store.export_jsonl(tmp_path / "audit.jsonl")
    records = _jsonl_records(export)
    executions = _rotation_executions(records)
    assert executions
    assert any(event.get("status") == "error" for event in executions)
    assert all(event.get("status") != "ok" for event in executions)
    rt.store.close()
