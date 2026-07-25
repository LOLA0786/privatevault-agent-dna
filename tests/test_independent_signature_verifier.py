"""The independent verifier anchors signatures to operator-trusted keys."""

import json
import subprocess
import sys
import time
from pathlib import Path

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.signer import ReceiptSigner, generate_keypair
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction

VERIFIER = Path("tools/verify_records.py")


class _Scorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def _artifacts(tmp_path):
    keys = generate_keypair()
    signer = ReceiptSigner(seed_hex=keys["signing_key"])
    store = SQLiteDecisionStore(tmp_path / "audit.db")
    recorder = DecisionRecorder(store=store, signer=signer)
    engine = DecisionEngine(scorer=_Scorer())

    for index in range(3):
        action = AgentAction(
            agent_id="independent-verifier-agent",
            capability=f"storage.read.{index}",
            timestamp=time.time() + index,
        )
        recorder.record(action, engine.decide(action))

    records = store.export_jsonl(tmp_path / "records.jsonl")
    envelopes = store.export_envelopes_jsonl(tmp_path / "envelopes.jsonl")
    store.close()

    return records, envelopes, keys


def _run(records, envelopes=None, trusted_keys=()):
    command = [sys.executable, str(VERIFIER), str(records)]

    if envelopes is not None:
        command.extend(["--envelopes", str(envelopes)])
        for key in trusted_keys:
            command.extend(["--trusted-key", key])

    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )


def test_existing_chain_only_invocation_remains_compatible(tmp_path):
    records, _, _ = _artifacts(tmp_path)

    result = _run(records)

    assert result.returncode == 0
    assert "VERDICT: PASS" in result.stdout


def test_trusted_envelopes_pass(tmp_path):
    records, envelopes, keys = _artifacts(tmp_path)

    result = _run(
        records,
        envelopes,
        trusted_keys=[keys["public_key"]],
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "envelopes checked: 3" in result.stdout
    assert "valid envelopes : 3" in result.stdout
    assert "VERDICT: PASS" in result.stdout


def test_valid_signature_from_untrusted_key_fails(tmp_path):
    records, envelopes, keys = _artifacts(tmp_path)
    attacker = generate_keypair()
    attacker_signer = ReceiptSigner(seed_hex=attacker["signing_key"])

    lines = envelopes.read_text(encoding="utf-8").splitlines()
    original = json.loads(lines[0])
    forged = attacker_signer.sign_hash(original["signed_hash"]).to_dict()
    lines[0] = json.dumps(
        forged,
        sort_keys=True,
        separators=(",", ":"),
    )
    envelopes.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    result = _run(
        records,
        envelopes,
        trusted_keys=[keys["public_key"]],
    )

    assert result.returncode == 1
    assert "untrusted public key" in result.stdout
    assert "VERDICT: FAIL" in result.stdout


def test_missing_envelope_fails(tmp_path):
    records, envelopes, keys = _artifacts(tmp_path)

    lines = envelopes.read_text(encoding="utf-8").splitlines()
    envelopes.write_text(
        "\n".join(lines[1:]) + "\n",
        encoding="utf-8",
    )

    result = _run(
        records,
        envelopes,
        trusted_keys=[keys["public_key"]],
    )

    assert result.returncode == 1
    assert "missing envelope for decision hash" in result.stdout
    assert "VERDICT: FAIL" in result.stdout


def test_envelope_option_requires_trusted_key(tmp_path):
    records, envelopes, _ = _artifacts(tmp_path)

    result = subprocess.run(
        [
            sys.executable,
            str(VERIFIER),
            str(records),
            "--envelopes",
            str(envelopes),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "must be supplied together" in result.stderr
