"""Ed25519 signing per SIGNING.md: sign-the-hash, chain coverage,
refusal of unsealed input, standalone verification."""

import time

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_record import build_record
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.signer import ReceiptSigner, generate_keypair, verify_envelope
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


KEYS = generate_keypair()


def _record():
    engine = DecisionEngine(scorer=StubScorer())
    a = AgentAction(agent_id="a1", capability="crm.read", timestamp=time.time())
    return build_record(a, engine.decide(a))


def test_sign_and_verify():
    signer = ReceiptSigner(seed_hex=KEYS["signing_key"])
    rec = _record()
    env = signer.sign_record(rec)
    assert env.algorithm == "Ed25519"
    assert env.signed_hash == rec.record_hash
    assert verify_envelope(env.to_dict(), rec.record_hash)


def test_signature_covers_history_via_hash():
    """Rule 2: prev_hash is inside record_hash, so re-chaining a signed
    record invalidates verification without touching the signature."""
    signer = ReceiptSigner(seed_hex=KEYS["signing_key"])
    rec = _record()
    env = signer.sign_record(rec)

    rec.prev_hash = "f" * 64          # re-chain attempt
    rec.record_hash = rec.compute_hash()   # attacker re-seals
    assert not verify_envelope(env.to_dict(), rec.record_hash)


def test_refuses_unsealed_record():
    signer = ReceiptSigner(seed_hex=KEYS["signing_key"])
    rec = _record()
    rec.record_hash = ""
    with pytest.raises(ValueError):
        signer.sign_record(rec)


def test_wrong_key_fails():
    signer = ReceiptSigner(seed_hex=KEYS["signing_key"])
    rec = _record()
    env = signer.sign_record(rec).to_dict()
    env["public_key"] = generate_keypair()["public_key"]
    assert not verify_envelope(env, rec.record_hash)


def test_recorder_signs_when_signer_attached():
    engine = DecisionEngine(scorer=StubScorer())
    recorder = DecisionRecorder(signer=ReceiptSigner(seed_hex=KEYS["signing_key"]))
    a = AgentAction(agent_id="a1", capability="crm.read", timestamp=time.time())
    rec = recorder.record(a, engine.decide(a))
    env = recorder.envelopes[rec.record_hash]
    assert verify_envelope(env, rec.record_hash)
