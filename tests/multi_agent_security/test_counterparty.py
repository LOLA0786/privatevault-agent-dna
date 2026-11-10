"""Mutual checkpoints: once the other party holds your checkpoint, dropping
history is something they can show."""

import hashlib
import itertools
import json
import runpy
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.checkpoint import build_checkpoint, checkpoint_hash
from agent_dna.decision import DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.multi_agent_security import (
    CheckpointRejected,
    CounterpartyLedger,
    verify_acknowledgement,
)
from agent_dna.multi_agent_security.counterparty import _record_hash
from agent_dna.open_authorizer import OpenAuthorizer
from agent_dna.signer import ReceiptSigner, generate_keypair
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction


class _Scorer:
    def score(self, action, prev=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


class Org:
    """One organisation: its own key, its own log."""

    def __init__(self, tmp_path, name):
        self.tmp = tmp_path / name
        self.tmp.mkdir()
        self.keys = generate_keypair()
        self.signer = ReceiptSigner(seed_hex=self.keys["signing_key"])
        self.store = SQLiteDecisionStore(self.tmp / "audit.db")
        self.recorder = DecisionRecorder(store=self.store, signer=self.signer)
        self.engine = DecisionEngine(scorer=_Scorer(), authorizer=OpenAuthorizer())
        self._tick = itertools.count(1)
        self._start = time.time()

    def act(self, agent="settlement-bot", times=1):
        for _ in range(times):
            action = AgentAction(
                agent_id=agent,
                capability="ledger.post",
                timestamp=self._start + next(self._tick),
            )
            record = self.recorder.record(action, self.engine.decide(action))
            self.recorder.report_outcome(record.decision_id, "ok", "posted")

    def export(self):
        path = Path(self.store.export_jsonl(self.tmp / f"x{next(self._tick)}.jsonl"))
        return path.read_text().splitlines()

    def checkpoint(self, signer="own"):
        return build_checkpoint(
            self.export(), signer=self.signer if signer == "own" else signer
        )


@pytest.fixture
def parties(tmp_path):
    seller, buyer = Org(tmp_path, "seller"), Org(tmp_path, "buyer")
    # the buyer keeps the seller's checkpoints, pinned to the seller's key
    ledger = CounterpartyLedger(
        buyer.tmp / "seller-checkpoints.jsonl", [seller.keys["public_key"]]
    )
    yield seller, buyer, ledger
    seller.store.close()
    buyer.store.close()


def test_honest_history_keeps_passing_as_it_grows(parties):
    seller, _, ledger = parties
    seller.act(times=3)
    ledger.accept(seller.checkpoint())
    seller.act(times=2)
    ledger.accept(seller.checkpoint())
    seller.act(times=4)
    assert ledger.audit(seller.export()) == []
    assert len(ledger.held()) == 2


def test_dropping_records_after_disclosure_is_caught_by_the_other_party(parties):
    seller, _, ledger = parties
    seller.act(times=4)
    ledger.accept(seller.checkpoint())
    truncated = seller.export()[:-2]
    failures = ledger.audit(truncated)
    assert failures and "INCOMPLETE EXPORT" in failures[0]


def test_rewriting_one_disclosed_record_is_caught(parties):
    seller, _, ledger = parties
    seller.act(times=3)
    ledger.accept(seller.checkpoint())
    lines = seller.export()
    forged = json.loads(lines[1])
    forged["record_hash"] = "0" * 64
    lines[1] = json.dumps(forged)
    failures = ledger.audit(lines)
    assert any("log_head mismatch" in failure for failure in failures)


def test_a_checkpoint_that_goes_backwards_is_not_accepted(parties):
    seller, _, ledger = parties
    seller.act(times=2)
    early = seller.checkpoint()
    seller.act(times=3)
    ledger.accept(seller.checkpoint())
    with pytest.raises(CheckpointRejected, match="goes backwards"):
        ledger.accept(early)


def test_same_count_different_history_is_refused(parties, tmp_path):
    seller, _, ledger = parties
    seller.act(times=2)
    ledger.accept(seller.checkpoint())
    # a second log of the same length, signed by the same seller key
    rewritten = Org(tmp_path, "rewritten")
    rewritten.act(times=2)
    other = build_checkpoint(rewritten.export(), signer=seller.signer)
    rewritten.store.close()
    with pytest.raises(CheckpointRejected, match="history was rewritten"):
        ledger.accept(other)


def test_only_the_pinned_counterparty_key_is_accepted(parties):
    seller, buyer, ledger = parties
    seller.act()
    with pytest.raises(CheckpointRejected, match="untrusted key"):
        ledger.accept(seller.checkpoint(signer=buyer.signer))
    with pytest.raises(CheckpointRejected, match="is unsigned"):
        ledger.accept(seller.checkpoint(signer=None))
    assert ledger.held() == []


def test_edited_checkpoint_is_not_accepted(parties):
    seller, _, ledger = parties
    seller.act(times=3)
    checkpoint = seller.checkpoint()
    with pytest.raises(CheckpointRejected, match="checkpoint_hash mismatch"):
        ledger.accept({**checkpoint, "record_count": 1})
    shrunk = {**checkpoint, "record_count": 1}
    shrunk["checkpoint_hash"] = checkpoint_hash(shrunk)
    with pytest.raises(CheckpointRejected, match="signature covers a different hash"):
        ledger.accept(shrunk)


def test_accepting_the_same_checkpoint_twice_keeps_one_copy(parties):
    seller, _, ledger = parties
    seller.act()
    checkpoint = seller.checkpoint()
    ledger.accept(checkpoint)
    ledger.accept(checkpoint)
    assert len(ledger.held()) == 1


def test_acknowledgement_proves_the_other_party_took_it(parties):
    seller, buyer, ledger = parties
    seller.act(times=2)
    checkpoint = ledger.accept(seller.checkpoint())
    ack = ledger.acknowledge(checkpoint, buyer.signer)
    buyer_key = [buyer.keys["public_key"]]
    assert verify_acknowledgement(ack, checkpoint, buyer_key) is None
    # not a receipt for some other checkpoint
    seller.act()
    later = seller.checkpoint()
    assert "different checkpoint" in verify_acknowledgement(ack, later, buyer_key)
    # not forgeable by the seller, and not editable
    assert "untrusted key" in verify_acknowledgement(
        ack, checkpoint, [seller.keys["public_key"]]
    )
    edited = {**ack, "record_count": 99}
    assert "altered" in verify_acknowledgement(edited, checkpoint, buyer_key)


def test_cannot_acknowledge_what_is_not_held(parties):
    seller, buyer, ledger = parties
    seller.act()
    with pytest.raises(CheckpointRejected, match="not held"):
        ledger.acknowledge(seller.checkpoint(), buyer.signer)


def test_an_ack_cannot_pass_as_a_checkpoint_signature(parties):
    """Each artifact is hashed under its own tag."""
    seller, buyer, ledger = parties
    seller.act()
    checkpoint = ledger.accept(seller.checkpoint())
    ack = ledger.acknowledge(checkpoint, buyer.signer)
    spoof = {**checkpoint, "signature": ack["signature"]}
    other = CounterpartyLedger(buyer.tmp / "x.jsonl", [buyer.keys["public_key"]])
    with pytest.raises(CheckpointRejected, match="signature covers a different hash"):
        other.accept(spoof)


def test_audit_with_nothing_held_says_so(parties):
    seller, _, ledger = parties
    seller.act()
    assert "nothing to audit against" in ledger.audit(seller.export())[0]


def test_a_ledger_needs_a_pinned_key(tmp_path):
    with pytest.raises(ValueError, match="must be pinned"):
        CounterpartyLedger(tmp_path / "x.jsonl", [])


@pytest.mark.parametrize("kind", ["decision", "execution"])
def test_payload_edit_with_original_hash_fails_both_auditors(parties, kind):
    seller, _, ledger = parties
    seller.act(times=4)
    checkpoint = ledger.accept(seller.checkpoint())
    lines = seller.export()
    index = next(i for i, line in enumerate(lines) if json.loads(line)["kind"] == kind)
    edited = json.loads(lines[index])
    edited["capability" if kind == "decision" else "outcome_note"] = (
        "payments.wire_everything, approved by CFO"
    )
    lines[index] = json.dumps(edited)  # deliberately keep the original record_hash
    failures = ledger.audit(lines)
    assert any("record_hash mismatch" in failure for failure in failures)
    path = seller.tmp / "tampered.jsonl"
    path.write_text("\n".join(lines) + "\n")
    cp_path = seller.tmp / "checkpoint.json"
    cp_path.write_text(json.dumps(checkpoint))
    independent = subprocess.run(
        [
            sys.executable,
            "tools/verify_records.py",
            str(path),
            "--checkpoint",
            str(cp_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert independent.returncode != 0
    assert "hash mismatch" in independent.stdout


def test_rehashing_edited_payload_still_fails_held_checkpoint(parties):
    seller, _, ledger = parties
    seller.act()
    ledger.accept(seller.checkpoint())
    lines = seller.export()
    record = json.loads(lines[0])
    record["capability"] = "payments.wire_everything"
    body = {k: v for k, v in record.items() if k != "record_hash"}
    record["record_hash"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    lines[0] = json.dumps(record)
    assert any("log_head mismatch" in f for f in ledger.audit(lines))


def test_record_hash_matches_standalone_verifier_for_live_export(parties):
    seller, _, _ = parties
    seller.act(times=3)
    independent_hash = runpy.run_path("tools/verify_records.py")["compute_hash"]
    for line in seller.export():
        record = json.loads(line)
        assert _record_hash(record) == independent_hash(record) == record["record_hash"]


def test_cannot_get_receipt_for_a_million_records_by_reusing_a_held_hash(parties):
    seller, buyer, ledger = parties
    seller.act(times=4)  # four decisions + four executions
    checkpoint = ledger.accept(seller.checkpoint())
    assert checkpoint["record_count"] == 8
    with pytest.raises(CheckpointRejected, match="checkpoint_hash mismatch"):
        ledger.acknowledge({**checkpoint, "record_count": 1_000_000}, buyer.signer)
    ack = ledger.acknowledge(checkpoint, buyer.signer)
    assert ack["record_count"] == ledger.held()[0]["record_count"] == 8


@pytest.mark.parametrize(
    "field,value", [("record_count", 1_000_000), ("log_head", "0" * 64)]
)
def test_ack_cannot_authenticate_changed_checkpoint_contents(parties, field, value):
    seller, buyer, ledger = parties
    seller.act()
    checkpoint = ledger.accept(seller.checkpoint())
    ack = ledger.acknowledge(checkpoint, buyer.signer)
    assert "checkpoint_hash mismatch" in verify_acknowledgement(
        ack, {**checkpoint, field: value}, [buyer.keys["public_key"]]
    )


@pytest.mark.parametrize("count", [1_000_000, True, -1])
def test_even_a_correctly_signed_ack_must_match_checkpoint_count(parties, count):
    seller, buyer, ledger = parties
    seller.act()
    checkpoint = ledger.accept(seller.checkpoint())
    ack = ledger.acknowledge(checkpoint, buyer.signer)
    ack["record_count"] = count
    body = {k: v for k, v in ack.items() if k not in ("ack_hash", "signature")}
    ack["ack_hash"] = hashlib.sha256(
        b"pv-checkpoint-ack/1:"
        + json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    ack["signature"] = buyer.signer.sign_hash(ack["ack_hash"]).to_dict()
    assert "record_count" in verify_acknowledgement(
        ack, checkpoint, [buyer.keys["public_key"]]
    )


@pytest.mark.parametrize(
    "line",
    [
        None,
        "{",
        "[]",
        "null",
        '{"record_hash": "a", "record_hash": "b"}',
        '{"nested": {"amount": NaN}}',
        '{"amount": 1e400}',
    ],
)
def test_malformed_export_is_a_failure_not_a_crash(parties, line):
    seller, _, ledger = parties
    seller.act()
    ledger.accept(seller.checkpoint())
    assert any("invalid record" in failure for failure in ledger.audit([line]))


@pytest.mark.parametrize("corruption", ["json", "contents", "signature"])
def test_corrupted_checkpoint_file_cannot_pass_audit_or_issue_receipt(
    parties, corruption
):
    seller, buyer, ledger = parties
    seller.act()
    checkpoint = ledger.accept(seller.checkpoint())
    broken = json.loads(json.dumps(checkpoint))
    if corruption == "contents":
        broken["record_count"] = 1_000_000
    elif corruption == "signature":
        broken["signature"]["signature"] = "0" * 128
    ledger.path.write_text("{" if corruption == "json" else json.dumps(broken) + "\n")
    assert "cannot read held checkpoints" in ledger.audit(seller.export())[0]
    with pytest.raises(CheckpointRejected, match="cannot read held checkpoints"):
        ledger.acknowledge(checkpoint, buyer.signer)
