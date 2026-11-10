"""A signed checkpoint makes record deletion visible to the verifier.

Chains, lineage and signatures prove the records in an export are genuine.
They cannot show that records are missing: a record removed from the end of
an agent's chain, a whole agent, or a single execution event leaves nothing
dangling, and its envelope goes with it. Every edit below returned
VERDICT: PASS in signed mode before checkpoints existed; each test first
shows that it still does without a checkpoint, then that the checkpoint
catches it."""

import itertools
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.checkpoint import build_checkpoint, checkpoint_hash
from agent_dna.decision import Decision, DecisionEngine, DecisionResult
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.grants import GrantRegistry
from agent_dna.signer import ReceiptSigner, generate_keypair
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction

VERIFIER = "tools/verify_records.py"


class _Scorer:
    def score(self, action, prev=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


class Export:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.keys = generate_keypair()
        self.signer = ReceiptSigner(seed_hex=self.keys["signing_key"])
        self.store = SQLiteDecisionStore(tmp_path / "audit.db")
        self.recorder = DecisionRecorder(store=self.store, signer=self.signer)
        registry = GrantRegistry()
        for agent in ("treasury-bot", "crm-bot"):
            registry.grant(agent_id=agent, capability="ledger.read", granted_by="ops")
        self.engine = DecisionEngine(scorer=_Scorer(), authorizer=registry)
        self._tick = itertools.count(1)
        self._start = time.time()

    def step(self, agent, outcome="ok"):
        action = AgentAction(
            agent_id=agent,
            capability="ledger.read",
            timestamp=self._start + next(self._tick),
        )
        record = self.recorder.record(action, self.engine.decide(action))
        self.recorder.report_outcome(record.decision_id, outcome, "done")

    def block_that_ran(self, agent):
        action = AgentAction(
            agent_id=agent,
            capability="payments.wire_all",
            timestamp=self._start + next(self._tick),
        )
        blocked = DecisionResult(
            decision=Decision.BLOCK,
            triggered_by="invariant",
            reason="forbidden",
            capability=action.capability,
            agent_id=agent,
            drift_score=0.0,
            severity=Severity.CRITICAL,
        )
        record = self.recorder.record(action, blocked)
        self.recorder.report_outcome(record.decision_id, "ok", "ran anyway")
        return record.decision_id

    def write(self, name="records"):
        records = Path(self.store.export_jsonl(self.tmp / f"{name}.jsonl"))
        envelopes = Path(self.store.export_envelopes_jsonl(self.tmp / f"{name}.env"))
        return records, envelopes

    def checkpoint(self, records, name="checkpoint.json", signer="default"):
        signer = self.signer if signer == "default" else signer
        with open(records, encoding="utf-8") as handle:
            checkpoint = build_checkpoint(handle, signer=signer)
        path = self.tmp / name
        path.write_text(json.dumps(checkpoint))
        return path

    def verify(self, records, envelopes=None, checkpoint=None):
        command = [sys.executable, VERIFIER, str(records)]
        if envelopes is not None:
            command += ["--envelopes", str(envelopes)]
            command += ["--trusted-key", self.keys["public_key"]]
        if checkpoint is not None:
            command += ["--checkpoint", str(checkpoint)]
        done = subprocess.run(command, capture_output=True, text=True, check=False)
        return done.returncode, done.stdout


def _rows(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line]


def _prune(export, records, envelopes, drop):
    """Remove matching records AND their envelopes, as an attacker with
    write access to the store or the export would."""
    rows = _rows(records)
    kept = [row for row in rows if not drop(row)]
    gone = {row["record_hash"] for row in rows} - {row["record_hash"] for row in kept}
    assert gone, "the edit removed nothing"
    out_records = export.tmp / "pruned.jsonl"
    out_records.write_text(
        "".join(
            json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in kept
        )
    )
    out_envelopes = export.tmp / "pruned.env"
    out_envelopes.write_text(
        "".join(
            json.dumps(e) + "\n"
            for e in _rows(envelopes)
            if e["signed_hash"] not in gone
        )
    )
    return out_records, out_envelopes


@pytest.fixture
def export(tmp_path):
    world = Export(tmp_path)
    world.step("treasury-bot")
    world.step("crm-bot")
    world.step("treasury-bot")
    world.blocked_id = world.block_that_ran("treasury-bot")
    world.step("treasury-bot")
    world.step("crm-bot")
    yield world
    world.store.close()


# ---- an honest export ------------------------------------------------------


def test_untouched_export_reproduces_its_checkpoint(tmp_path):
    world = Export(tmp_path)
    for agent in ("treasury-bot", "crm-bot", "treasury-bot"):
        world.step(agent)
    records, envelopes = world.write()
    checkpoint = world.checkpoint(records)
    code, out = world.verify(records, envelopes, checkpoint)
    world.store.close()
    assert code == 0, out
    assert "covers 6 record(s), signed by a trusted key" in out
    assert "origin          : verified" in out


def test_without_a_checkpoint_the_output_says_completeness_is_not_verified(tmp_path):
    world = Export(tmp_path)
    world.step("crm-bot")
    records, envelopes = world.write()
    code, out = world.verify(records, envelopes)
    world.store.close()
    assert code == 0
    assert "completeness    : NOT VERIFIED" in out


def test_chain_only_mode_says_origin_is_not_verified(tmp_path):
    world = Export(tmp_path)
    world.step("crm-bot")
    records, _ = world.write()
    code, out = world.verify(records)
    world.store.close()
    assert code == 0
    assert "origin          : NOT VERIFIED" in out


def test_later_records_extend_an_older_checkpoint(tmp_path):
    world = Export(tmp_path)
    world.step("treasury-bot")
    world.step("crm-bot")
    early, _ = world.write("early")
    checkpoint = world.checkpoint(early)
    world.step("treasury-bot")
    world.step("treasury-bot")
    records, envelopes = world.write()
    code, out = world.verify(records, envelopes, checkpoint)
    world.store.close()
    assert code == 0, out
    assert "covers 4 record(s)" in out
    assert "4 later record(s) not covered" in out


# ---- deletions: invisible without a checkpoint, caught with one ------------


def _assert_only_the_checkpoint_sees_it(export, drop, expect):
    records, envelopes = export.write()
    checkpoint = export.checkpoint(records)
    pruned_records, pruned_envelopes = _prune(export, records, envelopes, drop)

    code, out = export.verify(pruned_records, pruned_envelopes)
    assert "INCOMPLETE" not in out
    blind = code

    code, out = export.verify(pruned_records, pruned_envelopes, checkpoint)
    assert code == 1, out
    assert expect in out, out
    return blind


def test_deleting_the_execution_event_that_shows_a_block_ran(export):
    """One line removed erased the ENFORCEMENT DIVERGENCE finding."""
    blind = _assert_only_the_checkpoint_sees_it(
        export,
        lambda r: (
            r.get("kind") == "execution" and r["decision_ref"] == export.blocked_id
        ),
        "INCOMPLETE EXPORT",
    )
    assert blind == 0  # without the checkpoint the divergence is gone: PASS


def test_truncating_an_agents_chain_from_the_block_onward(export):
    records, _ = export.write("probe")
    rows = _rows(records)
    start = next(
        i for i, r in enumerate(rows) if r.get("decision_id") == export.blocked_id
    )
    doomed = {r["record_hash"] for r in rows[start:] if r["agent_id"] == "treasury-bot"}
    blind = _assert_only_the_checkpoint_sees_it(
        export, lambda r: r["record_hash"] in doomed, "INCOMPLETE"
    )
    assert blind == 0


def test_deleting_an_entire_agent(export):
    blind = _assert_only_the_checkpoint_sees_it(
        export, lambda r: r["agent_id"] == "treasury-bot", "INCOMPLETE"
    )
    assert blind == 0


def test_same_length_substitution_names_the_missing_agent(tmp_path):
    """Records removed and others kept so the count still fits: the head
    mismatch is reported with which agent's history changed."""
    world = Export(tmp_path)
    world.step("treasury-bot")
    world.step("crm-bot")
    early, _ = world.write("early")
    checkpoint = world.checkpoint(early)
    for _ in range(3):
        world.step("crm-bot")
    records, envelopes = world.write()
    pruned_records, pruned_envelopes = _prune(
        world, records, envelopes, lambda r: r["agent_id"] == "treasury-bot"
    )
    code, out = world.verify(pruned_records, pruned_envelopes, checkpoint)
    world.store.close()
    assert code == 1
    assert "log_head mismatch" in out
    assert "agent 'treasury-bot' is in the checkpoint, not the export" in out


# ---- the checkpoint itself cannot be forged or edited ----------------------


def _tamper(path, mutate):
    checkpoint = json.loads(path.read_text())
    mutate(checkpoint)
    path.write_text(json.dumps(checkpoint))


def test_edited_checkpoint_is_rejected(export):
    records, envelopes = export.write()
    checkpoint = export.checkpoint(records)
    _tamper(checkpoint, lambda c: c.update(record_count=c["record_count"] - 2))
    code, out = export.verify(records, envelopes, checkpoint)
    assert code == 1
    assert "checkpoint_hash mismatch" in out


def test_rehashed_checkpoint_fails_its_signature(export):
    """Shrink the checkpoint to fit a truncated export and recompute its
    hash: the signature no longer covers it."""
    records, envelopes = export.write()
    checkpoint = export.checkpoint(records)

    def shrink(c):
        c["record_count"] -= 2
        c["checkpoint_hash"] = checkpoint_hash(c)

    _tamper(checkpoint, shrink)
    code, out = export.verify(records, envelopes, checkpoint)
    assert code == 1
    assert "signature covers a different hash" in out


def test_checkpoint_from_an_untrusted_key_is_rejected(export):
    records, envelopes = export.write()
    stranger = ReceiptSigner(seed_hex=generate_keypair()["signing_key"])
    checkpoint = export.checkpoint(records, signer=stranger)
    code, out = export.verify(records, envelopes, checkpoint)
    assert code == 1
    assert "untrusted key" in out


def test_unsigned_checkpoint_is_rejected_when_keys_are_trusted(export):
    records, envelopes = export.write()
    checkpoint = export.checkpoint(records, signer=None)
    code, out = export.verify(records, envelopes, checkpoint)
    assert code == 1
    assert "is unsigned" in out


def test_a_record_envelope_cannot_stand_in_for_a_checkpoint_signature(export):
    """Domain separation: the checkpoint hash is taken under its own tag."""
    records, envelopes = export.write()
    checkpoint = export.checkpoint(records)
    borrowed = _rows(envelopes)[0]
    _tamper(checkpoint, lambda c: c.update(signature=borrowed))
    code, out = export.verify(records, envelopes, checkpoint)
    assert code == 1
    assert "signature covers a different hash" in out


def test_missing_checkpoint_file_fails(export):
    records, envelopes = export.write()
    code, out = export.verify(records, envelopes, export.tmp / "absent.json")
    assert code == 1
    assert "unreadable" in out


# ---- verifier input hardening that travelled with this change --------------


def test_overflowing_number_is_rejected_like_infinity(tmp_path):
    world = Export(tmp_path)
    world.step("crm-bot")
    records, _ = world.write()
    world.store.close()
    line = records.read_text().splitlines()[0]
    row = json.loads(line)
    poisoned = line.replace(
        f'"drift_score":{json.dumps(row["drift_score"])}', '"drift_score":1e999'
    )
    assert poisoned != line
    target = tmp_path / "overflow.jsonl"
    target.write_text(poisoned + "\n")
    code, out = world.verify(target)
    assert code == 1
    assert "non-finite number" in out


def test_non_object_line_fails_with_a_verdict(tmp_path):
    target = tmp_path / "list.jsonl"
    target.write_text("[1,2,3]\n")
    done = subprocess.run(
        [sys.executable, VERIFIER, str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 1
    assert "expected a JSON object" in done.stdout
    assert "VERDICT: FAIL" in done.stdout
    assert "Traceback" not in done.stderr
