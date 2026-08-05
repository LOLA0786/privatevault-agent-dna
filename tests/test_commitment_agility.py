"""drp/0.2: every commitment entry is load-bearing.

The point of a second hash algorithm is that an adversary who breaks the
first cannot substitute a payload. That only holds if the verifier
recomputes every entry present. A verifier that checks its preferred
algorithm and skips the rest accepts a record whose other entries are
forged — which is indistinguishable, to a future reader, from a record
that was never dual-committed at all.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_record import COMMITMENT_ALGORITHMS, build_record
from agent_dna.execution_record import (
    COMMITMENT_ALGORITHMS as EXEC_ALGORITHMS,
)
from agent_dna.execution_record import (
    build_execution_event,
)
from agent_dna.trace import AgentAction

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "tools" / "verify_records.py"


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def _sealed():
    """Build through the production path, not by hand: the claim is about
    what actually reaches an audit file."""
    engine = DecisionEngine(scorer=StubScorer())
    action = AgentAction(
        agent_id="agent-1",
        capability="crm.read",
        timestamp=time.time(),
        arguments={},
    )
    return build_record(action, engine.decide(action))


def test_algorithm_lists_agree_across_record_types():
    """Duplicated by design (module independence); pinned so they can't drift."""
    assert COMMITMENT_ALGORITHMS == EXEC_ALGORITHMS


def test_both_digests_cover_identical_bytes():
    rec = _sealed()
    assert rec.commitments["sha-256"] == rec.record_hash
    assert rec.commitments["sha-256"] != rec.commitments["sha3-256"]
    assert len(rec.commitments) == len(COMMITMENT_ALGORITHMS)


@pytest.mark.parametrize("algorithm", COMMITMENT_ALGORITHMS)
def test_forging_any_single_entry_fails_verification(algorithm):
    """Neither entry can be tampered with independently of the other."""
    rec = _sealed()
    rec.commitments = dict(rec.commitments) | {algorithm: "f" * 64}
    assert not rec.verify()


def test_dropping_an_entry_fails_verification():
    rec = _sealed()
    rec.commitments = {"sha-256": rec.commitments["sha-256"]}
    assert not rec.verify()


def test_unsealed_record_has_no_signing_digest():
    """No commitments, no signature. A signer must not be able to sign a
    record whose commitments were never computed."""
    rec = _sealed()
    rec.commitments = {}
    rec.record_hash = ""
    with pytest.raises(ValueError, match="not sealed"):
        rec.signing_digest()


def test_execution_event_commits_under_both(tmp_path):
    ev = build_execution_event(
        agent_id="a1", decision_id="d1", decision_hash="0" * 64, status="ok"
    )
    assert ev.verify()
    ev.commitments = dict(ev.commitments) | {"sha3-256": "e" * 64}
    assert not ev.verify()


def _run_verifier(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(path)],
        capture_output=True,
        text=True,
    )


def test_independent_verifier_catches_a_forged_sha3_entry(tmp_path):
    """The file-level claim: a forged second commitment is detectable
    from the audit file alone, by a verifier that imports nothing."""
    rec = _sealed()
    path = tmp_path / "forged.jsonl"

    clean = rec.to_dict()
    path.write_text(json.dumps(clean, sort_keys=True) + "\n")
    assert _run_verifier(path).returncode == 0, "clean record should pass"

    forged = dict(clean)
    forged["commitments"] = dict(clean["commitments"]) | {"sha3-256": "a" * 64}
    path.write_text(json.dumps(forged, sort_keys=True) + "\n")
    result = _run_verifier(path)
    assert result.returncode == 1
    assert "sha3-256 commitment mismatch" in result.stdout


def test_version_and_content_must_agree(tmp_path):
    """A 0.1 record carrying commitments is rejected: semantics come from
    the declared version, never from field presence."""
    rec = _sealed()
    d = rec.to_dict()
    d["protocol_version"] = "drp/0.1"
    path = tmp_path / "mixed.jsonl"
    path.write_text(json.dumps(d, sort_keys=True) + "\n")
    result = _run_verifier(path)
    assert result.returncode == 1
    assert "version and content disagree" in result.stdout
