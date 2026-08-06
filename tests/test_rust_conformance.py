"""Rust <-> DRP spec conformance.

The spec test vectors (spec/test-vectors/*.jsonl) are the protocol's
ground truth -- tools/verify_records.py consumes them with zero trust
in this codebase. This suite proves the Rust runtime reproduces the
EXACT record_hash for every record in the clean vector, and disagrees
with every tampered record. Any failure here means the Rust and
Python chains have forked: fix Rust, never the vector.

Skips cleanly when pv_runtime is not installed, so environments
without the Rust wheel (e.g. the pure-Python CI job) are unaffected.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pv_runtime = pytest.importorskip(
    "pv_runtime", reason="Rust wheel not installed (cd rust && maturin build)"
)

ROOT = Path(__file__).resolve().parents[1]
VECTOR_DIR = ROOT / "spec" / "test-vectors"


@pytest.fixture(scope="module")
def vectors(tmp_path_factory) -> dict:
    """Generate vectors with the canonical tool into a TEMP dir, then
    load them. Generation keeps this test honest against the CURRENT
    Python serialization -- but it must never overwrite the committed
    canonical vectors, which are the protocol's frozen ground truth
    (pinned by tests/test_vector_immutability.py). This fixture
    previously wrote into spec/test-vectors/ and silently regenerated
    the spec on every run; regression-locked by the immutability test."""
    gen_dir = tmp_path_factory.mktemp("rust_conformance_vectors")
    subprocess.run(
        [sys.executable, "tools/generate_test_vectors.py", "--out", str(gen_dir)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    out = {}
    for name in ("clean", "tampered_field"):
        path = gen_dir / f"{name}.jsonl"
        out[name] = [
            json.loads(line) for line in path.read_text().splitlines() if line.strip()
        ]
    return out


def _rust_hash(rec: dict) -> str:
    """Rebuild a vector record in Rust from its stored fields and
    return the hash Rust computes. No Python hashing involved."""
    if rec["kind"] == "decision":
        r = pv_runtime.DecisionRecord(
            protocol_version=rec["protocol_version"],
            action_digest=rec.get("action_digest"),
            decision_id=rec["decision_id"],
            agent_id=rec["agent_id"],
            capability=rec["capability"],
            decision=rec["decision"],
            triggered_by=rec["triggered_by"],
            timestamp=rec["timestamp"],
            parent_decision=rec["parent_decision"],
            prev_hash=rec["prev_hash"],
            reason=rec["reason"],
            severity=rec["severity"],
            drift_score=rec["drift_score"],
            evidence_json=json.dumps(rec["evidence"]),
            evidence_strength=rec["evidence_strength"],
            arguments_digest=rec["arguments_digest"],
            outcome=rec["outcome"],
            request_id=rec.get("request_id"),
            goal=rec.get("goal"),
            intent=rec.get("intent"),
            policy_id=rec.get("policy_id"),
            approval_ref=rec.get("approval_ref"),
            receipt_ref=rec.get("receipt_ref"),
            edges_json=json.dumps(rec["edges"]),
        )
    elif rec["kind"] == "execution":
        r = pv_runtime.ExecutionEvent(
            event_id=rec["event_id"],
            agent_id=rec["agent_id"],
            decision_ref=rec["decision_ref"],
            status=rec["status"],
            detail=rec["detail"],
            timestamp=rec["timestamp"],
            prev_hash=rec["prev_hash"],
            edges_json=json.dumps(rec["edges"]),
        )
    else:  # pragma: no cover - vector schema guard
        raise AssertionError(f"unknown record kind {rec['kind']!r}")
    r.seal()
    return r.record_hash


def test_rust_verifies_every_clean_vector_record(vectors):
    assert vectors["clean"], "clean vector is empty -- generator broken?"
    for i, rec in enumerate(vectors["clean"]):
        assert _rust_hash(rec) == rec["record_hash"], (
            f"clean.jsonl line {i + 1} ({rec['kind']} "
            f"{rec.get('decision_id') or rec.get('event_id')}): "
            "Rust hash differs from spec vector -- chain fork"
        )


def test_rust_rejects_tampered_vector(vectors):
    mismatches = sum(
        1 for rec in vectors["tampered_field"] if _rust_hash(rec) != rec["record_hash"]
    )
    assert mismatches >= 1, (
        "tampered_field.jsonl fully re-verified in Rust -- the tamper "
        "is invisible to the Rust runtime, tamper evidence is broken"
    )


def test_rust_and_python_agree_on_which_line_is_tampered(vectors):
    """Stronger property: per-record verdicts must be IDENTICAL, not
    just 'both found something'."""
    from agent_dna.decision_record import DecisionRecord as PyD
    from agent_dna.execution_record import ExecutionEvent as PyE

    def py_ok(rec: dict) -> bool:
        body = {k: v for k, v in rec.items() if k != "record_hash"}
        if rec["kind"] == "decision":
            obj = PyD(
                protocol_version=body["protocol_version"],
                action_digest=body.get("action_digest"),
                decision_id=body["decision_id"],
                parent_decision=body["parent_decision"],
                agent_id=body["agent_id"],
                capability=body["capability"],
                decision=body["decision"],
                triggered_by=body["triggered_by"],
                reason=body["reason"],
                severity=body["severity"],
                drift_score=body["drift_score"],
                evidence=body["evidence"],
                evidence_strength=body["evidence_strength"],
                arguments_digest=body["arguments_digest"],
                outcome=body["outcome"],
                request_id=body.get("request_id"),
                goal=body.get("goal"),
                intent=body.get("intent"),
                policy_id=body.get("policy_id"),
                approval_ref=body.get("approval_ref"),
                receipt_ref=body.get("receipt_ref"),
                edges=body["edges"],
                timestamp=body["timestamp"],
                prev_hash=body["prev_hash"],
            )
        else:
            obj = PyE(
                event_id=body["event_id"],
                agent_id=body["agent_id"],
                decision_ref=body["decision_ref"],
                status=body["status"],
                detail=body["detail"],
                edges=body["edges"],
                timestamp=body["timestamp"],
                prev_hash=body["prev_hash"],
            )
        return obj.compute_hash() == rec["record_hash"]

    for name in ("clean", "tampered_field"):
        for i, rec in enumerate(vectors[name]):
            rust_ok = _rust_hash(rec) == rec["record_hash"]
            assert rust_ok == py_ok(rec), (
                f"{name}.jsonl line {i + 1}: Rust says "
                f"{'valid' if rust_ok else 'tampered'}, Python says "
                f"the opposite -- verdict fork"
            )
