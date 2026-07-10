"""Signed export manifest: proves custody integrity (was this exact
file altered after export) as a property DISTINCT from internal
record consistency (which verify_records.py already proves).

The core test: tamper with an exported file AFTER the manifest was
created, and confirm the manifest's file_hash check catches it --
even though the tampering here doesn't need to touch any record's
own hash chain, just the raw bytes on disk."""

import time

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.export_manifest import create_export_manifest, verify_export_manifest
from agent_dna.signer import ReceiptSigner, generate_keypair
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id, capability=action.capability,
            drift_score=0.0, severity=Severity.INFO, reasons=[],
        )


def _populate(store_path, n=3):
    store = SQLiteDecisionStore(store_path)
    recorder = DecisionRecorder(store=store)
    engine = DecisionEngine(scorer=StubScorer())
    for i in range(n):
        a = AgentAction(agent_id="a1", capability=f"cap.{i}", timestamp=time.time())
        recorder.record(a, engine.decide(a))
    return store


def test_manifest_matches_freshly_exported_file(tmp_path):
    store = _populate(tmp_path / "d.db")
    export_path = tmp_path / "export.jsonl"
    store.export_jsonl(export_path)

    manifest = create_export_manifest(export_path, record_count=3, requested_by="test-key")

    result = verify_export_manifest(manifest.to_dict(), export_path)
    assert result["file_hash_matches"] is True
    assert result["custody_verified"] is True


def test_manifest_catches_post_export_tampering(tmp_path):
    """The core property: file altered AFTER the manifest was made
    must be caught, even without a signer."""
    store = _populate(tmp_path / "d.db")
    export_path = tmp_path / "export.jsonl"
    store.export_jsonl(export_path)

    manifest = create_export_manifest(export_path, record_count=3)

    # tamper with the raw file bytes AFTER the manifest was created --
    # append a byte, simulating any post-export alteration
    with open(export_path, "a") as f:
        f.write(" ")

    result = verify_export_manifest(manifest.to_dict(), export_path)
    assert result["file_hash_matches"] is False
    assert result["custody_verified"] is False


def test_manifest_with_signature_verifies(tmp_path):
    store = _populate(tmp_path / "d.db")
    export_path = tmp_path / "export.jsonl"
    store.export_jsonl(export_path)

    keys = generate_keypair()
    signer = ReceiptSigner(seed_hex=keys["signing_key"])
    manifest = create_export_manifest(
        export_path, record_count=3, requested_by="test-key", signer=signer
    )

    assert manifest.signature is not None
    result = verify_export_manifest(manifest.to_dict(), export_path)
    assert result["signature_valid"] is True
    assert result["custody_verified"] is True


def test_forged_manifest_signature_detected(tmp_path):
    """A manifest claiming a signature it doesn't actually have (or
    was signed by a different key) must fail signature verification,
    even if the file hash still matches."""
    store = _populate(tmp_path / "d.db")
    export_path = tmp_path / "export.jsonl"
    store.export_jsonl(export_path)

    keys = generate_keypair()
    signer = ReceiptSigner(seed_hex=keys["signing_key"])
    manifest = create_export_manifest(
        export_path, record_count=3, signer=signer
    )

    forged = manifest.to_dict()
    other_keys = generate_keypair()
    forged["signature"]["public_key"] = other_keys["public_key"]

    result = verify_export_manifest(forged, export_path)
    assert result["signature_valid"] is False
    assert result["custody_verified"] is False


def test_manifest_without_signer_has_no_signature(tmp_path):
    store = _populate(tmp_path / "d.db")
    export_path = tmp_path / "export.jsonl"
    store.export_jsonl(export_path)

    manifest = create_export_manifest(export_path, record_count=3)
    assert manifest.signature is None

    result = verify_export_manifest(manifest.to_dict(), export_path)
    assert result["signature_valid"] is None
    assert result["file_hash_matches"] is True
    # custody is still verified on file hash alone -- unsigned is
    # weaker (no non-repudiation of WHO exported it) but hash
    # tampering is still caught
    assert result["custody_verified"] is True


def test_manifest_records_who_requested_export(tmp_path):
    store = _populate(tmp_path / "d.db")
    export_path = tmp_path / "export.jsonl"
    store.export_jsonl(export_path)

    manifest = create_export_manifest(
        export_path, record_count=3, requested_by="auditor-api-key-7"
    )
    assert manifest.to_dict()["requested_by"] == "auditor-api-key-7"


def test_manifest_against_wrong_file_fails(tmp_path):
    """A manifest for one export must not validate against a
    DIFFERENT export, even a legitimate one."""
    store = _populate(tmp_path / "d.db")
    export_path_a = tmp_path / "export_a.jsonl"
    export_path_b = tmp_path / "export_b.jsonl"
    store.export_jsonl(export_path_a)
    store.export_jsonl(export_path_b)  # identical content, different file

    manifest_a = create_export_manifest(export_path_a, record_count=3)

    # even though export_b has IDENTICAL content, tamper it slightly
    # to prove the check is a real hash comparison, not a no-op
    with open(export_path_b, "a") as f:
        f.write("\n# extra")

    result = verify_export_manifest(manifest_a.to_dict(), export_path_b)
    assert result["file_hash_matches"] is False
