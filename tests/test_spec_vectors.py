"""Canonical spec test vectors: verifier verdicts must match the contract."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "tools" / "verify_records.py"
VECTORS = ROOT / "spec" / "test-vectors"

CONTRACT = [
    ("clean.jsonl", 0, "VERDICT: PASS"),
    ("tampered_field.jsonl", 1, "record_hash mismatch"),
    ("deleted_record.jsonl", 1, "chain break"),
    ("divergent.jsonl", 1, "ENFORCEMENT DIVERGENCE"),
]


@pytest.mark.parametrize("name,code,marker", CONTRACT)
def test_vector_verdict(name, code, marker):
    path = VECTORS / name
    assert path.exists(), f"missing vector {name} — run tools/generate_test_vectors.py"
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(path)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == code, proc.stdout
    assert marker in proc.stdout
