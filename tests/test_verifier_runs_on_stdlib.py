"""The record verifier runs on the Python standard library alone. With
site-packages off (-I -S) and from outside the repository, it passes the
committed clean vector and fails the tampered ones. Complements the static
import check in tests/test_verifier_independence.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "tools" / "verify_records.py"
VECTORS = ROOT / "spec" / "test-vectors"


def _verify(vector: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-S", str(VERIFIER), str(VECTORS / vector)],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_clean_vector_passes_on_the_standard_library_alone(tmp_path):
    run = _verify("clean.jsonl", tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "VERDICT: PASS" in run.stdout


@pytest.mark.parametrize(
    "vector", ["tampered_field.jsonl", "deleted_record.jsonl", "divergent.jsonl"]
)
def test_tampered_vectors_fail_on_the_standard_library_alone(tmp_path, vector):
    run = _verify(vector, tmp_path)
    assert run.returncode != 0, run.stdout
    assert "VERDICT: FAIL" in run.stdout
