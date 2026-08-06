"""Canonical pv-validation/1 vector: seal must remain byte-stable and
the stdlib verifier must accept it. Pinned hash — if metric math or
canonicalization ever changes, this test forces a deliberate,
reviewed vector regeneration (same discipline as the precedence
contract hash)."""

import json
import subprocess
import sys
from pathlib import Path

VECTOR = Path("spec/validation/vectors/valid_report.json")
PINNED = "d0f9b6cbd5b1a4800828e26ade3cd129448999d5585e624702fa57076a26a39b"


def test_vector_hash_pinned():
    env = json.loads(VECTOR.read_text())
    assert env["report_hash"] == PINNED, (
        "canonical vector hash changed — metric math or canonical JSON "
        "changed; regenerate the vector deliberately and update PINNED"
    )


def test_stdlib_verifier_accepts_vector():
    proc = subprocess.run(
        [sys.executable, "tools/verify_validation.py", str(VECTOR)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout
