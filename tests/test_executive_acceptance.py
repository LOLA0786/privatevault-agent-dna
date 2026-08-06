"""The executive acceptance demo is a maintained CI contract, not a
rehearsed happy path: it must exit 0 on every commit."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_executive_acceptance_demo_passes_end_to_end():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "executive_acceptance_demo.py")],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, (
        "acceptance demo failed:\n" + proc.stdout[-4000:] + proc.stderr[-2000:]
    )
    assert "ACCEPTANCE: PASSED" in proc.stdout
