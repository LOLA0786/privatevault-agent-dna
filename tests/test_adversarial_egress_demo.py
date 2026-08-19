from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_adversarial_egress_demo_uses_live_authorization_window() -> None:
    result = subprocess.run(
        [sys.executable, "tools/adversarial_egress_demo.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    output = result.stdout + result.stderr

    assert result.returncode == 0, output
    assert "verify_dispatch_witness OK" in output
    assert "EXECUTION_AUTHORIZATION_CONSUMED" in output
    assert "offline witness" in output
