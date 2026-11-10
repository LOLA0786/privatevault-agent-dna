"""The layer's demo attempts each attack and must report every one refused."""

import subprocess
import sys


def test_demo_refuses_every_attack():
    done = subprocess.run(
        [sys.executable, "examples/multi_agent_security_demo.py"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "RESULT: 14 of 14 scenarios went the right way" in done.stdout
    assert "[FAIL]" not in done.stdout
