"""The refund demo is an acceptance contract, not a script.

Exit 0 means the clean chain verified and all four attacks were refused.
If a control regresses, this fails in CI rather than in front of someone.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "refund_authorization_demo.py"


def _run():
    return subprocess.run(
        [sys.executable, str(DEMO)], capture_output=True, text=True, cwd=ROOT
    )


def test_demo_exits_zero():
    result = _run()
    assert result.returncode == 0, result.stdout + result.stderr


def test_only_the_honest_chain_is_accepted():
    assert "accepted: ['clean']" in _run().stdout


def test_each_attack_is_refused_for_its_own_reason():
    out = _run().stdout
    for fragment in (
        "observed action does not exactly match the authorized action",
        "observed outbound bytes are not the exact bytes authorized",
        "authorization_use_count: expected integer 1",
        "CONFIRMED effect requires evidence",
    ):
        assert fragment in out, f"missing refusal reason: {fragment}"
