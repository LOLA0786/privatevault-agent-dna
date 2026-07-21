"""tools/prove.py: seal functions and report shape. The full run is
exercised manually/CI (it re-runs pytest; running it inside pytest
would recurse), so tests here cover the sealing, parsing, and gate
logic it is built from."""

import hashlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path("tools").resolve()))
import prove  # noqa: E402


def test_seal_matches_canonical_sha256():
    body = {"b": 2, "a": 1}
    env = prove.seal(body)
    expect = hashlib.sha256(b'{"a":1,"b":2}').hexdigest()
    assert env["report_hash"] == expect


def test_pinned_artifact_hashes_exist():
    assert prove.sha256_file(prove.CONTRACT) is not None
    assert prove.sha256_file(prove.VECTOR) is not None
    assert prove.sha256_file(Path("does/not/exist")) is None


def test_git_state_shape():
    st = prove.git_state()
    assert set(st) == {"commit", "dirty"}
    assert isinstance(st["dirty"], bool)


def test_cli_help_runs():
    proc = subprocess.run([sys.executable, "tools/prove.py", "--help"],
                          capture_output=True, text=True)
    assert proc.returncode == 0
    assert "proof-of-run" in proc.stdout.lower()
