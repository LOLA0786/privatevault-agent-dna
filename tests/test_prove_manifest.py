"""tools/prove.py: seal functions and report shape. The full run is
exercised manually/CI (it re-runs pytest; running it inside pytest
would recurse), so tests here cover the sealing, parsing, and gate
logic it is built from."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

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
    assert prove.sha256_file(prove.DISCOVERY_VECTOR) is not None
    assert prove.sha256_file(Path("does/not/exist")) is None


def test_git_state_shape():
    st = prove.git_state()
    assert set(st) == {"commit", "dirty"}
    assert isinstance(st["dirty"], bool)


def test_cli_help_runs():
    proc = subprocess.run(
        [sys.executable, "tools/prove.py", "--help"], capture_output=True, text=True
    )
    assert proc.returncode == 0
    assert "proof-of-run" in proc.stdout.lower()


@pytest.mark.parametrize("code", [0, 1])
def test_live_audit_unavailable(monkeypatch, tmp_path, code):
    monkeypatch.setattr("tempfile.mkdtemp", lambda **kw: str(tmp_path))
    monkeypatch.setattr(
        prove.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess([], code, "", "synthetic failure"),
    )
    result = prove.run_audit_verifier()
    assert result["ok"] is False
    assert result["generator_error"] == "synthetic failure"


@pytest.mark.parametrize("audit_ok", [None, False, True, 1, "true"])
def test_mandatory_audit_controls_proof_exit(monkeypatch, tmp_path, audit_ok):
    good = {"ok": True, "summary_line": "stub", "passed": 1, "total": 1}
    for name in (
        "run_pytest",
        "run_adversarial",
        "run_validation_verifier",
        "run_discovery_verifier",
    ):
        monkeypatch.setattr(prove, name, lambda: dict(good))
    monkeypatch.setattr(prove, "run_audit_verifier", lambda: {"ok": audit_ok})
    output = tmp_path / "proof.json"
    monkeypatch.setattr(sys, "argv", ["prove.py", "-o", str(output)])
    assert prove.main() == (0 if audit_ok is True else 1)
    body = json.loads(output.read_text())["body"]
    assert body["all_gates_passed"] is (audit_ok is True)


def test_grouped_skips_count_each_case(monkeypatch):
    out = "PASSED tests/a.py::test_a\nSKIPPED [4] tests/b.py: reason\nSKIPPED [2] tests/c.py: reason\n"
    monkeypatch.setattr(
        prove.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess([], 0, out, ""),
    )
    result = prove.run_pytest()
    assert result["passed"] == 1
    assert result["skipped"] == 6
    assert result["ok"] is True
