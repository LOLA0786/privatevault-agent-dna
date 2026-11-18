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


def test_failure_details_are_printed_for_the_log():
    """A red claim gate shows pytest's tracebacks in the CI log, not only the
    one-line FAILED summary; the sealed report is unchanged."""
    failure_details = prove.failure_details
    out = (
        "....F.\n"
        "=================================== FAILURES ===================================\n"
        "_________________________________ test_outage _________________________________\n"
        '  File "tests/multi_instance/test_two_processes.py", line 194, in test_outage\n'
        "E   httpx.ReadError: [Errno 104] Connection reset by peer\n"
        "=========================== short test summary info ============================\n"
        "FAILED tests/multi_instance/test_two_processes.py::test_outage - httpx.ReadError\n"
        "1 failed, 5 passed in 1.00s\n"
    )
    details = failure_details(out)
    assert details.startswith("=") and "FAILURES" in details.splitlines()[0]
    assert "line 194" in details and "Connection reset" in details
    assert "short test summary" not in details and "1 failed" not in details
    assert failure_details("6 passed in 1.00s\n") == ""
    errors = "=== ERRORS ===\n_ ERROR at setup _\nE   boom\n=== short test summary info ===\n"
    assert "boom" in failure_details(errors)
    # -rA: the PASSES section (passing tests' captured output) is not failure detail
    with_passes = (
        "=== FAILURES ===\n_ test_a _\nE   real problem\n"
        "=== PASSES ===\n_ test_b _\nnoise from a passing test\n"
        "=== short test summary info ===\n"
    )
    detail = failure_details(with_passes)
    assert "real problem" in detail and "noise" not in detail and "PASSES" not in detail
    long = "=== FAILURES ===\n" + "x" * 500 + "TAIL"
    cut = failure_details(long, limit=100)
    assert cut.startswith("[... earlier") and cut.endswith("TAIL") and len(cut) < 200


def test_red_run_prints_tracebacks_and_keeps_the_report_shape(monkeypatch, capsys):
    fake = (
        "=== FAILURES ===\n_ test_x _\nE   httpx.ReadError: reset\n"
        "=== short test summary info ===\n"
        "FAILED tests/t.py::test_x - httpx.ReadError: reset\n"
        "PASSED tests/t.py::test_y\n1 failed, 1 passed in 0.1s\n"
    )

    def run(*args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stdout=fake, stderr="")

    monkeypatch.setattr(prove.subprocess, "run", run)
    result = prove.run_pytest()
    err = capsys.readouterr().err
    assert "httpx.ReadError: reset" in err and "_ test_x _" in err
    assert result["failed_tests"] == ["tests/t.py::test_x"] and not result["ok"]
    assert set(result) == {
        "passed",
        "failed",
        "skipped",
        "summary_line",
        "duration_s",
        "failed_tests",
        "failed_lines",
        "passed_tests",
        "ok",
    }

    monkeypatch.setattr(
        prove.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a, 0, stdout="PASSED t::y\n1 passed\n", stderr=""
        ),
    )
    prove.run_pytest()
    assert capsys.readouterr().err == ""
