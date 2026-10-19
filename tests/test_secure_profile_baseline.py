"""Secure profile vs the drift baseline (external retest 3: a granted `ls`
was held at 202 by drift with no explanation)."""

from __future__ import annotations

from tools.init_secure_profile import main, provision

from agent_dna.decision import DecisionEngine


def _env(path):
    return dict(
        line.split("=", 1)
        for line in (path / "secure.env").read_text().splitlines()
        if line and not line.startswith("#")
    )


def test_default_profile_leaves_baseline_unset(tmp_path):
    info = provision(tmp_path / "p", org="acme.example", agents=["coder"],
                     grants=[{"agent_id": "coder", "capability": "shell.exec"}])
    assert "PV_BASELINE_CAPABILITIES" not in _env(tmp_path / "p")
    assert info["granted_capabilities"] == ["shell.exec"]
    assert info["baseline_capabilities"] == []


def test_baseline_from_grants_writes_granted_capabilities(tmp_path):
    provision(tmp_path / "p", org="acme.example", agents=["coder"],
              grants=[{"agent_id": "coder", "capability": "shell.exec"},
                      {"agent_id": "coder", "capability": "fs.read"}],
              baseline_from_grants=True)
    assert _env(tmp_path / "p")["PV_BASELINE_CAPABILITIES"] == "fs.read,shell.exec"


def test_cli_explains_drift_when_baseline_not_set(tmp_path, capsys):
    assert main(["--out", str(tmp_path / "p"), "--grant", "coder=shell.exec"]) == 0
    out = capsys.readouterr().out
    assert "not in the drift baseline" in out and "--baseline-from-grants" in out


def test_drift_reason_names_the_missing_baseline():
    e = DecisionEngine()
    assert e._drift_hint("shell.exec") == ""  # not reported when unknown
    e.baseline_capabilities = frozenset({"fs.read"})
    assert "PV_BASELINE_CAPABILITIES" in e._drift_hint("shell.exec")
    assert e._drift_hint("fs.read") == ""
