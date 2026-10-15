"""Regression tests for the October 2026 CodeQL alert reconciliation.

Each test pins the behaviour behind one fixed alert class so a later change
cannot quietly reopen it.
"""

from __future__ import annotations

import importlib
import logging
import os
import random
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_dna.authority_v01 import _resource_wildcard_ok
from agent_dna.decision import fault_reason

ROOT = Path(__file__).resolve().parents[1]
SECRET = "postgres://admin:hunter2@db.internal/prod"


# ---- py/stack-trace-exposure: engine faults ------------------------------


def test_fault_reason_hides_message_and_logs_it(caplog):
    with caplog.at_level(logging.ERROR, logger="pv.engine"):
        reason = fault_reason(RuntimeError(SECRET))
    assert SECRET not in reason
    assert reason.startswith("engine_fault: RuntimeError (fault_id=")
    fault_id = re.search(r"fault_id=([0-9a-f]{16})", reason).group(1)
    logged = caplog.text
    assert SECRET in logged and fault_id in logged


def test_fault_ids_are_unique():
    a, b = fault_reason(ValueError("x")), fault_reason(ValueError("x"))
    assert a != b


# ---- py/stack-trace-exposure: /ready --------------------------------------


def test_ready_does_not_return_exception_text(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "r.db"))
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as c:

        def boom():
            raise RuntimeError(SECRET)

        monkeypatch.setattr(server.state["store"], "ping", boom)
        r = c.get("/ready")
    assert r.status_code == 503
    body = r.json()
    assert body["reason"] == "store_unavailable"
    assert body["detail"] == "RuntimeError"
    assert SECRET not in r.text


# ---- py/clear-text-logging-sensitive-data ---------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_init_platform_keys_never_prints_keys(tmp_path):
    out, secrets = tmp_path / "keys.json", tmp_path / "keys.secrets.txt"
    secrets.write_text("stale\n", encoding="utf-8")
    secrets.chmod(0o644)
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "init_platform_keys.py"),
            "--out",
            str(out),
            "--secrets-out",
            str(secrets),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    keys = re.findall(r"pv_[A-Za-z0-9_-]{20,}", secrets.read_text(encoding="utf-8"))
    assert len(keys) == 2
    for key in keys:
        assert key not in proc.stdout and key not in proc.stderr
    assert stat.S_IMODE(secrets.stat().st_mode) == 0o600


# ---- py/polynomial-redos: resource wildcard check -------------------------


_OLD_RESOURCE_RE = re.compile(r"[^*]+(?::\*)?\Z")


def test_resource_check_matches_previous_regex():
    rng = random.Random(1234)
    alphabet = "ab:*\n "
    cases = ["", ":*", "a", "a:*", "a:**", "*", "a*", "a:*:*", "a:b:*", ":", "a:"]
    cases += [
        "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
        for _ in range(5000)
    ]
    for case in cases:
        assert _resource_wildcard_ok(case) == bool(_OLD_RESOURCE_RE.fullmatch(case)), (
            repr(case)
        )


def test_resource_check_is_linear_on_hostile_input():
    assert _resource_wildcard_ok(":" * 200_000 + "**") is False
    assert _resource_wildcard_ok("a" * 200_000 + ":*") is True


# ---- js/xss-through-dom: architecture dashboard ---------------------------


def test_dashboard_escapes_every_innerhtml_number():
    template = (ROOT / "tools" / "architecture_dashboard.template.html").read_text(
        encoding="utf-8"
    )
    # the identity replacement is gone and raw counters are wrapped in esc()
    assert 'replace(/^api\\./, "api.")' not in template
    for raw in ("+ m.testFileImports +", "+ f.collected +", "+ pct +", "+ i +"):
        assert raw not in template, raw


def test_fault_reason_uses_class_level_public_reason_only():
    class BackendError(RuntimeError):
        public_reason = "policy backend unavailable (opa)"

    exc = BackendError("endpoint http://10.0.0.5:8181 timed out")
    exc.public_reason = SECRET  # instance attributes are never used
    reason = fault_reason(exc)
    assert "policy backend unavailable (opa)" in reason
    assert SECRET not in reason and "10.0.0.5" not in reason
