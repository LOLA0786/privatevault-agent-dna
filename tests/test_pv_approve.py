"""A person approves one wrapped payment call (ADR 0036).

The server behind pv wrap is tests/fake_payments_mcp.py, run as a real child
process, which logs every call it receives. The policy says refunds need
approval.

Claims -> tests:
  - A call that needs approval is refused with an id; after `pv approve <id>`
    the same call runs exactly once; the next one needs a new approval
    -> test_one_approval_runs_one_call
  - The approval covers only that action: other arguments are refused
    -> test_one_approval_runs_one_call
  - A copy of a used approval is refused by the single-use ledger
    -> test_a_replayed_approval_is_refused
  - An approval for one call filed under another call's name is refused
    -> test_an_approval_for_another_call_is_refused
  - pv approve refuses without a terminal, and pending requests expire
    -> test_pv_approve_*
  - Without approvers, the refusal says how to set them up
    -> test_without_approvers
  - The approver cannot be the agent; keys are owner-only
    -> test_approvers_init
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_dna.cli import main as pv
from agent_dna.quickstart import QuickstartError
from agent_dna.quickstart.approvals import (
    approve,
    init_approvers,
    list_pending,
    read_pending,
)
from agent_dna.quickstart.wrap import write_secret

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fake_payments_mcp.py"


def _home(tmp_path: Path, *, approvers: bool = True) -> Path:
    home = tmp_path / "pv"
    write_secret(home, "pay", "PAYMENTS_API_KEY", "sk_test_abcdefghijklmnop")
    assert (
        pv(["up", "--home", str(home), "--workdir", str(tmp_path), "--print-env"]) == 0
    )
    grants = json.loads((home / "grants.json").read_text())
    grants.append(
        {
            "agent_id": "claude-code",
            "capability": "mcp.pay.create_refund",
            "granted_by": "t",
            "expires_at": None,
        }
    )
    (home / "grants.json").write_text(json.dumps(grants))
    policy = json.loads((home / "policy.json").read_text())
    policy["policies"].append(
        {
            "id": "refunds-need-approval",
            "capability": "mcp.pay.create_refund",
            "outcome": "require_approval",
            "reason": "refunds need a person",
            "condition": {"field": "arguments.amount", "operator": ">=", "value": 0},
        }
    )
    (home / "policy.json").write_text(json.dumps(policy))
    if approvers:
        init_approvers(home, "cfo@bank.example")
    return home


def _refund(home: Path, log: Path, amount: int) -> dict:
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "create_refund",
                "arguments": {"charge": "ch_1", "amount": amount},
            },
        },
    ]
    env = {k: v for k, v in os.environ.items() if not k.startswith("PV_")}
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_dna.cli",
            "wrap",
            "--name",
            "pay",
            "--home",
            str(home),
            "--",
            sys.executable,
            str(FAKE),
            "--log",
            str(log),
            "--credential-var",
            "PAYMENTS_API_KEY",
        ],
        input="".join(json.dumps(m) + "\n" for m in messages),
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    replies = {r["id"]: r for r in map(json.loads, proc.stdout.splitlines())}
    return replies[3]


def _calls(log: Path) -> list[dict]:
    if not log.exists():
        return []
    return [json.loads(line)["arguments"] for line in log.read_text().splitlines()]


def _pending_id(reply: dict) -> str:
    reason = reply["error"]["data"]["reason"]
    return reason.split("pv approve ", 1)[1].split()[0]


def test_one_approval_runs_one_call(tmp_path):
    home, log = _home(tmp_path), tmp_path / "calls.log"
    first = _refund(home, log, 5000)
    assert first["error"]["data"]["decision"] == "require_approval"
    ident = _pending_id(first)
    assert [p["id"] for p in list_pending(home)] == [ident]
    approve(home, ident)

    other = _refund(home, log, 9999)  # a different action
    assert other["error"]["data"]["decision"] == "require_approval"
    ran = _refund(home, log, 5000)
    assert ran["result"]["content"][0]["text"] == "refunded 5000 on ch_1"
    again = _refund(home, log, 5000)
    assert again["error"]["data"]["decision"] == "require_approval"
    assert _calls(log) == [{"amount": 5000, "charge": "ch_1"}]

    with sqlite3.connect(home / "mcp" / "pay.db") as db:
        rows = db.execute(
            "SELECT decision, json_extract(body, '$.triggered_by'), "
            "json_extract(body, '$.approval_ref') FROM records "
            "WHERE capability = 'mcp.pay.create_refund'"
        ).fetchall()
    approved = [r for r in rows if r[0] == "allow"]
    assert len(approved) == 1
    assert approved[0][1] == "approval" and approved[0][2].startswith("sha256:")


def test_a_replayed_approval_is_refused(tmp_path):
    home, log = _home(tmp_path), tmp_path / "calls.log"
    approve(home, _pending_id(_refund(home, log, 5000)))
    (filed,) = (home / "approvals" / "approved").glob("*.json")
    kept = tmp_path / "kept.json"
    shutil.copy(filed, kept)
    assert "result" in _refund(home, log, 5000)
    shutil.copy(kept, filed)
    filed.chmod(0o600)
    replay = _refund(home, log, 5000)
    assert replay["error"]["data"]["decision"] == "require_approval"
    assert "approval refused" in replay["error"]["data"]["reason"]
    assert len(_calls(log)) == 1


def test_an_approval_for_another_call_is_refused(tmp_path):
    home, log = _home(tmp_path), tmp_path / "calls.log"
    approve(home, _pending_id(_refund(home, log, 10)))
    (small,) = (home / "approvals" / "approved").glob("*.json")
    big = read_pending(home, _pending_id(_refund(home, log, 50000)))
    small.rename(small.with_name(big["action_digest"].split(":", 1)[1] + ".json"))
    refused = _refund(home, log, 50000)
    assert refused["error"]["data"]["decision"] == "require_approval"
    assert "different action" in refused["error"]["data"]["reason"]
    assert _calls(log) == []


def test_pv_approve_needs_a_terminal(tmp_path):
    home, log = _home(tmp_path), tmp_path / "calls.log"
    ident = _pending_id(_refund(home, log, 5000))
    proc = subprocess.run(
        [sys.executable, "-m", "agent_dna.cli", "approve", ident, "--home", str(home)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=60,
    )
    assert proc.returncode == 2 and "terminal" in proc.stderr
    assert not list((home / "approvals" / "approved").glob("*.json"))


def test_pv_approve_lists_and_expires(tmp_path, monkeypatch, capsys):
    home, log = _home(tmp_path), tmp_path / "calls.log"
    ident = _pending_id(_refund(home, log, 5000))
    assert pv(["approve", "--home", str(home)]) == 0
    assert ident in capsys.readouterr().out
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 3600)
    with pytest.raises(QuickstartError, match="expired"):
        read_pending(home, ident)


def test_without_approvers(tmp_path):
    home, log = _home(tmp_path, approvers=False), tmp_path / "calls.log"
    reply = _refund(home, log, 5000)
    assert "pv approvers init" in reply["error"]["data"]["reason"]
    assert _calls(log) == []


def test_approvers_init(tmp_path):
    home = tmp_path / "pv"
    with pytest.raises(QuickstartError, match="cannot be the agent"):
        init_approvers(home, "claude-code")
    with pytest.raises(QuickstartError, match="principal"):
        init_approvers(home, "not-an-address")
    pv(["up", "--home", str(home), "--print-env"])
    init_approvers(home, "cfo@bank.example")
    for name in ("root.key", "approver.key", "receipt.key", "bundle.json"):
        mode = stat.S_IMODE((home / "approvers" / name).stat().st_mode)
        assert mode == 0o600, name
