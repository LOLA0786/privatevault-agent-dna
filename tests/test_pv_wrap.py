"""`pv wrap` runs an MCP server behind the PrivateVault gateway.

The server behind the gateway is tests/fake_payments_mcp.py, run as a real
child process; the client is a scripted MCP session on the gateway's stdio.

Claims -> tests:
  - A granted tool runs and the server is authenticated with a credential
    the client never supplied; an ungranted tool is refused and never
    reaches the server; decisions are named mcp.<server>.<tool> and sealed
    in the server's own ledger, whose chain verifies -> test_session_end_to_end
  - A credential the server sends back is redacted before the client sees
    it -> test_session_end_to_end (leak_key)
  - A request carrying the credential is refused before it is decided, and
    the session continues -> test_session_end_to_end (smuggle)
  - The server's environment holds its credential, ordinary variables and
    those named with --pass-env, not the caller's PV_* settings or other
    secrets; --pass-env refuses secret-looking and PV_* names
    -> test_session_end_to_end, test_pass_env_refuses_secrets
  - Undeclared tools are refused -> test_session_end_to_end
  - Everything on stdout is MCP (one JSON message per line)
    -> test_session_end_to_end
  - Credentials are stored owner-only, set one name at a time, listed by
    name only; a file others can read is refused -> test_secret_*
  - Bad names, a missing command and a bad prefix are refused
    -> test_refuses_*, test_gateway_rejects_bad_prefix
  - Granted capabilities join the drift baseline (so granted tools are not
    held for review) -> test_baseline_includes_grants
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from agent_dna.cli import main as pv
from agent_dna.gateway.errors import GatewayStartupError
from agent_dna.gateway.runtime import GatewayConfig, _validate_gateway_config
from agent_dna.quickstart import (
    BASELINE_CAPABILITIES,
    QuickstartError,
    baseline_capabilities,
)
from agent_dna.quickstart.wrap import read_secrets, secret_file, write_secret

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fake_payments_mcp.py"
KEY = "sk_live_FAKEKEY1234567890abcd"


def _grant(home: Path, *capabilities: str) -> None:
    path = home / "grants.json"
    grants = json.loads(path.read_text())
    for cap in capabilities:
        grants.append(
            {
                "agent_id": "claude-code",
                "capability": cap,
                "granted_by": "t",
                "expires_at": None,
            }
        )
    path.write_text(json.dumps(grants))


def _session(home: Path, log: Path, messages: list[dict]) -> tuple[list[dict], str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PV_")}
    env.update(
        PV_SECURE_PROFILE="1",  # inherited operator setting: must not apply
        GITHUB_TOKEN="ghp_callers_own_secret_value",  # must not reach the server
        CORP_PROXY_URL="http://proxy.corp.example:3128",  # passed by name only
    )
    stdin = "".join(json.dumps(m) + "\n" for m in messages)
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
            "--pass-env",
            "CORP_PROXY_URL",
            "--",
            sys.executable,
            str(FAKE),
            "--log",
            str(log),
            "--credential-var",
            "PAYMENTS_API_KEY",
        ],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    return [json.loads(line) for line in lines], proc.stdout + proc.stderr


def _call(mid: int, name: str, arguments: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": mid,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


def test_session_end_to_end(tmp_path):
    home = tmp_path / "pv"
    log = tmp_path / "calls.log"
    write_secret(home, "pay", "PAYMENTS_API_KEY", KEY)
    assert pv(["up", "--home", str(home), "--print-env"]) == 0  # starter files
    _grant(home, "mcp.pay.get_balance", "mcp.pay.leak_key", "mcp.pay.child_env")

    replies, everything = _session(
        home,
        log,
        [
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
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            _call(3, "get_balance"),
            _call(4, "create_refund", {"charge": "ch_1", "amount": 5000}),
            _call(5, "leak_key"),
            _call(6, "get_balance", {"note": f"use {KEY}"}),
            _call(7, "child_env"),
            _call(8, "not_a_tool"),
        ],
    )
    by_id = {r["id"]: r for r in replies}
    assert sorted(by_id) == [1, 2, 3, 4, 5, 6, 7, 8]  # stdout is MCP only

    assert by_id[3]["result"]["content"][0]["text"].endswith("(authenticated: True)")
    refused = by_id[4]["error"]
    assert refused["data"]["decision"] == "require_approval"
    assert "mcp.pay.create_refund" in refused["data"]["reason"]
    assert by_id[5]["result"]["content"][0]["text"] == "my key is <redacted>"
    assert "credential" in by_id[6]["error"]["message"]
    child = by_id[7]["result"]["content"][0]["text"].split(",")
    assert "PAYMENTS_API_KEY" in child and "PATH" in child
    assert not [
        n for n in child if n.startswith("PV_") and n != "PV_GATEWAY_SESSION_ID"
    ]
    assert "GITHUB_TOKEN" not in child
    assert "CORP_PROXY_URL" in child  # --pass-env
    assert by_id[8]["error"]["message"].startswith("tool not declared")
    assert KEY not in everything

    seen = [json.loads(line)["name"] for line in log.read_text().splitlines()]
    assert seen == ["get_balance", "leak_key", "child_env"]  # wire keeps the bare name

    from agent_dna.sqlite_store import SQLiteDecisionStore

    store = SQLiteDecisionStore(home / "mcp" / "pay.db")
    try:
        assert store.load_graph().verify_all() == {"claude-code": True}
    finally:
        store.close()
    rows = _decisions(home / "mcp" / "pay.db")
    assert ("mcp.pay.get_balance", "allow") in rows
    assert ("mcp.pay.create_refund", "require_approval") in rows
    assert not [c for c, _ in rows if not c.startswith("mcp.pay.")]


def _decisions(db: Path) -> list[tuple[str, str]]:
    import sqlite3

    with sqlite3.connect(db) as conn:
        return conn.execute(
            "SELECT capability, decision FROM records WHERE capability IS NOT NULL"
        ).fetchall()


def test_secret_files_are_owner_only(tmp_path):
    home = tmp_path / "pv"
    write_secret(home, "pay", "A_KEY", "one")
    path = secret_file(home, "pay")
    write_secret(home, "pay", "B_KEY", "two")
    assert read_secrets(path) == {"A_KEY": "one", "B_KEY": "two"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    write_secret(home, "pay", "A_KEY", "three")
    assert read_secrets(path)["A_KEY"] == "three"


def test_secret_readable_by_others_is_refused(tmp_path):
    home = tmp_path / "pv"
    write_secret(home, "pay", "A_KEY", "one")
    path = secret_file(home, "pay")
    path.chmod(0o644)
    with pytest.raises(QuickstartError, match="chmod 600"):
        read_secrets(path)


def test_secret_cli_lists_names_never_values(tmp_path, monkeypatch, capsys):
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO("v4lue-xyz\n"))
    assert pv(["secret", "set", "pay", "PAY_KEY", "--home", str(tmp_path)]) == 0
    assert pv(["secret", "list", "pay", "--home", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "PAY_KEY" in out and "v4lue-xyz" not in out
    assert read_secrets(secret_file(tmp_path, "pay")) == {"PAY_KEY": "v4lue-xyz"}


@pytest.mark.parametrize("value", ["", "two\nlines"])
def test_secret_value_must_be_one_line(tmp_path, value):
    with pytest.raises(QuickstartError):
        write_secret(tmp_path, "pay", "K", value)


@pytest.mark.parametrize("name", ["Stripe", "_x", "a.b", "a" * 41, "../x", ""])
def test_refuses_bad_server_names(tmp_path, capsys, name):
    rc = pv(["wrap", "--name", name, "--home", str(tmp_path), "--", "true"])
    assert rc == 2 and "server name" in capsys.readouterr().err


def test_refuses_missing_command(tmp_path, capsys):
    assert pv(["wrap", "--name", "pay", "--home", str(tmp_path)]) == 2
    assert "after --" in capsys.readouterr().err


@pytest.mark.parametrize(
    "prefix", ["mcp.pay", ".", "mcp..pay.", "mcp pay.", "mcp/pay."]
)
def test_gateway_rejects_bad_prefix(prefix):
    with pytest.raises(GatewayStartupError, match="capability_prefix"):
        _validate_gateway_config(
            GatewayConfig(
                agent_api_key="k",
                client_identity="c",
                transport="stdio",
                capability_prefix=prefix,
            )
        )


def test_baseline_includes_grants(tmp_path):
    grants = tmp_path / "grants.json"
    grants.write_text(
        json.dumps(
            [
                {"agent_id": "claude-code", "capability": "mcp.pay.get_balance"},
                {"agent_id": "someone-else", "capability": "mcp.pay.create_refund"},
                {"agent_id": "claude-code", "capability": "bad capability!"},
            ]
        )
    )
    caps = baseline_capabilities(grants).split(",")
    assert "mcp.pay.get_balance" in caps
    assert "mcp.pay.create_refund" not in caps and "bad capability!" not in caps
    assert set(BASELINE_CAPABILITIES.split(",")) <= set(caps)
    assert baseline_capabilities(tmp_path / "missing.json") == ",".join(
        sorted(BASELINE_CAPABILITIES.split(","))
    )


@pytest.mark.parametrize("var", ["GITHUB_TOKEN", "OPENAI_API_KEY", "PV_DB_PATH", "1X"])
def test_pass_env_refuses_secrets(tmp_path, capsys, var):
    rc = pv(
        [
            "wrap",
            "--name",
            "pay",
            "--home",
            str(tmp_path),
            "--pass-env",
            var,
            "--",
            "true",
        ]
    )
    assert rc == 2 and "--pass-env" in capsys.readouterr().err
