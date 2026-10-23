"""`pv up` starts a local PrivateVault for the Claude Code plugin in one command.

Claims -> tests:
  - The packaged starter config is the plugin's config, byte for byte
    -> test_packaged_starter_is_the_plugin_config
  - The state folder is created owner-only with the starter files, and a
    file the user edited is never overwritten -> test_prepare_home_*
  - Inherited PV_* settings are dropped and named; pv up sets its own
    -> test_server_environment_drops_inherited_settings
  - It runs without authentication, so it refuses any non-loopback
    address, a bad folder and a taken port, with exit 2 -> test_refuses_*
  - The real command, as a process, serves the starter policy: a
    destructive command is blocked, ls is allowed, the chain verifies
    -> test_pv_up_end_to_end
  - The plugin warns at session start when the API is down, with the
    command that starts it, and is silent when it is up
    -> test_session_start_*
  - A refused tool call names the start command (local API only)
    -> test_refusal_names_the_start_command
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from agent_dna.cli import main as pv
from agent_dna.quickstart import STARTER_FILES, prepare_home, server_environment

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "integrations" / "claude-code" / "privatevault"
START = "uvx --from git+https://github.com/LOLA0786/privatevault-agent-dna pv up"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, PLUGIN / "hooks" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_packaged_starter_is_the_plugin_config():
    for name in STARTER_FILES:
        packaged = ROOT / "agent_dna" / "quickstart" / name
        assert packaged.read_bytes() == (PLUGIN / "config" / name).read_bytes(), name


def test_prepare_home_creates_owner_only_folder(tmp_path):
    home = tmp_path / "pv"
    paths = prepare_home(home)
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    for name in STARTER_FILES:
        assert json.loads(paths[name].read_text())


def test_prepare_home_keeps_the_users_edits(tmp_path):
    home = tmp_path / "pv"
    prepare_home(home)
    (home / "policy.json").write_text('{"version": "1.0", "policies": []}')
    prepare_home(home)
    assert json.loads((home / "policy.json").read_text())["policies"] == []


def test_server_environment_drops_inherited_settings(tmp_path):
    env, dropped = server_environment(
        tmp_path,
        tmp_path,
        {"PATH": "/bin", "PV_SECURE_PROFILE": "1", "PV_API_KEYS_FILE": "/k"},
    )
    assert dropped == ["PV_API_KEYS_FILE", "PV_SECURE_PROFILE"]
    assert "PV_SECURE_PROFILE" not in env and env["PATH"] == "/bin"
    assert env["PV_ALLOW_NO_AUTH"] == "1"
    assert env["PV_DB_PATH"] == str(tmp_path / "ledger.db")
    assert env["PV_SHELL_WORKDIR"] == str(tmp_path)


def test_print_env(tmp_path, capsys):
    assert (
        pv(
            [
                "up",
                "--home",
                str(tmp_path / "h"),
                "--workdir",
                str(tmp_path),
                "--print-env",
            ]
        )
        == 0
    )
    printed = dict(line.split("=", 1) for line in capsys.readouterr().out.split())
    assert printed["PV_POLICY_FILE"] == str(tmp_path / "h" / "policy.json")
    assert (tmp_path / "h" / "grants.json").is_file()


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "example.com", "::"])
def test_refuses_non_loopback(tmp_path, capsys, host):
    assert pv(["up", "--host", host, "--home", str(tmp_path), "--print-env"]) == 2
    assert "not a loopback address" in capsys.readouterr().err
    assert not (tmp_path / "policy.json").exists()


def test_refuses_missing_workdir(tmp_path, capsys):
    rc = pv(["up", "--home", str(tmp_path), "--workdir", str(tmp_path / "nope")])
    assert rc == 2 and "is not a folder" in capsys.readouterr().err


def test_refuses_a_taken_port(tmp_path, capsys):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        rc = pv(
            [
                "up",
                "--home",
                str(tmp_path),
                "--workdir",
                str(tmp_path),
                "--port",
                str(port),
            ]
        )
    assert rc == 2 and "is in use" in capsys.readouterr().err


def _http(method: str, url: str, body: dict | None = None) -> tuple[int, dict]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def test_pv_up_end_to_end(tmp_path):
    port = _free_port()
    work = tmp_path / "project"
    work.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("PV_")}
    env["PV_SECURE_PROFILE"] = "1"  # inherited, must be ignored
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agent_dna.cli",
            "up",
            "--port",
            str(port),
            "--home",
            str(tmp_path / "home"),
            "--workdir",
            str(work),
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(150):
            try:
                if _http("GET", f"{base}/health")[0] == 200:
                    break
            except OSError:
                pass
            if proc.poll() is not None:
                pytest.fail(proc.stdout.read())
            time.sleep(0.2)
        else:
            pytest.fail("pv up did not become healthy")

        def decide(command):
            return _http(
                "POST",
                f"{base}/v1/decide",
                {
                    "agent_id": "claude-code",
                    "capability": "shell.exec",
                    "timestamp": time.time(),
                    "arguments": {"command": command},
                },
            )

        status, body = decide("rm -rf build")
        assert status == 403 and "destructive" in body["reason"]
        assert decide("ls -la")[0] == 200
        assert _http("GET", f"{base}/v1/verify")[1]["chain_integrity_verified"]
    finally:
        proc.terminate()
        out, _ = proc.communicate(timeout=20)
    assert "ignored    PV_SECURE_PROFILE" in out
    assert "/plugin install privatevault@privatevault" in out
    assert (tmp_path / "home" / "ledger.db").is_file()


# ------------------------------------------------------ the plugin's side


def _session_start(monkeypatch) -> dict | None:
    hook = _load("pv_session_start")
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"source": "startup"}'))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert hook.main() == 0
    return json.loads(out.getvalue()) if out.getvalue() else None


def test_session_start_wiring():
    hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]
    (group,) = hooks["SessionStart"]
    (command,) = group["hooks"]
    assert "${CLAUDE_PLUGIN_ROOT}/hooks/pv_session_start.py" in command["command"]


def test_session_start_warns_when_down(monkeypatch):
    monkeypatch.delenv("PV_FAIL_OPEN", raising=False)
    monkeypatch.setenv("PV_ENFORCE_URL", "http://127.0.0.1:1")
    out = _session_start(monkeypatch)
    assert "will be refused" in out["systemMessage"]
    assert f"{START} --port 1" in out["systemMessage"]
    assert out["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    assert START in out["hookSpecificOutput"]["additionalContext"]


def test_session_start_remote_api_gets_no_local_command(monkeypatch):
    monkeypatch.setenv("PV_ENFORCE_URL", "http://pv.invalid:8000")
    out = _session_start(monkeypatch)
    assert (
        START not in out["systemMessage"] and "PV_ENFORCE_URL" in out["systemMessage"]
    )


class _Healthy(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib handler name
        payload = b'{"status": "healthy"}'
        self.send_response(200 if self.path == "/health" else 404)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_a):
        pass


def test_session_start_silent_when_up(monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Healthy)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")  # must be bypassed
        monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
        monkeypatch.setenv(
            "PV_ENFORCE_URL", f"http://127.0.0.1:{server.server_address[1]}"
        )
        assert _session_start(monkeypatch) is None
    finally:
        server.shutdown()


def test_refusal_names_the_start_command(monkeypatch):
    hook = _load("pv_pretool")
    monkeypatch.delenv("PV_FAIL_OPEN", raising=False)
    monkeypatch.setenv("PV_ENFORCE_URL", "http://127.0.0.1:8000")
    decision, reason = hook.verdict(None, "URLError: refused")
    assert decision == "deny" and reason.endswith(START)
    monkeypatch.setenv("PV_ENFORCE_URL", "https://pv.bank.example")
    assert START not in hook.verdict(None, "URLError: refused")[1]
