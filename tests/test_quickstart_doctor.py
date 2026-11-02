"""`pv doctor` checks that Claude Code, the plugin and PrivateVault agree.

Claims -> tests:
  - A pinned key that is signing.key's passes; a missing, malformed or
    mismatched one fails and names the fix -> test_keys_*
  - Nothing answering fails with the start command -> test_server_down_*
  - A PrivateVault that does not sign fails and points at the docker compose
    quickstart; one signing with another key fails; one signing with the
    pinned key passes; something that is not PrivateVault fails -> test_signing_*
  - A local port that also answers on a network address warns; a remote
    server is not tested -> test_exposure_*
  - The installed hook is compared with this checkout's -> test_plugin_*
  - A default mode in which approvals cannot reach a person warns, using
    the highest-precedence settings file -> test_mode_*
  - The doctor's prompting modes are the hook's -> test_prompting_modes_match_the_hook
  - Too little disk warns, then fails -> test_disk_*
  - End to end, as processes: the server the Docker image runs (no signing
    key) is diagnosed as unsigned with exit 1, and a real `pv up` passes with
    exit 0 -> test_end_to_end_*
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_dna.cli import main as pv
from agent_dna.quickstart import PUBLIC_KEY_FILE, doctor, ensure_signing_key

ROOT = Path(__file__).resolve().parents[1]
HOOK = (
    ROOT / "integrations" / "claude-code" / "privatevault" / "hooks" / "pv_pretool.py"
)
OTHER_KEY = "ab" * 32


@pytest.fixture(autouse=True)
def _no_inherited_settings(monkeypatch):
    for name in ("PV_ENFORCE_URL", "PV_DECISION_KEY", "PV_HOME"):
        monkeypatch.delenv(name, raising=False)


def _home(tmp_path: Path) -> tuple[Path, str]:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    return home, ensure_signing_key(home)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _stub(manifest: object) -> tuple[str, ThreadingHTTPServer]:
    """A server whose /health is 200 and whose GET / is `manifest`."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = json.dumps({"status": "ok"} if self.path == "/health" else manifest)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}", server


def _manifest(signing: object) -> dict:
    return {"product": "PrivateVault Agent DNA", "signing": signing}


# ---------- keys -------------------------------------------------------------


def test_keys_ok_when_pin_is_signing_keys(tmp_path):
    home, public = _home(tmp_path)
    finding, pinned = doctor.check_keys(home)
    assert finding.status == "ok"
    assert pinned == public.lower()


def test_keys_fail_when_nothing_is_pinned(tmp_path):
    finding, pinned = doctor.check_keys(tmp_path / "empty")
    assert finding.status == "FAIL" and pinned is None
    assert "pv up" in finding.detail


def test_keys_fail_when_pin_is_not_signing_keys(tmp_path):
    home, _ = _home(tmp_path)
    (home / PUBLIC_KEY_FILE).write_text(OTHER_KEY + "\n")
    finding, _ = doctor.check_keys(home)
    assert finding.status == "FAIL"
    assert "rewrites the pinned key" in finding.detail


def test_keys_fail_on_a_malformed_pin(tmp_path):
    home, _ = _home(tmp_path)
    (home / PUBLIC_KEY_FILE).write_text("not-a-key\n")
    assert doctor.check_keys(home)[0].status == "FAIL"


def test_keys_follow_pv_decision_key_like_the_hook(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_DECISION_KEY", OTHER_KEY)
    finding, pinned = doctor.check_keys(tmp_path / "no-home")
    assert pinned == OTHER_KEY
    assert finding.status == "warn"  # pinned, but no signing.key to compare


# ---------- server and signing ----------------------------------------------


def test_server_down_fails_with_the_start_command():
    url = f"http://127.0.0.1:{_free_port()}"
    finding, manifest = doctor.check_server(url)
    assert finding.status == "FAIL" and manifest is None
    assert "pv up --port" in finding.detail


def test_signing_fails_on_an_unsigned_privatevault():
    url, server = _stub(_manifest("disabled"))
    try:
        _, manifest = doctor.check_server(url)
        finding = doctor.check_signing(url, manifest, OTHER_KEY)
    finally:
        server.shutdown()
    assert finding.status == "FAIL"
    assert "does not sign" in finding.detail
    assert "docker ps --filter publish=" in finding.detail


def test_signing_fails_on_another_key():
    url, server = _stub(_manifest({"algorithm": "Ed25519", "public_key": "cd" * 32}))
    try:
        _, manifest = doctor.check_server(url)
        finding = doctor.check_signing(url, manifest, OTHER_KEY)
    finally:
        server.shutdown()
    assert finding.status == "FAIL"
    assert "different PrivateVault" in finding.detail


def test_signing_ok_on_the_pinned_key():
    url, server = _stub(
        _manifest({"algorithm": "Ed25519", "public_key": OTHER_KEY.upper()})
    )
    try:
        _, manifest = doctor.check_server(url)
        finding = doctor.check_signing(url, manifest, OTHER_KEY)
    finally:
        server.shutdown()
    assert finding.status == "ok"


def test_signing_fails_when_it_is_not_privatevault():
    url, server = _stub({"hello": "world"})
    try:
        _, manifest = doctor.check_server(url)
        finding = doctor.check_signing(url, manifest, OTHER_KEY)
    finally:
        server.shutdown()
    assert finding.status == "FAIL"
    assert "lsof" in finding.detail


# ---------- exposure ---------------------------------------------------------


def test_exposure_warns_when_the_port_answers_on_the_network():
    finding = doctor.check_exposure(
        "http://127.0.0.1:8000", lan=lambda: "10.0.0.5", connect=lambda a, p: True
    )
    assert finding.status == "warn"
    assert "10.0.0.5" in finding.detail and "127.0.0.1:8000:8000" in finding.detail


def test_exposure_ok_when_only_this_machine_answers():
    finding = doctor.check_exposure(
        "http://127.0.0.1:8000", lan=lambda: "10.0.0.5", connect=lambda a, p: False
    )
    assert finding.status == "ok"


def test_exposure_skips_a_remote_server_and_no_network():
    remote = doctor.check_exposure("https://pv.example.com", lan=lambda: "10.0.0.5")
    offline = doctor.check_exposure("http://127.0.0.1:8000", lan=lambda: None)
    assert remote.status == "skip" and offline.status == "skip"


# ---------- plugin, mode, disk -----------------------------------------------


def _install(root: Path, content: bytes) -> None:
    hooks = root / "cache" / "privatevault" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "pv_pretool.py").write_bytes(content)


def test_plugin_matches_this_checkout(tmp_path):
    _install(tmp_path / "plugins", HOOK.read_bytes())
    assert doctor.check_plugin(tmp_path / "plugins", HOOK).status == "ok"


def test_plugin_differs_from_this_checkout(tmp_path):
    _install(tmp_path / "plugins", b"# an older hook\n")
    finding = doctor.check_plugin(tmp_path / "plugins", HOOK)
    assert finding.status == "warn" and "same version" in finding.detail


def test_plugin_missing_warns(tmp_path):
    assert doctor.check_plugin(tmp_path / "nope", HOOK).status == "warn"


def _settings(path: Path, mode: str) -> Path:
    path.write_text(json.dumps({"permissions": {"defaultMode": mode}}))
    return path


def test_mode_warns_for_a_mode_without_prompts(tmp_path):
    user = _settings(tmp_path / "user.json", "bypassPermissions")
    finding = doctor.check_mode([tmp_path / "missing.json", user])
    assert finding.status == "warn" and "bypassPermissions" in finding.detail


def test_mode_uses_the_highest_precedence_file(tmp_path):
    local = _settings(tmp_path / "local.json", "default")
    user = _settings(tmp_path / "user.json", "bypassPermissions")
    assert doctor.check_mode([local, user]).status == "ok"


def test_prompting_modes_match_the_hook():
    spec = importlib.util.spec_from_file_location("pv_pretool_for_doctor", HOOK)
    hook = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(HOOK.parent))
    try:
        spec.loader.exec_module(hook)
    finally:
        sys.path.remove(str(HOOK.parent))
    assert doctor.PROMPTING_MODES == hook.PROMPTING_MODES


def test_disk_warns_then_fails(tmp_path):
    def usage(free):
        return lambda path: SimpleNamespace(free=free)

    assert doctor.check_disk(tmp_path, usage(5 << 30)).status == "ok"
    assert doctor.check_disk(tmp_path, usage(500 << 20)).status == "warn"
    assert doctor.check_disk(tmp_path, usage(50 << 20)).status == "FAIL"


# ---------- end to end -------------------------------------------------------


def _serve(cmd: list[str], env: dict, base: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(150):
        try:
            with opener.open(f"{base}/health", timeout=2) as r:
                if r.status == 200:
                    return proc
        except OSError:
            pass
        if proc.poll() is not None:
            pytest.fail(proc.stdout.read())
        time.sleep(0.2)
    proc.terminate()
    pytest.fail(f"{cmd[:4]} did not become healthy")


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def _doctor(url: str, home: Path, capsys, monkeypatch, tmp_path) -> tuple[int, str]:
    monkeypatch.setenv("HOME", str(tmp_path / "user"))  # no real ~/.claude
    monkeypatch.chdir(tmp_path)
    code = pv(["doctor", "--url", url, "--home", str(home)])
    return code, capsys.readouterr().out


def _clean_env() -> dict:
    return {k: v for k, v in os.environ.items() if not k.startswith("PV_")}


def test_end_to_end_unsigned_server_is_diagnosed(tmp_path, capsys, monkeypatch):
    """The Docker image runs `uvicorn api.server:app` with no signing key:
    the plugin refuses every answer, and the doctor says why."""
    home, _ = _home(tmp_path)
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = _clean_env() | {
        "PV_ALLOW_NO_AUTH": "1",
        "PV_DB_PATH": str(tmp_path / "pv.db"),
    }
    proc = _serve(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "api.server:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env,
        base,
    )
    try:
        code, out = _doctor(base, home, capsys, monkeypatch, tmp_path)
    finally:
        _stop(proc)
    assert code == 1
    line = next(row for row in out.splitlines() if " signing " in row)
    assert line.split()[0] == "FAIL" and "does not sign" in line


def test_end_to_end_pv_up_passes(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    work = tmp_path / "project"
    work.mkdir()
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    proc = _serve(
        [
            sys.executable,
            "-m",
            "agent_dna.cli",
            "up",
            "--port",
            str(port),
            "--home",
            str(home),
            "--workdir",
            str(work),
        ],
        _clean_env(),
        base,
    )
    try:
        code, out = _doctor(base, home, capsys, monkeypatch, tmp_path)
    finally:
        _stop(proc)
    rows = {
        row.split()[1]: row.split()[0]
        for row in out.splitlines()
        if row.startswith("  ")
    }
    assert rows["keys"] == "ok" and rows["server"] == "ok" and rows["signing"] == "ok"
    assert code == 0, out
