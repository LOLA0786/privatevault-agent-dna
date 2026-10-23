"""Red team 2026-10-23 (Claude Code integration at 4bda17b): every finding,
reproduced through the plugin's hook and the real API configured exactly as
``pv up`` configures it.

Findings -> tests:
  F1  a swapped or emptied policy file switched every shell rule off
      -> test_f1_*
  F2  Write could replace PrivateVault's own policy and grants
      -> test_hook_decisions[f2-*]
  F3  git -c core.pager / core.editor / diff.external, GIT_PAGER=, git config
      ran arbitrary commands -> test_hook_decisions[f3-*]
  F4  uv run python -c / uv run python script.py skipped the interpreter
      checks -> test_hook_decisions[f4-*]
  F5  F=.env; cat $F and globs read credentials unnoticed
      -> test_hook_decisions[f5-*]
  F6  --pass-env TOKEN / PASSWORD / SECRET reached the wrapped server
      -> test_f6_secret_looking_names
  F7  Read (and Grep) were not checked at all -> test_hook_decisions[f7-*]
  F8  credentials.txt and .credentials were not credential names
      -> test_hook_decisions[f8-*]
  F9  git show HEAD:.env -> test_hook_decisions[f9]
  F10 malformed JSON-RPC ended the pv wrap session -> tests/test_pv_wrap.py
  F11 a hard-linked secret file was accepted -> test_f11_hard_linked_secret
  F12 Write /etc/passwd and WebFetch to cloud metadata were allowed
      -> test_hook_decisions[f12-*]
  F13 a plain-http PV_ENFORCE_URL on another machine was trusted
      -> test_f13_*
Retest at 0e262f7: ANSI-C quoting ($'.env'), parameter defaults
(${UNDEF:-.env}) and trims read credentials unnoticed; a custom PV_HOME left
~/.privatevault writable with a prompt -> test_hook_decisions[r-*]
Ordinary work still passes, read-only text tools included
-> test_hook_decisions[ok-*]
"""

from __future__ import annotations

import importlib
import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_dna.quickstart import (
    QuickstartError,
    check_private,
    prepare_home,
    server_environment,
)

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "integrations" / "claude-code" / "privatevault"


def _hook():
    spec = importlib.util.spec_from_file_location(
        "pv_pretool_rt", PLUGIN / "hooks" / "pv_pretool.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(hook, event, monkeypatch) -> dict | None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert hook.main() == 0
    text = out.getvalue()
    return json.loads(text)["hookSpecificOutput"] if text else None


def _project(root: Path) -> Path:
    work = root / "project"
    (work / "src").mkdir(parents=True)
    (work / ".env").write_text("API_TOKEN=sk-live-abcdef1234567890\n")
    (work / "credentials.txt").write_text("user: a\n")
    (work / ".credentials").write_text("user: a\n")
    (work / "README.md").write_text("hello\n")
    (work / "del.py").write_text('import os\nos.remove("x")\n')
    git = ["git", "-c", "user.email=a@b.example", "-c", "user.name=a"]
    subprocess.run(["git", "init", "-q"], cwd=work, check=True)
    subprocess.run([*git, "add", "-A"], cwd=work, check=True)
    subprocess.run([*git, "commit", "-qm", "i"], cwd=work, check=True)
    return work


@pytest.fixture()
def world(tmp_path, monkeypatch):
    """The API as pv up runs it (same environment), the hook pointed at it."""
    from fastapi.testclient import TestClient

    for name in [n for n in os.environ if n.startswith("PV_")]:
        monkeypatch.delenv(name)
    home = tmp_path / "pvhome"
    work = _project(tmp_path)
    prepare_home(home)
    env, _ = server_environment(home, work, {})
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("PV_HOME", str(home))  # read by the hook
    import api.server as server

    importlib.reload(server)
    hook = _hook()
    with TestClient(server.app) as client:

        def decide(payload):
            r = client.post("/v1/decide", json=payload)
            return r.status_code, r.json()

        monkeypatch.setattr(hook, "decide", decide)
        yield hook, home, work


def _bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


CASES = [
    # (id, event builder(home, work), expected permissionDecision or None)
    (
        "f2-write-policy",
        lambda h, w: {
            "tool_name": "Write",
            "tool_input": {"file_path": str(h / "policy.json"), "content": "{}"},
        },
        "deny",
    ),
    (
        "f2-edit-grants",
        lambda h, w: {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": str(h / "grants.json"),
                "old_string": "a",
                "new_string": "b",
            },
        },
        "deny",
    ),
    ("f2-shell-names-home", lambda h, w: _bash(f"cat {h}/grants.json"), "deny"),
    (
        "f2-shell-names-default-home",
        lambda h, w: _bash("cat ~/.privatevault/mcp-secrets/pay.env"),
        "deny",
    ),
    (
        "f3-core-pager",
        lambda h, w: _bash('git -c core.pager="rm -rf /tmp/x" log'),
        "deny",
    ),
    (
        "f3-core-editor",
        lambda h, w: _bash('git -c core.editor="rm -rf /tmp/x" rebase -i HEAD'),
        "deny",
    ),
    (
        "f3-diff-external",
        lambda h, w: _bash('git -c diff.external="rm -rf /tmp/x" diff'),
        "deny",
    ),
    ("f3-git-pager-env", lambda h, w: _bash('GIT_PAGER="rm -rf x" git log'), "deny"),
    (
        "f3-git-config-persist",
        lambda h, w: _bash('git config core.pager "rm -rf x"'),
        "deny",
    ),
    ("f3-rebase-exec", lambda h, w: _bash('git rebase -x "rm -rf /" HEAD~1'), "deny"),
    (
        "f4-uv-inline",
        lambda h, w: _bash("uv run python -c \"print(open('.env').read())\""),
        "deny",
    ),
    ("f4-uv-script", lambda h, w: _bash("uv run python del.py"), "deny"),
    ("f5-var", lambda h, w: _bash("F=.env; cat $F"), "ask"),
    ("f5-var-head", lambda h, w: _bash("F=.env; head $F"), "ask"),
    ("f5-ifs", lambda h, w: _bash("IFS=; x=.env; cat $x"), "ask"),
    ("f5-glob", lambda h, w: _bash("cat .e*"), "ask"),
    ("f5-braces", lambda h, w: _bash("cat .{e,x}nv"), "ask"),
    ("f5-home-glob", lambda h, w: _bash("cat ~/.ss*/id_*"), "ask"),
    (
        "f7-read-env",
        lambda h, w: {
            "tool_name": "Read",
            "tool_input": {"file_path": str(w / ".env")},
        },
        "ask",
    ),
    (
        "f7-grep-env",
        lambda h, w: {
            "tool_name": "Grep",
            "tool_input": {"pattern": "TOKEN", "path": str(w / ".env")},
        },
        "ask",
    ),
    (
        "f7-read-pv-state",
        lambda h, w: {
            "tool_name": "Read",
            "tool_input": {"file_path": str(h / "grants.json")},
        },
        "deny",
    ),
    ("f8-credentials-txt", lambda h, w: _bash("cat credentials.txt"), "ask"),
    ("f8-dot-credentials", lambda h, w: _bash("cat .credentials"), "ask"),
    ("f9", lambda h, w: _bash("git show HEAD:.env"), "ask"),
    (
        "f12-write-etc",
        lambda h, w: {
            "tool_name": "Write",
            "tool_input": {"file_path": "/etc/passwd", "content": "x"},
        },
        "ask",
    ),
    (
        "f12-imds",
        lambda h, w: {
            "tool_name": "WebFetch",
            "tool_input": {
                "url": "http://169.254.169.254/latest/meta-data/",
                "prompt": "p",
            },
        },
        "deny",
    ),
    (
        "f12-imds-decimal",
        lambda h, w: {
            "tool_name": "WebFetch",
            "tool_input": {"url": "http://2852039166/latest/", "prompt": "p"},
        },
        "deny",
    ),
    (
        "f12-gcp-metadata",
        lambda h, w: {
            "tool_name": "WebFetch",
            "tool_input": {
                "url": "http://metadata.google.internal/computeMetadata/v1/",
                "prompt": "p",
            },
        },
        "deny",
    ),
    (
        "f12-localhost",
        lambda h, w: {
            "tool_name": "WebFetch",
            "tool_input": {
                "url": "http://localhost:8000/v1/records/claude-code",
                "prompt": "p",
            },
        },
        "ask",
    ),
    (
        "cfg-claude-settings",
        lambda h, w: {
            "tool_name": "Write",
            "tool_input": {
                "file_path": str(w / ".claude" / "settings.local.json"),
                "content": "{}",
            },
        },
        "ask",
    ),
    (
        "cfg-mcp-json",
        lambda h, w: {
            "tool_name": "Write",
            "tool_input": {"file_path": str(w / ".mcp.json"), "content": "{}"},
        },
        "ask",
    ),
    (
        "cfg-git-hook",
        lambda h, w: {
            "tool_name": "Write",
            "tool_input": {
                "file_path": str(w / ".git" / "hooks" / "pre-commit"),
                "content": "x",
            },
        },
        "ask",
    ),
    # retest at 0e262f7: ANSI-C quoting and parameter defaults (F5 residual)
    ("r-ansi-c", lambda h, w: _bash("cat $'.env'"), "ask"),
    ("r-ansi-c-hex", lambda h, w: _bash(r"cat $'\x2e\x65\x6e\x76'"), "ask"),
    ("r-ansi-c-octal", lambda h, w: _bash(r"cat $'\056env'"), "ask"),
    ("r-ansi-c-key", lambda h, w: _bash("cat $'id_ed25519'"), "ask"),
    ("r-default", lambda h, w: _bash('f=${UNDEF:-.env}; cat "$f"'), "ask"),
    ("r-default-unset", lambda h, w: _bash("f=${x-.env}; cat $f"), "ask"),
    ("r-trim", lambda h, w: _bash("F=.envx; cat ${F%x}"), "ask"),
    ("r-sort-compress", lambda h, w: _bash("sort --compress-program=sh x"), "deny"),
    (
        "r-default-home",
        lambda h, w: {
            "tool_name": "Write",
            "tool_input": {"file_path": "~/.privatevault/policy.json", "content": "{}"},
        },
        "deny",
    ),
    # retest false positives: read-only text tools
    ("ok-wc", lambda h, w: _bash("wc -l README.md"), None),
    ("ok-sort-uniq", lambda h, w: _bash("cat README.md | sort | uniq -c"), None),
    ("ok-cut-tr", lambda h, w: _bash("cut -c1-3 README.md | tr a-z A-Z"), None),
    ("ok-diff", lambda h, w: _bash("diff README.md README.md"), None),
    ("ok-ls", lambda h, w: _bash("ls -la"), None),
    ("ok-git-status", lambda h, w: _bash("git status"), None),
    (
        "ok-git-commit-identity",
        lambda h, w: _bash(
            "git -c user.name=a -c user.email=a@b.example commit --allow-empty -m x"
        ),
        None,
    ),
    ("ok-git-push-upstream", lambda h, w: _bash("git push -u origin main"), None),
    ("ok-uv-pytest", lambda h, w: _bash("uv run pytest -q"), None),
    ("ok-cat-src-glob", lambda h, w: _bash("cat src/*"), None),
    (
        "ok-read-readme",
        lambda h, w: {
            "tool_name": "Read",
            "tool_input": {"file_path": str(w / "README.md")},
        },
        None,
    ),
    (
        "ok-write-project",
        lambda h, w: {
            "tool_name": "Write",
            "tool_input": {"file_path": str(w / "src" / "a.py"), "content": "x = 1\n"},
        },
        None,
    ),
    (
        "ok-fetch-public",
        lambda h, w: {
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://docs.python.org/3/", "prompt": "p"},
        },
        None,
    ),
]


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_hook_decisions(world, monkeypatch, case):
    hook, home, work = world
    _id, build, expected = case
    event = {**build(home, work), "cwd": str(work), "session_id": "s"}
    out = _run(hook, event, monkeypatch)
    got = None if out is None else out["permissionDecision"]
    assert got == expected, out


# ----------------------------------------------------------------- F1


def test_f1_symlinked_policy_is_refused(tmp_path):
    home = tmp_path / "pv"
    prepare_home(home)
    (home / "policy.json").unlink()
    attacker = tmp_path / "attacker.json"
    attacker.write_text('{"version": "1.0", "policies": []}')
    (home / "policy.json").symlink_to(attacker)
    with pytest.raises(QuickstartError, match="symbolic link"):
        prepare_home(home)


@pytest.mark.parametrize("mode", [0o666, 0o620])
def test_f1_policy_writable_by_others_is_refused(tmp_path, mode):
    home = tmp_path / "pv"
    prepare_home(home)
    (home / "policy.json").chmod(mode)
    with pytest.raises(QuickstartError, match="writable by other users"):
        prepare_home(home)


def test_f1_hard_linked_policy_is_refused(tmp_path):
    home = tmp_path / "pv"
    prepare_home(home)
    os.link(home / "policy.json", tmp_path / "other-name.json")
    with pytest.raises(QuickstartError, match="hard links"):
        check_private(home / "policy.json", directory=False)


def test_f1_state_folder_writable_by_others_is_refused(tmp_path):
    home = tmp_path / "pv"
    home.mkdir()
    home.chmod(0o777)
    with pytest.raises(QuickstartError, match="writable by other users"):
        check_private(home, directory=True)
    prepare_home(home)  # a folder the user owns is tightened, then accepted
    assert (home.stat().st_mode & 0o077) == 0


@pytest.mark.parametrize(
    "command", ["rm -rf /", "bash -c 'rm -rf /'", "$'\\x72m' -rf /", "$'rm' -rf /"]
)
def test_f1_empty_policy_still_blocks_destructive(tmp_path, monkeypatch, command):
    """Even a policy with no rules cannot let rm -rf through pv up, however
    the program name is spelled (retest: ANSI-C quoting)."""
    from fastapi.testclient import TestClient

    for name in [n for n in os.environ if n.startswith("PV_")]:
        monkeypatch.delenv(name)
    home = tmp_path / "pv"
    prepare_home(home)
    (home / "policy.json").write_text('{"version": "1.0", "policies": []}')
    env, _ = server_environment(home, tmp_path, {})
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as client:
        r = client.post(
            "/v1/decide",
            json={
                "agent_id": "claude-code",
                "capability": "shell.exec",
                "timestamp": 1,
                "arguments": {"command": command},
            },
        )
    assert r.status_code == 403 and r.json()["decision"] == "block"


# ----------------------------------------------------------------- F6, F11


@pytest.mark.parametrize(
    "name",
    [
        "TOKEN",
        "PASSWORD",
        "SECRET",
        "DB_PASSWD",
        "GH_AUTH",
        "MY_APIKEY",
        "SESSION_COOKIE",
        "KEY",
        "PRIVATE_PEM",
    ],
)
def test_f6_secret_looking_names(tmp_path, capsys, name):
    from agent_dna.cli import main as pv

    rc = pv(
        [
            "wrap",
            "--name",
            "pay",
            "--home",
            str(tmp_path),
            "--pass-env",
            name,
            "--",
            "true",
        ]
    )
    assert rc == 2 and "--pass-env" in capsys.readouterr().err


def test_f6_ordinary_names_still_pass():
    from agent_dna.gateway.credentials import UpstreamCredentials

    creds = UpstreamCredentials(
        passthrough=frozenset({"HTTPS_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS"})
    )
    env = creds.subprocess_env(
        {
            "HTTPS_PROXY": "http://p:3128",
            "NO_PROXY": "x",
            "NODE_EXTRA_CA_CERTS": "/ca.pem",
            "PATH": "/bin",
        }
    )
    assert env["HTTPS_PROXY"] == "http://p:3128" and env["PATH"] == "/bin"


def test_f11_hard_linked_secret(tmp_path):
    from agent_dna.quickstart.wrap import read_secrets, secret_file, write_secret

    write_secret(tmp_path, "pay", "PAYMENTS_API_KEY", "hardlink-secret-xyz")
    path = secret_file(tmp_path, "pay")
    os.link(path, tmp_path / "elsewhere.env")
    with pytest.raises(QuickstartError, match="hard links"):
        read_secrets(path)


# ----------------------------------------------------------------- F13


def test_f13_plain_http_elsewhere_is_refused_without_asking(monkeypatch):
    hook = _hook()
    monkeypatch.delenv("PV_ALLOW_INSECURE_URL", raising=False)
    monkeypatch.delenv("PV_FAIL_OPEN", raising=False)
    monkeypatch.setenv("PV_ENFORCE_URL", "http://pv.attacker.example:8000")
    status, body = hook.decide({"agent_id": "a", "capability": "shell.exec"})
    assert status is None and "plain http" in body
    out = _run(hook, _bash("ls"), monkeypatch)
    assert out["permissionDecision"] == "deny"


@pytest.mark.parametrize(
    "url,ok",
    [
        ("https://pv.bank.example", True),
        ("http://127.0.0.1:8000", True),
        ("http://localhost:9", True),
        ("http://10.0.0.5:8000", False),
        ("ftp://127.0.0.1", False),
    ],
)
def test_f13_which_urls_are_trusted(monkeypatch, url, ok):
    monkeypatch.delenv("PV_ALLOW_INSECURE_URL", raising=False)
    assert _hook().url_is_trustworthy(url) is ok


def test_hook_and_guard_agree_on_credential_names():
    from agent_dna.shell_guard import _SENSITIVE

    hook = _hook()
    names = [
        ".env",
        ".env.prod",
        "credentials.txt",
        ".credentials",
        "id_ed25519",
        "x/.ssh/config",
        "server.pem",
        "my-secret.yaml",
        "README.md",
        "src/main.py",
        "env.py",
    ]
    for name in names:
        assert bool(hook.SENSITIVE.search(name)) == bool(_SENSITIVE.search(name)), name
