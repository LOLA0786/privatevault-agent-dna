"""The plugin accepts only decisions signed by the pinned key (ADR 0035).

Claims -> tests:
  - The hook's standard-library Ed25519 agrees with libsodium (PyNaCl) and
    the RFC 8032 vectors -> test_ed25519_*
  - pv up creates an owner-only signing key once, publishes the public key
    for the plugin, signs every decision and never prints the seed
    -> test_pv_up_*
  - /v1/decide returns the record's signature when signing is on
    -> test_decide_returns_the_envelope
  - With a pinned key, a real signed allow for this call passes; a forged,
    unsigned, re-labelled, replayed, stale or foreign-key answer is refused;
    a block stays a block -> test_hook_*
  - With no key pinned the hook refuses, unless PV_ALLOW_UNSIGNED=1
    (ADR 0038) -> test_hook_without_a_pin_refuses
  - A signed decision names the whole tool input: an allow for one file
    content does not cover another -> test_a_decision_covers_only_its_content
  - An MCP input too large to check whole is refused, not truncated
    -> test_an_oversized_mcp_input_is_refused
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import io
import json
import os
import stat
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from agent_dna.cli import main as pv
from agent_dna.quickstart import (
    PUBLIC_KEY_FILE,
    SIGNING_KEY_FILE,
    QuickstartError,
    prepare_home,
    read_signing_key,
    server_environment,
)

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "integrations" / "claude-code" / "privatevault" / "hooks"


def _module(name: str):
    spec = importlib.util.spec_from_file_location(name, HOOKS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ------------------------------------------------------------- Ed25519

RFC8032 = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb882"
        "1590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1"
        "e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


@pytest.mark.parametrize("public,message,signature", RFC8032)
def test_ed25519_rfc8032_vectors(public, message, signature):
    ed = _module("pv_ed25519")
    pk, msg, sig = (bytes.fromhex(x) for x in (public, message, signature))
    assert ed.verify(pk, msg, sig)
    assert not ed.verify(pk, msg + b"x", sig)


def test_ed25519_agrees_with_libsodium():
    ed = _module("pv_ed25519")
    for i in range(40):
        sk = SigningKey.generate()
        msg = os.urandom(i * 3)
        sig = sk.sign(msg).signature
        pk = bytes(sk.verify_key)
        assert ed.verify(pk, msg, sig)
        flipped = bytearray(sig)
        flipped[i % 64] ^= 1 << (i % 8)
        assert not ed.verify(pk, msg, bytes(flipped))
        assert not ed.verify(bytes(SigningKey.generate().verify_key), msg, sig)
    assert not ed.verify(b"\x00" * 31, b"", b"\x00" * 64)


# ------------------------------------------------------------- pv up


def test_pv_up_creates_one_key_and_never_prints_it(tmp_path, capsys):
    home = tmp_path / "pv"
    assert pv(["up", "--home", str(home), "--print-env"]) == 0
    seed_path, pub_path = home / SIGNING_KEY_FILE, home / PUBLIC_KEY_FILE
    assert stat.S_IMODE(seed_path.stat().st_mode) == 0o600
    seed, public = read_signing_key(home)
    assert pub_path.read_text().strip() == public
    out = capsys.readouterr().out
    assert seed not in out and f"PV_TRUSTED_PUBLIC_KEYS={public}" in out
    assert pv(["up", "--home", str(home), "--print-env"]) == 0
    assert read_signing_key(home) == (seed, public)  # stable across starts


def test_pv_up_refuses_a_linked_signing_key(tmp_path):
    home = tmp_path / "pv"
    prepare_home(home)
    (home / SIGNING_KEY_FILE).unlink()
    other = tmp_path / "elsewhere.key"
    other.write_text("00" * 32)
    (home / SIGNING_KEY_FILE).symlink_to(other)
    with pytest.raises(QuickstartError, match="symbolic link"):
        prepare_home(home)


# ------------------------------------------------------------- the API and hook


@pytest.fixture()
def world(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    for name in [n for n in os.environ if n.startswith("PV_")]:
        monkeypatch.delenv(name)
    home = tmp_path / "pvhome"
    work = tmp_path / "project"
    work.mkdir()
    prepare_home(home)
    env, _ = server_environment(home, work, {})
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    import api.server as server

    importlib.reload(server)
    monkeypatch.setenv("PV_HOME", str(home))  # where the hook finds the pin
    hook = _module("pv_pretool")
    with TestClient(server.app) as client:

        def real(payload):
            r = client.post("/v1/decide", json=payload)
            return r.status_code, r.json()

        monkeypatch.setattr(hook, "decide", real)
        yield hook, home, work, real


def _run(hook, event, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert hook.main() == 0
    return json.loads(out.getvalue())["hookSpecificOutput"] if out.getvalue() else None


def _ls(work, tool_use_id="tu-1"):
    return {
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_use_id": tool_use_id,
        "cwd": str(work),
    }


def test_decide_returns_the_envelope(world):
    hook, home, work, real = world
    status, body = real(
        {
            "agent_id": "claude-code",
            "capability": "shell.exec",
            "timestamp": 1,
            "request_id": "r",
            "arguments": {"command": "ls"},
        }
    )
    assert status == 200
    assert body["envelope"]["signed_hash"] == body["record"]["record_hash"]
    assert body["envelope"]["public_key"] == read_signing_key(home)[1]


def test_hook_accepts_a_real_signed_allow(world, monkeypatch):
    hook, home, work, _ = world
    checked = []
    original = hook.signature_problem
    monkeypatch.setattr(
        hook, "signature_problem", lambda *a: checked.append(1) or original(*a)
    )
    assert _run(hook, _ls(work), monkeypatch) is None
    assert checked == [1]


def _answer_for(real, request_id, command="ls"):
    digest = hashlib.sha256(
        json.dumps({"command": command}, separators=(",", ":")).encode()
    ).hexdigest()
    return real(
        {
            "agent_id": "claude-code",
            "capability": "shell.exec",
            "timestamp": 1,
            "request_id": request_id,
            "arguments": {"command": command, "touches": [], "input_sha256": digest},
        }
    )


@pytest.mark.parametrize(
    "forge,why",
    [
        ("unsigned", "no signed decision record"),
        ("relabelled", "does not match its hash"),
        ("replayed", "different call (request_id)"),
        ("foreign-key", "key other than the pinned one"),
        ("bad-signature", "does not verify"),
        ("body-says-ask", "decision differs"),
    ],
)
def test_hook_refuses_a_forged_answer(world, monkeypatch, forge, why):
    hook, home, work, real = world
    status, genuine = _answer_for(real, "tu-1")
    _, other = _answer_for(real, "someone-else")
    _, blocked = _answer_for(real, "tu-1", command="rm -rf build")
    forged = json.loads(json.dumps(genuine))
    if forge == "unsigned":
        forged.pop("envelope")
    elif forge == "relabelled":
        blocked["record"]["decision"] = "allow"
        forged = {**blocked, "decision": "allow"}
        status = 200
    elif forge == "replayed":
        forged = other
    elif forge == "foreign-key":
        sk = SigningKey.generate()
        h = forged["record"]["record_hash"]
        forged["envelope"].update(
            public_key=bytes(sk.verify_key).hex(),
            signature=sk.sign(h.encode()).signature.hex(),
        )
    elif forge == "bad-signature":
        sig = bytearray.fromhex(forged["envelope"]["signature"])
        sig[0] ^= 1
        forged["envelope"]["signature"] = sig.hex()
    elif forge == "body-says-ask":
        forged["decision"] = "require_approval"  # the signed record says allow
        status = 202
    monkeypatch.setattr(hook, "decide", lambda payload: (status, forged))
    out = _run(hook, _ls(work, "tu-1"), monkeypatch)
    assert out["permissionDecision"] == "deny"
    assert why in out["permissionDecisionReason"]


def test_hook_refuses_a_stale_answer(world, monkeypatch):
    hook, home, work, real = world
    status, genuine = _answer_for(real, "tu-1")
    monkeypatch.setattr(hook, "decide", lambda payload: (status, genuine))
    monkeypatch.setattr(
        hook.time, "time", lambda: genuine["record"]["timestamp"] + 3600
    )
    out = _run(hook, _ls(work, "tu-1"), monkeypatch)
    assert "not from now" in out["permissionDecisionReason"]


def test_a_block_stays_a_block(world, monkeypatch):
    hook, home, work, _ = world
    event = {**_ls(work), "tool_input": {"command": "rm -rf build"}}
    assert _run(hook, event, monkeypatch)["permissionDecision"] == "deny"


def test_hook_refuses_when_the_pin_is_malformed(world, monkeypatch):
    hook, home, work, _ = world
    monkeypatch.setenv("PV_DECISION_KEY", "not-hex")
    out = _run(hook, _ls(work), monkeypatch)
    assert (
        out["permissionDecision"] == "deny"
        and "unreadable" in out["permissionDecisionReason"]
    )


def test_hook_without_a_pin_refuses(tmp_path, monkeypatch):
    """ADR 0038: a hardened hook does not run unchecked."""
    hook = _module("pv_pretool")
    monkeypatch.delenv("PV_DECISION_KEY", raising=False)
    monkeypatch.delenv("PV_ALLOW_UNSIGNED", raising=False)
    monkeypatch.setenv("PV_HOME", str(tmp_path / "empty"))
    monkeypatch.setattr(
        hook, "decide", lambda payload: (200, {"decision": "allow", "reason": "ok"})
    )
    out = _run(hook, _ls(tmp_path), monkeypatch)
    assert out["permissionDecision"] == "deny"
    assert "no PrivateVault decision key is pinned" in out["permissionDecisionReason"]
    monkeypatch.setenv("PV_ALLOW_UNSIGNED", "1")
    assert _run(hook, _ls(tmp_path), monkeypatch) is None


def _write(work, content, tool_use_id):
    return {
        "tool_name": "Write",
        "tool_input": {"file_path": str(work / "app.py"), "content": content},
        "tool_use_id": tool_use_id,
        "cwd": str(work),
    }


def test_a_decision_covers_only_its_content(world, monkeypatch):
    """The reviewer's point (2026-10-25): a write was bound by its path only.
    Now a genuine signed allow for one content is refused for another."""
    hook, home, work, real = world
    seen = []
    monkeypatch.setattr(hook, "decide", lambda p: seen.append(real(p)) or seen[-1])
    assert _run(hook, _write(work, "print('ok')\n", "tu-w"), monkeypatch) is None
    status, answer = seen[0]
    monkeypatch.setattr(hook, "decide", lambda payload: (status, answer))
    out = _run(hook, _write(work, "import os; os.system('x')\n", "tu-w"), monkeypatch)
    assert out["permissionDecision"] == "deny"
    assert "different call (arguments_digest)" in out["permissionDecisionReason"]
    assert hook.input_sha256({"a": 1, "b": "x"}) == hook.input_sha256(
        {"b": "x", "a": 1}
    )


def test_an_oversized_mcp_input_is_refused(world, monkeypatch):
    hook, home, work, real = world
    asked = []
    monkeypatch.setattr(hook, "decide", lambda p: asked.append(p) or real(p))
    event = {
        "tool_name": "mcp__s__t",
        "tool_input": {"blob": "x" * (hook.MAX_INPUT_BYTES + 1)},
        "tool_use_id": "tu-big",
        "cwd": str(work),
    }
    out = _run(hook, event, monkeypatch)
    assert out["permissionDecision"] == "deny"
    assert "limit the policy can check whole" in out["permissionDecisionReason"]
    assert asked == []  # refused before anything is sent
    small = {**event, "tool_input": {"blob": "x" * 20_000}}
    _run(hook, small, monkeypatch)
    assert asked[-1]["arguments"]["blob"] == "x" * 20_000  # sent whole


# ------------------------------------------------- an ask needs a person (0037)


def _read_env(work, mode):
    (work / ".env").write_text("STRIPE_SECRET_KEY=sk_test_demo123\n")
    event = {
        "tool_name": "Read",
        "tool_input": {"file_path": str(work / ".env")},
        "tool_use_id": f"tu-{mode}",
        "cwd": str(work),
    }
    if mode is not None:
        event["permission_mode"] = mode
    return event


@pytest.mark.parametrize("mode", [None, "default", "plan"])
def test_an_ask_reaches_a_person(world, monkeypatch, mode):
    hook, home, work, _ = world
    out = _run(hook, _read_env(work, mode), monkeypatch)
    assert out["permissionDecision"] == "ask"
    assert "requires approval" in out["permissionDecisionReason"]


@pytest.mark.parametrize(
    "mode", ["auto", "bypassPermissions", "acceptEdits", "dontAsk", "a-new-mode"]
)
def test_an_ask_no_one_would_see_is_refused(world, monkeypatch, mode):
    """Found live (2026-10-24): in auto mode a Read of .env, which the
    policy sends for approval, ran with no prompt and printed the key."""
    hook, home, work, _ = world
    out = _run(hook, _read_env(work, mode), monkeypatch)
    assert out["permissionDecision"] == "deny"
    assert repr(mode) in out["permissionDecisionReason"]
    assert "shift+tab" in out["permissionDecisionReason"]


def test_the_mode_never_loosens_a_decision(world, monkeypatch):
    hook, home, work, _ = world
    blocked = {**_ls(work), "tool_input": {"command": "rm -rf build"}}
    allowed = _ls(work, "tu-2")
    for mode in ("default", "auto", "bypassPermissions"):
        assert (
            _run(hook, {**blocked, "permission_mode": mode}, monkeypatch)[
                "permissionDecision"
            ]
            == "deny"
        )
        assert _run(hook, {**allowed, "permission_mode": mode}, monkeypatch) is None


def test_fail_open_asks_only_when_a_person_would_see_it(tmp_path, monkeypatch):
    hook = _module("pv_pretool")
    monkeypatch.setenv("PV_FAIL_OPEN", "1")
    monkeypatch.setattr(hook, "decide", lambda payload: (None, "connection refused"))
    event = {**_ls(tmp_path), "permission_mode": "default"}
    assert _run(hook, event, monkeypatch)["permissionDecision"] == "ask"
    event["permission_mode"] = "auto"
    assert _run(hook, event, monkeypatch)["permissionDecision"] == "deny"
