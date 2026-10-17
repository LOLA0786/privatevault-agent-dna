"""OAuth sign-in for PrivateVault Audit, end to end over real HTTP.

Walks the flow Claude's connector client runs: protected-resource
discovery from a 401, authorization-server metadata, Dynamic Client
Registration, /authorize with PKCE S256, sign-in with an audit-scoped key,
code exchange, MCP calls with the bearer token, and refresh rotation.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import socket
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import anyio
import httpx
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from agent_dna.audit_connector.__main__ import main as cli_main
from agent_dna.audit_connector.server import build_oauth_server

CALLBACK = "https://claude.ai/api/mcp/auth_callback"
TOOLS = {
    "list_blocked_actions",
    "list_agent_actions",
    "get_decision",
    "verify_audit_trail",
    "activity_summary",
    "list_revocations",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def hosted(deployment):
    import uvicorn

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    server, _ = build_oauth_server("http://testserver", base, http=deployment["http"])
    app = server.streamable_http_app(host="127.0.0.1")
    uv = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not uv.started and time.time() < deadline:
        time.sleep(0.05)
    assert uv.started
    with httpx.Client(base_url=base, follow_redirects=False, timeout=10) as http:
        yield {**deployment, "base": base, "web": http}
    uv.should_exit = True
    thread.join(timeout=10)


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _register(h: dict[str, Any]) -> str:
    r = h["web"].post(
        "/register",
        json={
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": "Claude",
        },
    )
    assert r.status_code == 201, r.text
    return str(r.json()["client_id"])


def _start_login(h: dict[str, Any], client_id: str, challenge: str) -> str:
    r = h["web"].get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": CALLBACK,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st-123",
            "scope": "audit:read",
            "resource": f"{h['base']}/mcp",
        },
    )
    assert r.status_code == 302, r.text
    login = urlparse(r.headers["location"])
    assert login.path == "/login"
    return f"/login?{login.query}"


def _sign_in(h: dict[str, Any], login_path: str, key: str) -> httpx.Response:
    return h["web"].post(login_path, data={"api_key": key})


def _code(h: dict[str, Any], client_id: str, challenge: str) -> str:
    r = _sign_in(h, _start_login(h, client_id, challenge), h["audit_key"])
    assert r.status_code == 302, r.text
    target = urlparse(r.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == CALLBACK
    query = parse_qs(target.query)
    assert query["state"] == ["st-123"]
    return query["code"][0]


def _token(h: dict[str, Any], **form: str) -> httpx.Response:
    return h["web"].post("/token", data=form)


def _tokens(h: dict[str, Any]) -> dict[str, Any]:
    client_id = _register(h)
    verifier, challenge = _pkce()
    code = _code(h, client_id, challenge)
    r = _token(
        h,
        grant_type="authorization_code",
        code=code,
        redirect_uri=CALLBACK,
        client_id=client_id,
        code_verifier=verifier,
        resource=f"{h['base']}/mcp",
    )
    assert r.status_code == 200, r.text
    body = r.json()
    body["client_id"] = client_id
    body["code"] = code
    body["verifier"] = verifier
    return body


def _mcp(
    base: str,
    access_token: str,
    tool: str | None = None,
    args: dict[str, Any] | None = None,
):
    async def go():
        http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {access_token}"})
        async with Client(
            streamable_http_client(f"{base}/mcp", http_client=http)
        ) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            result = await client.call_tool(tool, args or {}) if tool else None
            return names, result

    return anyio.run(go)


def test_discovery_starts_from_a_401(hosted):
    base, http = hosted["base"], hosted["web"]
    r = http.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert r.status_code == 401
    assert (
        f'resource_metadata="{base}/.well-known/oauth-protected-resource/mcp"'
        in r.headers["www-authenticate"]
    )

    prm = http.get("/.well-known/oauth-protected-resource/mcp").json()
    assert prm["resource"] == f"{base}/mcp"
    assert prm["authorization_servers"][0].rstrip("/") == base
    assert prm["scopes_supported"] == ["audit:read"]

    asm = http.get("/.well-known/oauth-authorization-server").json()
    assert asm["issuer"].rstrip("/") == base
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["registration_endpoint"] == f"{base}/register"
    assert asm["token_endpoint"] == f"{base}/token"
    assert set(asm["grant_types_supported"]) >= {"authorization_code", "refresh_token"}


def test_login_page_shows_the_redirect_host_and_refuses_wrong_keys(hosted):
    client_id = _register(hosted)
    _, challenge = _pkce()
    login = _start_login(hosted, client_id, challenge)

    page = hosted["web"].get(login)
    assert page.status_code == 200
    assert "claude.ai" in page.text and "read-only" in page.text
    assert page.headers["x-frame-options"] == "DENY"

    wrong = _sign_in(hosted, login, "pv_not-a-key")
    assert wrong.status_code == 401 and "not accepted" in wrong.text

    full = _sign_in(hosted, login, hosted["full_key"])
    assert full.status_code == 401 and "full-scope" in full.text

    ok = _sign_in(hosted, login, hosted["audit_key"])  # failures did not burn the link
    assert ok.status_code == 302
    again = _sign_in(hosted, login, hosted["audit_key"])
    assert again.status_code == 400  # single use


def test_signed_in_user_calls_tools_with_their_key(hosted):
    tokens = _tokens(hosted)
    assert hosted["audit_key"] not in str(tokens)
    names, result = _mcp(
        hosted["base"], tokens["access_token"], "list_agent_actions", {"agent_id": "a1"}
    )
    assert names == TOOLS
    assert not result.is_error
    assert result.structured_content["total"] == len(hosted["decisions"])

    _, verify = _mcp(hosted["base"], tokens["access_token"], "verify_audit_trail")
    assert verify.structured_content["chain_integrity_verified"] is True


def test_code_is_single_use_and_pkce_bound(hosted):
    tokens = _tokens(hosted)
    replay = _token(
        hosted,
        grant_type="authorization_code",
        code=tokens["code"],
        redirect_uri=CALLBACK,
        client_id=tokens["client_id"],
        code_verifier=tokens["verifier"],
    )
    assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"

    client_id = _register(hosted)
    _, challenge = _pkce()
    code = _code(hosted, client_id, challenge)
    wrong_verifier = _token(
        hosted,
        grant_type="authorization_code",
        code=code,
        redirect_uri=CALLBACK,
        client_id=client_id,
        code_verifier=secrets.token_urlsafe(48),
    )
    assert wrong_verifier.status_code == 400
    assert wrong_verifier.json()["error"] == "invalid_grant"


def test_refresh_rotates_and_revokes_the_old_pair(hosted):
    tokens = _tokens(hosted)
    r = _token(
        hosted,
        grant_type="refresh_token",
        refresh_token=tokens["refresh_token"],
        client_id=tokens["client_id"],
    )
    assert r.status_code == 200, r.text
    fresh = r.json()
    assert fresh["refresh_token"] != tokens["refresh_token"]

    reused = _token(
        hosted,
        grant_type="refresh_token",
        refresh_token=tokens["refresh_token"],
        client_id=tokens["client_id"],
    )
    assert reused.status_code == 400 and reused.json()["error"] == "invalid_grant"

    old = hosted["web"].post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={
            "Authorization": f"Bearer {tokens['access_token']}",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert old.status_code == 401

    names, _ = _mcp(hosted["base"], fresh["access_token"])
    assert names == TOOLS


def test_token_endpoint_accepts_form_encoding_only_path(hosted):
    """Claude sends application/x-www-form-urlencoded to /token."""
    r = hosted["web"].post(
        "/token",
        content=b"grant_type=refresh_token&refresh_token=nope&client_id=nope",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code in (400, 401)
    assert r.headers["content-type"].startswith("application/json")


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--public-url", "http://audit.example.com"], "https"),
        (["--public-url", "https://audit.example.com/mcp"], "without a path"),
        (["--public-url", "audit.example.com"], "absolute URL"),
        (["--host", "0.0.0.0"], "--public-url"),
    ],
)
def test_cli_refuses_unsafe_hosted_settings(argv, message, monkeypatch, capsys):
    monkeypatch.delenv("PV_AUDIT_PUBLIC_URL", raising=False)
    monkeypatch.setenv("PV_AUDIT_API_KEY", "pv_x")
    assert cli_main(argv) == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    ("uri", "allowed"),
    [
        (CALLBACK, True),
        ("http://localhost:3118/callback", True),
        ("http://127.0.0.1:51234/callback", True),
        ("https://evil.example/callback", False),
        ("https://claude.ai/other", False),
        ("http://localhost.evil.example/callback", False),
    ],
)
def test_registration_only_accepts_claude_and_loopback_redirects(hosted, uri, allowed):
    r = hosted["web"].post(
        "/register",
        json={
            "redirect_uris": [uri],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    if allowed:
        assert r.status_code == 201, r.text
    else:
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"


def test_operator_can_allow_extra_redirects():
    from agent_dna.audit_connector.oauth import redirect_allowed

    inspector = "http://inspector.internal:6274/oauth/callback"
    assert not redirect_allowed(inspector)
    assert redirect_allowed(inspector, [inspector])


def test_login_page_lets_the_browser_follow_the_redirect_to_claude(hosted):
    """Browsers apply CSP form-action to the redirect after a form POST.
    With form-action 'self' only, a successful sign-in left the user on our
    page and every retry said "expired" (seen with claude.ai, 2026-10-17)."""
    client_id = _register(hosted)
    _, challenge = _pkce()
    login = _start_login(hosted, client_id, challenge)
    csp = hosted["web"].get(login).headers["content-security-policy"]
    form_action = next(d for d in csp.split(";") if d.strip().startswith("form-action"))
    assert "'self'" in form_action and "https://claude.ai" in form_action
    assert "frame-ancestors 'none'" in csp

    assert _sign_in(hosted, login, hosted["audit_key"]).status_code == 302
    after = hosted["web"].get(login)
    assert after.status_code == 400 and "Already signed in" in after.text
