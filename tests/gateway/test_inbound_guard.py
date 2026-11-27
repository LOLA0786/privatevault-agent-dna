"""The gateway's listeners refuse what a web page or a rebound name could send.

Audit finding (core A): the MCP proxy (/mcp, /ops) and the HTTPS egress
listener (/egress, /ops) acted on any request, with no Host, Origin or
Content-Type check and an unbounded body. On loopback, a web page could
still POST to them as text/plain, which needs no CORS preflight, and a
DNS-rebound name could read their answers.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_dna.gateway.http_sse_proxy import build_asgi_app
from agent_dna.gateway.https_egress import build_https_egress_asgi_app

BASE = "http://127.0.0.1:8765"
LISTENERS = {
    "mcp": (build_asgi_app, "/mcp"),
    "egress": (build_https_egress_asgi_app, "/egress"),
}


class _Session:
    framed = True

    def handle_message(self, message):
        return SimpleNamespace(
            client_message={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        )


class _Gateway:
    config = SimpleNamespace(
        transport="http+sse", max_message_bytes=1 << 20, max_json_depth=64
    )

    def ops_summary(self):
        return {"ok": True}

    def open_session(self):
        return _Session()


@pytest.fixture(params=sorted(LISTENERS))
def listener(request):
    build, post_path = LISTENERS[request.param]
    return TestClient(build(_Gateway()), base_url=BASE), post_path


def test_ops_answers_on_the_listeners_own_address(listener):
    client, _ = listener
    response = client.get("/ops")
    assert response.status_code == 200 and response.json() == {"ok": True}


def test_a_rebound_host_is_refused(listener):
    client, _ = listener
    assert (
        client.get("/ops", headers={"host": "attacker.example:8765"}).status_code == 421
    )


def test_a_browser_page_cannot_post_to_it(listener):
    client, path = listener
    response = client.post(
        path,
        content=b'{"jsonrpc":"2.0","id":1,"method":"tools/call"}',
        headers={"origin": "https://attacker.example", "content-type": "text/plain"},
    )
    assert response.status_code == 403


def test_an_oversized_body_is_refused_before_it_is_buffered(listener, monkeypatch):
    monkeypatch.setenv("PV_GATEWAY_MAX_BODY_BYTES", "64")
    client, path = listener
    response = client.post(
        path,
        content=b"{" + b" " * 200 + b"}",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


def test_an_operator_can_allow_the_host_a_proxy_uses(listener, monkeypatch):
    monkeypatch.setenv("PV_GATEWAY_ALLOWED_HOSTS", "gateway.bank.internal:443")
    client, _ = listener
    assert (
        client.get("/ops", headers={"host": "gateway.bank.internal:443"}).status_code
        == 200
    )


def test_the_mcp_endpoint_takes_only_json():
    client = TestClient(build_asgi_app(_Gateway()), base_url=BASE)
    response = client.post(
        "/mcp",
        content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
        headers={"content-type": "text/plain"},
    )
    assert response.status_code == 415


def test_an_mcp_client_is_still_served():
    client = TestClient(build_asgi_app(_Gateway()), base_url=BASE)
    response = client.post(
        "/mcp",
        content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 200 and response.json()["result"] == {"tools": []}
