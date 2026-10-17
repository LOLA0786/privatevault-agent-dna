"""PrivateVault Audit connector against the real API with an audit-scoped key.

The connector is read-only twice over: every tool carries readOnlyHint, and
the only credential it holds is an audit-scoped key, which the API refuses
on every enforcement endpoint.
"""

from __future__ import annotations

import importlib
import json
import socket
import threading
import time
from typing import Any

import anyio
import pytest
from fastapi.testclient import TestClient
from mcp import Client

from agent_dna.apikeys import generate_key
from agent_dna.audit_connector import AuditApiClient, AuditApiError, build_server
from agent_dna.audit_connector.__main__ import main as cli_main
from tests.decide_binding import decide_json

TOOLS = {
    "list_blocked_actions",
    "list_agent_actions",
    "get_decision",
    "verify_audit_trail",
    "activity_summary",
    "list_revocations",
}


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    """A real API with one full key (agent a1), one audit key and a grant
    for crm.read_contact only; ungranted capabilities are blocked."""
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "audit.db"))
    monkeypatch.delenv("PV_RECEIPT_SIGNING_KEY", raising=False)
    full = generate_key("a1", scope="full")
    audit = generate_key("auditor-1", scope="audit")
    keyfile = tmp_path / "keys.json"
    keyfile.write_text(
        json.dumps(
            {
                full["hash"]: {"name": "a1", "scope": "full"},
                audit["hash"]: {"name": "auditor-1", "scope": "audit"},
            }
        )
    )
    grants = tmp_path / "grants.json"
    grants.write_text(
        json.dumps(
            [{"agent_id": "a1", "capability": "crm.read_contact", "granted_by": "test"}]
        )
    )
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keyfile))
    monkeypatch.setenv("PV_GRANTS_FILE", str(grants))
    monkeypatch.setenv("PV_UNGRANTED_DECISION", "block")

    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as http:
        for capability in (
            "crm.read_contact",
            "payments.pay_invoice",
            "crm.read_contact",
        ):
            http.post(
                "/v1/decide",
                json=decide_json("a1", capability),
                headers={"X-API-Key": full["key"]},
            )
        export = [
            json.loads(line)
            for line in http.get(
                "/v1/audit/export", headers={"X-API-Key": audit["key"]}
            ).text.splitlines()
            if line.strip()
        ]
        yield {
            "http": http,
            "audit_key": audit["key"],
            "full_key": full["key"],
            "decisions": [r for r in export if r.get("kind", "decision") == "decision"],
        }


def _server(dep: dict[str, Any], key: str | None = None):
    return build_server(
        AuditApiClient("http://testserver", key or dep["audit_key"], http=dep["http"])
    )


def _call(server, name: str, args: dict[str, Any] | None = None):
    async def go():
        async with Client(server) as client:
            return await client.call_tool(name, args or {})

    return anyio.run(go)


def _tools(server):
    async def go():
        async with Client(server) as client:
            return (await client.list_tools()).tools

    return anyio.run(go)


def test_every_tool_is_annotated_read_only(deployment):
    tools = _tools(_server(deployment))
    assert {t.name for t in tools} == TOOLS
    for tool in tools:
        assert len(tool.name) <= 64
        assert tool.title
        assert tool.annotations is not None
        assert tool.annotations.title
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.description


def test_blocked_actions_match_the_sealed_records(deployment):
    blocked = [d for d in deployment["decisions"] if d["decision"] == "block"]
    assert blocked, "fixture should produce a blocked decision"
    result = _call(_server(deployment), "list_blocked_actions")
    assert not result.is_error
    out = result.structured_content
    assert out["total"] == len(blocked)
    assert {a["decision_id"] for a in out["actions"]} == {
        d["decision_id"] for d in blocked
    }
    assert all(a["capability"] == "payments.pay_invoice" for a in out["actions"])
    assert all("arguments" not in a for a in out["actions"])


def test_agent_actions_newest_first_and_limited(deployment):
    decisions = deployment["decisions"]
    result = _call(
        _server(deployment), "list_agent_actions", {"agent_id": "a1", "limit": 2}
    )
    out = result.structured_content
    assert out["total"] == len(decisions)
    assert [a["decision_id"] for a in out["actions"]] == [
        d["decision_id"] for d in reversed(decisions)
    ][:2]


def test_unknown_agent_and_decision_are_actionable_errors(deployment):
    server = _server(deployment)
    r = _call(server, "list_agent_actions", {"agent_id": "nobody"})
    assert r.is_error and "nobody" in r.content[0].text
    r = _call(server, "get_decision", {"decision_id": "dec-missing"})
    assert r.is_error and "dec-missing" in r.content[0].text
    r = _call(server, "list_blocked_actions", {"limit": 0})
    assert r.is_error and "limit" in r.content[0].text


def test_get_decision_returns_the_sealed_record(deployment):
    target = deployment["decisions"][1]
    out = _call(
        _server(deployment), "get_decision", {"decision_id": target["decision_id"]}
    ).structured_content
    assert out["record_hash"] == target["record_hash"]
    assert out["decision"] == target["decision"]
    assert out["arguments_digest"] == target["arguments_digest"]


def test_verify_and_summary(deployment):
    server = _server(deployment)
    verify = _call(server, "verify_audit_trail").structured_content
    assert verify["chain_integrity_verified"] is True
    assert verify["broken_chains"] == []
    summary = _call(server, "activity_summary").structured_content
    assert summary["decisions"] == len(deployment["decisions"])
    assert sum(summary["by_agent"]["a1"].values()) == len(deployment["decisions"])
    assert summary["runtime"]["product"] == "PrivateVault Agent DNA"


def test_wrong_key_is_reported_without_echoing_it(deployment):
    bogus = "pv_not-a-real-key-123"
    result = _call(_server(deployment, key=bogus), "activity_summary")
    assert result.is_error
    text = result.content[0].text
    assert "rejected" in text and bogus not in text


def test_audit_key_cannot_reach_enforcement(deployment):
    """The connector's only credential has no write path, whatever a tool did."""
    r = deployment["http"].post(
        "/v1/decide",
        json=decide_json("a1", "crm.read_contact"),
        headers={"X-API-Key": deployment["audit_key"]},
    )
    assert r.status_code == 401


def test_client_errors_name_the_endpoint(deployment):
    client = AuditApiClient(
        "http://testserver", deployment["audit_key"], http=deployment["http"]
    )
    client._headers = {"X-API-Key": "wrong"}
    with pytest.raises(AuditApiError, match="rejected"):
        client.verify()
    with pytest.raises(ValueError):
        AuditApiClient("http://testserver", "")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_streamable_http_end_to_end(deployment):
    """A real MCP client over Streamable HTTP, as Claude connects."""
    import uvicorn

    port = _free_port()
    app = _server(deployment).streamable_http_app(host="127.0.0.1")
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    uv = uvicorn.Server(config)
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 10
        while not uv.started and time.time() < deadline:
            time.sleep(0.05)
        assert uv.started

        async def go():
            async with Client(f"http://127.0.0.1:{port}/mcp") as client:
                names = {t.name for t in (await client.list_tools()).tools}
                result = await client.call_tool("verify_audit_trail", {})
                return names, result

        names, result = anyio.run(go)
        assert names == TOOLS
        assert result.structured_content["chain_integrity_verified"] is True
    finally:
        uv.should_exit = True
        thread.join(timeout=10)


def test_cli_refuses_public_bind_and_missing_key(monkeypatch, capsys):
    monkeypatch.setenv("PV_AUDIT_API_KEY", "pv_x")
    assert cli_main(["--host", "0.0.0.0"]) == 2
    assert "refusing to bind" in capsys.readouterr().err
    monkeypatch.delenv("PV_AUDIT_API_KEY")
    assert cli_main([]) == 2
    assert "PV_AUDIT_API_KEY" in capsys.readouterr().err


def test_revocations_without_signer_is_an_actionable_error(deployment):
    """No execution signer configured: the tool reports it, it does not crash."""
    result = _call(_server(deployment), "list_revocations")
    if result.is_error:
        assert "/v1/revocations" in result.content[0].text
    else:
        assert result.structured_content["signed"] is True
