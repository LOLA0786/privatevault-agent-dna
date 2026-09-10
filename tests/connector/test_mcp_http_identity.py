"""
Per-session identity over streamable HTTP — the real transport.

A guarded MCPServer server runs in a forked process with the real
enforcement stack (engine, breaker pre-tripped for one agent, key
registry). Real MCP SDK clients connect over HTTP with different
Authorization headers:

  session A (valid key, agent not suspended)  -> tool executes
  session B (valid key, agent SUSPENDED)      -> BLOCK, signed hash in-band
  session C (no header)                        -> identity BLOCK

Chain-side assertions live in test_mcp_adapter.py (in-memory, same
process); this file proves the transport + per-session identity.
"""

import asyncio
import json
import multiprocessing
import socket
import time

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from agent_dna.apikeys import generate_key


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(port, keys_path, breaker_db, suspended_agent, static_key, effects):
    """Child process: build the real stack and serve streamable HTTP."""
    from mcp.server.mcpserver import MCPServer

    from agent_dna.apikeys import ApiKeyRegistry
    from agent_dna.circuit_breaker import (
        BreakerConfig,
        CircuitBreaker,
        GuardedEngine,
    )
    from agent_dna.connector import ConnectorMiddleware
    from agent_dna.connector.adapters import guard_fastmcp
    from agent_dna.decision_recorder import DecisionRecorder
    from agent_dna.open_authorizer import OpenAuthorizer
    from tests.test_multi_writer_safety import _engine

    breaker = CircuitBreaker(
        breaker_db,
        BreakerConfig(
            max_decisions=None,
            window_seconds=60.0,
            max_cumulative_amount=None,
            max_consecutive_refusals=None,
        ),
    )
    breaker._trip(suspended_agent, "volume_trip: pre-tripped for test", time.time())
    core = _engine()
    core.authorizer = OpenAuthorizer()
    middleware = ConnectorMiddleware(
        engine=GuardedEngine(core, breaker),
        recorder=DecisionRecorder(),
        keys=ApiKeyRegistry(str(keys_path)),
    )
    server = MCPServer("http-guarded")

    @server.tool()
    def read_contact(contact_id: str) -> str:
        with effects.open("a") as f:
            f.write(contact_id + "\n")
        return f"contact {contact_id}"

    # A privileged stdio default must never authenticate an anonymous HTTP call.
    guard_fastmcp(server, middleware, api_key=static_key)
    server.run(transport="streamable-http", host="127.0.0.1", port=port)


@pytest.fixture(scope="module")
def http_stack(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("http_identity")
    agent_a = generate_key("http-agent-a", scope="full")
    agent_b = generate_key("http-agent-b", scope="full")
    keys_path = tmp / "keys.json"
    keys_path.write_text(
        json.dumps(
            {
                agent_a["hash"]: {"name": "http-agent-a", "scope": "full"},
                agent_b["hash"]: {"name": "http-agent-b", "scope": "full"},
            }
        )
    )
    port = _free_port()
    effects = tmp / "effects.txt"
    effects.touch()
    proc = multiprocessing.get_context("fork").Process(
        target=_serve,
        args=(
            port,
            keys_path,
            tmp / "breaker.db",
            "http-agent-b",
            agent_a["key"],
            effects,
        ),
        daemon=True,
    )
    proc.start()
    url = f"http://127.0.0.1:{port}/mcp"
    yield url, agent_a["key"], agent_b["key"], effects
    proc.terminate()
    proc.join(timeout=5)


@pytest.fixture(params=["legacy", "auto"])
def mcp_mode(request):
    return request.param


async def _call(url, key, mode, contact_id="C-1"):
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    deadline = time.time() + 15
    while True:
        try:
            async with httpx2.AsyncClient(headers=headers, trust_env=False) as hc:
                transport = streamable_http_client(url, http_client=hc)
                async with Client(transport, mode=mode) as client:
                    return await client.call_tool(
                        "read_contact", {"contact_id": contact_id}
                    )
        except Exception:
            if time.time() > deadline:
                raise
            await asyncio.sleep(0.5)


@pytest.mark.asyncio
async def test_valid_session_executes(http_stack, mcp_mode):
    url, key_a, _, effects = http_stack
    contact_id = f"allowed-{mcp_mode}"
    r = await _call(url, key_a, mcp_mode, contact_id)
    assert not r.is_error
    assert f"contact {contact_id}" in r.content[0].text
    assert effects.read_text().splitlines().count(contact_id) == 1


@pytest.mark.asyncio
async def test_suspended_agent_blocked_per_session(http_stack, mcp_mode):
    """Same server, different bearer key -> different agent -> its
    suspension applies while agent A's sessions keep working."""
    url, _, key_b, effects = http_stack
    contact_id = f"suspended-{mcp_mode}"
    r = await _call(url, key_b, mcp_mode, contact_id)
    assert r.is_error
    text = r.content[0].text
    assert "circuit_breaker" in text
    assert "record_hash=" in text
    assert contact_id not in effects.read_text().splitlines()


@pytest.mark.asyncio
@pytest.mark.parametrize("key", [None, "pv_wrong-key"])
async def test_anonymous_session_identity_block(http_stack, mcp_mode, key):
    url, _, _, effects = http_stack
    contact_id = f"unauthenticated-{mcp_mode}-{key}"
    r = await _call(url, key, mcp_mode, contact_id)
    assert r.is_error
    assert "identity" in r.content[0].text
    assert contact_id not in effects.read_text().splitlines()


@pytest.mark.asyncio
async def test_concurrent_http_identities_do_not_inherit_static_key(
    http_stack, mcp_mode
):
    url, key_a, key_b, effects = http_stack
    contacts = [f"concurrent-{mcp_mode}-{i}" for i in range(3)]
    allowed, suspended, anonymous = await asyncio.gather(
        *(
            _call(url, key, mcp_mode, contact)
            for key, contact in zip([key_a, key_b, None], contacts, strict=True)
        )
    )
    assert not allowed.is_error
    assert suspended.is_error and "circuit_breaker" in suspended.content[0].text
    assert anonymous.is_error and "identity" in anonymous.content[0].text
    observed = effects.read_text().splitlines()
    assert observed.count(contacts[0]) == 1
    assert contacts[1] not in observed
    assert contacts[2] not in observed
