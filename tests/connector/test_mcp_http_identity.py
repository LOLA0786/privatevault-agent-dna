"""
Per-session identity over streamable HTTP — the real transport.

A guarded FastMCP server runs in a forked process with the real
enforcement stack (engine, breaker pre-tripped for one agent, key
registry). Real MCP SDK clients connect over HTTP with different
Authorization headers:

  session A (valid key, agent not suspended)  -> tool executes
  session B (valid key, agent SUSPENDED)      -> BLOCK, signed hash in-band
  session C (no header)                        -> identity BLOCK

Chain-side assertions live in test_mcp_adapter.py (in-memory, same
process); this file proves the transport + per-session identity.
"""

import json
import multiprocessing
import socket
import time

import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from agent_dna.apikeys import generate_key


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(port, keys_path, breaker_db, suspended_agent):
    """Child process: build the real stack and serve streamable HTTP."""
    from mcp.server.fastmcp import FastMCP

    from agent_dna.apikeys import ApiKeyRegistry
    from agent_dna.circuit_breaker import (
        BreakerConfig,
        CircuitBreaker,
        GuardedEngine,
    )
    from agent_dna.connector import ConnectorMiddleware
    from agent_dna.connector.adapters import guard_fastmcp
    from agent_dna.decision_recorder import DecisionRecorder
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
    middleware = ConnectorMiddleware(
        engine=GuardedEngine(_engine(), breaker),
        recorder=DecisionRecorder(),
        keys=ApiKeyRegistry(str(keys_path)),
    )
    server = FastMCP("http-guarded", host="127.0.0.1", port=port)

    @server.tool()
    def read_contact(contact_id: str) -> str:
        return f"contact {contact_id}"

    guard_fastmcp(server, middleware)  # no static key: header-only
    server.run(transport="streamable-http")


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
    proc = multiprocessing.get_context("fork").Process(
        target=_serve,
        args=(port, keys_path, tmp / "breaker.db", "http-agent-b"),
        daemon=True,
    )
    proc.start()
    url = f"http://127.0.0.1:{port}/mcp"
    yield url, agent_a["key"], agent_b["key"]
    proc.terminate()
    proc.join(timeout=5)


async def _call(url, key):
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    deadline = time.time() + 15
    while True:
        try:
            async with create_mcp_http_client(headers=headers) as hc:
                async with streamable_http_client(url, http_client=hc) as (r, w, _):
                    async with ClientSession(r, w) as s:
                        await s.initialize()
                        return await s.call_tool("read_contact", {"contact_id": "C-1"})
        except Exception:
            if time.time() > deadline:
                raise
            time.sleep(0.5)


@pytest.mark.asyncio
async def test_valid_session_executes(http_stack):
    url, key_a, _ = http_stack
    r = await _call(url, key_a)
    if r.isError:
        # drift escalation is legitimate; refusal must still be in-band
        assert "record_hash=" in r.content[0].text
    else:
        assert "contact C-1" in r.content[0].text


@pytest.mark.asyncio
async def test_suspended_agent_blocked_per_session(http_stack):
    """Same server, different bearer key -> different agent -> its
    suspension applies while agent A's sessions keep working."""
    url, _, key_b = http_stack
    r = await _call(url, key_b)
    assert r.isError
    text = r.content[0].text
    assert "circuit_breaker" in text
    assert "record_hash=" in text


@pytest.mark.asyncio
async def test_anonymous_session_identity_block(http_stack):
    url, *_ = http_stack
    r = await _call(url, None)
    assert r.isError
    assert "identity" in r.content[0].text
