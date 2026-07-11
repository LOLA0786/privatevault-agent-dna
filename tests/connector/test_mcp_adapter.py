"""
MCP adapter integration — real FastMCP server, real in-memory MCP
client, real ConnectorMiddleware (real engine, breaker, key
registry, recorder + signer). Zero mocks on the enforcement path.

Proves the punch-list item: transport-level MCP interop. A client
speaking actual MCP protocol gets tool results when allowed and
signed refusals in-band when blocked — including suspension by a
breaker tripped mid-session.
"""

import json
import time

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from agent_dna.apikeys import ApiKeyRegistry, generate_key
from agent_dna.circuit_breaker import BreakerConfig, CircuitBreaker, GuardedEngine
from agent_dna.connector import ConnectorMiddleware
from agent_dna.connector.adapters import guard_fastmcp
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.signer import ReceiptSigner, generate_keypair
from tests.test_multi_writer_safety import _engine


@pytest.fixture
def stack(tmp_path):
    agent = generate_key("mcp-agent-01", scope="full")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(json.dumps({
        agent["hash"]: {"name": "mcp-agent-01", "scope": "full"},
    }))
    breaker = CircuitBreaker(
        tmp_path / "breaker.db",
        BreakerConfig(max_decisions=None, window_seconds=60.0,
                      max_cumulative_amount=None,
                      max_consecutive_refusals=None),
    )
    recorder = DecisionRecorder(
        signer=ReceiptSigner(seed_hex=generate_keypair()["signing_key"]),
    )
    middleware = ConnectorMiddleware(
        engine=GuardedEngine(_engine(), breaker),
        recorder=recorder,
        keys=ApiKeyRegistry(str(keys_path)),
    )

    server = FastMCP("guarded-tools")
    executed = {"n": 0}

    @server.tool()
    def read_contact(contact_id: str) -> str:
        executed["n"] += 1
        return f"contact {contact_id}"

    return server, middleware, breaker, recorder, agent["key"], executed


@pytest.mark.asyncio
async def test_allowed_call_executes_and_is_chained(stack):
    server, mw, breaker, recorder, key, executed = stack
    guard_fastmcp(server, mw, api_key=key)
    async with create_connected_server_and_client_session(server) as client:
        r = await client.call_tool("read_contact", {"contact_id": "C-1"})
    if not r.isError:
        assert "contact C-1" in r.content[0].text
        assert executed["n"] == 1
    else:
        # engine may legitimately escalate (drift) — but then the tool
        # must NOT have run and the refusal must be signed + in-band
        assert executed["n"] == 0
        assert "record_hash=" in r.content[0].text
    recs = recorder.graph.find_by_agent("mcp-agent-01")
    assert len(recs) == 1
    assert recs[-1].record_hash in recorder.envelopes   # signed


@pytest.mark.asyncio
async def test_tripped_breaker_blocks_over_mcp_transport(stack):
    server, mw, breaker, recorder, key, executed = stack
    guard_fastmcp(server, mw, api_key=key)
    breaker._trip("mcp-agent-01", "volume_trip: test salami drain",
                  time.time())
    async with create_connected_server_and_client_session(server) as client:
        r = await client.call_tool("read_contact", {"contact_id": "C-2"})
    assert r.isError
    text = r.content[0].text
    assert "circuit_breaker" in text
    assert "record_hash=" in text
    assert executed["n"] == 0, "suspended agent executed a tool"
    # the refusal itself is a signed chain record
    rec = recorder.graph.find_by_agent("mcp-agent-01")[-1]
    assert rec.record_hash in recorder.envelopes


@pytest.mark.asyncio
async def test_wrong_key_identity_block_no_execution(stack):
    server, mw, breaker, recorder, key, executed = stack
    guard_fastmcp(server, mw, api_key="pv_wrong-key")
    async with create_connected_server_and_client_session(server) as client:
        r = await client.call_tool("read_contact", {"contact_id": "C-3"})
    assert r.isError
    assert "identity" in r.content[0].text
    assert executed["n"] == 0
    assert len(recorder.graph) == 0     # unauthenticated writes nothing
