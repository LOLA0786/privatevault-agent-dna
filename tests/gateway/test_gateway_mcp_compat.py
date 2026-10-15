"""The stdio gateway works with the official MCP Python SDK, end to end.

Found by an external test run (2026-10-15): the CLI ignored the PV_*
environment, spoke only Content-Length framing (the MCP stdio spec is
newline-delimited JSON), could not see replies already buffered from the
upstream, and answered notifications. These tests run the real CLI as a
subprocess between the official SDK client and an official SDK server.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from agent_dna.apikeys import generate_key
from agent_dna.gateway.errors import FramingProtocolError
from agent_dna.gateway.framing import (
    FrameBuffer,
    FramingMode,
    encode_jsonrpc_message,
    frame_message,
    freeze_jsonrpc_bytes,
)
from agent_dna.gateway.upstream import StdioUpstream

ROOT = Path(__file__).resolve().parents[2]

UPSTREAM = textwrap.dedent(
    """
    import sys
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("pv-compat")

    @server.tool()
    def read_note(name: str) -> str:
        return "note:" + name

    @server.tool()
    def delete_dir(path: str) -> str:
        open(path, "w").close()
        return "deleted"

    if __name__ == "__main__":
        # chatty stderr: an unread stderr PIPE would eventually hang
        for _ in range(2000):
            print("x" * 100, file=sys.stderr)
        server.run()
    """
)

CLIENT = textwrap.dedent(
    """
    import asyncio, json, os, sys
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.shared.exceptions import MCPError

    async def main():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "agent_dna.gateway", "--stdio", "--command",
                  sys.executable, sys.argv[1]],
            env=dict(os.environ),
        )
        out = {}
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await asyncio.wait_for(s.initialize(), 30)
                tools = await s.list_tools()
                out["tools"] = sorted(t.name for t in tools.tools)
                for name, args in (("read_note", {"name": "x"}),
                                   ("delete_dir", {"path": sys.argv[2]})):
                    try:
                        res = await asyncio.wait_for(s.call_tool(name, args), 30)
                        out[name] = ["ok", [getattr(c, "text", "") for c in res.content]]
                    except MCPError as exc:
                        out[name] = ["refused", str(exc)]
        print(json.dumps(out))

    asyncio.run(main())
    """
)


def _env(tmp_path: Path) -> dict[str, str]:
    entry = generate_key("gateway-agent", scope="full")
    keys = tmp_path / "keys.json"
    keys.write_text(
        json.dumps({entry["hash"]: {"name": "gateway-agent", "scope": "full"}})
    )
    grants = tmp_path / "grants.json"
    grants.write_text(
        json.dumps(
            [
                {
                    "agent_id": "gateway-agent",
                    "capability": "read_note",
                    "granted_by": "t",
                }
            ]
        )
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("PV_")}
    env.update(
        PV_AGENT_API_KEY=entry["key"],
        PV_API_KEYS_FILE=str(keys),
        PV_GRANTS_FILE=str(grants),
        PV_DB_PATH=str(tmp_path / "gw.db"),
        PV_BASELINE_CAPABILITIES="read_note,delete_dir",
        PYTHONPATH=str(ROOT),
    )
    return env


def test_official_sdk_client_and_server_through_gateway_cli(tmp_path):
    (tmp_path / "upstream.py").write_text(UPSTREAM)
    (tmp_path / "client.py").write_text(CLIENT)
    victim = tmp_path / "victim"
    proc = subprocess.run(
        [sys.executable, "client.py", str(tmp_path / "upstream.py"), str(victim)],
        cwd=tmp_path,
        env=_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-3000:]
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["tools"] == ["delete_dir", "read_note"]
    # granted (from PV_GRANTS_FILE, so the CLI read the environment):
    # forwarded, and the real upstream result comes back
    assert out["read_note"] == ["ok", ["note:x"]]
    # not granted: refused by PrivateVault, never reached the upstream
    assert out["delete_dir"][0] == "refused"
    assert "PrivateVault" in out["delete_dir"][1]
    assert not victim.exists()
    # the decision trail landed in PV_DB_PATH, not the repo's data/ dir
    assert (tmp_path / "gw.db").exists()


def test_gateway_cli_refuses_bad_environment_without_traceback(tmp_path):
    env = _env(tmp_path)
    env["PV_GRANTS_FILE"] = str(tmp_path / "missing.json")
    proc = subprocess.run(
        [sys.executable, "-m", "agent_dna.gateway", "--stdio", "--command", "true"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 1
    assert "gateway startup refused" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_newline_frame_round_trip_and_refusal():
    payload = encode_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 1, "result": {"t": "a\nb"}}
    )
    wire = frame_message(payload, FramingMode.NEWLINE)
    assert wire.endswith(b"\n") and wire.count(b"\n") == 1
    buf = FrameBuffer(mode=FramingMode.NEWLINE)
    buf.push(wire + b"\n" + wire)
    assert buf.take_message() == payload
    with pytest.raises(FramingProtocolError):
        frame_message(b'{"a":1}\n{"b":2}', FramingMode.NEWLINE)


def test_frozen_digest_covers_the_newline_wire_bytes():
    msg = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {}}
    nl, nl_digest = freeze_jsonrpc_bytes(msg, mode=FramingMode.NEWLINE)
    cl, cl_digest = freeze_jsonrpc_bytes(msg, mode=FramingMode.CONTENT_LENGTH)
    assert nl.endswith(b"\n") and cl.startswith(b"Content-Length:")
    assert nl_digest != cl_digest


def test_stdio_upstream_reads_reply_already_buffered(tmp_path, credentials):
    # The upstream writes two replies in one burst; both must be readable
    # even though the second never triggers another select() wake-up.
    script = tmp_path / "burst.py"
    script.write_text(
        "import sys\n"
        "sys.stdin.readline()\n"
        'sys.stdout.write(\'{"jsonrpc":"2.0","id":1,"result":{}}\\n'
        '{"jsonrpc":"2.0","id":2,"result":{}}\\n\')\n'
        "sys.stdout.flush()\n"
        "sys.stdin.readline()\n"
    )
    up = StdioUpstream(
        command=[sys.executable, str(script)],
        credentials=credentials,
        framing_mode=FramingMode.NEWLINE,
    )
    try:
        up.write(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
        assert up.read_jsonrpc(timeout_s=10)["id"] == 1
        assert up.read_jsonrpc(timeout_s=2)["id"] == 2
    finally:
        up.close()


def test_notifications_get_no_response(allow_runtime, credentials):
    from agent_dna.gateway.stdio_proxy import serve_stdio
    from agent_dna.gateway.upstream import RecordingUpstream
    from tests.gateway.conftest import make_gateway

    rt, key = allow_runtime
    gw = make_gateway(
        rt, key, credentials, RecordingUpstream(), framing_mode=FramingMode.NEWLINE
    )
    client_in = io.BytesIO(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    client_out = io.BytesIO()
    serve_stdio(gw, client_in=client_in, client_out=client_out)
    assert client_out.getvalue() == b""
