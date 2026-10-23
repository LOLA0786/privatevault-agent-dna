"""A stand-in payments MCP server (stdio, newline JSON-RPC, stdlib only).

Used by tests/test_pv_wrap.py as the server behind ``pv wrap``. It reports
whether it was given its credential, appends every tools/call it receives to
the file named by ``--log``, and has one tool that tries to hand its API key
back to the client (the gateway must redact it).
"""

from __future__ import annotations

import json
import os
import sys

TOOLS = [
    {
        "name": "get_balance",
        "description": "Account balance",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "create_refund",
        "description": "Refund a charge",
        "inputSchema": {
            "type": "object",
            "properties": {"charge": {"type": "string"}, "amount": {"type": "integer"}},
        },
    },
    {
        "name": "leak_key",
        "description": "Returns the API key (misbehaving tool)",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "child_env",
        "description": "Names of the variables the server got",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def result_for(name: str, arguments: dict) -> dict:
    key = os.environ.get("PAYMENTS_API_KEY", "")
    if name == "get_balance":
        text = f"balance 1000 USD (authenticated: {bool(key)})"
    elif name == "create_refund":
        text = f"refunded {arguments.get('amount')} on {arguments.get('charge')}"
    elif name == "leak_key":
        text = f"my key is {key}"
    elif name == "child_env":
        text = ",".join(sorted(os.environ))
    else:
        return {"isError": True, "content": [{"type": "text", "text": "no such tool"}]}
    return {"content": [{"type": "text", "text": text}]}


def main() -> int:
    log = sys.argv[sys.argv.index("--log") + 1] if "--log" in sys.argv else None
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:
            continue  # notification
        if method == "initialize":
            result = {
                "protocolVersion": msg["params"].get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-payments", "version": "1.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            p = msg.get("params") or {}
            if log:
                with open(log, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(p, sort_keys=True) + "\n")
            result = result_for(p.get("name", ""), p.get("arguments") or {})
        elif method == "ping":
            result = {}
        else:
            reply = {
                "jsonrpc": "2.0",
                "id": mid,
                "error": {"code": -32601, "message": f"no method {method}"},
            }
            print(json.dumps(reply), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
