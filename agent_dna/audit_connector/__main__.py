"""Run PrivateVault Audit as a Streamable HTTP MCP server.

    PV_AUDIT_URL=http://127.0.0.1:8000 PV_AUDIT_API_KEY=<audit-scoped key> \\
        python -m agent_dna.audit_connector --port 8790

The MCP endpoint is http://127.0.0.1:8790/mcp. It has no user
authentication yet (OAuth comes next), so it binds to loopback only and
refuses any other host.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys

from agent_dna.audit_connector.client import AuditApiClient
from agent_dna.audit_connector.server import build_server


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent_dna.audit_connector")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--path", default="/mcp")
    parser.add_argument(
        "--pv-url", default=os.environ.get("PV_AUDIT_URL", "http://127.0.0.1:8000")
    )
    args = parser.parse_args(argv)

    if not _is_loopback(args.host):
        print(
            f"refusing to bind {args.host}: the audit connector has no user "
            "authentication yet; bind to 127.0.0.1",
            file=sys.stderr,
        )
        return 2
    api_key = os.environ.get("PV_AUDIT_API_KEY", "")
    if not api_key:
        print("PV_AUDIT_API_KEY is not set (use an audit-scoped key)", file=sys.stderr)
        return 2

    import uvicorn

    server = build_server(AuditApiClient(args.pv_url, api_key))
    app = server.streamable_http_app(streamable_http_path=args.path, host=args.host)
    print(
        f"PrivateVault Audit MCP on http://{args.host}:{args.port}{args.path}",
        file=sys.stderr,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
