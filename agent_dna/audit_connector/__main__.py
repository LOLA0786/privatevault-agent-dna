"""Run PrivateVault Audit as a Streamable HTTP MCP server.

Local mode (one operator-held key, no sign-in, loopback only):

    PV_AUDIT_URL=http://127.0.0.1:8000 PV_AUDIT_API_KEY=<audit-scoped key> \\
        python -m agent_dna.audit_connector --port 8790

Hosted mode (each user signs in with OAuth; behind your TLS proxy):

    PV_AUDIT_URL=http://127.0.0.1:8000 python -m agent_dna.audit_connector \\
        --public-url https://audit.example.com --host 0.0.0.0 --port 8790

The MCP endpoint is <public-url>/mcp. Users add that URL to Claude and sign
in with their organisation's audit-scoped key.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from typing import Any
from urllib.parse import urlparse

from mcp.server.transport_security import TransportSecuritySettings

from agent_dna.audit_connector.client import AuditApiClient
from agent_dna.audit_connector.server import build_oauth_server, build_server


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _public_url_problem(public_url: str) -> str | None:
    parsed = urlparse(public_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return "--public-url must be an absolute URL such as https://audit.example.com"
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        return "--public-url must be an origin without a path, such as https://audit.example.com"
    if parsed.scheme != "https" and not _is_loopback(parsed.hostname):
        return (
            "--public-url must use https (OAuth tokens must not travel in clear text)"
        )
    return None


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def _build_app(args: argparse.Namespace) -> tuple[Any, str] | str:
    """The ASGI app and the URL it serves, or a startup error."""
    if args.public_url:
        problem = _public_url_problem(args.public_url)
        if problem:
            return problem
        extra = [
            u
            for u in os.environ.get("PV_AUDIT_EXTRA_REDIRECT_URIS", "").split(",")
            if u
        ]
        server, _ = build_oauth_server(
            args.pv_url, args.public_url, path=args.path, extra_redirect_uris=extra
        )
        netloc = urlparse(args.public_url).netloc
        security = TransportSecuritySettings(
            allowed_hosts=[netloc, "127.0.0.1:*", "localhost:*"],
            allowed_origins=[f"https://{netloc}", "https://claude.ai"],
        )
        app = server.streamable_http_app(
            streamable_http_path=args.path, host=args.host, transport_security=security
        )
        return app, args.public_url.rstrip("/") + args.path

    if not _is_loopback(args.host):
        return (
            f"refusing to bind {args.host} without user sign-in: pass "
            "--public-url to enable OAuth, or bind to 127.0.0.1"
        )
    api_key = os.environ.get("PV_AUDIT_API_KEY", "")
    if not api_key:
        return "PV_AUDIT_API_KEY is not set (use an audit-scoped key), or pass --public-url"
    server = build_server(AuditApiClient(args.pv_url, api_key))
    app = server.streamable_http_app(streamable_http_path=args.path, host=args.host)
    return app, f"http://{args.host}:{args.port}{args.path}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent_dna.audit_connector")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--path", default="/mcp")
    parser.add_argument(
        "--pv-url", default=os.environ.get("PV_AUDIT_URL", "http://127.0.0.1:8000")
    )
    parser.add_argument(
        "--public-url",
        default=os.environ.get("PV_AUDIT_PUBLIC_URL", ""),
        help="public https origin of this server; enables OAuth sign-in",
    )
    args = parser.parse_args(argv)

    built = _build_app(args)
    if isinstance(built, str):
        return _fail(built)
    app, url = built

    import uvicorn

    mode = "OAuth sign-in" if args.public_url else "local, no sign-in"
    print(f"PrivateVault Audit MCP ({mode}) on {url}", file=sys.stderr)
    uvicorn.run(
        app, host=args.host, port=args.port, log_level="warning", proxy_headers=True
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
