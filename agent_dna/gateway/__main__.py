"""Out-of-process MCP / HTTPS-egress gateway.

Run as a separate principal from the model:

    python -m agent_dna.gateway --stdio --command npx -- some-mcp-server
    python -m agent_dna.gateway --http-url https://mcp.example/mcp
    python -m agent_dna.gateway --https-egress https://api.example/v1 --capability crm.read_contact
"""

from __future__ import annotations

import argparse
import os
import sys

from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.gateway.credentials import UpstreamCredentials
from agent_dna.gateway.errors import GatewayStartupError
from agent_dna.gateway.http_sse_proxy import build_asgi_app
from agent_dna.gateway.https_egress import build_https_egress_asgi_app
from agent_dna.gateway.runtime import GatewayConfig, McpGateway
from agent_dna.gateway.stdio_proxy import serve_stdio


def _credentials_from_env() -> UpstreamCredentials:
    token = os.environ.get("PV_UPSTREAM_TOKEN", "")
    env = {}
    headers = {}
    if token:
        env["UPSTREAM_TOKEN"] = token
        headers["Authorization"] = f"Bearer {token}"
    extra = os.environ.get("PV_UPSTREAM_AUTH_HEADER", "")
    if extra:
        headers["Authorization"] = extra
    return UpstreamCredentials(env=env, headers=headers)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent_dna.gateway")
    parser.add_argument("--agent-key", default=os.environ.get("PV_AGENT_API_KEY", ""))
    parser.add_argument(
        "--client-identity",
        default=os.environ.get("PV_CLIENT_IDENTITY", "gateway-client"),
    )
    parser.add_argument("--stdio", action="store_true")
    parser.add_argument("--command", nargs="+", default=None)
    parser.add_argument("--http-url", default="")
    parser.add_argument("--https-egress", default="")
    parser.add_argument(
        "--capability",
        default=os.environ.get("PV_HTTPS_EGRESS_CAPABILITY", ""),
        help="named capability for --https-egress (required in that mode)",
    )
    parser.add_argument("--http-bind", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8088)
    args = parser.parse_args(argv)

    if not args.agent_key:
        print("PV_AGENT_API_KEY / --agent-key is required", file=sys.stderr)
        return 2
    modes = sum(bool(x) for x in (args.stdio, args.http_url, args.https_egress))
    if modes != 1:
        print(
            "exactly one of --stdio, --http-url, --https-egress is required",
            file=sys.stderr,
        )
        return 2
    if args.https_egress and not args.capability:
        print(
            "--https-egress requires --capability / PV_HTTPS_EGRESS_CAPABILITY",
            file=sys.stderr,
        )
        return 2
    if args.stdio and not args.command:
        print("--stdio requires --command", file=sys.stderr)
        return 2

    runtime = build_production_runtime(RuntimeConfig())
    credentials = _credentials_from_env()
    try:
        if args.stdio:
            gw = McpGateway.from_stdio_command(
                runtime,
                config=GatewayConfig(
                    agent_api_key=args.agent_key,
                    client_identity=args.client_identity,
                    transport="stdio",
                ),
                credentials=credentials,
                command=list(args.command),
            )
            serve_stdio(gw)
            return 0
        if args.http_url:
            gw = McpGateway.from_http_url(
                runtime,
                config=GatewayConfig(
                    agent_api_key=args.agent_key,
                    client_identity=args.client_identity,
                    transport="http+sse",
                ),
                credentials=credentials,
                url=args.http_url,
            )
            import uvicorn

            uvicorn.run(build_asgi_app(gw), host=args.http_bind, port=args.http_port)
            return 0
        gw = McpGateway.from_https_egress(
            runtime,
            config=GatewayConfig(
                agent_api_key=args.agent_key,
                client_identity=args.client_identity,
                transport="https-egress",
            ),
            credentials=credentials,
            url=args.https_egress,
            capability=args.capability,
        )
        import uvicorn

        uvicorn.run(
            build_https_egress_asgi_app(gw),
            host=args.http_bind,
            port=args.http_port,
        )
        return 0
    except GatewayStartupError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
