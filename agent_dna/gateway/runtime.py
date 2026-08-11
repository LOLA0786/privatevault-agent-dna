"""Gateway process entry — refuses to start without a production runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_dna.composition import ProductionRuntime
from agent_dna.gateway.credentials import UpstreamCredentials
from agent_dna.gateway.errors import GatewayStartupError
from agent_dna.gateway.mediator import GatewayMediator
from agent_dna.gateway.metrics import GatewayMetrics
from agent_dna.gateway.session import GatewaySession, new_session_id
from agent_dna.gateway.upstream import (
    HttpSseUpstream,
    StdioUpstream,
    UpstreamTransport,
)


@dataclass(frozen=True)
class GatewayConfig:
    """Operator configuration only — nothing here is caller-skippable."""

    agent_api_key: str
    client_identity: str
    transport: str  # "stdio" | "http+sse"
    upstream_timeout_s: float = 5.0
    framed: bool = True


class McpGateway:
    """Inline MCP gateway bound to a ``ProductionRuntime``."""

    def __init__(
        self,
        runtime: ProductionRuntime | None,
        *,
        config: GatewayConfig,
        credentials: UpstreamCredentials,
        upstream: UpstreamTransport,
        metrics: GatewayMetrics | None = None,
    ) -> None:
        if runtime is None:
            raise GatewayStartupError(
                "refusing to start MCP gateway without a configured runtime"
            )
        if not runtime.apikeys.enabled:
            raise GatewayStartupError(
                "refusing to start MCP gateway without enabled API key identity"
            )
        if not config.agent_api_key:
            raise GatewayStartupError(
                "refusing to start MCP gateway without agent API key"
            )
        if config.transport not in {"stdio", "http+sse"}:
            raise GatewayStartupError(
                f"unsupported gateway transport {config.transport!r}"
            )
        self.runtime = runtime
        self.config = config
        self.credentials = credentials
        self.upstream = upstream
        self.metrics = metrics if metrics is not None else GatewayMetrics()
        self._middleware = runtime.middleware()

    @classmethod
    def from_stdio_command(
        cls,
        runtime: ProductionRuntime | None,
        *,
        config: GatewayConfig,
        credentials: UpstreamCredentials,
        command: list[str],
        metrics: GatewayMetrics | None = None,
    ) -> McpGateway:
        if runtime is None:
            raise GatewayStartupError(
                "refusing to start MCP gateway without a configured runtime"
            )
        if not command:
            raise GatewayStartupError("stdio upstream command is required")
        upstream = StdioUpstream(command=list(command), credentials=credentials)
        return cls(
            runtime,
            config=config,
            credentials=credentials,
            upstream=upstream,
            metrics=metrics,
        )

    @classmethod
    def from_http_url(
        cls,
        runtime: ProductionRuntime | None,
        *,
        config: GatewayConfig,
        credentials: UpstreamCredentials,
        url: str,
        metrics: GatewayMetrics | None = None,
    ) -> McpGateway:
        if runtime is None:
            raise GatewayStartupError(
                "refusing to start MCP gateway without a configured runtime"
            )
        if not url:
            raise GatewayStartupError("HTTP upstream URL is required")
        upstream = HttpSseUpstream(url=url, credentials=credentials)
        return cls(
            runtime,
            config=config,
            credentials=credentials,
            upstream=upstream,
            metrics=metrics,
        )

    def open_session(self, *, client_identity: str | None = None) -> GatewayMediator:
        session = GatewaySession(
            session_id=new_session_id(),
            client_identity=client_identity or self.config.client_identity,
            upstream_identity=self.upstream.identity,
            transport=self.config.transport,
        )
        return GatewayMediator(
            middleware=self._middleware,
            upstream=self.upstream,
            credentials=self.credentials,
            session=session,
            metrics=self.metrics,
            agent_api_key=self.config.agent_api_key,
            upstream_timeout_s=self.config.upstream_timeout_s,
            framed=self.config.framed,
        )

    def ops_summary(self) -> dict[str, Any]:
        return {
            "gateway": True,
            "transport": self.config.transport,
            "upstream_identity": self.upstream.identity,
            "metrics": self.metrics.ops_fields(),
            "bypass_detection": {
                "claim": (
                    "mediated egress with detectable bypass; "
                    "complete mediation is not claimed"
                ),
                "upstream_unattributed_sessions": (
                    self.metrics.upstream_unattributed_sessions
                ),
            },
        }
