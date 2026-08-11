"""Gateway process entry — refuses to start without a production runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_dna.composition import ProductionRuntime
from agent_dna.gateway.credentials import UpstreamCredentials
from agent_dna.gateway.errors import GatewayStartupError
from agent_dna.gateway.framing import (
    DEFAULT_MAX_MESSAGE_BYTES,
    FramingMode,
)
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
    """Operator configuration only — nothing here is caller-skippable.

    ``framing_mode`` defaults to Content-Length. Newline framing is
    test-only: it requires ``_test_allow_newline_framing=True``, which
    production constructors never set.
    """

    agent_api_key: str
    client_identity: str
    transport: str  # "stdio" | "http+sse"
    upstream_timeout_s: float = 5.0
    framed: bool = True
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    framing_mode: FramingMode = FramingMode.CONTENT_LENGTH
    # Explicit test-only escape hatch. Production config cannot select
    # newline framing without this flag, and public constructors leave it False.
    _test_allow_newline_framing: bool = False


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
        if config.max_message_bytes <= 0:
            raise GatewayStartupError("max_message_bytes must be positive")
        if config.framing_mode is FramingMode.NEWLINE:
            if not config._test_allow_newline_framing:
                raise GatewayStartupError(
                    "newline framing is test-only; production config must use "
                    "content-length framing"
                )
        elif config.framing_mode is not FramingMode.CONTENT_LENGTH:
            raise GatewayStartupError(
                f"unsupported framing_mode {config.framing_mode!r}"
            )
        if config.transport not in {"stdio", "http+sse"}:
            raise GatewayStartupError(
                f"unsupported gateway transport {config.transport!r}"
            )
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
        # Production constructor: Content-Length only.
        if config.framing_mode is not FramingMode.CONTENT_LENGTH:
            raise GatewayStartupError(
                "from_stdio_command requires content-length framing"
            )
        upstream = StdioUpstream(
            command=list(command),
            credentials=credentials,
            max_message_bytes=config.max_message_bytes,
            framing_mode=FramingMode.CONTENT_LENGTH,
        )
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
        upstream = HttpSseUpstream(
            url=url,
            credentials=credentials,
            max_message_bytes=config.max_message_bytes,
        )
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
            max_message_bytes=self.config.max_message_bytes,
        )

    def ops_summary(self) -> dict[str, Any]:
        return {
            "gateway": True,
            "transport": self.config.transport,
            "framing_mode": self.config.framing_mode.value,
            "max_message_bytes": self.config.max_message_bytes,
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
