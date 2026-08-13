"""Gateway process entry — refuses to start without a production runtime."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlparse

from agent_dna.composition import ProductionRuntime
from agent_dna.gateway.credentials import UpstreamCredentials
from agent_dna.gateway.errors import GatewayStartupError
from agent_dna.gateway.framing import (
    DEFAULT_MAX_MESSAGE_BYTES,
    MAX_JSON_DEPTH,
    FramingMode,
)
from agent_dna.gateway.https_egress import (
    HttpsEgressResult,
    HttpsEgressUpstream,
    dispatch_https_egress,
    require_https_url,
)
from agent_dna.gateway.mediator import GatewayMediator
from agent_dna.gateway.metrics import GatewayMetrics
from agent_dna.gateway.session import GatewaySession, new_session_id
from agent_dna.gateway.upstream import (
    HttpSseUpstream,
    StdioUpstream,
    UpstreamTransport,
)

PRODUCTION_UPSTREAM_TYPES = (StdioUpstream, HttpSseUpstream, HttpsEgressUpstream)
UNDECLARED_POLICIES = frozenset({"finding", "block"})


@dataclass(frozen=True)
class GatewayConfig:
    """Operator configuration only — nothing here is caller-skippable.

    ``framing_mode`` defaults to Content-Length. Newline framing is
    test-only: it requires ``_test_allow_newline_framing=True``, which
    production constructors never set.
    """

    agent_api_key: str
    client_identity: str
    transport: str  # "stdio" | "http+sse" | "https-egress"
    upstream_timeout_s: float = 5.0
    framed: bool = True
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_json_depth: int = MAX_JSON_DEPTH
    framing_mode: FramingMode = FramingMode.CONTENT_LENGTH
    # TLS verification is on by default. Disabling it requires the
    # operator flag ``allow_insecure_tls``; callers cannot skip this.
    tls_verify: bool = True
    allow_insecure_tls: bool = False
    https_only: bool = True
    allow_insecure_http: bool = False
    fail_closed_on_unattributed: bool = True
    undeclared_tool_policy: str = "finding"
    max_same_origin_redirects: int = 1
    https_egress_capability: str = ""
    # Explicit test-only escape hatches. Production constructors leave these False.
    _test_allow_newline_framing: bool = False
    _test_allow_inprocess: bool = False


def _validate_gateway_config(config: GatewayConfig) -> None:
    if config.max_message_bytes <= 0:
        raise GatewayStartupError("max_message_bytes must be positive")
    if config.max_json_depth <= 0:
        raise GatewayStartupError("max_json_depth must be positive")
    if config.undeclared_tool_policy not in UNDECLARED_POLICIES:
        raise GatewayStartupError(
            f"undeclared_tool_policy must be one of {sorted(UNDECLARED_POLICIES)}"
        )
    if config.max_same_origin_redirects < 0:
        raise GatewayStartupError("max_same_origin_redirects must be >= 0")
    _validate_framing_mode(config)
    _validate_transport_tls(config)


def _validate_framing_mode(config: GatewayConfig) -> None:
    if config.framing_mode is FramingMode.NEWLINE:
        if not config._test_allow_newline_framing:
            raise GatewayStartupError(
                "newline framing is test-only; production config must use "
                "content-length framing"
            )
        return
    if config.framing_mode is not FramingMode.CONTENT_LENGTH:
        raise GatewayStartupError(f"unsupported framing_mode {config.framing_mode!r}")


def _validate_transport_tls(config: GatewayConfig) -> None:
    if config.transport not in {"stdio", "http+sse", "https-egress"}:
        raise GatewayStartupError(f"unsupported gateway transport {config.transport!r}")
    if config.transport in {"http+sse", "https-egress"} and not config.tls_verify:
        if not config.allow_insecure_tls:
            raise GatewayStartupError(
                "TLS certificate verification is on by default; refusing "
                "to start with TLS disabled without allow_insecure_tls"
            )


def _harden_production_config(config: GatewayConfig) -> GatewayConfig:
    return replace(config, undeclared_tool_policy="block")


def _require_https(url: str, config: GatewayConfig) -> None:
    if not config.https_only:
        return
    require_https_url(url, allow_insecure_http=config.allow_insecure_http)


class McpGateway:
    """MCP / HTTPS-egress gateway bound to a ``ProductionRuntime``.

    Production composition is out-of-process: ``from_stdio_command``,
    ``from_http_url``, or ``from_https_egress``. An in-process mock
    upstream requires ``_test_allow_inprocess``.
    """

    def __init__(
        self,
        runtime: ProductionRuntime | None,
        *,
        config: GatewayConfig,
        credentials: UpstreamCredentials,
        upstream: UpstreamTransport,
        metrics: GatewayMetrics | None = None,
    ) -> None:
        _validate_gateway_config(config)
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
        if (
            type(upstream) not in PRODUCTION_UPSTREAM_TYPES
            and not config._test_allow_inprocess
        ):
            raise GatewayStartupError(
                "in-process upstream is test-only; production must use "
                "from_stdio_command, from_http_url, or from_https_egress"
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
        if config.framing_mode is not FramingMode.CONTENT_LENGTH:
            raise GatewayStartupError(
                "from_stdio_command requires content-length framing"
            )
        upstream = StdioUpstream(
            command=list(command),
            credentials=credentials,
            max_message_bytes=config.max_message_bytes,
            max_json_depth=config.max_json_depth,
            framing_mode=FramingMode.CONTENT_LENGTH,
        )
        return cls(
            runtime,
            config=_harden_production_config(config),
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
        _require_https(url, config)
        if config.https_only and urlparse(url).scheme == "http":
            if not config.allow_insecure_http:
                raise GatewayStartupError(
                    "HTTPS-only: refusing http:// without allow_insecure_http"
                )
        upstream = HttpSseUpstream(
            url=url,
            credentials=credentials,
            max_message_bytes=config.max_message_bytes,
            max_json_depth=config.max_json_depth,
            tls_verify=config.tls_verify,
            timeout_s=config.upstream_timeout_s,
        )
        return cls(
            runtime,
            config=_harden_production_config(config),
            credentials=credentials,
            upstream=upstream,
            metrics=metrics,
        )

    @classmethod
    def from_https_egress(
        cls,
        runtime: ProductionRuntime | None,
        *,
        config: GatewayConfig,
        credentials: UpstreamCredentials,
        url: str,
        capability: str,
        metrics: GatewayMetrics | None = None,
    ) -> McpGateway:
        if runtime is None:
            raise GatewayStartupError(
                "refusing to start MCP gateway without a configured runtime"
            )
        if not url:
            raise GatewayStartupError("HTTPS egress URL is required")
        if not capability:
            raise GatewayStartupError("HTTPS egress requires a named capability")
        cfg = replace(
            config,
            transport="https-egress",
            https_egress_capability=capability,
        )
        _require_https(url, cfg)
        upstream = HttpsEgressUpstream(
            url=url,
            credentials=credentials,
            max_message_bytes=cfg.max_message_bytes,
            max_json_depth=cfg.max_json_depth,
            tls_verify=cfg.tls_verify,
            timeout_s=cfg.upstream_timeout_s,
        )
        return cls(
            runtime,
            config=_harden_production_config(cfg),
            credentials=credentials,
            upstream=upstream,
            metrics=metrics,
        )

    def dispatch_named_https(
        self, *, method: str, body: bytes, url: str | None = None
    ) -> HttpsEgressResult:
        """Production HTTPS-egress path: freeze/decide/verify against the named URL."""
        if self.config.transport != "https-egress":
            raise GatewayStartupError(
                "dispatch_named_https requires transport=https-egress"
            )
        if self.metrics.bypass_tripped and self.config.fail_closed_on_unattributed:
            raise GatewayStartupError(
                "unattributed upstream sessions reported; refusing new sessions"
            )
        named = getattr(self.upstream, "url", "")
        if not named:
            raise GatewayStartupError("https-egress upstream has no url")
        dest = url if url is not None else named
        if dest != named:
            raise GatewayStartupError(
                "https egress destination is the operator-named URL; "
                "callers cannot retarget"
            )
        capability = self.config.https_egress_capability
        if not capability:
            raise GatewayStartupError("HTTPS egress requires a named capability")
        session_id = new_session_id()
        self.upstream.bind_session(session_id)
        return dispatch_https_egress(
            middleware=self._middleware,
            upstream=self.upstream,
            credentials=self.credentials,
            agent_api_key=self.config.agent_api_key,
            session_id=session_id,
            client_identity=self.config.client_identity,
            capability=capability,
            method=method,
            url=named,
            body=body,
            max_same_origin_redirects=self.config.max_same_origin_redirects,
        )

    def open_session(self, *, client_identity: str | None = None) -> GatewayMediator:
        if self.metrics.bypass_tripped and self.config.fail_closed_on_unattributed:
            raise GatewayStartupError(
                "unattributed upstream sessions reported; refusing new sessions"
            )
        session = GatewaySession(
            session_id=new_session_id(),
            client_identity=client_identity or self.config.client_identity,
            upstream_identity=self.upstream.identity,
            transport=self.config.transport,
        )
        self.upstream.bind_session(session.session_id)
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
            max_json_depth=self.config.max_json_depth,
            fail_closed_on_unattributed=self.config.fail_closed_on_unattributed,
            undeclared_tool_policy=self.config.undeclared_tool_policy,
            max_same_origin_redirects=self.config.max_same_origin_redirects,
        )

    def ops_summary(self) -> dict[str, Any]:
        return {
            "gateway": True,
            "transport": self.config.transport,
            "framing_mode": self.config.framing_mode.value,
            "max_message_bytes": self.config.max_message_bytes,
            "max_json_depth": self.config.max_json_depth,
            "tls_verify": self.config.tls_verify,
            "https_only": self.config.https_only,
            "undeclared_tool_policy": self.config.undeclared_tool_policy,
            "fail_closed_on_unattributed": self.config.fail_closed_on_unattributed,
            "in_process": type(self.upstream) not in PRODUCTION_UPSTREAM_TYPES,
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
                "fail_closed": bool(self.metrics.bypass_tripped)
                and self.config.fail_closed_on_unattributed,
            },
        }
