"""Bake-off hardening: monopoly, HTTPS, catalog, witness, out-of-process, egress."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.gateway.errors import (
    FramingProtocolError,
    GatewayStartupError,
    SameOriginRedirectError,
)
from agent_dna.gateway.framing import (
    MCP_BYPASS_DETECTED,
    MCP_UNDECLARED_TOOL,
    encode_jsonrpc_message,
)
from agent_dna.gateway.https_egress import (
    HttpsEgressUpstream,
    dispatch_https_egress,
    freeze_https_egress,
    parse_https_egress_wire,
)
from agent_dna.gateway.runtime import GatewayConfig, McpGateway
from agent_dna.gateway.session import new_session_id
from agent_dna.gateway.upstream import RecordingUpstream
from tests.gateway.conftest import TOOL, make_gateway
from tests.gateway.test_mediation_adversarial import _tools_call


@dataclass
class _FakeHttpsEgress:
    identity: str = "https-egress://test"
    writes: list[bytes] = field(default_factory=list)
    last_body: bytes = b'{"ok":true}'
    session_id: str = ""

    def bind_session(self, session_id: str) -> None:
        self.session_id = session_id

    def write(self, wire_bytes: bytes) -> None:
        self.writes.append(wire_bytes)

    def close(self) -> None:
        return None


def test_unattributed_sessions_fail_closed_not_forwarded(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    gw = make_gateway(rt, key, credentials, upstream)
    gw.metrics.note_upstream_unattributed(1)
    with pytest.raises(GatewayStartupError, match="unattributed"):
        gw.open_session()
    # Existing session opened before the trip still fail-closes on the next call.
    gw2 = make_gateway(rt, key, credentials, RecordingUpstream())
    med = gw2.open_session()
    gw2.metrics.note_upstream_unattributed(1)
    result = med.handle_message(_tools_call())
    if result.forwarded:
        raise AssertionError("bypass signal must fail closed")
    if result.client_message["error"]["code"] != MCP_BYPASS_DETECTED:
        raise AssertionError("bypass must use MCP_BYPASS_DETECTED")


def test_session_attribution_is_applied_and_is_not_the_secret(
    allow_runtime, credentials
):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    upstream.queue_result(1, {"content": [{"type": "text", "text": "ok"}]})
    med = make_gateway(rt, key, credentials, upstream).open_session()
    result = med.handle_message(_tools_call())
    if not result.forwarded:
        raise AssertionError("attributed allow must still forward")
    if not upstream.attributions or upstream.attributions[0] != med.session.session_id:
        raise AssertionError("upstream write must carry gateway session attribution")
    if med.session.session_id in credentials.secret_values():
        raise AssertionError("session id must not be an upstream secret")


def test_inprocess_upstream_refused_without_test_flag(allow_runtime, credentials):
    rt, key = allow_runtime
    with pytest.raises(GatewayStartupError, match="in-process upstream is test-only"):
        McpGateway(
            rt,
            config=GatewayConfig(
                agent_api_key=key,
                client_identity="x",
                transport="stdio",
            ),
            credentials=credentials,
            upstream=RecordingUpstream(),
        )


def test_https_only_refuses_http_url_without_operator_flag(allow_runtime, credentials):
    rt, key = allow_runtime
    with pytest.raises(GatewayStartupError, match="HTTPS-only"):
        McpGateway.from_http_url(
            rt,
            config=GatewayConfig(
                agent_api_key=key,
                client_identity="x",
                transport="http+sse",
            ),
            credentials=credentials,
            url="http://mcp.example/mcp",
        )


def test_same_origin_redirect_is_redecided_not_followed_silently(
    allow_runtime, credentials
):
    rt, key = allow_runtime
    upstream = RecordingUpstream(redirect_once_to="https://vault.example/mcp-b")
    upstream.queue_result(1, {"content": [{"type": "text", "text": "ok"}]})
    med = make_gateway(rt, key, credentials, upstream).open_session()
    result = med.handle_message(_tools_call(request_id=1))
    if not result.forwarded:
        raise AssertionError("re-decided same-origin hop must be allowed to complete")
    if len(upstream.writes) != 1:
        raise AssertionError(
            "redirect is not followed until re-decide; one successful write"
        )
    outcomes = list(rt.recorder.graph._executions.values())  # noqa: SLF001
    statuses = {ev.status for ev in outcomes}
    if "indeterminate" not in statuses:
        raise AssertionError(
            "original destination must be indeterminate, not silent ok"
        )
    if "ok" not in statuses:
        raise AssertionError("re-decided hop may complete ok")


def test_hardened_profile_blocks_undeclared_tools(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(
        rt, key, credentials, upstream, undeclared_tool_policy="block"
    ).open_session()
    result = med.handle_message(_tools_call())
    if result.forwarded or upstream.writes:
        raise AssertionError("no catalog yet: hardened profile must not forward")
    if result.client_message["error"]["code"] != MCP_UNDECLARED_TOOL:
        raise AssertionError("undeclared tool must be BLOCK, not a finding-only")


def test_response_digest_is_bound_to_the_same_decision(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    upstream.queue_result(1, {"content": [{"type": "text", "text": "ok"}]})
    med = make_gateway(rt, key, credentials, upstream).open_session()
    result = med.handle_message(_tools_call())
    if not result.forwarded or not result.response_digest:
        raise AssertionError("allowed call must witness response bytes")
    expected = sha256_bytes_digest(encode_jsonrpc_message(result.client_message))
    if result.response_digest != expected:
        raise AssertionError(
            "witness must be the digest of bytes returned to the client"
        )
    outcomes = list(rt.recorder.graph._executions.values())  # noqa: SLF001
    if not outcomes or outcomes[-1].response_digest != expected:
        raise AssertionError("execution event must carry the same response digest")
    if outcomes[-1].status != "ok":
        raise AssertionError("witnessed completion is ok, not inferred")


def test_https_egress_freeze_decide_verify(allow_runtime, credentials):
    rt, key = allow_runtime
    body = b'{"ping":true}'
    url = "https://saas.example/v1/act"
    wire, digest = freeze_https_egress(method="POST", url=url, body=body)
    if sha256_bytes_digest(wire) != digest:
        raise AssertionError("https egress digest must cover exact bytes")
    upstream = _FakeHttpsEgress()
    out = dispatch_https_egress(
        middleware=rt.middleware(),
        upstream=upstream,
        credentials=credentials,
        agent_api_key=key,
        session_id=new_session_id(),
        client_identity="gateway-agent@test",
        capability=TOOL,
        method="POST",
        url=url,
        body=body,
    )
    if not out.forwarded:
        raise AssertionError("granted https egress must forward frozen bytes")
    if upstream.writes != [wire]:
        raise AssertionError("only frozen bytes may be written")
    if out.response_digest != sha256_bytes_digest(upstream.last_body):
        raise AssertionError("https egress must witness the response body")
    if out.wire_digest != digest:
        raise AssertionError("request witness must match freeze")


def test_https_egress_deny_never_forwards(deny_runtime, credentials):
    rt, key = deny_runtime
    upstream = _FakeHttpsEgress()
    out = dispatch_https_egress(
        middleware=rt.middleware(),
        upstream=upstream,
        credentials=credentials,
        agent_api_key=key,
        session_id=new_session_id(),
        client_identity="gateway-agent@test",
        capability=TOOL,
        method="POST",
        url="https://saas.example/v1/act",
        body=b"{}",
    )
    if out.forwarded or upstream.writes:
        raise AssertionError("denied https egress must not hit the network")
    if out.status != "refused":
        raise AssertionError("denied egress is refused, not ok")


def test_freeze_https_egress_refuses_http() -> None:
    with pytest.raises(FramingProtocolError, match="https://"):
        freeze_https_egress(method="POST", url="http://saas.example/x", body=b"{}")


def test_https_egress_write_refuses_destination_swap(credentials) -> None:
    up = HttpsEgressUpstream(url="https://saas.example/v1/act", credentials=credentials)
    wire, _ = freeze_https_egress(
        method="POST", url="https://evil.example/x", body=b"{}"
    )
    with pytest.raises(FramingProtocolError, match="sealed destination"):
        up.write(wire)
    if up.writes:
        raise AssertionError("mismatched destination must not be written")


def test_https_egress_write_uses_frozen_method(credentials) -> None:
    up = HttpsEgressUpstream(url="https://saas.example/v1/act", credentials=credentials)
    captured: dict[str, str] = {}

    class _Resp:
        status = 200
        _sent = False

        def read(self, n: int) -> bytes:
            del n
            if self._sent:
                return b""
            self._sent = True
            return b'{"ok":true}'

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *args: object) -> bool:
            del args
            return False

    def fake_open(req: Any, timeout: float | None = None) -> _Resp:
        del timeout
        captured["method"] = str(req.get_method())
        captured["url"] = str(req.get_full_url())
        return _Resp()

    up._opener.open = fake_open  # noqa: SLF001
    wire, _ = freeze_https_egress(method="PUT", url=up.url, body=b"x")
    parsed = parse_https_egress_wire(wire)
    if parsed != ("PUT", up.url, b"x"):
        raise AssertionError("wire parse must invert freeze")
    up.write(wire)
    if captured.get("method") != "PUT":
        raise AssertionError("write must use the frozen method, not always POST")
    if captured.get("url") != up.url:
        raise AssertionError("write must hit the sealed URL")


def test_https_egress_same_origin_redirect_is_redecided(
    allow_runtime, credentials
) -> None:
    rt, key = allow_runtime

    @dataclass
    class _RedirectOnceHttps:
        url: str = "https://saas.example/v1/act"
        identity: str = "https-egress://test"
        writes: list[bytes] = field(default_factory=list)
        last_body: bytes = b'{"ok":true}'
        session_id: str = ""
        _redirected: bool = False

        def bind_session(self, session_id: str) -> None:
            self.session_id = session_id

        def write(self, wire_bytes: bytes) -> None:
            self.writes.append(wire_bytes)
            if not self._redirected:
                self._redirected = True
                raise SameOriginRedirectError("https://saas.example/v1/act-b")

    upstream = _RedirectOnceHttps()
    out = dispatch_https_egress(
        middleware=rt.middleware(),
        upstream=upstream,
        credentials=credentials,
        agent_api_key=key,
        session_id=new_session_id(),
        client_identity="gateway-agent@test",
        capability=TOOL,
        method="POST",
        url="https://saas.example/v1/act",
        body=b"{}",
    )
    if not out.forwarded:
        raise AssertionError("re-decided same-origin https hop must complete")
    if len(upstream.writes) != 2:
        raise AssertionError("original hop plus one re-decided write")
    statuses = {ev.status for ev in rt.recorder.graph._executions.values()}  # noqa: SLF001
    if "indeterminate" not in statuses:
        raise AssertionError("original https destination must be indeterminate")
    if "ok" not in statuses:
        raise AssertionError("re-decided https hop may complete ok")
    method, dest, _body = parse_https_egress_wire(upstream.writes[1])
    if method != "POST" or dest != "https://saas.example/v1/act-b":
        raise AssertionError("second write must be frozen against the new location")


def test_production_constructors_force_undeclared_block(
    allow_runtime, credentials
) -> None:
    rt, key = allow_runtime
    gw = McpGateway.from_http_url(
        rt,
        config=GatewayConfig(
            agent_api_key=key,
            client_identity="x",
            transport="http+sse",
            undeclared_tool_policy="finding",
        ),
        credentials=credentials,
        url="https://mcp.example/mcp",
    )
    if gw.config.undeclared_tool_policy != "block":
        raise AssertionError(
            "production constructors force undeclared_tool_policy=block"
        )


def test_https_egress_requires_named_capability(allow_runtime, credentials) -> None:
    rt, key = allow_runtime
    with pytest.raises(GatewayStartupError, match="named capability"):
        McpGateway.from_https_egress(
            rt,
            config=GatewayConfig(
                agent_api_key=key,
                client_identity="x",
                transport="https-egress",
            ),
            credentials=credentials,
            url="https://saas.example/v1/act",
            capability="",
        )


def test_cli_https_egress_requires_capability() -> None:
    from agent_dna.gateway.__main__ import main

    rc = main(
        [
            "--agent-key",
            "k",
            "--https-egress",
            "https://saas.example/v1",
        ]
    )
    if rc != 2:
        raise AssertionError("CLI must refuse https-egress without a capability")
