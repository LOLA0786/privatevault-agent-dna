"""Adversarial tests for MCP gateway phase 2 — protocol reality."""

from __future__ import annotations

from typing import Any
from urllib.request import Request

import pytest

from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.gateway.errors import (
    CrossOriginRedirectError,
    FramingProtocolError,
    GatewayStartupError,
)
from agent_dna.gateway.framing import (
    MAX_JSON_DEPTH,
    MCP_DUPLICATE_ID,
    MCP_ENFORCEMENT_APPROVAL,
    MCP_ENFORCEMENT_DENIED,
    MCP_INDETERMINATE,
    MCP_SAMPLING_REFUSED,
    MCP_UNKNOWN_METHOD,
    MCP_UNMATCHED_ID,
    MCP_UPSTREAM_DEAD,
    encode_jsonrpc_message,
    freeze_tools_call_bytes,
    parse_jsonrpc,
)
from agent_dna.gateway.mediator import PendingDispatch
from agent_dna.gateway.metrics import GatewayMetrics
from agent_dna.gateway.protocol import MethodClass, classify_method
from agent_dna.gateway.runtime import GatewayConfig, McpGateway
from agent_dna.gateway.upstream import (
    RecordingUpstream,
    SameOriginRedirectHandler,
    origins_equal,
    read_bounded_http_body,
)
from tests.gateway.conftest import TOOL, make_gateway
from tests.gateway.test_mediation_adversarial import _tools_call


def _denied(result) -> None:
    err = result.client_message["error"]
    if err["code"] not in {MCP_ENFORCEMENT_DENIED, MCP_ENFORCEMENT_APPROVAL}:
        raise AssertionError(f"expected policy refusal, got {err}")


def test_classify_method_is_exact_membership_not_substring():
    if classify_method("sampling/createMessage") is not MethodClass.REFUSED:
        raise AssertionError("sampling/createMessage must be refused")
    if classify_method("sampling/createMessageX") is not MethodClass.UNKNOWN:
        raise AssertionError("suffix must not inherit sampling refusal")
    if classify_method("tools/call") is not MethodClass.GATED:
        raise AssertionError("tools/call must be gated")
    if classify_method("prompts/get") is not MethodClass.GATED:
        raise AssertionError("prompts/get must be gated")
    if classify_method("elicitation/create") is not MethodClass.UNKNOWN:
        raise AssertionError("unenumerated methods fail closed")


def _require_pending(prepared: object, label: str) -> PendingDispatch:
    if not isinstance(prepared, PendingDispatch):
        raise AssertionError(f"{label} must be ALLOW")
    return prepared


def _assert_own_bytes(
    writes: list[bytes],
    expected_a: bytes,
    digest_a: str,
    expected_b: bytes,
    digest_b: str,
) -> None:
    if writes != [expected_a, expected_b]:
        raise AssertionError("writes must be the frozen bytes of each ALLOW")
    if sha256_bytes_digest(writes[0]) != digest_a:
        raise AssertionError("id=1 witness must bind its own bytes")
    if sha256_bytes_digest(writes[1]) != digest_b:
        raise AssertionError("id=3 witness must bind its own bytes")


def test_interleaved_allow_and_deny_bind_own_bytes(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()

    deny = med.handle_message(_tools_call(request_id=2, name="other.tool"))
    _denied(deny)
    if deny.forwarded or upstream.writes:
        raise AssertionError("denied tools/call must never be forwarded")

    allow_a = {"note": "allow-a"}
    allow_b = {"note": "allow-b"}
    pending_a = _require_pending(
        med.prepare_tools_call(request_id=1, tool_name=TOOL, arguments=allow_a),
        "id=1",
    )
    pending_b = _require_pending(
        med.prepare_tools_call(request_id=3, tool_name=TOOL, arguments=allow_b),
        "id=3",
    )
    med.begin_pending(pending_a)
    med.begin_pending(pending_b)
    expected_a, digest_a = freeze_tools_call_bytes(
        request_id=1, tool_name=TOOL, arguments=allow_a, framed=True
    )
    expected_b, digest_b = freeze_tools_call_bytes(
        request_id=3, tool_name=TOOL, arguments=allow_b, framed=True
    )
    _assert_own_bytes(upstream.writes, expected_a, digest_a, expected_b, digest_b)

    upstream.queue_result(3, {"content": [{"type": "text", "text": "b"}]})
    upstream.queue_message(
        {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
    )
    upstream.queue_result(99, {"content": "never-sent-id"})
    upstream.queue_result(1, {"content": [{"type": "text", "text": "a"}]})

    result_a = med.complete_inflight(1)
    result_b = med.complete_inflight(3)
    if not result_a.forwarded or result_a.client_message.get("id") != 1:
        raise AssertionError("response id=1 must bind to decision 1")
    if not result_b.forwarded or result_b.client_message.get("id") != 3:
        raise AssertionError("response id=3 must bind to decision 3")
    if result_a.pending is None or result_a.pending.wire_digest != digest_a:
        raise AssertionError("completed id=1 must keep its own wire digest")
    if result_b.pending is None or result_b.pending.wire_digest != digest_b:
        raise AssertionError("completed id=3 must keep its own wire digest")
    if med.metrics.unmatched_responses < 1:
        raise AssertionError("id never sent must be rejected, not matched")


def test_duplicate_client_id_while_inflight_is_not_forwarded(
    allow_runtime, credentials
):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    pending = med.prepare_tools_call(
        request_id=1, tool_name=TOOL, arguments={"note": "first"}
    )
    if not isinstance(pending, PendingDispatch):
        raise AssertionError("expected ALLOW")
    med.begin_pending(pending)
    dup = med.handle_message(_tools_call(request_id=1, arguments={"note": "second"}))
    if dup.client_message["error"]["code"] != MCP_DUPLICATE_ID:
        raise AssertionError("duplicate in-flight id must be refused")
    if dup.forwarded:
        raise AssertionError("duplicate id must not forward a second call")
    if len(upstream.writes) != 1:
        raise AssertionError("duplicate id must not write a second request")


def test_duplicate_upstream_id_does_not_cross_bind(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    p1 = med.prepare_tools_call(request_id=1, tool_name=TOOL, arguments={"n": "one"})
    p2 = med.prepare_tools_call(request_id=2, tool_name=TOOL, arguments={"n": "two"})
    if not isinstance(p1, PendingDispatch) or not isinstance(p2, PendingDispatch):
        raise AssertionError("both calls must be ALLOW")
    med.begin_pending(p1)
    med.begin_pending(p2)
    upstream.queue_result(1, {"content": "first"})
    upstream.queue_result(1, {"content": "duplicate-for-other-decision"})
    first = med.complete_inflight(1)
    second = med.complete_inflight(2)
    if first.client_message.get("id") != 1:
        raise AssertionError("first response must complete id=1")
    if second.indeterminate is not True:
        raise AssertionError("duplicate upstream id must not complete the other call")
    if second.client_message["error"]["code"] != MCP_INDETERMINATE:
        raise AssertionError("unmatched sibling must be indeterminate, not ok")
    outcomes = list(rt.recorder.graph._executions.values())  # noqa: SLF001
    two = next(ev for ev in outcomes if ev.decision_ref == p2.decision_id)
    if two.status == "ok":
        raise AssertionError("id=2 must not be sealed ok from a duplicate id=1")


def test_sampling_create_message_from_client_is_refused(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    result = med.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "sampling/createMessage",
            "params": {"messages": [{"role": "user", "content": "pwn"}]},
        }
    )
    if result.forwarded:
        raise AssertionError("sampling/createMessage must not be forwarded")
    if result.client_message["error"]["code"] != MCP_SAMPLING_REFUSED:
        raise AssertionError("sampling/createMessage must be explicitly refused")
    if upstream.writes:
        raise AssertionError("refused sampling must not reach upstream")
    kinds = [f["kind"] for f in med.session.findings]
    if "sampling_refused" not in kinds:
        raise AssertionError("refusal must be recorded")


def test_server_initiated_sampling_mid_call_is_not_a_response(
    allow_runtime, credentials
):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    pending = med.prepare_tools_call(
        request_id=1, tool_name=TOOL, arguments={"note": "mid"}
    )
    if not isinstance(pending, PendingDispatch):
        raise AssertionError("expected ALLOW")
    med.begin_pending(pending)
    upstream.queue_message(
        {
            "jsonrpc": "2.0",
            "id": 77,
            "method": "sampling/createMessage",
            "params": {"messages": []},
        }
    )
    upstream.queue_result(1, {"content": [{"type": "text", "text": "ok"}]})
    result = med.complete_inflight(1)
    if result.client_message.get("id") != 1:
        raise AssertionError("sampling request must not replace the tools/call result")
    if result.client_message.get("method") == "sampling/createMessage":
        raise AssertionError("sampling must not be forwarded to the client")
    kinds = [f["kind"] for f in med.session.findings]
    if "sampling_refused" not in kinds:
        raise AssertionError("server-initiated sampling must be recorded as refused")
    if len(upstream.writes) < 2:
        raise AssertionError("gateway must error the sampling request back upstream")


def test_unknown_method_fails_closed_and_records_name(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    result = med.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "elicitation/create",
            "params": {},
        }
    )
    if result.forwarded or upstream.writes:
        raise AssertionError("unknown method must not be forwarded")
    err = result.client_message["error"]
    if err["code"] != MCP_UNKNOWN_METHOD:
        raise AssertionError("unknown method must fail closed")
    if err["data"]["method"] != "elicitation/create":
        raise AssertionError("recorded method name must be exact")


def test_prompts_get_is_gated_not_passthrough(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    result = med.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "prompts/get",
            "params": {"name": "welcome"},
        }
    )
    if result.forwarded or upstream.writes:
        raise AssertionError("prompts/get must be gated through decide")
    err = result.client_message["error"]
    if err["code"] not in {MCP_ENFORCEMENT_DENIED, MCP_ENFORCEMENT_APPROVAL}:
        raise AssertionError("ungranted prompts/get must not be forwarded")


def test_resources_read_and_subscribe_are_gated(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    for method in ("resources/read", "resources/subscribe"):
        result = med.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": method,
                "params": {"uri": "file:///etc/passwd"},
            }
        )
        _denied(result)
        if result.forwarded:
            raise AssertionError(f"{method} must be gated through decide")
    if upstream.writes:
        raise AssertionError("denied resource methods must not be forwarded")


def test_initialize_records_capabilities_and_undeclared_tools_are_findings(
    allow_runtime, credentials
):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    upstream.queue_result(
        1,
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "sampling": {}},
            "serverInfo": {"name": "mock", "version": "0"},
            "tools": [{"name": TOOL}],
        },
    )
    init = med.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
        }
    )
    if not init.forwarded:
        raise AssertionError("initialize is passthrough")
    if med.session.initialize_capabilities is None:
        raise AssertionError("initialize capabilities must be recorded")
    if "sampling" not in med.session.initialize_capabilities:
        raise AssertionError("declared sampling capability must be recorded")
    if med.session.declared_tool_names != frozenset({TOOL}):
        raise AssertionError("initialize tool names must be recorded")

    upstream.queue_result(
        2,
        {"tools": [{"name": TOOL}, {"name": "evil.undeclared"}]},
    )
    listed = med.handle_message(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    )
    if not listed.forwarded:
        raise AssertionError("tools/list is passthrough")
    extras = [f for f in med.session.findings if f["kind"] == "undeclared_tools"]
    if not extras:
        raise AssertionError("tools not declared at initialize must be a finding")


def test_oversized_upstream_response_is_not_success(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    gw = McpGateway(
        rt,
        config=GatewayConfig(
            agent_api_key=key,
            client_identity="gateway-agent@test",
            transport="stdio",
            upstream_timeout_s=0.2,
            framed=True,
            max_message_bytes=512,
            _test_allow_inprocess=True,
        ),
        credentials=credentials,
        upstream=upstream,
        metrics=GatewayMetrics(),
    )
    med = gw.open_session()
    upstream.queue_result(1, {"blob": "x" * 4000})
    result = med.handle_message(_tools_call(request_id=1))
    if result.client_message.get("result") is not None:
        raise AssertionError("oversized upstream body must not succeed")
    if result.client_message["error"]["code"] != MCP_INDETERMINATE:
        raise AssertionError("oversized upstream body must be indeterminate")
    outcomes = list(rt.recorder.graph._executions.values())  # noqa: SLF001
    if any(ev.status == "ok" for ev in outcomes):
        raise AssertionError("oversized response must not seal ok")


def test_deeply_nested_upstream_json_is_rejected(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    gw = McpGateway(
        rt,
        config=GatewayConfig(
            agent_api_key=key,
            client_identity="gateway-agent@test",
            transport="stdio",
            upstream_timeout_s=0.2,
            framed=True,
            max_json_depth=8,
            _test_allow_inprocess=True,
        ),
        credentials=credentials,
        upstream=upstream,
        metrics=GatewayMetrics(),
    )
    med = gw.open_session()
    nested: Any = "leaf"
    for _ in range(20):
        nested = {"n": nested}
    upstream.queue_result(1, nested)
    result = med.handle_message(_tools_call(request_id=1))
    if result.client_message["error"]["code"] != MCP_INDETERMINATE:
        raise AssertionError("deep JSON must not bind as a success")
    if any(
        ev.status == "ok"
        for ev in rt.recorder.graph._executions.values()  # noqa: SLF001
    ):
        raise AssertionError("deep JSON must not seal ok")


def test_upstream_death_does_not_false_complete(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    pending = med.prepare_tools_call(
        request_id=1, tool_name=TOOL, arguments={"note": "die"}
    )
    if not isinstance(pending, PendingDispatch):
        raise AssertionError("expected ALLOW")
    med.begin_pending(pending)
    upstream.die()
    result = med.complete_inflight(1)
    if result.client_message["error"]["code"] != MCP_UPSTREAM_DEAD:
        raise AssertionError("upstream death must be a defined failure")
    if result.indeterminate is not True:
        raise AssertionError("in-flight call on death is indeterminate")
    outcomes = list(rt.recorder.graph._executions.values())  # noqa: SLF001
    if any(ev.status == "ok" for ev in outcomes):
        raise AssertionError("upstream death must not seal ok")
    if not any(ev.status == "indeterminate" for ev in outcomes):
        raise AssertionError("consumed permit must record first-class indeterminate")


def test_upstream_restart_is_a_new_principal(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    bound = med.session.upstream_identity
    upstream.restart()
    if upstream.identity == bound:
        raise AssertionError("restart must change upstream identity")
    result = med.handle_message(_tools_call(request_id=1))
    if result.client_message["error"]["code"] != MCP_UPSTREAM_DEAD:
        raise AssertionError("old session must not carry over to the new process")
    if result.forwarded:
        raise AssertionError("restarted principal must not inherit the session")


def test_graceful_shutdown_with_inflight_is_indeterminate(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    pending = med.prepare_tools_call(
        request_id=1, tool_name=TOOL, arguments={"note": "shutdown"}
    )
    if not isinstance(pending, PendingDispatch):
        raise AssertionError("expected ALLOW")
    med.begin_pending(pending)
    med.shutdown()
    outcomes = list(rt.recorder.graph._executions.values())  # noqa: SLF001
    if not outcomes:
        raise AssertionError("shutdown must record in-flight outcomes")
    if any(ev.status == "ok" for ev in outcomes):
        raise AssertionError("shutdown must not false-complete")
    if not any("shutdown" in ev.detail for ev in outcomes):
        raise AssertionError("shutdown reason must be in the outcome")


def test_client_reconnect_does_not_resume_another_session(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    gw = make_gateway(rt, key, credentials, upstream)
    first = gw.open_session()
    second = gw.open_session()
    if first.session.session_id == second.session.session_id:
        raise AssertionError("reconnect must mint a new session id")
    pending = first.prepare_tools_call(
        request_id=1, tool_name=TOOL, arguments={"note": "s1"}
    )
    if not isinstance(pending, PendingDispatch):
        raise AssertionError("expected ALLOW")
    first.begin_pending(pending)
    stolen = second.complete_inflight(1)
    if stolen.client_message["error"]["code"] != MCP_UNMATCHED_ID:
        raise AssertionError("new session must not complete the prior session's id")
    if 1 in second._inflight or "1" in second._inflight:  # noqa: SLF001
        raise AssertionError("new session must start with empty in-flight map")


def test_tls_verify_off_refuses_start_without_operator_flag(credentials):
    with pytest.raises(GatewayStartupError, match="allow_insecure_tls"):
        McpGateway(
            None,
            config=GatewayConfig(
                agent_api_key="pv_x",
                client_identity="x",
                transport="http+sse",
                tls_verify=False,
            ),
            credentials=credentials,
            upstream=RecordingUpstream(),
        )


def test_tls_insecure_requires_explicit_operator_flag_then_runtime(
    credentials,
):
    with pytest.raises(GatewayStartupError, match="without a configured runtime"):
        McpGateway(
            None,
            config=GatewayConfig(
                agent_api_key="pv_x",
                client_identity="x",
                transport="http+sse",
                tls_verify=False,
                allow_insecure_tls=True,
            ),
            credentials=credentials,
            upstream=RecordingUpstream(),
        )


def test_cross_origin_redirect_is_refused():
    if origins_equal("https://vault.example/mcp", "https://evil.example/mcp"):
        raise AssertionError("different hosts are not the same origin")
    if not origins_equal(
        "https://vault.example/mcp", "https://vault.example:443/other"
    ):
        raise AssertionError("default https port must compare equal")
    handler = SameOriginRedirectHandler()
    req = Request("https://vault.example/mcp")
    with pytest.raises(CrossOriginRedirectError):
        handler.redirect_request(
            req, None, 302, "Found", {}, "https://evil.example/mcp"
        )


def test_never_ending_sse_stream_hits_byte_bound():
    class _Endless:
        def read(self, size: int = -1) -> bytes:
            n = 64 if size <= 0 else size
            return b"x" * n

    with pytest.raises(FramingProtocolError, match="exceeds max_message_bytes"):
        read_bounded_http_body(_Endless(), max_bytes=256)


def test_parse_jsonrpc_depth_cap_matches_constant():
    nested: Any = 0
    for _ in range(MAX_JSON_DEPTH + 5):
        nested = {"n": nested}
    raw = encode_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "result": nested})
    with pytest.raises(FramingProtocolError, match="max depth"):
        parse_jsonrpc(raw)


def test_unmatched_response_id_never_sent_is_rejected(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    pending = med.prepare_tools_call(
        request_id=1, tool_name=TOOL, arguments={"note": "u"}
    )
    if not isinstance(pending, PendingDispatch):
        raise AssertionError("expected ALLOW")
    med.begin_pending(pending)
    upstream.queue_result(99, {"content": "nope"})
    upstream.queue_result(1, {"content": "ok"})
    result = med.complete_inflight(1)
    if result.client_message.get("id") != 1:
        raise AssertionError("unmatched id must not steal the correlated result")
    if med.metrics.unmatched_responses < 1:
        raise AssertionError("id never sent must increment unmatched")
    findings = [f["kind"] for f in med.session.findings]
    if "unmatched_response_id" not in findings:
        raise AssertionError("unmatched id must be recorded")
