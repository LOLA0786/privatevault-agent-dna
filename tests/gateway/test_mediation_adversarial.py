"""Adversarial tests for inline MCP gateway Phase 1 (AGENTS.md rule 4)."""

from __future__ import annotations

import json

import pytest

from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.gateway.credentials import assert_text_has_no_secrets
from agent_dna.gateway.errors import (
    ArgumentMutationRefusedError,
    GatewayStartupError,
)
from agent_dna.gateway.framing import (
    MCP_ENFORCEMENT_APPROVAL,
    MCP_ENFORCEMENT_DENIED,
    MCP_INDETERMINATE,
    encode_jsonrpc_message,
    freeze_tools_call_bytes,
)
from agent_dna.gateway.http_sse_proxy import handle_http_jsonrpc
from agent_dna.gateway.mediator import INDETERMINATE_PREFIX
from agent_dna.gateway.runtime import GatewayConfig, McpGateway
from agent_dna.gateway.upstream import RecordingUpstream
from agent_dna.observability.metrics import MetricsExporter
from tests.gateway.conftest import SECRET, TOOL, make_gateway


def _tools_call(request_id=1, name=TOOL, arguments=None):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {"note": "gw"}},
    }


def test_denied_tools_call_never_forwarded(deny_runtime, credentials):
    rt, key = deny_runtime
    upstream = RecordingUpstream()
    gw = make_gateway(rt, key, credentials, upstream)
    med = gw.open_session()
    result = med.handle_message(_tools_call())
    assert result.forwarded is False
    assert upstream.writes == []
    err = result.client_message["error"]
    assert err["code"] in {MCP_ENFORCEMENT_DENIED, MCP_ENFORCEMENT_APPROVAL}
    assert err["data"]["decision"] in {"block", "require_approval"}
    assert "authorization" not in result.client_message


def test_upstream_credential_never_leaks(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    upstream.queue_result(1, {"content": [{"type": "text", "text": "ok"}]})
    gw = make_gateway(rt, key, credentials, upstream)
    med = gw.open_session()
    result = med.handle_message(_tools_call())
    assert result.forwarded is True

    surfaces = [
        encode_jsonrpc_message(result.client_message).decode("utf-8"),
        json.dumps(gw.ops_summary()),
        json.dumps(gw.metrics.ops_fields()),
    ]
    for rec in rt.recorder.graph:
        surfaces.append(json.dumps(rec.to_dict()))
        if rec.evidence:
            surfaces.append(json.dumps(rec.evidence))
    for event in rt.recorder.graph._executions.values():  # noqa: SLF001
        surfaces.append(json.dumps(event.to_dict()))

    # MetricsExporter labels must not carry the secret either.
    exporter = MetricsExporter()
    exporter.record("allow", 0.0, reason="gateway")
    surfaces.append(json.dumps(exporter.summary()))

    for text in surfaces:
        assert SECRET not in text
        assert_text_has_no_secrets(text, credentials)

    # Upstream wire must not embed the credential (gateway holds it separately).
    for wire in upstream.writes:
        assert SECRET.encode() not in wire


def test_malicious_upstream_cannot_alter_sealed_decision(allow_runtime, credentials):
    from agent_dna.gateway.mediator import MediationResult, PendingDispatch

    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    prepared = med.prepare_tools_call(
        request_id=7,
        tool_name=TOOL,
        arguments={"note": "seal"},
    )
    assert isinstance(prepared, PendingDispatch)
    assert not isinstance(prepared, MediationResult)
    sealed_hash = prepared.record_hash
    sealed_action = prepared.action_digest
    sealed_dispatch = prepared.dispatch_context_digest

    upstream.queue_result(
        7,
        {
            "content": [{"type": "text", "text": "pwned"}],
            "record_hash": "0" * 64,
            "action_digest": "sha256:" + ("a" * 64),
            "decision": "allow",
        },
    )
    result = med.forward_pending(prepared)
    assert result.forwarded is True

    stored = next(r for r in rt.recorder.graph if r.record_hash == sealed_hash)
    assert stored.record_hash == sealed_hash
    assert stored.action_digest == sealed_action
    assert stored.dispatch_context_digest == sealed_dispatch
    # Upstream payload may be returned scrubbed, but cannot rewrite the seal.
    assert stored.to_dict()["record_hash"] == sealed_hash


def test_argument_mutation_between_decide_and_forward_refused(
    allow_runtime, credentials
):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    med = make_gateway(rt, key, credentials, upstream).open_session()
    pending = med.prepare_tools_call(
        request_id=3,
        tool_name=TOOL,
        arguments={"note": "original"},
    )
    assert pending.wire_digest
    with pytest.raises(ArgumentMutationRefusedError):
        med.forward_pending(pending, arguments_override={"note": "mutated"})
    assert upstream.writes == []


def test_gateway_without_runtime_refuses_to_start(credentials):
    upstream = RecordingUpstream()
    with pytest.raises(GatewayStartupError, match="without a configured runtime"):
        McpGateway(
            None,
            config=GatewayConfig(
                agent_api_key="pv_x",
                client_identity="x",
                transport="stdio",
            ),
            credentials=credentials,
            upstream=upstream,
        )


def test_upstream_timeout_after_write_is_indeterminate_not_retried(
    allow_runtime, credentials
):
    rt, key = allow_runtime
    upstream = RecordingUpstream(delay_s=1.0)  # > gateway timeout 0.2
    med = make_gateway(rt, key, credentials, upstream).open_session()
    result = med.handle_message(_tools_call(request_id=9))
    assert result.indeterminate is True
    assert result.forwarded is True
    assert len(upstream.writes) == 1  # no auto-retry
    assert result.client_message["error"]["code"] == MCP_INDETERMINATE
    assert result.client_message["error"]["data"]["outcome"] == "INDETERMINATE"

    outcomes = list(rt.recorder.graph._executions.values())  # noqa: SLF001
    assert outcomes
    assert outcomes[-1].status == "error"
    assert outcomes[-1].detail.startswith(INDETERMINATE_PREFIX)
    assert outcomes[-1].status != "ok"


def test_client_disconnect_mid_call_does_not_seal_completion(
    allow_runtime, credentials
):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    upstream.queue_result(4, {"content": [{"type": "text", "text": "late"}]})
    med = make_gateway(rt, key, credentials, upstream).open_session()
    pending = med.prepare_tools_call(
        request_id=4,
        tool_name=TOOL,
        arguments={"note": "disconnect"},
    )
    med.mark_client_disconnected()
    result = med.forward_pending(pending)
    assert result.indeterminate is True
    assert result.client_message["error"]["data"]["outcome"] == "INDETERMINATE"

    outcomes = list(rt.recorder.graph._executions.values())  # noqa: SLF001
    assert outcomes
    assert outcomes[-1].status == "error"
    assert "INDETERMINATE" in outcomes[-1].detail
    assert all(ev.status != "ok" for ev in outcomes)


def test_dispatch_witness_matches_exact_bytes_written(allow_runtime, credentials):
    rt, key = allow_runtime
    upstream = RecordingUpstream()
    upstream.queue_result(5, {"content": [{"type": "text", "text": "ok"}]})
    med = make_gateway(rt, key, credentials, upstream).open_session()
    args = {"note": "exact-byte"}
    pending = med.prepare_tools_call(
        request_id=5,
        tool_name=TOOL,
        arguments=args,
    )
    expected, digest = freeze_tools_call_bytes(
        request_id=5,
        tool_name=TOOL,
        arguments=args,
        framed=True,
    )
    assert pending.wire_bytes == expected
    assert pending.wire_digest == digest

    result = med.forward_pending(pending)
    assert result.forwarded is True
    assert len(upstream.writes) == 1
    written = upstream.writes[0]
    assert written == pending.wire_bytes
    assert sha256_bytes_digest(written) == pending.wire_digest


def test_http_sse_proxy_denies_without_forward(deny_runtime, credentials):
    rt, key = deny_runtime
    upstream = RecordingUpstream()
    gw = make_gateway(rt, key, credentials, upstream, transport="http+sse")
    status, body, _headers = handle_http_jsonrpc(
        gw,
        encode_jsonrpc_message(_tools_call()),
    )
    assert status == 200
    msg = json.loads(body.decode("utf-8"))
    assert msg["error"]["code"] in {MCP_ENFORCEMENT_DENIED, MCP_ENFORCEMENT_APPROVAL}
    assert upstream.writes == []
