"""Tool-call mediation: decide → freeze bytes → forward → outcome."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from agent_dna.connector.middleware import ConnectorMiddleware
from agent_dna.connector.models import ToolCallRequest
from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.gateway.credentials import (
    UpstreamCredentials,
    assert_text_has_no_secrets,
    scrub_mapping,
)
from agent_dna.gateway.errors import (
    ArgumentMutationRefusedError,
    ClientDisconnectedError,
    CrossOriginRedirectError,
    DuplicateRequestIdError,
    FramingProtocolError,
    SameOriginRedirectError,
    UpstreamDeadError,
    UpstreamPrincipalChangedError,
    UpstreamTimeoutError,
)
from agent_dna.gateway.framing import (
    DEFAULT_MAX_MESSAGE_BYTES,
    MAX_JSON_DEPTH,
    MCP_BYPASS_DETECTED,
    MCP_DUPLICATE_ID,
    MCP_ENFORCEMENT_APPROVAL,
    MCP_ENFORCEMENT_DENIED,
    MCP_GATEWAY_FAULT,
    MCP_INDETERMINATE,
    MCP_REDIRECT_REFUSED,
    MCP_SAMPLING_REFUSED,
    MCP_UNDECLARED_TOOL,
    MCP_UNKNOWN_METHOD,
    MCP_UNMATCHED_ID,
    MCP_UPSTREAM_DEAD,
    build_prompts_get_message,
    build_resource_message,
    encode_jsonrpc_message,
    frame_stdio,
    freeze_jsonrpc_bytes,
    freeze_tools_call_bytes,
    mcp_error_response,
    parse_jsonrpc,
)
from agent_dna.gateway.metrics import GatewayMetrics
from agent_dna.gateway.protocol import (
    MethodClass,
    classify_method,
    is_jsonrpc_request,
    is_jsonrpc_response,
    jsonrpc_id_key,
    tool_names_from_list_result,
)
from agent_dna.gateway.session import GatewaySession
from agent_dna.gateway.upstream import UpstreamTransport

INDETERMINATE_PREFIX = "INDETERMINATE:"
ADAPTER_NAME = "mcp-gateway"
RESOURCE_METHODS = frozenset({"resources/read", "resources/subscribe"})
PROMPT_METHODS = frozenset({"prompts/get"})


@dataclass(frozen=True)
class PendingDispatch:
    """Frozen post-decide dispatch state. Only ``wire_bytes`` may be written."""

    decision_id: str
    record_hash: str
    tool_name: str
    arguments: dict[str, Any]
    request_id: Any
    wire_bytes: bytes
    wire_digest: str
    action_digest: str
    dispatch_context_digest: str
    method: str = "tools/call"


@dataclass
class MediationResult:
    client_message: dict[str, Any]
    pending: PendingDispatch | None = None
    forwarded: bool = False
    indeterminate: bool = False
    response_digest: str = ""


class GatewayMediator:
    """Complete mediation for one gateway session."""

    def __init__(
        self,
        *,
        middleware: ConnectorMiddleware,
        upstream: UpstreamTransport,
        credentials: UpstreamCredentials,
        session: GatewaySession,
        metrics: GatewayMetrics,
        agent_api_key: str,
        upstream_timeout_s: float = 5.0,
        framed: bool = True,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        max_json_depth: int = MAX_JSON_DEPTH,
        fail_closed_on_unattributed: bool = True,
        undeclared_tool_policy: str = "finding",
        max_same_origin_redirects: int = 1,
    ) -> None:
        self.middleware = middleware
        self.upstream = upstream
        self.credentials = credentials
        self.session = session
        self.metrics = metrics
        self.agent_api_key = agent_api_key
        self.upstream_timeout_s = upstream_timeout_s
        self.framed = framed
        self.max_message_bytes = max_message_bytes
        self.max_json_depth = max_json_depth
        self.fail_closed_on_unattributed = fail_closed_on_unattributed
        self.undeclared_tool_policy = undeclared_tool_policy
        self.max_same_origin_redirects = max_same_origin_redirects
        self.metrics.note_session(session.session_id)
        self._client_connected = True
        self._inflight: dict[str, PendingDispatch] = {}
        self._pending_responses: dict[str, dict[str, Any]] = {}
        self._bound_upstream_identity = session.upstream_identity
        self._redirects_used = 0
        bind = getattr(self.upstream, "bind_session", None)
        if callable(bind):
            bind(session.session_id)

    def mark_client_disconnected(self) -> None:
        self._client_connected = False

    def shutdown(self) -> None:
        """Graceful stop: in-flight calls become indeterminate; never ``ok``."""
        for pending in list(self._inflight.values()):
            self._record_indeterminate(pending, "graceful shutdown with call in flight")
            self.metrics.tools_calls_indeterminate += 1
        self._inflight.clear()
        self._pending_responses.clear()
        self.upstream.close()

    def handle_raw(self, raw: bytes | str) -> bytes:
        """Handle one client JSON-RPC message; return exact response bytes."""
        message = parse_jsonrpc(
            raw,
            max_message_bytes=self.max_message_bytes,
            max_json_depth=self.max_json_depth,
        )
        result = self.handle_message(message)
        payload = encode_jsonrpc_message(result.client_message)
        out = frame_stdio(payload) if self.framed else payload
        text = out.decode("utf-8", errors="replace")
        assert_text_has_no_secrets(text, self.credentials)
        return out

    def handle_message(self, message: dict[str, Any]) -> MediationResult:
        request_id = message.get("id")
        if not is_jsonrpc_request(message):
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message="gateway does not accept client JSON-RPC responses",
                )
            )
        method = message.get("method")
        klass = classify_method(method)
        if klass is MethodClass.REFUSED:
            return self._refuse_sampling(request_id)
        if klass is MethodClass.UNKNOWN:
            return self._refuse_unknown(method, request_id)
        if self._bypass_blocks():
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_BYPASS_DETECTED,
                    message=(
                        "unattributed upstream sessions reported — "
                        "fail closed, not forwarded"
                    ),
                )
            )
        try:
            self._require_same_principal()
        except UpstreamPrincipalChangedError:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_UPSTREAM_DEAD,
                    message="upstream identity changed — session does not carry over",
                )
            )
        if klass is MethodClass.PASSTHROUGH:
            return self._passthrough(message)
        return self._mediate_gated(message)

    def _refuse_sampling(self, request_id: Any) -> MediationResult:
        self.session.record_finding(
            "sampling_refused",
            "sampling/createMessage",
        )
        return MediationResult(
            client_message=mcp_error_response(
                request_id,
                code=MCP_SAMPLING_REFUSED,
                message=(
                    "sampling/createMessage refused — untrusted upstream "
                    "must not drive the client model"
                ),
                data={"method": "sampling/createMessage"},
            )
        )

    def _refuse_unknown(self, method: Any, request_id: Any) -> MediationResult:
        recorded = method if isinstance(method, str) else ""
        self.session.record_finding("unknown_method", recorded)
        self.metrics.unknown_methods_refused += 1
        return MediationResult(
            client_message=mcp_error_response(
                request_id,
                code=MCP_UNKNOWN_METHOD,
                message="unknown MCP method — not forwarded",
                data={"method": recorded},
            )
        )

    def _passthrough(self, message: dict[str, Any]) -> MediationResult:
        method = str(message.get("method"))
        request_id = message.get("id")
        self.session.record_passthrough(method, request_id)
        self.metrics.passthrough_recorded += 1
        try:
            self._require_same_principal()
        except UpstreamPrincipalChangedError:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_UPSTREAM_DEAD,
                    message="upstream identity changed — session does not carry over",
                )
            )
        wire = encode_jsonrpc_message(message)
        if self.framed:
            wire = frame_stdio(wire)
        assert_text_has_no_secrets(
            wire.decode("utf-8", errors="replace"), self.credentials
        )
        try:
            self.upstream.write(wire)
        except UpstreamDeadError:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_UPSTREAM_DEAD,
                    message="upstream died — not forwarded as success",
                ),
                indeterminate=True,
            )
        if request_id is None:
            return MediationResult(
                client_message={"jsonrpc": "2.0", "result": None},
                forwarded=True,
            )
        try:
            upstream_msg = self._await_correlated(request_id, pending=None)
        except UpstreamTimeoutError:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_INDETERMINATE,
                    message="upstream timeout on passthrough",
                ),
                indeterminate=True,
            )
        except UpstreamDeadError:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_UPSTREAM_DEAD,
                    message="upstream died during passthrough",
                ),
                indeterminate=True,
            )
        except UpstreamPrincipalChangedError:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_UPSTREAM_DEAD,
                    message="upstream identity changed — session does not carry over",
                ),
                indeterminate=True,
            )
        except CrossOriginRedirectError:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_REDIRECT_REFUSED,
                    message="cross-origin redirect refused",
                )
            )
        if upstream_msg.get("error", {}).get("code") == MCP_UNMATCHED_ID:
            return MediationResult(client_message=upstream_msg)
        scrubbed = scrub_mapping(upstream_msg, self.credentials)
        assert_text_has_no_secrets(
            encode_jsonrpc_message(scrubbed).decode("utf-8"),
            self.credentials,
        )
        self._ingest_passthrough_result(method, scrubbed)
        return MediationResult(client_message=scrubbed, forwarded=True)

    def prepare_tools_call(
        self,
        *,
        request_id: Any,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> PendingDispatch | MediationResult:
        """Decide and freeze exact upstream bytes. Does not write upstream."""
        self.metrics.tools_calls_mediated += 1
        if (
            self.session.declared_tool_names is not None
            and tool_name not in self.session.declared_tool_names
        ):
            self.session.record_finding("undeclared_tool", tool_name)
        return self._decide_and_freeze(
            request_id=request_id,
            method="tools/call",
            capability=tool_name,
            arguments=dict(arguments),
            resource=f"mcp:{tool_name}",
            operation="tools/call",
        )

    def prepare_resource_call(
        self,
        *,
        request_id: Any,
        method: str,
        uri: str,
    ) -> PendingDispatch | MediationResult:
        """Gate resources/read and resources/subscribe through decide."""
        if method not in RESOURCE_METHODS:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message="not a gated resource method",
                    data={"method": method},
                )
            )
        return self._decide_and_freeze(
            request_id=request_id,
            method=method,
            capability=method,
            arguments={"uri": uri},
            resource=uri,
            operation=method,
        )

    def _decide_and_freeze(
        self,
        *,
        request_id: Any,
        method: str,
        capability: str,
        arguments: dict[str, Any],
        resource: str,
        operation: str,
    ) -> PendingDispatch | MediationResult:
        verdict = self.middleware.handle(
            ToolCallRequest(
                adapter=ADAPTER_NAME,
                tool=capability,
                api_key=self.agent_api_key,
                arguments=dict(arguments),
                context={
                    "transport": self.session.transport,
                    "destination": self.session.upstream_identity,
                    "operation": operation,
                    "wire_content_type": "application/json",
                    "subject_principal": self.session.client_identity,
                    "resource": resource,
                    "gateway_session_id": self.session.session_id,
                },
                evidence=None,
            )
        )
        if verdict.decision == "block":
            self.metrics.tools_calls_denied += 1
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_ENFORCEMENT_DENIED,
                    message="PrivateVault BLOCK — not forwarded",
                    data={
                        "triggered_by": verdict.triggered_by,
                        "reason": verdict.reason,
                        "record_hash": verdict.record_hash,
                        "decision": verdict.decision,
                    },
                )
            )
        if verdict.decision == "require_approval":
            self.metrics.tools_calls_require_approval += 1
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_ENFORCEMENT_APPROVAL,
                    message="PrivateVault REQUIRE_APPROVAL — not forwarded",
                    data={
                        "triggered_by": verdict.triggered_by,
                        "reason": verdict.reason,
                        "record_hash": verdict.record_hash,
                        "decision": verdict.decision,
                    },
                )
            )
        if verdict.decision != "allow" or not verdict.record_hash:
            self.metrics.tools_calls_denied += 1
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message="non-allow verdict — not forwarded",
                    data={"decision": verdict.decision},
                )
            )

        if method == "tools/call":
            wire_bytes, wire_digest = freeze_tools_call_bytes(
                request_id=request_id,
                tool_name=capability,
                arguments=dict(arguments),
                framed=self.framed,
            )
        elif method == "prompts/get":
            frozen = build_prompts_get_message(
                request_id=request_id,
                name=str(arguments.get("name", "")),
            )
            wire_bytes, wire_digest = freeze_jsonrpc_bytes(frozen, framed=self.framed)
        else:
            frozen = build_resource_message(
                method=method,
                request_id=request_id,
                uri=str(arguments.get("uri", "")),
            )
            wire_bytes, wire_digest = freeze_jsonrpc_bytes(frozen, framed=self.framed)
        assert_text_has_no_secrets(
            wire_bytes.decode("utf-8", errors="replace"),
            self.credentials,
        )

        record = self._lookup_record(verdict.record_hash)
        return PendingDispatch(
            decision_id=record["decision_id"],
            record_hash=verdict.record_hash,
            tool_name=capability,
            arguments=dict(arguments),
            request_id=request_id,
            wire_bytes=wire_bytes,
            wire_digest=wire_digest,
            action_digest=str(record["action_digest"]),
            dispatch_context_digest=str(record["dispatch_context_digest"]),
            method=method,
        )

    def begin_pending(self, pending: PendingDispatch) -> None:
        """Write frozen bytes and register in-flight. Does not wait."""
        try:
            key = jsonrpc_id_key(pending.request_id)
        except FramingProtocolError as exc:
            raise DuplicateRequestIdError(str(exc)) from exc
        if key in self._inflight:
            raise DuplicateRequestIdError(
                "JSON-RPC id already in flight; refusing cross-bind"
            )
        self._require_same_principal()
        if sha256_bytes_digest(pending.wire_bytes) != pending.wire_digest:
            raise RuntimeError("wire digest mismatch before write")
        self.upstream.write(pending.wire_bytes)
        self._inflight[key] = pending

    def complete_inflight(self, request_id: Any) -> MediationResult:
        """Correlate the next matching upstream response to ``request_id``."""
        try:
            key = jsonrpc_id_key(request_id)
        except FramingProtocolError:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message="JSON-RPC id is required for correlation",
                )
            )
        pending = self._inflight.get(key)
        if pending is None:
            self.metrics.unmatched_responses += 1
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_UNMATCHED_ID,
                    message="no in-flight call for this id",
                )
            )
        return self._finish_pending(pending)

    def _override_wire_bytes(
        self, pending: PendingDispatch, arguments_override: dict[str, Any]
    ) -> bytes:
        if pending.method == "tools/call":
            alt, _ = freeze_tools_call_bytes(
                request_id=pending.request_id,
                tool_name=pending.tool_name,
                arguments=arguments_override,
                framed=self.framed,
            )
            return alt
        if pending.method == "prompts/get":
            frozen = build_prompts_get_message(
                request_id=pending.request_id,
                name=str(arguments_override.get("name", "")),
            )
            alt, _ = freeze_jsonrpc_bytes(frozen, framed=self.framed)
            return alt
        frozen = build_resource_message(
            method=pending.method,
            request_id=pending.request_id,
            uri=str(arguments_override.get("uri", "")),
        )
        alt, _ = freeze_jsonrpc_bytes(frozen, framed=self.framed)
        return alt

    def forward_pending(
        self,
        pending: PendingDispatch,
        *,
        arguments_override: dict[str, Any] | None = None,
    ) -> MediationResult:
        """Write frozen bytes upstream. Mutation attempts are refused."""
        if arguments_override is not None:
            alt = self._override_wire_bytes(pending, arguments_override)
            if alt != pending.wire_bytes:
                raise ArgumentMutationRefusedError(
                    "arguments mutated between decide and forward"
                )

        if sha256_bytes_digest(pending.wire_bytes) != pending.wire_digest:
            raise RuntimeError("wire digest mismatch before write")

        written = False
        try:
            self.begin_pending(pending)
            written = True
            if not self._client_connected:
                self._record_indeterminate(
                    pending,
                    "client disconnected after upstream write",
                )
                raise ClientDisconnectedError(
                    "client disconnected mid-call; completion not sealed"
                )
            return self._finish_pending(pending)
        except (
            DuplicateRequestIdError,
            UpstreamTimeoutError,
            ClientDisconnectedError,
            UpstreamDeadError,
            UpstreamPrincipalChangedError,
            CrossOriginRedirectError,
            SameOriginRedirectError,
        ) as exc:
            return self._result_from_forward_error(exc, pending, written)

    def _result_from_forward_error(
        self,
        exc: BaseException,
        pending: PendingDispatch,
        written: bool,
    ) -> MediationResult:
        if isinstance(exc, DuplicateRequestIdError):
            return MediationResult(
                client_message=mcp_error_response(
                    pending.request_id,
                    code=MCP_DUPLICATE_ID,
                    message="duplicate JSON-RPC id — not forwarded",
                    data={"record_hash": pending.record_hash},
                )
            )
        if isinstance(exc, UpstreamTimeoutError):
            if not written:
                raise exc
            self._fail_inflight(pending, "upstream timeout after request was written")
            return self._indeterminate_result(
                pending,
                code=MCP_INDETERMINATE,
                message="upstream timeout after forward — indeterminate",
                extra={"wire_digest": pending.wire_digest},
            )
        if isinstance(exc, ClientDisconnectedError):
            self._drop_inflight(pending)
            self.metrics.tools_calls_indeterminate += 1
            return self._indeterminate_result(
                pending,
                code=MCP_INDETERMINATE,
                message="client disconnected mid-call — indeterminate",
            )
        if isinstance(exc, UpstreamDeadError):
            self._fail_inflight(
                pending,
                "upstream died after request was written",
                fail_all=True,
            )
            return self._indeterminate_result(
                pending,
                code=MCP_UPSTREAM_DEAD,
                message="upstream died — indeterminate",
                forwarded=written,
            )
        if isinstance(exc, UpstreamPrincipalChangedError):
            self._fail_inflight(
                pending,
                "upstream identity changed mid-session",
                fail_all=True,
            )
            return self._indeterminate_result(
                pending,
                code=MCP_UPSTREAM_DEAD,
                message="upstream restarted — session does not carry over",
                forwarded=written,
            )
        if isinstance(exc, SameOriginRedirectError):
            return self._redecide_same_origin(pending, exc.location, written)
        self._fail_inflight(pending, "cross-origin redirect refused")
        return self._indeterminate_result(
            pending,
            code=MCP_REDIRECT_REFUSED,
            message="cross-origin redirect refused — not followed",
            forwarded=written,
        )

    def _indeterminate_result(
        self,
        pending: PendingDispatch,
        *,
        code: int,
        message: str,
        forwarded: bool = True,
        extra: dict[str, Any] | None = None,
    ) -> MediationResult:
        data: dict[str, Any] = {
            "record_hash": pending.record_hash,
            "outcome": "INDETERMINATE",
        }
        if extra:
            data.update(extra)
        return MediationResult(
            client_message=mcp_error_response(
                pending.request_id,
                code=code,
                message=message,
                data=data,
            ),
            pending=pending,
            forwarded=forwarded,
            indeterminate=True,
        )

    def _finish_pending(self, pending: PendingDispatch) -> MediationResult:
        try:
            upstream_msg = self._await_correlated(pending.request_id, pending=pending)
        except UpstreamTimeoutError:
            self._fail_inflight(pending, "upstream timeout after request was written")
            return MediationResult(
                client_message=mcp_error_response(
                    pending.request_id,
                    code=MCP_INDETERMINATE,
                    message="upstream timeout after forward — indeterminate",
                    data={
                        "record_hash": pending.record_hash,
                        "wire_digest": pending.wire_digest,
                        "outcome": "INDETERMINATE",
                    },
                ),
                pending=pending,
                forwarded=True,
                indeterminate=True,
            )
        except UpstreamDeadError:
            self._fail_inflight(
                pending,
                "upstream died after request was written",
                fail_all=True,
            )
            return MediationResult(
                client_message=mcp_error_response(
                    pending.request_id,
                    code=MCP_UPSTREAM_DEAD,
                    message="upstream died — indeterminate",
                    data={
                        "record_hash": pending.record_hash,
                        "outcome": "INDETERMINATE",
                    },
                ),
                pending=pending,
                forwarded=True,
                indeterminate=True,
            )
        except UpstreamPrincipalChangedError:
            self._fail_inflight(
                pending,
                "upstream identity changed mid-session",
                fail_all=True,
            )
            return MediationResult(
                client_message=mcp_error_response(
                    pending.request_id,
                    code=MCP_UPSTREAM_DEAD,
                    message="upstream restarted — session does not carry over",
                    data={
                        "record_hash": pending.record_hash,
                        "outcome": "INDETERMINATE",
                    },
                ),
                pending=pending,
                forwarded=True,
                indeterminate=True,
            )
        except CrossOriginRedirectError:
            self._fail_inflight(pending, "cross-origin redirect refused")
            return MediationResult(
                client_message=mcp_error_response(
                    pending.request_id,
                    code=MCP_REDIRECT_REFUSED,
                    message="cross-origin redirect refused — not followed",
                    data={"record_hash": pending.record_hash},
                ),
                pending=pending,
                forwarded=True,
                indeterminate=True,
            )

        self._drop_inflight(pending)

        if not self._client_connected:
            self._record_indeterminate(
                pending,
                "client disconnected before response delivery",
            )
            self.metrics.tools_calls_indeterminate += 1
            return MediationResult(
                client_message=mcp_error_response(
                    pending.request_id,
                    code=MCP_INDETERMINATE,
                    message="client disconnected before delivery — indeterminate",
                    data={
                        "record_hash": pending.record_hash,
                        "outcome": "INDETERMINATE",
                    },
                ),
                pending=pending,
                forwarded=True,
                indeterminate=True,
            )

        if upstream_msg.get("error", {}).get("code") in {
            MCP_UNMATCHED_ID,
            MCP_INDETERMINATE,
        }:
            if upstream_msg["error"]["code"] == MCP_INDETERMINATE:
                return MediationResult(
                    client_message=upstream_msg,
                    pending=pending,
                    forwarded=True,
                    indeterminate=True,
                )
            return MediationResult(client_message=upstream_msg, pending=pending)

        scrubbed = scrub_mapping(upstream_msg, self.credentials)
        if "result" in scrubbed or "error" in scrubbed:
            response_bytes = encode_jsonrpc_message(scrubbed)
            assert_text_has_no_secrets(
                response_bytes.decode("utf-8"),
                self.credentials,
            )
            response_digest = sha256_bytes_digest(response_bytes)
            self._report_outcome(
                pending,
                "ok",
                "upstream responded",
                response_digest=response_digest,
            )
            self.metrics.tools_calls_allowed += 1
            return MediationResult(
                client_message=scrubbed,
                pending=pending,
                forwarded=True,
                response_digest=response_digest,
            )
        self._record_indeterminate(pending, "malformed upstream response")
        self.metrics.tools_calls_indeterminate += 1
        return MediationResult(
            client_message=mcp_error_response(
                pending.request_id,
                code=MCP_INDETERMINATE,
                message="malformed upstream response — indeterminate",
                data={"record_hash": pending.record_hash},
            ),
            pending=pending,
            forwarded=True,
            indeterminate=True,
        )

    def _mediate_gated(self, message: dict[str, Any]) -> MediationResult:
        request_id = message.get("id")
        method = message.get("method")
        precheck = self._gated_precheck(method, request_id)
        if precheck is not None:
            return precheck
        prepared = self._prepare_gated_message(message)
        if isinstance(prepared, MediationResult):
            return prepared
        return self.forward_pending(prepared)

    def _gated_precheck(self, method: Any, request_id: Any) -> MediationResult | None:
        if not isinstance(method, str):
            return self._refuse_unknown(method, request_id)
        if request_id is None:
            return MediationResult(
                client_message=mcp_error_response(
                    None,
                    code=MCP_GATEWAY_FAULT,
                    message="gated MCP methods require a JSON-RPC id",
                    data={"method": method},
                )
            )
        try:
            key = jsonrpc_id_key(request_id)
        except FramingProtocolError:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message="JSON-RPC id must be a string or integer",
                )
            )
        if key in self._inflight:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_DUPLICATE_ID,
                    message="duplicate JSON-RPC id already in flight — not forwarded",
                    data={"method": method},
                )
            )
        return None

    def _prepare_gated_message(
        self, message: dict[str, Any]
    ) -> PendingDispatch | MediationResult:
        request_id = message.get("id")
        method = str(message.get("method"))
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message=f"{method} params must be an object",
                )
            )
        if method == "tools/call":
            blocked = self._block_undeclared_tool(request_id, params)
            if blocked is not None:
                return blocked
            return self._prepare_tools_from_params(request_id, params)
        if method in RESOURCE_METHODS:
            return self._prepare_resource_from_params(request_id, method, params)
        if method in PROMPT_METHODS:
            return self._prepare_prompt_from_params(request_id, params)
        return self._refuse_unknown(method, request_id)

    def _prepare_tools_from_params(
        self, request_id: Any, params: dict[str, Any]
    ) -> PendingDispatch | MediationResult:
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(tool_name, str) or not tool_name:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message="tools/call requires params.name",
                )
            )
        if not isinstance(arguments, dict):
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message="tools/call params.arguments must be an object",
                )
            )
        return self.prepare_tools_call(
            request_id=request_id,
            tool_name=tool_name,
            arguments=arguments,
        )

    def _prepare_resource_from_params(
        self, request_id: Any, method: str, params: dict[str, Any]
    ) -> PendingDispatch | MediationResult:
        uri = params.get("uri")
        if not isinstance(uri, str) or not uri:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message=f"{method} requires params.uri",
                )
            )
        return self.prepare_resource_call(
            request_id=request_id,
            method=method,
            uri=uri,
        )

    def _prepare_prompt_from_params(
        self, request_id: Any, params: dict[str, Any]
    ) -> PendingDispatch | MediationResult:
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message="prompts/get requires params.name",
                )
            )
        return self._decide_and_freeze(
            request_id=request_id,
            method="prompts/get",
            capability="prompts/get",
            arguments={"name": name},
            resource=f"mcp-prompt:{name}",
            operation="prompts/get",
        )

    def _block_undeclared_tool(
        self, request_id: Any, params: dict[str, Any]
    ) -> MediationResult | None:
        if self.undeclared_tool_policy != "block":
            return None
        tool_name = params.get("name")
        declared = self.session.declared_tool_names
        if (
            isinstance(tool_name, str)
            and declared is not None
            and tool_name in declared
        ):
            return None
        recorded = tool_name if isinstance(tool_name, str) else ""
        self.session.record_finding("undeclared_tool_blocked", recorded)
        self.metrics.tools_calls_denied += 1
        return MediationResult(
            client_message=mcp_error_response(
                request_id,
                code=MCP_UNDECLARED_TOOL,
                message="tool not declared at initialize/tools/list — not forwarded",
                data={"method": "tools/call", "tool": recorded},
            )
        )

    def _bypass_blocks(self) -> bool:
        return bool(self.metrics.bypass_tripped) and self.fail_closed_on_unattributed

    def _redecide_same_origin(
        self, pending: PendingDispatch, location: str, written: bool
    ) -> MediationResult:
        if self._redirects_used >= self.max_same_origin_redirects:
            self._fail_inflight(pending, "same-origin redirect hop budget exhausted")
            return self._indeterminate_result(
                pending,
                code=MCP_REDIRECT_REFUSED,
                message="redirect hop budget exhausted — not followed",
                forwarded=written,
            )
        self._redirects_used += 1
        self._record_indeterminate(
            pending, "same-origin redirect; re-deciding at new destination"
        )
        self._drop_inflight(pending)
        self.session.upstream_identity = location
        if hasattr(self.upstream, "url"):
            self.upstream.url = location
            self.upstream.identity = "http:" + location
            self._bound_upstream_identity = self.upstream.identity
        if pending.method == "tools/call":
            resource = f"mcp:{pending.tool_name}"
        elif pending.method == "prompts/get":
            resource = f"mcp-prompt:{pending.arguments.get('name', '')}"
        else:
            resource = str(pending.arguments.get("uri", location))
        prepared = self._decide_and_freeze(
            request_id=pending.request_id,
            method=pending.method,
            capability=pending.tool_name,
            arguments=dict(pending.arguments),
            resource=resource,
            operation=pending.method,
        )
        if isinstance(prepared, MediationResult):
            return prepared
        return self.forward_pending(prepared)

    def _await_correlated(
        self,
        request_id: Any,
        *,
        pending: PendingDispatch | None,
    ) -> dict[str, Any]:
        key = jsonrpc_id_key(request_id)
        buffered = self._pending_responses.pop(key, None)
        if buffered is not None:
            return buffered
        deadline = time.monotonic() + self.upstream_timeout_s
        while True:
            self._require_same_principal()
            remaining = max(0.0, deadline - time.monotonic())
            if remaining <= 0:
                raise UpstreamTimeoutError("upstream timeout awaiting correlated id")
            raw_msg = self.upstream.read_jsonrpc(timeout_s=remaining)
            routed = self._route_upstream_message(raw_msg, key, request_id, pending)
            if routed is not None:
                return routed

    def _route_upstream_message(
        self,
        raw_msg: Any,
        key: str,
        request_id: Any,
        pending: PendingDispatch | None,
    ) -> dict[str, Any] | None:
        accepted, protocol_fault = self._try_accept_upstream(raw_msg)
        if protocol_fault:
            return self._on_malformed_upstream(raw_msg, request_id, pending)
        if is_jsonrpc_request(accepted):
            self._handle_upstream_initiated(accepted)
            return None
        if not is_jsonrpc_response(accepted):
            self.metrics.unmatched_responses += 1
            self.session.record_finding("unclassifiable_upstream", "")
            return None
        return self._match_or_buffer_response(accepted, key)

    def _on_malformed_upstream(
        self,
        raw_msg: Any,
        request_id: Any,
        pending: PendingDispatch | None,
    ) -> dict[str, Any] | None:
        fault_id = raw_msg.get("id") if isinstance(raw_msg, dict) else None
        if self._ids_equal(fault_id, request_id) and pending is not None:
            self._record_indeterminate(pending, "malformed upstream response")
            self.metrics.tools_calls_indeterminate += 1
            return mcp_error_response(
                request_id,
                code=MCP_INDETERMINATE,
                message="malformed upstream response — indeterminate",
                data={
                    "record_hash": pending.record_hash,
                    "outcome": "INDETERMINATE",
                },
            )
        self.metrics.unmatched_responses += 1
        self.session.record_finding("malformed_upstream_frame", "")
        return None

    def _match_or_buffer_response(
        self, msg: dict[str, Any], key: str
    ) -> dict[str, Any] | None:
        try:
            resp_key = jsonrpc_id_key(msg.get("id"))
        except FramingProtocolError:
            self._reject_unmatched(msg)
            return None
        if resp_key == key:
            return msg
        if resp_key in self._inflight:
            if resp_key in self._pending_responses:
                self._reject_unmatched(msg)
                return None
            self._pending_responses[resp_key] = msg
            return None
        self._reject_unmatched(msg)
        return None

    def _try_accept_upstream(self, msg: Any) -> tuple[dict[str, Any], bool]:
        if not isinstance(msg, dict):
            return {}, True
        try:
            raw = encode_jsonrpc_message(msg)
            parsed = parse_jsonrpc(
                raw,
                max_message_bytes=self.max_message_bytes,
                max_json_depth=self.max_json_depth,
            )
        except (FramingProtocolError, TypeError, ValueError):
            return {}, True
        return parsed, False

    def _ids_equal(self, left: Any, right: Any) -> bool:
        try:
            return jsonrpc_id_key(left) == jsonrpc_id_key(right)
        except FramingProtocolError:
            return False

    def _reject_unmatched(self, message: dict[str, Any]) -> None:
        self.metrics.unmatched_responses += 1
        self.session.record_finding("unmatched_response_id", "")
        # Never bind to an in-flight decision.

    def _handle_upstream_initiated(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        klass = classify_method(method)
        req_id = message.get("id")
        if klass is MethodClass.REFUSED:
            self._refuse_server_sampling(req_id)
            return
        recorded = method if isinstance(method, str) else ""
        self.session.record_finding("server_initiated", recorded)
        if klass is MethodClass.UNKNOWN or klass is MethodClass.GATED:
            self._error_server_method(req_id, recorded)
            return
        if req_id is None:
            self.session.record_passthrough(recorded, None)
            self.metrics.passthrough_recorded += 1
            return
        if recorded == "ping":
            self._write_to_upstream({"jsonrpc": "2.0", "id": req_id, "result": {}})
            self.session.record_passthrough(recorded, req_id)
            self.metrics.passthrough_recorded += 1
            return
        self._error_server_method(req_id, recorded)

    def _refuse_server_sampling(self, req_id: Any) -> None:
        self.session.record_finding("sampling_refused", "sampling/createMessage")
        if req_id is None:
            return
        self._write_to_upstream(
            mcp_error_response(
                req_id,
                code=MCP_SAMPLING_REFUSED,
                message=(
                    "sampling/createMessage refused — untrusted upstream "
                    "must not drive the client model"
                ),
                data={"method": "sampling/createMessage"},
            )
        )

    def _error_server_method(self, req_id: Any, recorded: str) -> None:
        self.metrics.unknown_methods_refused += 1
        if req_id is None:
            return
        self._write_to_upstream(
            mcp_error_response(
                req_id,
                code=MCP_UNKNOWN_METHOD,
                message="server-initiated method refused — not forwarded",
                data={"method": recorded},
            )
        )

    def _write_to_upstream(self, message: dict[str, Any]) -> None:
        wire = encode_jsonrpc_message(message)
        if self.framed:
            wire = frame_stdio(wire)
        assert_text_has_no_secrets(
            wire.decode("utf-8", errors="replace"), self.credentials
        )
        self.upstream.write(wire)

    def _ingest_passthrough_result(self, method: str, response: dict[str, Any]) -> None:
        result = response.get("result")
        if method == "initialize" and isinstance(result, dict):
            caps = result.get("capabilities")
            if isinstance(caps, dict):
                self.session.initialize_capabilities = scrub_mapping(
                    caps, self.credentials
                )
            names = tool_names_from_list_result(result)
            if names:
                self.session.declared_tool_names = names
        elif method == "tools/list":
            names = tool_names_from_list_result(result)
            if self.session.declared_tool_names is not None:
                extra = names - self.session.declared_tool_names
                if extra:
                    self.session.record_finding(
                        "undeclared_tools",
                        ",".join(sorted(extra)),
                    )
            if names:
                self.session.declared_tool_names = names

    def _require_same_principal(self) -> None:
        current = self.upstream.identity
        if current != self._bound_upstream_identity:
            raise UpstreamPrincipalChangedError(
                "upstream identity changed; session does not carry over"
            )

    def _lookup_record(self, record_hash: str) -> dict[str, Any]:
        recorder = self.middleware.recorder
        for rec in recorder.graph:
            if rec.record_hash == record_hash:
                return rec.to_dict()
        store = recorder.store
        if store is not None and hasattr(store, "get_decision_by_record_hash"):
            found = store.get_decision_by_record_hash(record_hash)
            if found is not None:
                return found
        raise RuntimeError("sealed decision record not found after allow")

    def _report_outcome(
        self,
        pending: PendingDispatch,
        status: str,
        detail: str,
        *,
        response_digest: str = "",
    ) -> None:
        self.middleware.recorder.report_outcome(
            pending.decision_id,
            status,
            detail,
            response_digest=response_digest,
        )

    def _record_indeterminate(self, pending: PendingDispatch, reason: str) -> None:
        detail = f"{INDETERMINATE_PREFIX} {reason}"
        try:
            self._report_outcome(pending, "indeterminate", detail)
        except (KeyError, ValueError):
            pass

    def _drop_inflight(self, pending: PendingDispatch) -> None:
        try:
            key = jsonrpc_id_key(pending.request_id)
        except FramingProtocolError:
            return
        self._inflight.pop(key, None)

    def _fail_inflight(
        self,
        pending: PendingDispatch,
        reason: str,
        *,
        fail_all: bool = False,
    ) -> None:
        self._record_indeterminate(pending, reason)
        self.metrics.tools_calls_indeterminate += 1
        self._drop_inflight(pending)
        if fail_all:
            self._fail_remaining_inflight(reason)

    def _fail_remaining_inflight(self, reason: str) -> None:
        for leftover in list(self._inflight.values()):
            self._record_indeterminate(leftover, reason)
            self.metrics.tools_calls_indeterminate += 1
        self._inflight.clear()
        self._pending_responses.clear()
