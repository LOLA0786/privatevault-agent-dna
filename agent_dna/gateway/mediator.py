"""Tool-call mediation: decide → freeze bytes → forward → outcome."""

from __future__ import annotations

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
    UpstreamTimeoutError,
)
from agent_dna.gateway.framing import (
    DEFAULT_MAX_MESSAGE_BYTES,
    MCP_ENFORCEMENT_APPROVAL,
    MCP_ENFORCEMENT_DENIED,
    MCP_GATEWAY_FAULT,
    MCP_INDETERMINATE,
    encode_jsonrpc_message,
    frame_stdio,
    freeze_tools_call_bytes,
    mcp_error_response,
    parse_jsonrpc,
)
from agent_dna.gateway.metrics import GatewayMetrics
from agent_dna.gateway.session import GatewaySession
from agent_dna.gateway.upstream import UpstreamTransport

INDETERMINATE_PREFIX = "INDETERMINATE:"
ADAPTER_NAME = "mcp-gateway"


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


@dataclass
class MediationResult:
    client_message: dict[str, Any]
    pending: PendingDispatch | None = None
    forwarded: bool = False
    indeterminate: bool = False


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
        self.metrics.note_session(session.session_id)
        self._client_connected = True

    def mark_client_disconnected(self) -> None:
        self._client_connected = False

    def handle_raw(self, raw: bytes | str) -> bytes:
        """Handle one client JSON-RPC message; return exact response bytes."""
        message = parse_jsonrpc(raw, max_message_bytes=self.max_message_bytes)
        result = self.handle_message(message)
        payload = encode_jsonrpc_message(result.client_message)
        out = frame_stdio(payload) if self.framed else payload
        text = out.decode("utf-8", errors="replace")
        assert_text_has_no_secrets(text, self.credentials)
        return out

    def handle_message(self, message: dict[str, Any]) -> MediationResult:
        method = message.get("method")
        request_id = message.get("id")
        if method == "tools/call":
            return self._mediate_tools_call(message)
        if method is None:
            # JSON-RPC response from client (unusual) — refuse
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message="gateway does not accept client JSON-RPC responses",
                )
            )
        # Non-consequential: passthrough + record
        return self._passthrough(message)

    def _passthrough(self, message: dict[str, Any]) -> MediationResult:
        method = str(message.get("method"))
        request_id = message.get("id")
        self.session.record_passthrough(method, request_id)
        self.metrics.passthrough_recorded += 1
        wire = encode_jsonrpc_message(message)
        if self.framed:
            wire = frame_stdio(wire)
        assert_text_has_no_secrets(
            wire.decode("utf-8", errors="replace"), self.credentials
        )
        self.upstream.write(wire)
        if request_id is None:
            # notification — no response body required
            return MediationResult(
                client_message={"jsonrpc": "2.0", "result": None},
                forwarded=True,
            )
        try:
            upstream_msg = self.upstream.read_jsonrpc(timeout_s=self.upstream_timeout_s)
        except UpstreamTimeoutError:
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_INDETERMINATE,
                    message="upstream timeout on passthrough",
                ),
                indeterminate=True,
            )
        scrubbed = scrub_mapping(upstream_msg, self.credentials)
        assert_text_has_no_secrets(
            encode_jsonrpc_message(scrubbed).decode("utf-8"),
            self.credentials,
        )
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
        verdict = self.middleware.handle(
            ToolCallRequest(
                adapter=ADAPTER_NAME,
                tool=tool_name,
                api_key=self.agent_api_key,
                arguments=dict(arguments),
                context={
                    "transport": self.session.transport,
                    "destination": self.session.upstream_identity,
                    "operation": "tools/call",
                    "wire_content_type": "application/json",
                    "subject_principal": self.session.client_identity,
                    "resource": f"mcp:{tool_name}",
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

        wire_bytes, wire_digest = freeze_tools_call_bytes(
            request_id=request_id,
            tool_name=tool_name,
            arguments=dict(arguments),
            framed=self.framed,
        )
        assert_text_has_no_secrets(
            wire_bytes.decode("utf-8", errors="replace"),
            self.credentials,
        )

        # Recover sealed digests from the recorder graph/store.
        record = self._lookup_record(verdict.record_hash)
        return PendingDispatch(
            decision_id=record["decision_id"],
            record_hash=verdict.record_hash,
            tool_name=tool_name,
            arguments=dict(arguments),
            request_id=request_id,
            wire_bytes=wire_bytes,
            wire_digest=wire_digest,
            action_digest=str(record["action_digest"]),
            dispatch_context_digest=str(record["dispatch_context_digest"]),
        )

    def forward_pending(
        self,
        pending: PendingDispatch,
        *,
        arguments_override: dict[str, Any] | None = None,
    ) -> MediationResult:
        """Write frozen bytes upstream. Mutation attempts are refused."""
        if arguments_override is not None:
            alt, _ = freeze_tools_call_bytes(
                request_id=pending.request_id,
                tool_name=pending.tool_name,
                arguments=arguments_override,
                framed=self.framed,
            )
            if alt != pending.wire_bytes:
                raise ArgumentMutationRefusedError(
                    "arguments mutated between decide and forward"
                )

        # Exact-byte check: digest of bytes we are about to write.
        if sha256_bytes_digest(pending.wire_bytes) != pending.wire_digest:
            raise RuntimeError("wire digest mismatch before write")

        written = False
        try:
            self.upstream.write(pending.wire_bytes)
            written = True
            if not self._client_connected:
                self._record_indeterminate(
                    pending,
                    "client disconnected after upstream write",
                )
                raise ClientDisconnectedError(
                    "client disconnected mid-call; completion not sealed"
                )
            upstream_msg = self.upstream.read_jsonrpc(timeout_s=self.upstream_timeout_s)
        except UpstreamTimeoutError:
            if written:
                self._record_indeterminate(
                    pending,
                    "upstream timeout after request was written",
                )
                self.metrics.tools_calls_indeterminate += 1
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
            raise
        except ClientDisconnectedError:
            self.metrics.tools_calls_indeterminate += 1
            return MediationResult(
                client_message=mcp_error_response(
                    pending.request_id,
                    code=MCP_INDETERMINATE,
                    message="client disconnected mid-call — indeterminate",
                    data={
                        "record_hash": pending.record_hash,
                        "outcome": "INDETERMINATE",
                    },
                ),
                pending=pending,
                forwarded=True,
                indeterminate=True,
            )

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

        # Malicious upstream cannot alter the sealed decision: we only
        # scrub and return the response; sealed digests stay as decided.
        scrubbed = scrub_mapping(upstream_msg, self.credentials)
        if "result" in scrubbed or "error" in scrubbed:
            self._report_outcome(pending, "ok", "upstream responded")
            self.metrics.tools_calls_allowed += 1
        else:
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

        # Never echo credential material; never let upstream rewrite our
        # sealed decision identifiers into a success fabrication for deny.
        assert_text_has_no_secrets(
            encode_jsonrpc_message(scrubbed).decode("utf-8"),
            self.credentials,
        )
        return MediationResult(
            client_message=scrubbed,
            pending=pending,
            forwarded=True,
        )

    def _mediate_tools_call(self, message: dict[str, Any]) -> MediationResult:
        request_id = message.get("id")
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return MediationResult(
                client_message=mcp_error_response(
                    request_id,
                    code=MCP_GATEWAY_FAULT,
                    message="tools/call params must be an object",
                )
            )
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

        prepared = self.prepare_tools_call(
            request_id=request_id,
            tool_name=tool_name,
            arguments=arguments,
        )
        if isinstance(prepared, MediationResult):
            return prepared
        return self.forward_pending(prepared)

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
        self, pending: PendingDispatch, status: str, detail: str
    ) -> None:
        self.middleware.recorder.report_outcome(
            pending.decision_id,
            status,
            detail,
        )

    def _record_indeterminate(self, pending: PendingDispatch, reason: str) -> None:
        detail = f"{INDETERMINATE_PREFIX} {reason}"
        try:
            self._report_outcome(pending, "error", detail)
        except (KeyError, ValueError):
            # Duplicate outcome or missing decision — still fail closed
            # for the client path; do not claim success.
            pass
