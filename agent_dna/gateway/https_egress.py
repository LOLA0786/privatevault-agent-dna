"""Named HTTPS egress — same freeze/decide/verify story as MCP.

This is not MCP. It is a second transport: an enumerated method to an
operator-named HTTPS URL, with credentials held only here. The client
never receives the upstream secret; the gateway writes only frozen bytes.
"""

from __future__ import annotations

import json
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse

from agent_dna.connector.middleware import ConnectorMiddleware
from agent_dna.connector.models import ToolCallRequest
from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.gateway.credentials import (
    UpstreamCredentials,
    assert_text_has_no_secrets,
)
from agent_dna.gateway.errors import (
    CrossOriginRedirectError,
    FramingProtocolError,
    GatewayStartupError,
    SameOriginRedirectError,
)
from agent_dna.gateway.framing import (
    DEFAULT_MAX_MESSAGE_BYTES,
    MAX_JSON_DEPTH,
    parse_jsonrpc,
)
from agent_dna.gateway.upstream import (
    SealedDestinationRedirectHandler,
    origins_equal,
    read_bounded_http_body,
)

HTTPS_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"})
ADAPTER_NAME = "https-egress"


def freeze_https_egress(*, method: str, url: str, body: bytes) -> tuple[bytes, str]:
    """Canonical request bytes: METHOD SP URL LF body."""
    if method not in HTTPS_METHODS:
        raise FramingProtocolError(f"HTTPS method {method!r} is not enumerated")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise FramingProtocolError("HTTPS egress requires https://")
    wire = method.encode("ascii") + b" " + url.encode("utf-8") + b"\n" + body
    return wire, sha256_bytes_digest(wire)


def parse_https_egress_wire(wire_bytes: bytes) -> tuple[str, str, bytes]:
    """Invert freeze_https_egress. Fail closed on any other layout."""
    if b"\n" not in wire_bytes:
        raise FramingProtocolError("https egress wire missing LF separator")
    head, body = wire_bytes.split(b"\n", 1)
    try:
        method_b, url_b = head.split(b" ", 1)
        method = method_b.decode("ascii")
        url = url_b.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise FramingProtocolError(
            "https egress wire is not METHOD SP URL LF body"
        ) from exc
    if method not in HTTPS_METHODS:
        raise FramingProtocolError(f"HTTPS method {method!r} is not enumerated")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise FramingProtocolError("HTTPS egress requires https://")
    return method, url, body


def require_https_url(url: str, *, allow_insecure_http: bool) -> None:
    scheme = urlparse(url).scheme.lower()
    if scheme == "https":
        return
    if scheme == "http" and allow_insecure_http:
        return
    raise GatewayStartupError(
        "HTTPS-only: refusing non-https URL without allow_insecure_http"
    )


@dataclass
class HttpsEgressUpstream:
    """Send frozen bytes to a named HTTPS origin. Credentials stay here."""

    url: str
    credentials: UpstreamCredentials
    identity: str = ""
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_json_depth: int = MAX_JSON_DEPTH
    tls_verify: bool = True
    timeout_s: float = 30.0
    writes: list[bytes] = field(default_factory=list)
    last_status: int = 0
    last_body: bytes = b""
    _session_id: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.url:
            raise ValueError("HttpsEgressUpstream requires a url")
        if not self.identity:
            self.identity = "https-egress:" + self.url
        ctx = (
            ssl.create_default_context()
            if self.tls_verify
            else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        )
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._opener = urlrequest.build_opener(
            SealedDestinationRedirectHandler(),
            urlrequest.HTTPSHandler(context=ctx),
        )

    def bind_session(self, session_id: str) -> None:
        self._session_id = session_id

    def write(self, wire_bytes: bytes) -> None:
        method, url, body = parse_https_egress_wire(wire_bytes)
        if url != self.url:
            raise FramingProtocolError(
                f"https egress sealed destination is {self.url!r}; "
                f"wire url {url!r} refused"
            )
        self.writes.append(wire_bytes)
        headers = {
            "Content-Type": "application/octet-stream",
            **self.credentials.http_headers(session_id=self._session_id),
        }
        req = urlrequest.Request(url, data=body, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout_s) as resp:
                self.last_status = int(getattr(resp, "status", 200) or 200)
                self.last_body = read_bounded_http_body(
                    resp, max_bytes=self.max_message_bytes
                )
        except (CrossOriginRedirectError, SameOriginRedirectError):
            raise
        except urlerror.URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, (CrossOriginRedirectError, SameOriginRedirectError)):
                raise reason from exc
            raise ConnectionError(f"https egress error: {exc}") from exc

    def read_jsonrpc(self, *, timeout_s: float) -> dict[str, Any]:
        del timeout_s
        if not self.last_body:
            return {"jsonrpc": "2.0", "id": None, "result": None}
        try:
            return parse_jsonrpc(
                self.last_body,
                max_message_bytes=self.max_message_bytes,
                max_json_depth=self.max_json_depth,
            )
        except FramingProtocolError:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "result": {
                    "status": self.last_status,
                    "body_digest": sha256_bytes_digest(self.last_body),
                },
            }

    def close(self) -> None:
        return None


@dataclass
class HttpsEgressResult:
    forwarded: bool
    wire_bytes: bytes
    wire_digest: str
    response_digest: str
    record_hash: str | None
    status: str


def _lookup_record(middleware: ConnectorMiddleware, record_hash: str) -> Any:
    recorder = middleware.recorder
    for rec in recorder.graph:
        if rec.record_hash == record_hash:
            return rec
    raise RuntimeError("sealed decision record not found after allow")


def _refuse(
    *,
    wire: bytes,
    wire_digest: str,
    record_hash: str | None,
) -> HttpsEgressResult:
    return HttpsEgressResult(
        forwarded=False,
        wire_bytes=wire,
        wire_digest=wire_digest,
        response_digest="",
        record_hash=record_hash,
        status="refused",
    )


def _complete_ok(
    middleware: ConnectorMiddleware,
    record: Any,
    *,
    wire: bytes,
    wire_digest: str,
    response_digest: str,
) -> HttpsEgressResult:
    middleware.recorder.report_outcome(
        record.decision_id,
        "ok",
        "https egress responded",
        response_digest=response_digest,
    )
    return HttpsEgressResult(
        forwarded=True,
        wire_bytes=wire,
        wire_digest=wire_digest,
        response_digest=response_digest,
        record_hash=record.record_hash,
        status="ok",
    )


def _complete_indeterminate(
    middleware: ConnectorMiddleware,
    record: Any,
    *,
    wire: bytes,
    wire_digest: str,
    detail: str,
) -> HttpsEgressResult:
    middleware.recorder.report_outcome(
        record.decision_id,
        "indeterminate",
        detail,
    )
    return HttpsEgressResult(
        forwarded=False,
        wire_bytes=wire,
        wire_digest=wire_digest,
        response_digest="",
        record_hash=record.record_hash,
        status="indeterminate",
    )


def _decide_https(
    middleware: ConnectorMiddleware,
    *,
    agent_api_key: str,
    session_id: str,
    client_identity: str,
    capability: str,
    method: str,
    url: str,
    wire_digest: str,
) -> Any:
    return middleware.handle(
        ToolCallRequest(
            adapter=ADAPTER_NAME,
            tool=capability,
            api_key=agent_api_key,
            arguments={"method": method, "url": url, "body_digest": wire_digest},
            context={
                "transport": "https-egress",
                "destination": url,
                "operation": method,
                "wire_content_type": "application/octet-stream",
                "subject_principal": client_identity,
                "resource": url,
                "gateway_session_id": session_id,
            },
            evidence=None,
        )
    )


def _redecide_https_redirect(
    *,
    middleware: ConnectorMiddleware,
    upstream: Any,
    credentials: UpstreamCredentials,
    agent_api_key: str,
    session_id: str,
    client_identity: str,
    capability: str,
    method: str,
    original_url: str,
    location: str,
    body: bytes,
    original_record: Any,
    original_wire: bytes,
    original_digest: str,
) -> HttpsEgressResult:
    middleware.recorder.report_outcome(
        original_record.decision_id,
        "indeterminate",
        f"same-origin redirect to {location}; re-deciding",
    )
    if not origins_equal(original_url, location):
        return HttpsEgressResult(
            forwarded=False,
            wire_bytes=original_wire,
            wire_digest=original_digest,
            response_digest="",
            record_hash=original_record.record_hash,
            status="indeterminate",
        )
    wire, wire_digest = freeze_https_egress(method=method, url=location, body=body)
    assert_text_has_no_secrets(wire.decode("utf-8", errors="replace"), credentials)
    if hasattr(upstream, "url"):
        upstream.url = location
        upstream.identity = "https-egress:" + location
    verdict = _decide_https(
        middleware,
        agent_api_key=agent_api_key,
        session_id=session_id,
        client_identity=client_identity,
        capability=capability,
        method=method,
        url=location,
        wire_digest=wire_digest,
    )
    if verdict.decision != "allow" or not verdict.record_hash:
        return _refuse(
            wire=wire, wire_digest=wire_digest, record_hash=verdict.record_hash
        )
    record = _lookup_record(middleware, verdict.record_hash)
    try:
        upstream.write(wire)
    except SameOriginRedirectError:
        return _complete_indeterminate(
            middleware,
            record,
            wire=wire,
            wire_digest=wire_digest,
            detail="same-origin redirect hop budget exhausted",
        )
    except (
        CrossOriginRedirectError,
        ConnectionError,
        OSError,
        FramingProtocolError,
    ) as exc:
        return _complete_indeterminate(
            middleware,
            record,
            wire=wire,
            wire_digest=wire_digest,
            detail=f"https egress failed after re-decision: {exc}",
        )
    last_body = bytes(getattr(upstream, "last_body", b""))
    return _complete_ok(
        middleware,
        record,
        wire=wire,
        wire_digest=wire_digest,
        response_digest=sha256_bytes_digest(last_body),
    )


def dispatch_https_egress(
    *,
    middleware: ConnectorMiddleware,
    upstream: Any,
    credentials: UpstreamCredentials,
    agent_api_key: str,
    session_id: str,
    client_identity: str,
    capability: str,
    method: str,
    url: str,
    body: bytes,
    max_same_origin_redirects: int = 1,
) -> HttpsEgressResult:
    """Decide → freeze exact bytes → send only those bytes → witness response."""
    upstream.bind_session(session_id)
    wire, wire_digest = freeze_https_egress(method=method, url=url, body=body)
    assert_text_has_no_secrets(wire.decode("utf-8", errors="replace"), credentials)
    verdict = _decide_https(
        middleware,
        agent_api_key=agent_api_key,
        session_id=session_id,
        client_identity=client_identity,
        capability=capability,
        method=method,
        url=url,
        wire_digest=wire_digest,
    )
    if verdict.decision != "allow" or not verdict.record_hash:
        return _refuse(
            wire=wire, wire_digest=wire_digest, record_hash=verdict.record_hash
        )
    record = _lookup_record(middleware, verdict.record_hash)
    try:
        upstream.write(wire)
    except SameOriginRedirectError as exc:
        if max_same_origin_redirects < 1:
            return _complete_indeterminate(
                middleware,
                record,
                wire=wire,
                wire_digest=wire_digest,
                detail="same-origin redirect hop budget exhausted",
            )
        return _redecide_https_redirect(
            middleware=middleware,
            upstream=upstream,
            credentials=credentials,
            agent_api_key=agent_api_key,
            session_id=session_id,
            client_identity=client_identity,
            capability=capability,
            method=method,
            original_url=url,
            location=exc.location,
            body=body,
            original_record=record,
            original_wire=wire,
            original_digest=wire_digest,
        )
    except (
        CrossOriginRedirectError,
        ConnectionError,
        OSError,
        FramingProtocolError,
    ) as exc:
        return _complete_indeterminate(
            middleware,
            record,
            wire=wire,
            wire_digest=wire_digest,
            detail=f"https egress failed after allow: {exc}",
        )
    last_body = bytes(getattr(upstream, "last_body", b""))
    return _complete_ok(
        middleware,
        record,
        wire=wire,
        wire_digest=wire_digest,
        response_digest=sha256_bytes_digest(last_body),
    )


def handle_https_egress_http(
    gateway: Any,
    body: bytes,
    *,
    method: str = "POST",
) -> tuple[int, bytes, dict[str, str]]:
    """Mediate one named-HTTPS POST from the local client. Not JSON-RPC."""
    result = gateway.dispatch_named_https(method=method, body=body)
    extra: dict[str, str] = {}
    if result.wire_digest:
        extra["x-pv-request-digest"] = result.wire_digest
    if result.response_digest:
        extra["x-pv-response-digest"] = result.response_digest
    if result.forwarded:
        upstream_body = bytes(getattr(gateway.upstream, "last_body", b""))
        return (
            200,
            upstream_body,
            {"content-type": "application/octet-stream", **extra},
        )
    status_code = 403 if result.status == "refused" else 502
    payload = json.dumps(
        {
            "status": result.status,
            "forwarded": False,
            "record_hash": result.record_hash,
            "wire_digest": result.wire_digest,
        }
    ).encode("utf-8")
    return status_code, payload, {"content-type": "application/json", **extra}


def build_https_egress_asgi_app(gateway: Any) -> Callable[..., Any]:
    """POST /egress (or /) with the SaaS body; GET /ops for summary.

    Destination is the operator-named URL. Method comes from
    ``X-PV-Http-Method`` (default POST). This is not an MCP proxy.
    """

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        path = scope.get("path", "/")
        method = scope.get("method", "GET")
        if method == "GET" and path in {"/ops", "/v1/gateway/ops"}:
            body = json.dumps(gateway.ops_summary()).encode("utf-8")
            await _send_http(send, 200, body, {"content-type": "application/json"})
            return
        if method == "POST" and path in {"/egress", "/"}:
            chunks: list[bytes] = []
            while True:
                event = await receive()
                if event["type"] == "http.request":
                    chunks.append(event.get("body", b""))
                    if not event.get("more_body"):
                        break
            http_method = _header(scope, b"x-pv-http-method") or "POST"
            status, body, headers = handle_https_egress_http(
                gateway, b"".join(chunks), method=http_method
            )
            await _send_http(send, status, body, headers)
            return
        await _send_http(
            send,
            404,
            b'{"error":"not found"}',
            {"content-type": "application/json"},
        )

    return app


def _header(scope: dict[str, Any], name: bytes) -> str:
    for key, value in scope.get("headers") or []:
        if key == name:
            return bytes(value).decode("ascii")
    return ""


async def _send_http(
    send: Any,
    status: int,
    body: bytes,
    headers: dict[str, str],
) -> None:
    header_pairs = [(k.encode("ascii"), v.encode("ascii")) for k, v in headers.items()]
    header_pairs.append((b"content-length", str(len(body)).encode("ascii")))
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": header_pairs,
        }
    )
    await send({"type": "http.response.body", "body": body})
