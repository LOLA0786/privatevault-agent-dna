"""Sidecar-owned egress transport.

Production owns destination routing, credentials, TLS validation, and the
exact bytes written. An arbitrary ``SendFn`` callback is test-only and does
not prove those bytes reached a peer.

Each ``connect`` returns a per-dispatch session. The transport object must
not store a shared live connection.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.client import HTTPSConnection
from typing import Any, Protocol
from urllib.parse import urlparse

SendFn = Callable[[bytes, Mapping[str, Any]], Any]

DEFAULT_MAX_RESPONSE_BODY_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_RESPONSE_HEADER_BYTES = 64 * 1024

DISPATCH_CREDENTIAL_MISMATCH = "DISPATCH_CREDENTIAL_MISMATCH"
DISPATCH_RESPONSE_OVERSIZE = "DISPATCH_RESPONSE_OVERSIZE"


class SidecarResponseError(RuntimeError):
    """Raised after the request was written, while reading the response."""

    send_began = True


class SidecarResponseOversizeError(SidecarResponseError):
    """Response headers or body exceeded the sidecar bound."""


@dataclass(frozen=True)
class SidecarSendResult:
    """What the sidecar independently observed at the wire."""

    peer_identity_bytes: bytes
    bytes_committed: bytes
    response_body: bytes
    send_began: bool
    http_status: int


class SidecarSession(Protocol):
    peer_identity_bytes: bytes
    closed: bool

    def write(self, wire: bytes, *, operation: str) -> SidecarSendResult:
        """Write ``wire`` on this session's authenticated connection."""

    def close(self) -> None:
        """Release the connection. Idempotent."""


class SidecarTransport(Protocol):
    def connect(
        self, destination: str, *, credential_audience: str = ""
    ) -> SidecarSession:
        """TLS handshake for one dispatch. Must not send the request body."""


def _split_operation(operation: str) -> tuple[str, str]:
    parts = operation.strip().split(None, 1)
    if len(parts) != 2:
        raise ValueError(f"sidecar operation is not METHOD PATH: {operation!r}")
    method, path = parts[0].upper(), parts[1]
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
        raise ValueError(f"sidecar HTTP method {method!r} is not enumerated")
    if not path.startswith("/"):
        raise ValueError("sidecar path must be absolute")
    return method, path


def _parse_https_destination(destination: str) -> tuple[str, int]:
    parsed = urlparse(destination if "://" in destination else "https://" + destination)
    if parsed.scheme != "https":
        raise RuntimeError("sidecar egress is HTTPS-only")
    host = parsed.hostname
    if not host:
        raise RuntimeError("sidecar destination has no hostname")
    return host, parsed.port or 443


def require_credential_binding(
    *,
    destination: str,
    credential_audience: str,
    allowed_destinations: frozenset[str],
    allowed_audiences: frozenset[str],
    has_credentials: bool,
) -> None:
    """Refuse credential attachment unless destination and audience match."""
    dest_host, _port = _parse_https_destination(destination)
    allowed_hosts = allowed_destinations
    if has_credentials:
        if not allowed_hosts or not allowed_audiences:
            raise RuntimeError(
                "sidecar credentials require an allowlisted destination and "
                "credential_audience before they may be attached"
            )
        if destination not in allowed_hosts and dest_host not in allowed_hosts:
            raise RuntimeError(
                f"sidecar destination {destination!r} is not in the credential "
                "allowlist"
            )
        if credential_audience not in allowed_audiences:
            raise RuntimeError(
                f"sidecar credential_audience {credential_audience!r} is not "
                "in the credential allowlist"
            )
        return
    if (
        allowed_hosts
        and destination not in allowed_hosts
        and dest_host not in allowed_hosts
    ):
        raise RuntimeError(f"sidecar destination {destination!r} is not allowlisted")


def _header_bytes_len(headers: Mapping[str, str]) -> int:
    total = 0
    for key, value in headers.items():
        total += len(str(key).encode("latin-1")) + len(str(value).encode("latin-1")) + 4
    return total


def _read_bounded_body(resp: Any, *, max_bytes: int) -> bytes:
    buf = bytearray()
    while True:
        chunk = resp.read(min(65536, max_bytes + 1 - len(buf)))
        if not chunk:
            return bytes(buf)
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise SidecarResponseOversizeError(
                f"sidecar response body exceeds max_response_bytes {max_bytes}"
            )


@dataclass
class RecordingSidecarSession:
    parent: RecordingSidecarTransport
    peer_identity_bytes: bytes
    http_status: int
    closed: bool = False

    def write(self, wire: bytes, *, operation: str) -> SidecarSendResult:
        if self.closed:
            raise RuntimeError("sidecar session already closed")
        if not self.parent._handshook:
            raise RuntimeError("sidecar write before TLS handshake")
        self.parent.last_operation = operation
        committed = (
            self.parent.substitute_bytes
            if self.parent.substitute_bytes is not None
            else wire
        )
        self.parent.writes.append(committed)
        if self.parent.write_error is not None:
            raise self.parent.write_error
        return SidecarSendResult(
            peer_identity_bytes=self.peer_identity_bytes,
            bytes_committed=committed,
            response_body=self.parent.response_body,
            send_began=True,
            http_status=self.http_status,
        )

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.parent.close_count += 1


@dataclass
class RecordingSidecarTransport:
    """Test double: records exact writes and returns a configured TLS peer."""

    peer_identity: bytes
    writes: list[bytes] = field(default_factory=list)
    handshake_error: BaseException | None = None
    write_error: BaseException | None = None
    substitute_bytes: bytes | None = None
    destination_seen: str = ""
    last_operation: str = ""
    handshake_count: int = 0
    close_count: int = 0
    http_status: int = 200
    response_body: bytes = b'{"ok":true}'
    allowed_destinations: frozenset[str] = field(default_factory=frozenset)
    allowed_audiences: frozenset[str] = field(default_factory=frozenset)
    credentials_headers: Mapping[str, str] = field(default_factory=dict)
    _handshook: bool = False

    def connect(
        self, destination: str, *, credential_audience: str = ""
    ) -> RecordingSidecarSession:
        require_credential_binding(
            destination=destination,
            credential_audience=credential_audience,
            allowed_destinations=self.allowed_destinations,
            allowed_audiences=self.allowed_audiences,
            has_credentials=bool(self.credentials_headers),
        )
        self.handshake_count += 1
        self.destination_seen = destination
        if self.handshake_error is not None:
            raise self.handshake_error
        self._handshook = True
        return RecordingSidecarSession(
            parent=self,
            peer_identity_bytes=self.peer_identity,
            http_status=self.http_status,
        )


@dataclass
class CallbackSidecarSession:
    parent: CallbackSidecarTransport
    peer_identity_bytes: bytes
    closed: bool = False

    def write(self, wire: bytes, *, operation: str) -> SidecarSendResult:
        del operation
        if self.closed:
            raise RuntimeError("sidecar session already closed")
        self.parent.writes.append(wire)
        response = self.parent.send(wire, {})
        body = b""
        status = 200
        if isinstance(response, (bytes, bytearray)):
            body = bytes(response)
        elif isinstance(response, Mapping) and "status" in response:
            raw = response.get("status")
            if isinstance(raw, int):
                status = raw
        return SidecarSendResult(
            peer_identity_bytes=self.peer_identity_bytes,
            bytes_committed=wire,
            response_body=body,
            send_began=True,
            http_status=status,
        )

    def close(self) -> None:
        self.closed = True
        self.parent.close_count += 1


@dataclass
class CallbackSidecarTransport:
    """Test-only callback wrapper. Does not prove bytes on the wire."""

    send: SendFn
    peer_identity: bytes
    writes: list[bytes] = field(default_factory=list)
    destination_seen: str = ""
    close_count: int = 0

    def connect(
        self, destination: str, *, credential_audience: str = ""
    ) -> CallbackSidecarSession:
        del credential_audience
        self.destination_seen = destination
        return CallbackSidecarSession(
            parent=self, peer_identity_bytes=self.peer_identity
        )


class TlsHttpsSidecarSession:
    """One dispatch's TLS connection. Not shared across calls."""

    def __init__(
        self,
        *,
        conn: HTTPSConnection,
        peer_identity_bytes: bytes,
        headers: Mapping[str, str],
        max_response_bytes: int,
        max_header_bytes: int,
    ) -> None:
        self.peer_identity_bytes = peer_identity_bytes
        self.closed = False
        self._conn: HTTPSConnection | None = conn
        self._headers = dict(headers)
        self._max_response_bytes = max_response_bytes
        self._max_header_bytes = max_header_bytes

    def write(self, wire: bytes, *, operation: str) -> SidecarSendResult:
        if self.closed or self._conn is None:
            raise RuntimeError("sidecar session already closed")
        method, path = _split_operation(operation)
        headers = {
            "Content-Type": "application/octet-stream",
            **self._headers,
        }
        self._conn.request(method, path, body=wire, headers=headers)
        try:
            resp = self._conn.getresponse()
            header_map = {k: v for k, v in resp.getheaders()}
            if _header_bytes_len(header_map) > self._max_header_bytes:
                raise SidecarResponseOversizeError(
                    "sidecar response headers exceed max_header_bytes "
                    f"{self._max_header_bytes}"
                )
            body = _read_bounded_body(resp, max_bytes=self._max_response_bytes)
        except SidecarResponseOversizeError:
            raise
        except Exception as exc:
            raise SidecarResponseError(f"{type(exc).__name__}: {exc}") from exc
        return SidecarSendResult(
            peer_identity_bytes=self.peer_identity_bytes,
            bytes_committed=wire,
            response_body=body,
            send_began=True,
            http_status=int(resp.status),
        )

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        conn = self._conn
        self._conn = None
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


@dataclass
class TlsHttpsSidecarTransport:
    """Production sole-egress HTTPS transport.

    Destination comes from the sealed dispatch record. Credentials and TLS
    verification stay here. Peer identity is the DER of the authenticated
    TLS certificate — never a caller-supplied byte string.

    Each ``connect`` allocates a new connection. Nothing is stored on this
    object that another dispatch could observe.
    """

    credentials_headers: Mapping[str, str] = field(default_factory=dict)
    allowed_destinations: frozenset[str] = field(default_factory=frozenset)
    allowed_audiences: frozenset[str] = field(default_factory=frozenset)
    timeout_s: float = 30.0
    tls_verify: bool = True
    ca_file: str | None = None
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BODY_BYTES
    max_header_bytes: int = DEFAULT_MAX_RESPONSE_HEADER_BYTES

    def connect(
        self, destination: str, *, credential_audience: str = ""
    ) -> TlsHttpsSidecarSession:
        require_credential_binding(
            destination=destination,
            credential_audience=credential_audience,
            allowed_destinations=self.allowed_destinations,
            allowed_audiences=self.allowed_audiences,
            has_credentials=bool(self.credentials_headers),
        )
        host, port = _parse_https_destination(destination)
        if not self.tls_verify:
            raise RuntimeError("production sidecar refuses TLS verification off")
        ctx = ssl.create_default_context()
        if self.ca_file:
            ctx.load_verify_locations(cafile=self.ca_file)
        headers = dict(self.credentials_headers)
        conn = HTTPSConnection(host, port=port, timeout=self.timeout_s, context=ctx)
        try:
            conn.connect()
            sock = conn.sock
            if sock is None or not hasattr(sock, "getpeercert"):
                raise RuntimeError("sidecar TLS handshake produced no peer certificate")
            der = sock.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("sidecar TLS peer certificate is empty")
        except Exception:
            try:
                conn.close()
            except OSError:
                pass
            raise
        return TlsHttpsSidecarSession(
            conn=conn,
            peer_identity_bytes=bytes(der),
            headers=headers,
            max_response_bytes=self.max_response_bytes,
            max_header_bytes=self.max_header_bytes,
        )
