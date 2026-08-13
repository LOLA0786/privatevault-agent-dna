"""Sidecar-owned egress transport.

Production owns destination routing, credentials, TLS validation, and the
exact bytes written. An arbitrary ``SendFn`` callback is test-only and does
not prove those bytes reached a peer.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.client import HTTPSConnection
from typing import Any, Protocol
from urllib.parse import urlparse

SendFn = Callable[[bytes, Mapping[str, Any]], Any]


@dataclass(frozen=True)
class SidecarSendResult:
    """What the sidecar independently observed at the wire."""

    peer_identity_bytes: bytes
    bytes_committed: bytes
    response_body: bytes
    send_began: bool


class SidecarTransport(Protocol):
    def handshake(self, destination: str) -> bytes:
        """Authenticate the peer (TLS). Must not send the request body."""

    def write(self, wire: bytes, *, operation: str) -> SidecarSendResult:
        """Write ``wire`` on the already-authenticated connection."""


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
    _handshook: bool = False

    def handshake(self, destination: str) -> bytes:
        self.destination_seen = destination
        if self.handshake_error is not None:
            raise self.handshake_error
        self._handshook = True
        return self.peer_identity

    def write(self, wire: bytes, *, operation: str) -> SidecarSendResult:
        if not self._handshook:
            raise RuntimeError("sidecar write before TLS handshake")
        self.last_operation = operation
        committed = self.substitute_bytes if self.substitute_bytes is not None else wire
        self.writes.append(committed)
        if self.write_error is not None:
            raise self.write_error
        return SidecarSendResult(
            peer_identity_bytes=self.peer_identity,
            bytes_committed=committed,
            response_body=b'{"ok":true}',
            send_began=True,
        )


@dataclass
class CallbackSidecarTransport:
    """Test-only callback wrapper. Does not prove bytes on the wire."""

    send: SendFn
    peer_identity: bytes
    writes: list[bytes] = field(default_factory=list)
    destination_seen: str = ""

    def handshake(self, destination: str) -> bytes:
        self.destination_seen = destination
        return self.peer_identity

    def write(self, wire: bytes, *, operation: str) -> SidecarSendResult:
        del operation
        self.writes.append(wire)
        response = self.send(wire, {})
        body = b""
        if isinstance(response, (bytes, bytearray)):
            body = bytes(response)
        return SidecarSendResult(
            peer_identity_bytes=self.peer_identity,
            bytes_committed=wire,
            response_body=body,
            send_began=True,
        )


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


@dataclass
class TlsHttpsSidecarTransport:
    """Production sole-egress HTTPS transport.

    Destination comes from the sealed dispatch record. Credentials and TLS
    verification stay here. Peer identity is the DER of the authenticated
    TLS certificate — never a caller-supplied byte string.
    """

    credentials_headers: Mapping[str, str] = field(default_factory=dict)
    timeout_s: float = 30.0
    tls_verify: bool = True
    _conn: HTTPSConnection | None = field(default=None, init=False, repr=False)
    _peer: bytes = field(default=b"", init=False, repr=False)
    _destination: str = field(default="", init=False, repr=False)

    def handshake(self, destination: str) -> bytes:
        parsed = urlparse(
            destination if "://" in destination else "https://" + destination
        )
        if parsed.scheme != "https":
            raise RuntimeError("sidecar egress is HTTPS-only")
        host = parsed.hostname
        if not host:
            raise RuntimeError("sidecar destination has no hostname")
        port = parsed.port or 443
        ctx = ssl.create_default_context()
        if not self.tls_verify:
            raise RuntimeError("production sidecar refuses TLS verification off")
        conn = HTTPSConnection(host, port=port, timeout=self.timeout_s, context=ctx)
        conn.connect()
        sock = conn.sock
        if sock is None or not hasattr(sock, "getpeercert"):
            conn.close()
            raise RuntimeError("sidecar TLS handshake produced no peer certificate")
        der = sock.getpeercert(binary_form=True)
        if not der:
            conn.close()
            raise RuntimeError("sidecar TLS peer certificate is empty")
        self._conn = conn
        self._peer = bytes(der)
        self._destination = host
        return self._peer

    def write(self, wire: bytes, *, operation: str) -> SidecarSendResult:
        if self._conn is None:
            raise RuntimeError("sidecar write before TLS handshake")
        method, path = _split_operation(operation)
        headers = {
            "Content-Type": "application/octet-stream",
            **dict(self.credentials_headers),
        }
        try:
            self._conn.request(method, path, body=wire, headers=headers)
            resp = self._conn.getresponse()
            body = resp.read()
        except Exception:
            self._close()
            raise
        peer = self._peer
        self._close()
        return SidecarSendResult(
            peer_identity_bytes=peer,
            bytes_committed=wire,
            response_body=body,
            send_began=True,
        )

    def _close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None
