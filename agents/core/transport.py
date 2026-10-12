"""Demo-grade sidecar transport that writes into an in-process receiver.

DEMO GRADE. ``peer_identity_bytes`` is a fixed label (``tls-spki:<receiver>``),
not an authenticated certificate: there is no TLS here because the receiver
runs in the same process. The production transport is
``TlsHttpsSidecarTransport``, which derives peer identity from the handshake.
Everything else is faithful: the sidecar verifies, consumes, writes the exact
bytes once, presents the permit header, and signs witness and closure over
what came back.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_dna.connector.adapters.sidecar_transport import SidecarSendResult


class AsgiSidecarSession:
    def __init__(
        self, client: Any, peer_identity_bytes: bytes, transport: AsgiSidecarTransport
    ):
        self.client = client
        self.peer_identity_bytes = peer_identity_bytes
        self.closed = False
        self._transport = transport

    def write(
        self,
        wire: bytes,
        *,
        operation: str,
        extra_headers: Mapping[str, str] | None = None,
    ) -> SidecarSendResult:
        if self.closed:
            raise RuntimeError("session closed")
        method, path = operation.split(None, 1)
        headers = {"Content-Type": "application/json", **dict(extra_headers or {})}
        response = self.client.request(
            method.upper(), path, content=wire, headers=headers
        )
        self._transport.last_response_headers = {
            k.lower(): v for k, v in response.headers.items()
        }
        return SidecarSendResult(
            peer_identity_bytes=self.peer_identity_bytes,
            bytes_committed=wire,
            response_body=bytes(response.content),
            send_began=True,
            http_status=int(response.status_code),
        )

    def close(self) -> None:
        self.closed = True


class AsgiSidecarTransport:
    """``SidecarTransport`` over any client with ``.request(method, path, ...)``."""

    allowed_destinations: frozenset[str] = frozenset()
    allowed_audiences: frozenset[str] = frozenset()
    credentials_headers: dict[str, str] = {}

    def __init__(self, client: Any, *, peer_label: str) -> None:
        self.client = client
        self.peer_identity_bytes = peer_label.encode("utf-8")
        self.last_response_headers: dict[str, str] = {}

    def connect(
        self, destination: str, *, credential_audience: str = ""
    ) -> AsgiSidecarSession:
        return AsgiSidecarSession(self.client, self.peer_identity_bytes, self)
