"""mTLS for the receiver gate: who presented the permit (ADR 0022).

The gate needs the TLS client certificate a request arrived with. ASGI has a
standard place for it (the ``tls`` extension, ``client_cert_chain`` as PEM),
but uvicorn does not fill it in. ``ClientCertH11Protocol`` is uvicorn's HTTP/1.1
protocol plus one step: when a TLS connection is made it reads the verified
client certificate from the connection and puts its DER into the scope of
every request on that connection (``scope["state"]``, from which no request
header or body can write). ``client_certificate(scope)`` reads either.

``serve_mtls`` runs an ASGI app with this protocol and a TLS server context
that requires a client certificate signed by the operator's client CA, so an
unauthenticated client never completes the handshake.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Mapping
from typing import Any

from uvicorn.protocols.http.h11_impl import H11Protocol

from agent_dna.presenter_identity import certificate_der_from_pem

STATE_KEY = "pv.tls.client_certificate_der"


def client_certificate(scope: Mapping[str, Any]) -> bytes | None:
    """DER of the request's TLS client certificate, or None."""
    tls = (scope.get("extensions") or {}).get("tls")
    if isinstance(tls, Mapping):
        chain = tls.get("client_cert_chain") or []
        if chain:
            return certificate_der_from_pem(chain[0])
        return None
    state = scope.get("state")
    if isinstance(state, Mapping):
        der = state.get(STATE_KEY)
        if isinstance(der, bytes | bytearray) and der:
            return bytes(der)
    return None


class ClientCertH11Protocol(H11Protocol):
    """uvicorn HTTP/1.1 that exposes the verified TLS client certificate."""

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        ssl_object = transport.get_extra_info("ssl_object")
        der = (
            ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        )
        # A fresh dict per connection: the request scopes of this connection
        # copy it, other connections never see it.
        self.app_state = {**self.app_state, STATE_KEY: der or None}


def serve_mtls(
    app: Any,
    *,
    host: str,
    port: int,
    certfile: str,
    keyfile: str,
    client_ca_file: str,
    log_level: str = "info",
) -> None:
    """Serve ``app`` over TLS, requiring a client certificate from the CA."""
    import uvicorn

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        http=ClientCertH11Protocol,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        ssl_ca_certs=client_ca_file,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        log_level=log_level,
    )
    uvicorn.Server(config).run()
