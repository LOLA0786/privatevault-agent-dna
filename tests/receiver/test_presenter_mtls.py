"""Presenter binding over real mTLS: the gate under uvicorn, real handshakes.

The gate runs as it does in production (``ClientCertH11Protocol`` with a TLS
context that requires a client certificate from the operator's CA) in front
of a real upstream. Agent A's permit binds A's client key. Then:

  - agent B, with its own valid certificate from the same CA, presents A's
    exact permit and bytes -> refused before the upstream, permit intact;
  - A presents them -> admitted and forwarded once; a second try is refused;
  - a client with a certificate from another CA, or none, cannot connect.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_dna.connector.adapters.sidecar_transport import TlsHttpsSidecarTransport
from agent_dna.presenter_identity import (
    certificate_der_from_file,
    presenter_identity_digest,
)
from agent_dna.receiver import gate as g
from agent_dna.receiver.asgi import ReceiverGateProxy
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from agent_dna.receiver.tls import ClientCertH11Protocol

from ._pki import Pki
from ._world import PARAMETERS, PATH, World, wire_for

uvicorn = pytest.importorskip("uvicorn")


class _Upstream(BaseHTTPRequestHandler):
    received: list[bytes] = []

    def do_POST(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).received.append(body)
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: object) -> None:
        return


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def deployment(tmp_path):
    pki = Pki(tmp_path / "pki")
    server_leaf = pki.leaf("gate", server=True)
    a, b = pki.leaf("agent-a"), pki.leaf("agent-b")
    rogue_ca = Pki(tmp_path / "rogue", name="rogue-ca")
    rogue = rogue_ca.leaf("rogue")

    _Upstream.received = []
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    world = World(tmp_path)
    app = ReceiverGateProxy(
        world.gate,
        f"http://127.0.0.1:{upstream.server_address[1]}",
        allow_http_upstream=True,
    )
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            http=ClientCertH11Protocol,
            ssl_certfile=str(server_leaf.cert),
            ssl_keyfile=str(server_leaf.key),
            ssl_ca_certs=str(pki.ca_cert),
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            log_level="warning",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started, "gate did not start"
    yield {"port": port, "pki": pki, "a": a, "b": b, "rogue": rogue, "world": world}
    server.should_exit = True
    thread.join(timeout=10)
    upstream.shutdown()


def _post(dep, leaf, permit):
    ctx = ssl.create_default_context(cafile=str(dep["pki"].ca_cert))
    if leaf is not None:
        ctx.load_cert_chain(str(leaf.cert), str(leaf.key))
    conn = http.client.HTTPSConnection(
        "127.0.0.1", dep["port"], context=ctx, timeout=10
    )
    try:
        body = wire_for(PARAMETERS)
        conn.request(
            "POST",
            PATH,
            body=body,
            headers={
                PERMIT_HEADER: encode_permit_header(permit),
                "Content-Type": "application/json",
            },
        )
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def _live_permit(world, presenter):
    now = datetime.now(UTC).replace(microsecond=0)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return world.permit(
        presenter=presenter,
        not_before=(now - timedelta(seconds=5)).strftime(fmt),
        expires_at=(now + timedelta(seconds=60)).strftime(fmt),
    )


def _digest(leaf):
    return presenter_identity_digest(certificate_der_from_file(leaf.cert))


def test_only_the_bound_presenter_gets_through(deployment):
    dep = deployment
    permit = _live_permit(dep["world"], _digest(dep["a"]))

    status, body = _post(dep, dep["b"], permit)  # valid cert, wrong key
    assert status == 403 and g.RECEIVER_PRESENTER_MISMATCH.encode() in body
    assert _Upstream.received == []  # never reached the system of record

    status, body = _post(dep, dep["a"], permit)  # the bound presenter
    assert status == 200, body
    assert _Upstream.received == [wire_for(PARAMETERS)]

    status, body = _post(dep, dep["a"], permit)  # single use still holds
    assert status == 409 and g.RECEIVER_PERMIT_CONSUMED.encode() in body
    assert len(_Upstream.received) == 1


@pytest.mark.parametrize("who", ["rogue", None])
def test_clients_without_a_trusted_certificate_cannot_connect(deployment, who):
    dep = deployment
    permit = _live_permit(dep["world"], _digest(dep["a"]))
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        _post(dep, dep[who] if who else None, permit)
    assert _Upstream.received == []


def test_sidecar_reports_the_digest_to_request(deployment):
    dep = deployment
    transport = TlsHttpsSidecarTransport(
        client_cert_file=str(dep["a"].cert), client_key_file=str(dep["a"].key)
    )
    assert transport.presenter_identity_digest == _digest(dep["a"])
    with pytest.raises(ValueError, match="go together"):
        TlsHttpsSidecarTransport(client_cert_file=str(dep["a"].cert))
