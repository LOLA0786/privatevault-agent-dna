"""Run the receiver gate: ``python -m network.receiver_kit.serve``.

This is the image's default command. With ``PV_RECEIVER_TLS_CERT``,
``PV_RECEIVER_TLS_KEY`` and ``PV_RECEIVER_CLIENT_CA`` set, the gate serves
HTTPS and requires every client to present a certificate signed by that CA;
the certificate's key is what a presenter-bound permit is checked against
(ADR 0022). Without them the gate does not start, unless
``PV_RECEIVER_ALLOW_PLAINTEXT=1`` (local demo) makes it serve plain HTTP.
With ``PV_REVOCATION_URL`` it keeps the signed revocation list fresh
(``revocations.py``). ``PV_RECEIVER_HOST`` / ``PV_RECEIVER_PORT`` default to
0.0.0.0:8080.
"""

from __future__ import annotations

import os
import sys

from agent_dna.receiver.asgi import ReceiverGateProxy
from agent_dna.receiver.tls import serve_mtls
from network.receiver_kit.config import build_gate, describe, settings_from_env
from network.receiver_kit.revocations import start_refresher


def main() -> int:
    settings = settings_from_env()
    gate = build_gate(settings)
    app = ReceiverGateProxy(
        gate, settings.upstream, allow_http_upstream=settings.allow_http_upstream
    )
    print(describe(settings, gate), file=sys.stderr, flush=True)
    start_refresher(gate, settings)
    host = os.environ.get("PV_RECEIVER_HOST", "0.0.0.0")  # noqa: S104 - container default
    port = int(os.environ.get("PV_RECEIVER_PORT", "8080"))
    if settings.mtls:
        assert settings.tls_cert_file and settings.tls_key_file
        assert settings.tls_client_ca_file
        serve_mtls(
            app,
            host=host,
            port=port,
            certfile=str(settings.tls_cert_file),
            keyfile=str(settings.tls_key_file),
            client_ca_file=str(settings.tls_client_ca_file),
        )
    else:
        import uvicorn

        uvicorn.run(app, host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
