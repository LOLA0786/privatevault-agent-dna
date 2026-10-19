"""ASGI entry point: ``uvicorn network.receiver_kit.app:app``.

Configuration comes from the environment (see ``config.py``). A bad or
missing setting raises at import time, so uvicorn exits instead of serving an
unconfigured gate. uvicorn cannot require client certificates, so this entry
point serves plain HTTP and therefore needs ``PV_RECEIVER_ALLOW_PLAINTEXT=1``;
the image runs ``serve.py``, which serves mutual TLS.
"""

from __future__ import annotations

import sys

from agent_dna.receiver.asgi import ReceiverGateProxy
from network.receiver_kit.config import (
    ConfigError,
    build_gate,
    describe,
    settings_from_env,
)
from network.receiver_kit.revocations import start_refresher

settings = settings_from_env()
if settings.mtls:
    raise ConfigError(
        "uvicorn cannot require client certificates: run "
        "`python -m network.receiver_kit.serve` for mutual TLS"
    )
gate = build_gate(settings)
app = ReceiverGateProxy(
    gate, settings.upstream, allow_http_upstream=settings.allow_http_upstream
)
print(describe(settings, gate), file=sys.stderr, flush=True)
refresher = start_refresher(gate, settings)
