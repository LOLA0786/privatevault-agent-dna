"""ASGI entry point: ``uvicorn network.receiver_kit.app:app``.

Configuration comes from the environment (see ``config.py``). A bad or
missing setting raises at import time, so uvicorn exits instead of serving an
unconfigured gate.
"""

from __future__ import annotations

import sys

from agent_dna.receiver.asgi import ReceiverGateProxy
from network.receiver_kit.config import build_gate, describe, settings_from_env

settings = settings_from_env()
gate = build_gate(settings)
app = ReceiverGateProxy(
    gate, settings.upstream, allow_http_upstream=settings.allow_http_upstream
)
print(describe(settings, gate), file=sys.stderr, flush=True)
