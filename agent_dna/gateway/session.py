"""Per-connection session identity for bypass measurement."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GatewaySession:
    session_id: str
    client_identity: str
    upstream_identity: str
    transport: str
    started_at: float = field(default_factory=time.time)
    # Non-mintable audit of passthrough methods (initialize, tools/list, …).
    passthrough_log: list[dict[str, Any]] = field(default_factory=list)

    def record_passthrough(self, method: str, request_id: Any) -> None:
        self.passthrough_log.append(
            {
                "method": method,
                "request_id": request_id,
                "at": time.time(),
            }
        )


def new_session_id() -> str:
    return "gws_" + secrets.token_hex(16)
