"""Gateway metrics — never authorize; labels must never carry secrets."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GatewayMetrics:
    sessions_started: int = 0
    tools_calls_mediated: int = 0
    tools_calls_allowed: int = 0
    tools_calls_denied: int = 0
    tools_calls_require_approval: int = 0
    tools_calls_indeterminate: int = 0
    passthrough_recorded: int = 0
    # Operator-supplied: sessions the upstream observed that did not
    # present a gateway session token / attribution header.
    upstream_unattributed_sessions: int = 0
    _session_ids: set[str] = field(default_factory=set)

    def note_session(self, session_id: str) -> None:
        if session_id not in self._session_ids:
            self._session_ids.add(session_id)
            self.sessions_started += 1

    def note_upstream_unattributed(self, count: int = 1) -> None:
        if count < 0:
            raise ValueError("count must be non-negative")
        self.upstream_unattributed_sessions += count

    def ops_fields(self) -> dict[str, int]:
        """Safe ops summary — integers only, no credential material."""
        return {
            "gateway_sessions_started": self.sessions_started,
            "gateway_tools_calls_mediated": self.tools_calls_mediated,
            "gateway_tools_calls_allowed": self.tools_calls_allowed,
            "gateway_tools_calls_denied": self.tools_calls_denied,
            "gateway_tools_calls_require_approval": self.tools_calls_require_approval,
            "gateway_tools_calls_indeterminate": self.tools_calls_indeterminate,
            "gateway_passthrough_recorded": self.passthrough_recorded,
            "upstream_unattributed_sessions": self.upstream_unattributed_sessions,
        }
