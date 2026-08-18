"""Upstream credential isolation.

Credentials live only inside ``UpstreamCredentials`` and are applied
to the upstream process env or HTTP headers. They must never appear
in client messages, decision records, evidence, logs, or metrics.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from agent_dna.gateway.errors import CredentialLeakError

GATEWAY_SESSION_HEADER = "X-PV-Gateway-Session"
GATEWAY_SESSION_ENV = "PV_GATEWAY_SESSION_ID"

# Names copied from the parent into a stdio child. Secrets, cloud
# provider keys, and PV_* operator config are not on this list.
STDIO_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "LC_NUMERIC",
        "TZ",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
    }
)


def _leaks_secret_name(name: str) -> bool:
    upper = name.upper()
    if upper.startswith(("PV_", "AWS_", "GOOGLE_", "ANTHROPIC_", "OPENAI_")):
        return True
    return upper.endswith("_KEY") or upper.endswith("_TOKEN")


@dataclass(frozen=True)
class UpstreamCredentials:
    """Opaque upstream secrets. Values are never part of ``repr``."""

    env: Mapping[str, str] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return (
            f"UpstreamCredentials(env_keys={sorted(self.env)}, "
            f"header_keys={sorted(self.headers)})"
        )

    def secret_values(self) -> frozenset[str]:
        values = set(self.env.values()) | set(self.headers.values())
        return frozenset(v for v in values if v)

    def subprocess_env(
        self,
        base: Mapping[str, str] | None = None,
        *,
        session_id: str = "",
    ) -> dict[str, str]:
        src = dict(base) if base is not None else {}
        out: dict[str, str] = {}
        for key in STDIO_ENV_ALLOWLIST:
            if key in src and not _leaks_secret_name(key):
                value = src[key]
                if value:
                    out[key] = value
        out.update(self.env)
        if session_id:
            out[GATEWAY_SESSION_ENV] = session_id
        return out

    def http_headers(self, *, session_id: str = "") -> dict[str, str]:
        out = dict(self.headers)
        if session_id:
            out[GATEWAY_SESSION_HEADER] = session_id
        return out


def assert_text_has_no_secrets(text: str, credentials: UpstreamCredentials) -> None:
    """Fail closed if any credential value appears in ``text``."""
    for secret in credentials.secret_values():
        if secret and secret in text:
            raise CredentialLeakError(
                "upstream credential value present outside credential boundary"
            )


def scrub_mapping(value: Any, credentials: UpstreamCredentials) -> Any:
    """Recursively replace credential substrings in string leaves."""
    secrets = credentials.secret_values()
    if not secrets:
        return value

    def scrub(node: Any) -> Any:
        if isinstance(node, str):
            out = node
            for secret in secrets:
                if secret and secret in out:
                    out = out.replace(secret, "<redacted>")
            return out
        if isinstance(node, Mapping):
            return {str(k): scrub(v) for k, v in node.items()}
        if isinstance(node, list):
            return [scrub(v) for v in node]
        return node

    return scrub(value)
