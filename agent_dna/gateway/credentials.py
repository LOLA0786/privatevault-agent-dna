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

    def subprocess_env(self, base: Mapping[str, str] | None = None) -> dict[str, str]:
        out = dict(base or {})
        out.update(self.env)
        return out

    def http_headers(self) -> dict[str, str]:
        return dict(self.headers)


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
