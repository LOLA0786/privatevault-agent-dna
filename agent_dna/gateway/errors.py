"""Gateway failure modes — all fail closed."""

from __future__ import annotations


class GatewayStartupError(RuntimeError):
    """Refused to start: missing runtime, identity, or upstream config."""


class ArgumentMutationRefusedError(RuntimeError):
    """Arguments changed between decide and the frozen upstream bytes."""


# Back-compat alias used in early drafts / docs.
ArgumentMutationRefused = ArgumentMutationRefusedError


class CredentialLeakError(RuntimeError):
    """A secret was about to leave the credential boundary."""


class UpstreamTimeoutError(TimeoutError):
    """Upstream did not answer after bytes were written."""


class ClientDisconnectedError(ConnectionError):
    """Client gone mid-call; must not seal a successful completion."""


class FramingProtocolError(ValueError):
    """Malformed MCP framing or JSON-RPC — never forward, never seal success."""


class UpstreamDeadError(ConnectionError):
    """Upstream process died or closed; in-flight calls are indeterminate."""


class CrossOriginRedirectError(ConnectionError):
    """HTTP redirect changed origin after the dispatch destination was sealed."""


class UnmatchedResponseError(ValueError):
    """Upstream response id was never sent by this session."""


class DuplicateRequestIdError(ValueError):
    """JSON-RPC id is already in flight; refusing cross-bind."""


class UpstreamPrincipalChangedError(ConnectionError):
    """Upstream restarted; the new process is a different principal."""


class SameOriginRedirectError(ConnectionError):
    """Same-origin redirect: do not follow until a new decision is minted."""

    def __init__(self, location: str) -> None:
        self.location = location
        super().__init__(f"same-origin redirect requires re-decision: {location}")


class BypassDetectedError(RuntimeError):
    """Upstream reported sessions that lacked gateway attribution."""
