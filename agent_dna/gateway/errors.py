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
