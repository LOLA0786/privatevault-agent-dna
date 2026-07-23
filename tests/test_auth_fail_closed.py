"""The API fails closed when no auth is configured.

Reproduced from an external release audit: with PV_API_KEYS_FILE unset,
ApiKeyRegistry.enabled is False and every enforcement endpoint ran in
"auth-disabled" mode -- an open enforcement API by omission. The open
state is now reachable only via an explicit PV_ALLOW_NO_AUTH opt-in.
"""

import pytest

from agent_dna.apikeys import ApiKeyRegistry
from api.server import _assert_auth_configured


def test_no_keys_no_override_refuses_startup(monkeypatch):
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    with pytest.raises(RuntimeError, match="refuses to start"):
        _assert_auth_configured(auth_enabled=False)


def test_explicit_override_permits_startup(monkeypatch):
    monkeypatch.setenv("PV_ALLOW_NO_AUTH", "1")
    _assert_auth_configured(auth_enabled=False)


def test_configured_keys_start_normally(monkeypatch):
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    _assert_auth_configured(auth_enabled=True)


def test_registry_without_keys_file_is_disabled(monkeypatch):
    """Ground truth for the bug: no keys file means auth is off."""
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    assert ApiKeyRegistry().enabled is False
