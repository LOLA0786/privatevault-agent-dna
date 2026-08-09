"""Shared pytest fixtures and suite bootstrap."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_TESTS_DIR = Path(__file__).resolve().parent


def _prefer_local_tests_package() -> None:
    """Prefer this repo's ``tests`` package over ambient PYTHONPATH shadows."""
    root = str(_REPO_ROOT)
    while root in sys.path:
        sys.path.remove(root)
    sys.path.insert(0, root)

    existing = sys.modules.get("tests")
    if existing is None:
        return

    existing_paths = [Path(p).resolve() for p in getattr(existing, "__path__", [])]
    if _TESTS_DIR.resolve() in existing_paths:
        return

    for name in list(sys.modules):
        if name == "tests" or name.startswith("tests."):
            del sys.modules[name]


_prefer_local_tests_package()


@pytest.fixture(autouse=True, scope="session")
def _suite_opts_into_no_auth():
    """The suite boots API instances without a real key file. Since
    0.2.1 the API fails closed on missing auth config, so the suite
    opts in explicitly -- the same deliberate choice docker-compose and
    the CI smoke test make. Tests that exercise the auth gate itself
    override this with monkeypatch.delenv.
    """
    os.environ.setdefault("PV_ALLOW_NO_AUTH", "1")
    yield
