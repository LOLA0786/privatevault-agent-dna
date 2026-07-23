"""Shared pytest fixtures."""


import os

import pytest


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
