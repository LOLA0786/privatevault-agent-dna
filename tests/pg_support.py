"""Shared PostgreSQL test support: a fresh database per test.

Tests mark themselves with ``requires_pg``; the ``dsn`` fixture lives in
conftest.py so every test module can request it.
They run when TEST_DATABASE_URL points at a server where the user may
create databases (CI starts PostgreSQL 16); otherwise they are skipped.
"""

from __future__ import annotations

import os

import pytest

ADMIN_URL = os.environ.get("TEST_DATABASE_URL", "")
requires_pg = pytest.mark.skipif(
    not ADMIN_URL, reason="set TEST_DATABASE_URL to run the PostgreSQL tests"
)
