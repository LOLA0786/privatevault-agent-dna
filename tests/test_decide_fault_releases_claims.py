"""ADR 0047: a decide that fails partway, after the engine allowed it and
before its record is sealed, gives back everything it claimed so far, and
fails closed: the caller gets an error, no record and no permit.

Here the daily-limit step raises after the transaction reservation was
claimed. Without the release, the reservation would block the honest retry
for the same refund until it lapsed.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

import api.server as server
from agent_dna.grants import GrantRegistry, collect_spend
from tests.test_decide_reservation import _decide, env  # noqa: F401 - fixture


def test_fault_before_the_seal_releases_the_reservation(env, monkeypatch):  # noqa: F811
    def store_down(*_args, **_kwargs):
        raise RuntimeError("limit store unavailable")

    monkeypatch.setattr(server, "_claim_decide_limit", store_down)
    with pytest.raises(RuntimeError, match="limit store unavailable"):
        _decide(env, {"refund_id": "RF-9", "amount": 1999})
    monkeypatch.undo()

    retry = _decide(env, {"refund_id": "RF-9", "amount": 1999})
    assert retry.status_code == 200, retry.text


def test_release_claims_gives_back_grant_spend():
    reg = GrantRegistry()
    g = reg.grant(
        agent_id="a1", capability="payments.issue_refund", granted_by="ops", budget=100
    )
    with collect_spend() as commits:
        reg.record_spend(g.grant_id, 40)
    assert g.spent == Decimal("40")
    server._release_claims(None, "holder", None, None, commits)
    assert g.spent == Decimal("0")
