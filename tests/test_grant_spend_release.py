"""ADR 0046: grant spend a decide committed but did not keep is given back.

The API server opens collect_spend() around the engine; when a later control
refuses the decide (facts, reservation, daily limit, chain budget) or the
record cannot be written, _seal_decision releases what was committed. Here:
the SQLite ledger's release, the registry's release, and what is collected.
End to end: tests/demos/test_live_checkout_grant_spend.py. PostgreSQL:
tests/test_pg_grants.py.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from agent_dna.grant_spend import GrantBudgetExceededError, GrantSpendLedger
from agent_dna.grants import GrantRegistry, collect_spend, release_spend


def _registry(budget: float = 1000, ledger: GrantSpendLedger | None = None):
    reg = GrantRegistry()
    if ledger is not None:
        reg.attach_spend_ledger(ledger)
    g = reg.grant(
        agent_id="a1",
        capability="payments.issue_refund",
        granted_by="ops@corp",
        budget=budget,
    )
    return reg, g


def test_sqlite_release_gives_back_and_never_goes_below_zero(tmp_path):
    ledger = GrantSpendLedger(tmp_path / "spend.db")
    ledger.commit_spend("g1", Decimal("100.50"), 1000)
    assert ledger.release_spend("g1", Decimal("40.25")) == Decimal("60.25")
    assert ledger.spent("g1") == Decimal("60.25")
    assert ledger.release_spend("g1", 500) == Decimal("0")
    assert ledger.spent("g1") == Decimal("0")


def test_sqlite_release_of_an_uncharged_grant_creates_no_row(tmp_path):
    ledger = GrantSpendLedger(tmp_path / "spend.db")
    assert ledger.release_spend("never-charged", 10) == Decimal("0")
    rows = ledger._conn.execute("SELECT COUNT(*) FROM grant_spend").fetchone()
    assert rows[0] == 0


@pytest.mark.parametrize("durable", [False, True])
def test_registry_release_matches_its_commit(tmp_path, durable):
    ledger = GrantSpendLedger(tmp_path / "spend.db") if durable else None
    reg, g = _registry(ledger=ledger)
    reg.record_spend(g.grant_id, 300)
    reg.release_spend(g.grant_id, 100)
    assert g.spent == Decimal("200")
    if ledger is not None:
        assert ledger.spent(g.grant_id) == Decimal("200")


def test_only_commits_inside_the_block_are_collected():
    reg, g = _registry()
    reg.record_spend(g.grant_id, 10)
    with collect_spend() as commits:
        reg.record_spend(g.grant_id, 20)
    reg.record_spend(g.grant_id, 30)
    assert [(c.grant_id, c.amount) for c in commits] == [(g.grant_id, Decimal("20"))]
    release_spend(commits)
    assert g.spent == Decimal("40")
    release_spend(None)  # nothing collected: nothing to give back
    assert g.spent == Decimal("40")


def test_a_refused_commit_is_not_collected():
    reg, g = _registry(budget=50)
    with collect_spend() as commits, pytest.raises(GrantBudgetExceededError):
        reg.record_spend(g.grant_id, 60)
    assert commits == []
    assert g.spent == Decimal("0")
