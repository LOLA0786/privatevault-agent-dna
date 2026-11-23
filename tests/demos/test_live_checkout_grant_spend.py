"""ADR 0046, end to end: a decide the engine allowed and charged to the
refund grant, then refused by a later control, gives the charge back.

Found by the continuous challenger's budget oracle: refused lies spent the
agent's grant until every honest refund waited for a human. Both refusals
here come after the engine: the fact check (ADR 0045) and the transaction
reservation (ADR 0041).
"""

from __future__ import annotations

import sqlite3
from decimal import Decimal
from typing import Any

from demos.live_checkout import attacks


def _spent(w: Any) -> Decimal:
    """What the refund grant has been charged, from the server's own ledger."""
    db = w.run_dir / "privatevault" / "pv.db"
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT spent FROM grant_spend").fetchall()
    finally:
        con.close()
    return sum((Decimal(r[0]) for r in rows), Decimal("0"))


def test_refused_decides_give_back_the_grant_spend(tmp_path):
    w = attacks.start_world(tmp_path / "run")
    try:
        before = _spent(w)
        # A lie the policy allows: the engine charges the grant, then the
        # system of record contradicts it.
        honest = w.arguments("ORD-70340", 3000, "kavya.n@okaxis")
        claim = honest["original_amount"] * 3
        lie = {
            **honest,
            "amount": claim,
            "original_amount": claim,
            "customer_amount_today_after": honest["customer_amount_today_after"]
            - honest["amount"]
            + claim,
        }
        refused = w.p.pv.decide(w.p.tool, lie)
        assert refused.decision == "block" and "FACTS_MISMATCH" in refused.reason
        assert _spent(w) == before

        # One refund decided twice before it is paid: the engine allows and
        # charges both; the reservation refuses the second.
        a = w.arguments("ORD-70234", 850, "card:visa-4421")
        first = w.p.pv.decide(w.p.tool, a)
        second = w.p.pv.decide(w.p.tool, a)
        assert first.allowed
        assert second.decision == "block"
        assert second.triggered_by == "transaction_reservation"
        assert _spent(w) == before + 850
    finally:
        attacks.stop_world(w)
