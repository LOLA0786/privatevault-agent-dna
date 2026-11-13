"""N-1 end to end: the agent side is made to mint a second permit; the
receiver does not execute it (ADR 0039).

Someone who can write the agent-side database deletes the row that made a
decision mint once, or the row that made an approval single-use, and gets a
second, valid, signed permit. These tests do exactly that against the real
server, then present both permits to a real receiver gate with its own
ledger. The first executes; the second is refused. Nothing here stops the
second MINT: that needs state outside the agent-side database.
"""

from __future__ import annotations

from datetime import timedelta

from agent_dna.receiver import gate as g
from tests.test_api_approval_bridge import (  # noqa: F401 - fixture
    PEER,
    WIRE,
    _decide,
    _dispatch,
    _execution_action,
    world,
)
from tests.test_authority_freshness import _approved, _at, _gate, _mint, _present
from tests.test_authorize_mint_claim import _authorize_body


def _db(env):
    return env["server"].state["store"]._conn


def _when(auth):
    return _at(auth["not_before"]) + timedelta(seconds=1)


def test_a_decision_minted_twice_executes_once(world, tmp_path):  # noqa: F811
    approval, record, body = _approved(world, ttl=600)
    first = _mint(world, body)
    assert first.status_code == 200, first.text
    permit_1 = first.json()["authorization"]

    # the attack: forget that this decision already minted
    _db(world).execute(
        "DELETE FROM execution_authorization_mint WHERE decision_id = ?",
        (record["decision_id"],),
    )
    _db(world).commit()
    second = _mint(world, body)
    assert second.status_code == 200, second.text  # the agent side is fooled
    permit_2 = second.json()["authorization"]
    assert (
        permit_2["execution_authorization_id"] != permit_1["execution_authorization_id"]
    )
    assert permit_2["decision_receipt_digest"] == permit_1["decision_receipt_digest"]

    gate = _gate(world, tmp_path)
    assert _present(gate, permit_1, at=_when(permit_1)).admitted
    refused = _present(gate, permit_2, at=_when(permit_2))
    assert not refused.admitted
    assert refused.reason_code == g.RECEIVER_DUPLICATE_DECISION
    assert refused.http_status == 409


def test_one_approval_used_twice_executes_once(world, tmp_path):  # noqa: F811
    approval, record, body = _approved(world, ttl=600)
    first = _mint(world, body)
    assert first.status_code == 200, first.text
    permit_1 = first.json()["authorization"]

    # the attack: forget that the approval was used, and use it again
    _db(world).execute("DELETE FROM approval_consume")
    _db(world).commit()
    again = _decide(world["client"], world["key"], approval)
    assert again.status_code == 200, again.text  # a second decision
    record_2 = again.json()["record"]
    assert record_2["decision_id"] != record["decision_id"]
    body_2 = _authorize_body(
        record_2, wire=WIRE, peer=PEER, dispatch=_dispatch(), action=_execution_action()
    )
    body_2["approval_artifact_digest"] = body["approval_artifact_digest"]
    second = _mint(world, body_2)
    assert second.status_code == 200, second.text  # the agent side is fooled
    permit_2 = second.json()["authorization"]
    assert permit_2["approval_artifact_digest"] == permit_1["approval_artifact_digest"]

    gate = _gate(world, tmp_path)
    assert _present(gate, permit_1, at=_when(permit_1)).admitted
    refused = _present(gate, permit_2, at=_when(permit_2))
    assert not refused.admitted
    assert refused.reason_code == g.RECEIVER_DUPLICATE_APPROVAL
