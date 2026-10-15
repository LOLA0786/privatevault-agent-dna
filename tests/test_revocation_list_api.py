"""Revoking a grant reaches receivers through GET /v1/revocations."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from agent_dna.revocation_list import RECEIVER_PERMIT_REVOKED, RevocationListCache
from tests.test_grant_revocation import _attach, _decide
from tests.test_wire_action_binding import _authorize, env  # noqa: F401


def test_revoked_grant_permit_is_on_the_signed_list(env):  # noqa: F811
    server, store, ledger, grant_id = _attach(env)
    record = _decide(env["client"], env["key"])
    minted = _authorize(env["client"], env["key"], record)
    permit = minted.json()["authorization"]
    ledger.revoke(grant_id, revoked_by="ops", reason="fraud", store=store)

    r = env["client"].get("/v1/revocations", headers={"X-API-Key": env["key"]})
    assert r.status_code == 200, r.text
    document = r.json()
    assert permit["execution_authorization_id"] in document["revoked_authorizations"]

    bundle = json.loads(Path(server.os.environ["PV_TRUST_BUNDLE"]).read_text())
    cache = RevocationListCache(bundle)
    cache.update(document, now=datetime.now(UTC))
    code, _ = cache.refusal(permit, now=datetime.now(UTC))
    assert code == RECEIVER_PERMIT_REVOKED


def test_revocation_list_requires_a_key(env):  # noqa: F811
    assert env["client"].get("/v1/revocations").status_code == 401
