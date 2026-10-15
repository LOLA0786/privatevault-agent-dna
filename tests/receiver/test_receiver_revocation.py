"""A receiver holding a permit honours PrivateVault's revocations.

The gate checks a signed pv-revocation-list/0.1 and fails closed when its
copy is missing or expired.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import sign_document
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from agent_dna.revocation_list import (
    RECEIVER_PERMIT_REVOKED,
    RECEIVER_REVOCATION_LIST_STALE,
    REVOCATION_LIST_SPEC,
    RevocationListCache,
    RevocationListError,
)

from ._world import NOW, ORG, PARAMETERS, PATH, World, wire_for


def _rl(
    signer, *, revoked=(), agents=(), org=ORG, issued=NOW, ttl=30, key_id="ea-signer"
):
    return sign_document(
        {
            "spec": REVOCATION_LIST_SPEC,
            "organisation_id": org,
            "list_id": "rl-test",
            "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "next_update": (issued + timedelta(seconds=ttl)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "revoked_authorizations": sorted(revoked),
            "suspended_agents": sorted(agents),
            "organisation_suspended": False,
            "signer_key_id": key_id,
        },
        signer,
        signature_field="signature",
    )


def _world(tmp_path):
    world = World(tmp_path)
    world.gate.revocations = RevocationListCache(world.bundle)
    return world


def _send(world, permit, at=NOW):
    return world.gate.check(
        method="POST",
        path=PATH,
        headers=[
            (PERMIT_HEADER, encode_permit_header(permit)),
            ("Content-Type", "application/json"),
        ],
        body=wire_for(PARAMETERS),
        received_at=at,
    )


def test_fresh_list_without_the_permit_admits(tmp_path):
    world = _world(tmp_path)
    world.gate.revocations.update(_rl(world.signer), now=NOW)
    assert _send(world, world.permit()).admitted


def test_listed_permit_is_refused_and_not_consumed(tmp_path):
    world = _world(tmp_path)
    permit = world.permit()
    world.gate.revocations.update(
        _rl(world.signer, revoked=[permit["execution_authorization_id"]]), now=NOW
    )
    d = _send(world, permit)
    assert not d.admitted and d.reason_code == RECEIVER_PERMIT_REVOKED


def test_suspended_agent_is_refused(tmp_path):
    world = _world(tmp_path)
    permit = world.permit()
    agent = permit["action"]["subject_key_id"]
    world.gate.revocations.update(_rl(world.signer, agents=[agent]), now=NOW)
    assert _send(world, permit).reason_code == RECEIVER_PERMIT_REVOKED


def test_missing_list_fails_closed(tmp_path):
    world = _world(tmp_path)
    d = _send(world, world.permit())
    assert not d.admitted and d.reason_code == RECEIVER_REVOCATION_LIST_STALE


def test_expired_list_fails_closed(tmp_path):
    world = _world(tmp_path)
    world.gate.revocations.update(_rl(world.signer, ttl=10), now=NOW)
    d = _send(world, world.permit(), at=NOW + timedelta(seconds=11))
    assert not d.admitted and d.reason_code == RECEIVER_REVOCATION_LIST_STALE


@pytest.mark.parametrize("attack", ["wrong_key", "other_org", "edited", "unknown_key"])
def test_untrusted_lists_are_rejected(tmp_path, attack):
    world = _world(tmp_path)
    cache = world.gate.revocations
    if attack == "wrong_key":
        doc = _rl(SigningKey.generate())
    elif attack == "other_org":
        doc = _rl(world.signer, org="evil.example")
    elif attack == "unknown_key":
        doc = _rl(world.signer, key_id="nope")
    else:
        doc = _rl(world.signer, revoked=["eauth-x"])
        doc["revoked_authorizations"] = []  # strip a revocation after signing
    with pytest.raises(RevocationListError):
        cache.update(doc, now=NOW)


def test_older_list_cannot_roll_back_a_newer_one(tmp_path):
    world = _world(tmp_path)
    permit = world.permit()
    cache = world.gate.revocations
    cache.update(
        _rl(world.signer, revoked=[permit["execution_authorization_id"]]), now=NOW
    )
    with pytest.raises(RevocationListError, match="rollback"):
        cache.update(_rl(world.signer, issued=NOW - timedelta(seconds=5)), now=NOW)
    assert _send(world, permit).reason_code == RECEIVER_PERMIT_REVOKED


def test_gate_without_revocations_is_unchanged(tmp_path):
    world = World(tmp_path)
    assert _send(world, world.permit()).admitted
