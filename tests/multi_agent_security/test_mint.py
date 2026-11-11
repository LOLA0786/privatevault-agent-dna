"""A decision made under a delegation chain never outlives the chain.

Review of #223 (High): an ALLOW obtained while a delegation was valid could
be taken to /v1/authorize after the delegation had expired, and a permit was
minted that lived roughly another minute. The decision now seals when its
delegated authority ends and who it rests on, and minting honours both."""

from datetime import UTC, datetime, timedelta

from agent_dna.consensus.signing import generate_voter_keypair
from agent_dna.multi_agent_security import (
    DelegationGate,
    DelegationPolicy,
    delegated_action_id,
    issue_link,
    link_hash,
    sign_presentation,
)
from agent_dna.multi_agent_security.gate import sealed_delegation, sealed_dispatch
from tests.decide_binding import decide_json, dispatch_context_for
from tests.test_authority_freshness import _at, _mint, _reason, freeze_mint_clock
from tests.test_authorize_mint_claim import (  # noqa: F401 - fixture
    AGENT,
    ARGS,
    ORG,
    _authorize_body,
    mint_env,
)

CAP = "crm.read_contact"
KEYS = {n: generate_voter_keypair() for n in ("operator", "planner", AGENT)}


def _policy(**extra):
    return DelegationPolicy.from_dict(
        {
            "audience": "pv-test",
            "roots": {"operator": KEYS["operator"]["public_key"]},
            "agents": {n: KEYS[n]["public_key"] for n in ("planner", AGENT)},
            "required_agents": [AGENT],
            **extra,
        }
    )


def _engine(env):
    engine = env["server"].state["engine"]
    return getattr(engine, "engine", engine)


def _delegated_allow(env, *, ttl):
    """A sealed ALLOW for AGENT under a chain that lives ``ttl`` seconds."""
    _engine(env).delegation = DelegationGate(_policy())
    root = issue_link(
        KEYS["operator"]["signing_key"],
        delegator="operator",
        delegate="planner",
        capabilities=["crm."],
        may_delegate=True,
        ttl=ttl,
    )
    leaf = issue_link(
        KEYS["planner"]["signing_key"],
        delegator="planner",
        delegate=AGENT,
        capabilities=[CAP],
        parent=root,
        ttl=ttl,
    )
    body = decide_json(
        AGENT,
        CAP,
        arguments=dict(ARGS),
        resource="crm:contact",
        org=ORG,
        dispatch_context=dispatch_context_for(
            adapter="https",
            transport="https",
            operation="GET /v1/contacts",
            destination="crm.store.example",
            wire_content_type="application/json",
        ),
    )
    bound = sealed_dispatch(body["execution_action"], body["dispatch_context"])
    body["evidence"] = {
        "delegation": {
            "chain": [root, leaf],
            "presentation": sign_presentation(
                KEYS[AGENT]["signing_key"],
                audience="pv-test",
                chain_hash=link_hash(leaf),
                action_id=delegated_action_id(AGENT, CAP, dict(ARGS), bound),
            ),
        }
    }
    response = env["client"].post(
        "/v1/decide", headers={"X-API-Key": env["key"]}, json=body
    )
    assert response.status_code == 200, response.text
    return response.json()["record"], leaf


def test_mint_after_the_delegation_expired_is_refused(mint_env, monkeypatch):  # noqa: F811
    """The reviewer's reproduction."""
    record, leaf = _delegated_allow(mint_env, ttl=20)
    after = datetime.fromtimestamp(leaf["expires_at"], UTC) + timedelta(seconds=5)
    freeze_mint_clock(monkeypatch, mint_env["server"], after)
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403, refused.text
    assert _reason(refused) == "AUTHORIZE_AUTHORITY_EXPIRED"
    assert "delegation chain" in refused.json()["detail"]["detail"]


def test_a_permit_never_outlives_the_delegation(mint_env):  # noqa: F811
    record, leaf = _delegated_allow(mint_env, ttl=20)
    minted = _mint(mint_env, _authorize_body(record))
    assert minted.status_code == 200, minted.text
    chain_end = datetime.fromtimestamp(leaf["expires_at"], UTC).replace(microsecond=0)
    assert _at(minted.json()["authorization"]["expires_at"]) == chain_end


def test_a_long_delegation_does_not_lengthen_a_permit(mint_env):  # noqa: F811
    """The cap only ever shortens."""
    record, _ = _delegated_allow(mint_env, ttl=3600)
    minted = _mint(mint_env, _authorize_body(record))
    assert minted.status_code == 200, minted.text
    lifetime = _at(minted.json()["authorization"]["expires_at"]) - datetime.now(UTC)
    assert lifetime < timedelta(minutes=10)


def test_mint_is_refused_once_someone_in_the_chain_is_revoked(mint_env):  # noqa: F811
    """A decision allowed before a revocation used to mint after it."""
    record, _ = _delegated_allow(mint_env, ttl=600)
    _engine(mint_env).delegation = DelegationGate(_policy(revoked_agents=["planner"]))
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403, refused.text
    assert _reason(refused) == "AUTHORIZE_GRANT_REVOKED"
    assert "'planner' is revoked" in refused.json()["detail"]["detail"]


def test_mint_is_refused_once_a_link_in_the_chain_is_revoked(mint_env):  # noqa: F811
    record, _ = _delegated_allow(mint_env, ttl=600)
    root_hash = sealed_delegation(record["reason"])["links"][0]
    _engine(mint_env).delegation = DelegationGate(_policy(revoked=[root_hash]))
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403
    assert _reason(refused) == "AUTHORIZE_GRANT_REVOKED"


def test_the_expiry_is_in_the_signed_record_not_in_server_memory(mint_env, monkeypatch):  # noqa: F811
    """A restart or another replica reads the same sealed record: the cap
    needs no gate to be configured where the mint happens."""
    record, leaf = _delegated_allow(mint_env, ttl=20)
    _engine(mint_env).delegation = None
    after = datetime.fromtimestamp(leaf["expires_at"], UTC) + timedelta(seconds=5)
    freeze_mint_clock(monkeypatch, mint_env["server"], after)
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403
    assert _reason(refused) == "AUTHORIZE_AUTHORITY_EXPIRED"


# ---- review of #225 (High): the approval path carried no seal ---------------
#
# A delegated action with no grant is held; a person approves it; the ALLOW
# that results was built on the approval path, where the seal was not added,
# so minting checked neither the chain's expiry nor its revocation.

from agent_dna.approval_v01 import approval_artifact_digest  # noqa: E402
from tests.test_api_approval_bridge import (  # noqa: E402, F401 - fixture
    CAP as PAY,
)
from tests.test_api_approval_bridge import (  # noqa: E402, F401
    PEER,
    WIRE,
    _dispatch,
    _execution_action,
    world,
)

PAY_ARGS = {"amount": 18000, "currency": "INR", "payee_id": "V-100"}


def _approved_under_a_chain(env, *, ttl):
    """Held (no grant) -> approved by a person -> ALLOW, all under a chain
    that lives ``ttl`` seconds. Returns the sealed record, the authorize
    body and the chain's last link."""
    _engine(env).delegation = DelegationGate(_policy())
    root = issue_link(
        KEYS["operator"]["signing_key"],
        delegator="operator",
        delegate="planner",
        capabilities=["payments."],
        may_delegate=True,
        ttl=ttl,
    )
    leaf = issue_link(
        KEYS["planner"]["signing_key"],
        delegator="planner",
        delegate=AGENT,
        capabilities=[PAY],
        parent=root,
        ttl=ttl,
    )

    def decide(approval=None):
        body = decide_json(
            AGENT,
            PAY,
            arguments=dict(PAY_ARGS),
            resource="vendor:V-100",
            org=ORG,
            dispatch_context=dispatch_context_for(
                adapter="https",
                transport="https",
                operation="POST /api/v1/transfers",
                destination="payments.partner.example",
                wire_content_type="application/json",
            ),
        )
        body["execution_action"] = _execution_action()
        body["request_id"] = "req-inv-1"
        bound = sealed_dispatch(body["execution_action"], body["dispatch_context"])
        body["evidence"] = {
            "delegation": {
                "chain": [root, leaf],
                "presentation": sign_presentation(  # single use: one per call
                    KEYS[AGENT]["signing_key"],
                    audience="pv-test",
                    chain_hash=link_hash(leaf),
                    action_id=delegated_action_id(AGENT, PAY, dict(PAY_ARGS), bound),
                ),
            }
        }
        if approval is not None:
            body["approval"] = approval
        return env["client"].post(
            "/v1/decide", headers={"X-API-Key": env["key"]}, json=body
        )

    held = decide()
    assert held.status_code == 202, held.text  # valid chain, but no grant
    approval = env["approver"].approve(
        _execution_action(), request_id="req-inv-1", artifact_ttl_s=600
    )
    allowed = decide(approval)
    assert allowed.status_code == 200, allowed.text
    record = allowed.json()["record"]
    assert record["triggered_by"] == "approval"
    body = _authorize_body(
        record, wire=WIRE, peer=PEER, dispatch=_dispatch(), action=_execution_action()
    )
    body["approval_artifact_digest"] = approval_artifact_digest(approval["artifact"])
    return record, body, leaf


def test_an_approved_allow_carries_the_seal_too(world):  # noqa: F811
    record, _, leaf = _approved_under_a_chain(world, ttl=600)
    sealed = sealed_delegation(record["reason"])
    assert sealed is not None, record["reason"]
    assert sealed["chain"] == link_hash(leaf)
    assert sealed["parties"] == ["operator", "planner", AGENT]


def test_approved_allow_does_not_mint_after_its_chain_expired(world, monkeypatch):  # noqa: F811
    """The reviewer's reproduction: a 20-second chain, held, approved, then
    minted 30 seconds after the chain ended. It used to succeed, with a
    permit lasting 90 seconds past the chain."""
    record, body, leaf = _approved_under_a_chain(world, ttl=20)
    after = datetime.fromtimestamp(leaf["expires_at"], UTC) + timedelta(seconds=30)
    freeze_mint_clock(monkeypatch, world["server"], after)
    refused = _mint(world, body)
    assert refused.status_code == 403, refused.text
    assert _reason(refused) == "AUTHORIZE_AUTHORITY_EXPIRED"
    assert "delegation chain" in refused.json()["detail"]["detail"]


def test_approved_allow_permit_is_capped_at_the_chain(world):  # noqa: F811
    record, body, leaf = _approved_under_a_chain(world, ttl=20)
    minted = _mint(world, body)
    assert minted.status_code == 200, minted.text
    chain_end = datetime.fromtimestamp(leaf["expires_at"], UTC).replace(microsecond=0)
    assert _at(minted.json()["authorization"]["expires_at"]) == chain_end


def test_approved_allow_does_not_mint_after_a_revocation(world):  # noqa: F811
    record, body, _ = _approved_under_a_chain(world, ttl=600)
    _engine(world).delegation = DelegationGate(_policy(revoked_agents=["planner"]))
    refused = _mint(world, body)
    assert refused.status_code == 403, refused.text
    assert _reason(refused) == "AUTHORIZE_GRANT_REVOKED"


def test_a_delegated_allow_without_a_seal_does_not_mint(world):  # noqa: F811
    """Whatever path produced it: where a chain is required, a sealed record
    that carries none is not minted from."""
    _engine(world).delegation = None  # decided with no gate: no seal
    from tests.test_api_approval_bridge import _decide

    approval = world["approver"].approve(_execution_action(), request_id="req-inv-1")
    allowed = _decide(world["client"], world["key"], approval)
    assert allowed.status_code == 200, allowed.text
    record = allowed.json()["record"]
    assert sealed_delegation(record["reason"]) is None
    body = _authorize_body(
        record, wire=WIRE, peer=PEER, dispatch=_dispatch(), action=_execution_action()
    )
    body["approval_artifact_digest"] = approval_artifact_digest(approval["artifact"])
    _engine(world).delegation = DelegationGate(_policy())  # now it is required
    refused = _mint(world, body)
    assert refused.status_code == 403, refused.text
    assert _reason(refused) == "AUTHORIZE_AUTHORITY_UNKNOWN"
    assert "requires a delegation chain" in refused.json()["detail"]["detail"]


# ---- revocation routes that used to let a pending mint through --------------


def test_rotating_a_key_withdraws_what_was_decided_under_the_old_one(mint_env):  # noqa: F811
    record, _ = _delegated_allow(mint_env, ttl=600)
    rotated = generate_voter_keypair()["public_key"]
    raw = {
        "audience": "pv-test",
        "roots": {"operator": KEYS["operator"]["public_key"]},
        "agents": {"planner": rotated, AGENT: KEYS[AGENT]["public_key"]},
        "required_agents": [AGENT],
    }
    _engine(mint_env).delegation = DelegationGate(DelegationPolicy.from_dict(raw))
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403, refused.text
    assert "'planner''s pinned key changed" in refused.json()["detail"]["detail"]


def test_removing_an_agent_withdraws_what_was_decided_through_it(mint_env):  # noqa: F811
    record, _ = _delegated_allow(mint_env, ttl=600)
    raw = {
        "audience": "pv-test",
        "roots": {"operator": KEYS["operator"]["public_key"]},
        "agents": {AGENT: KEYS[AGENT]["public_key"]},  # the middle agent is gone
        "required_agents": [AGENT],
    }
    _engine(mint_env).delegation = DelegationGate(DelegationPolicy.from_dict(raw))
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403
    assert (
        "'planner' is no longer a pinned identity"
        in (refused.json()["detail"]["detail"])
    )


def _config_file(tmp_path, **extra):
    import json

    path = tmp_path / "delegation.json"
    path.write_text(
        json.dumps(
            {
                "audience": "pv-test",
                "roots": {"operator": KEYS["operator"]["public_key"]},
                "agents": {n: KEYS[n]["public_key"] for n in ("planner", AGENT)},
                "required_agents": [AGENT],
                **extra,
            }
        )
    )
    return path


def test_a_revocation_written_to_the_file_applies_without_a_restart(mint_env, tmp_path):  # noqa: F811
    record, _ = _delegated_allow(mint_env, ttl=600)
    path = _config_file(tmp_path)
    _engine(mint_env).delegation = DelegationGate.from_file(path)
    # the operator edits the file; nothing is restarted
    _config_file(tmp_path, revoked_agents=["planner"], revoked=[])
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403, refused.text
    assert "'planner' is revoked" in refused.json()["detail"]["detail"]


def test_a_broken_edit_refuses_everything_until_it_is_fixed(mint_env, tmp_path):  # noqa: F811
    """A half-written revocation must not leave the old configuration in
    force."""
    record, _ = _delegated_allow(mint_env, ttl=600)
    path = _config_file(tmp_path)
    gate = DelegationGate.from_file(path)
    _engine(mint_env).delegation = gate
    path.write_text('{"audience": "pv-test", "roots": {')
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403
    assert "configuration is unusable" in refused.json()["detail"]["detail"]
    verdict = gate.check(
        agent_id=AGENT, capability=CAP, arguments={}, amount=None, evidence={}
    )
    assert verdict.refused and "delegation_config_invalid" in verdict.reason
    _config_file(tmp_path)  # fixed
    assert _mint(mint_env, _authorize_body(record)).status_code == 200


# ---- review of #226 (Medium): minting trusted whatever the database held ----
#
# On a running server the reviewer edited a seal's expiry in the database,
# grafted another decision's seal, and flipped a stored BLOCK to ALLOW. All
# three minted a signed permit. No signing key was needed, only write access
# to the decision store.

import hashlib  # noqa: E402
import json  # noqa: E402

import pytest  # noqa: E402

from agent_dna.signer import generate_keypair  # noqa: E402
from tests.test_authorize_mint_claim import (  # noqa: E402
    _decide_allow,
    build_mint_env,
)


@pytest.fixture
def signed_env(tmp_path, monkeypatch):
    """The mint environment with decision records signed, as the secure
    profile and any production deployment run."""
    keys = generate_keypair()
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", keys["signing_key"])
    monkeypatch.setenv("PV_TRUSTED_PUBLIC_KEYS", keys["public_key"])
    yield from build_mint_env(tmp_path, monkeypatch)


def _store(env):
    return env["server"].state["store"]


def _rewrite(env, record, mutate, *, rehash=False, graft_envelope_from=None):
    """Edit a stored decision the way someone with database access would."""
    conn = _store(env)._conn
    body = dict(record)
    mutate(body)
    old_hash = record["record_hash"]
    if rehash:
        unsigned = {k: v for k, v in body.items() if k != "record_hash"}
        body["record_hash"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    conn.execute(
        "UPDATE records SET body = ? WHERE record_id = ?",
        (json.dumps(body), record["decision_id"]),
    )
    if graft_envelope_from is not None:
        donor = _store(env).get_envelope(graft_envelope_from)
        conn.execute(
            "INSERT OR REPLACE INTO envelopes (record_hash, agent_id, envelope) "
            "VALUES (?, ?, ?)",
            (body["record_hash"], body["agent_id"], json.dumps(donor)),
        )
    conn.commit()
    assert _store(env).get_decision(record["decision_id"]) != record
    return body, old_hash


def _refused_as_tampered(env, body):
    refused = _mint(env, body)
    assert refused.status_code == 403, refused.text
    assert _reason(refused) == "AUTHORIZE_RECORD_HASH_MISMATCH"
    return refused.json()["detail"]["detail"]


def test_an_untouched_record_still_mints(mint_env):  # noqa: F811
    record = _decide_allow(mint_env["client"], mint_env["key"])
    assert _mint(mint_env, _authorize_body(record)).status_code == 200


def test_a_seal_edited_in_the_database_does_not_mint(mint_env):  # noqa: F811
    record, _ = _delegated_allow(mint_env, ttl=20)
    far_future = record["reason"].replace(
        f'"expires_at":{sealed_delegation(record["reason"])["expires_at"]}',
        '"expires_at":9999999999.0',
    )
    assert far_future != record["reason"]
    _rewrite(mint_env, record, lambda b: b.update(reason=far_future))
    detail = _refused_as_tampered(mint_env, _authorize_body(record))
    assert "does not match its own hash" in detail


def test_a_seal_grafted_from_another_decision_does_not_mint(mint_env):  # noqa: F811
    short, _ = _delegated_allow(mint_env, ttl=20)
    long_lived, _ = _delegated_allow(mint_env, ttl=3600)
    donor_seal = long_lived["reason"][long_lived["reason"].rfind("; delegation=") :]
    own = short["reason"][: short["reason"].rfind("; delegation=")]
    _rewrite(mint_env, short, lambda b: b.update(reason=own + donor_seal))
    _refused_as_tampered(mint_env, _authorize_body(short))


def test_a_stored_block_flipped_to_allow_does_not_mint(mint_env):  # noqa: F811
    allowed = _decide_allow(mint_env["client"], mint_env["key"])
    # a genuine BLOCK for the same agent and action: a chain is required
    _engine(mint_env).delegation = DelegationGate(_policy())
    blocked = mint_env["client"].post(
        "/v1/decide",
        headers={"X-API-Key": mint_env["key"]},
        json=decide_json(
            AGENT,
            CAP,
            arguments=dict(ARGS),
            resource="crm:contact",
            org=ORG,
            dispatch_context=dispatch_context_for(
                adapter="https",
                transport="https",
                operation="GET /v1/contacts",
                destination="crm.store.example",
                wire_content_type="application/json",
            ),
        ),
    )
    assert blocked.status_code == 403, blocked.text
    block = blocked.json()["record"]
    assert block["decision"] == "block"
    _engine(mint_env).delegation = None

    def flip(body):
        body.update(
            decision="allow",
            triggered_by="baseline",
            reason="Behavior matches trusted profile.",
        )

    flipped, _ = _rewrite(mint_env, block, flip)
    body = _authorize_body({**allowed, **flipped})
    _refused_as_tampered(mint_env, body)


def test_without_record_signing_only_the_hash_is_checked(mint_env):  # noqa: F811
    """A stated limit, pinned so it cannot change unnoticed: with decision
    signing off there is no signature to check, so an edit whose hash was
    recomputed is not detected. Run with PV_RECEIPT_SIGNING_KEY (the secure
    profile does) to close it; the two tests below show it closed."""
    record, _ = _delegated_allow(mint_env, ttl=600)
    edited, _ = _rewrite(
        mint_env, record, lambda b: b.update(reason=b["reason"] + " "), rehash=True
    )
    assert _mint(mint_env, _authorize_body(edited)).status_code == 200


def test_recomputing_the_hash_does_not_help_without_the_signing_key(signed_env):  # noqa: F811
    """A careful attacker fixes the hash too. The signature is over the old
    hash, and there is none for the new one."""
    record, _ = _delegated_allow(signed_env, ttl=20)
    edited, _ = _rewrite(
        signed_env,
        record,
        lambda b: b.update(reason=b["reason"].replace('"depth":2', '"depth":2 ')),
        rehash=True,
    )
    body = _authorize_body(edited)
    detail = _refused_as_tampered(signed_env, body)
    assert "no valid signature" in detail


def test_borrowing_another_records_signature_does_not_help(signed_env):  # noqa: F811
    record, _ = _delegated_allow(signed_env, ttl=20)
    edited, old_hash = _rewrite(
        signed_env,
        record,
        lambda b: b.update(reason=b["reason"] + " "),
        rehash=True,
        graft_envelope_from=record["record_hash"],
    )
    detail = _refused_as_tampered(signed_env, _authorize_body(edited))
    assert "no valid signature" in detail


# ---- review of #226 (Low): a decision with no chain skipped the file --------


def _plain_config(tmp_path, **extra):
    path = tmp_path / "delegation.json"
    path.write_text(
        json.dumps(
            {
                "audience": "pv-test",
                "roots": {"operator": KEYS["operator"]["public_key"]},
                "agents": {n: KEYS[n]["public_key"] for n in ("planner", AGENT)},
                **extra,
            }
        )
    )
    return path


def test_an_unsealed_allow_follows_a_requirement_added_to_the_file(mint_env, tmp_path):  # noqa: F811
    path = _plain_config(tmp_path)  # nothing requires a chain yet
    _engine(mint_env).delegation = DelegationGate.from_file(path)
    record = _decide_allow(mint_env["client"], mint_env["key"])
    assert sealed_delegation(record["reason"]) is None
    _plain_config(tmp_path, required_agents=[AGENT])  # edited, no restart
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403, refused.text
    assert "requires a delegation chain" in refused.json()["detail"]["detail"]


def test_an_unsealed_allow_does_not_mint_while_the_file_is_broken(mint_env, tmp_path):  # noqa: F811
    """'A file that does not load refuses everything' was not true for a
    decision that never had a chain."""
    path = _plain_config(tmp_path)
    _engine(mint_env).delegation = DelegationGate.from_file(path)
    record = _decide_allow(mint_env["client"], mint_env["key"])
    path.write_text("{ not json")
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403, refused.text
    assert "configuration is unusable" in refused.json()["detail"]["detail"]
    _plain_config(tmp_path)
    assert _mint(mint_env, _authorize_body(record)).status_code == 200
