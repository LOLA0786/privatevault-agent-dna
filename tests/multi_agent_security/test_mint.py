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
