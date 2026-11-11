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
