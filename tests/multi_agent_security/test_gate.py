"""Delegation enforced inside /v1/decide: chains are checked on every call,
the holder must prove its key, and a refusal cannot be approved away."""

import importlib
import json
import time

import pytest
from fastapi.testclient import TestClient

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.consensus.signing import generate_voter_keypair
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.multi_agent_security import (
    DelegationConfigError,
    DelegationGate,
    DelegationPolicy,
    SqliteNonceLedger,
    delegated_action_id,
    issue_link,
    link_hash,
    sign_presentation,
)
from agent_dna.open_authorizer import OpenAuthorizer
from agent_dna.signer import generate_keypair
from agent_dna.trace import AgentAction
from tests.decide_binding import decide_json

AUDIENCE = "pv-test"
CAP = "payments.pay_invoice"
ARGS = {"amount": 150, "payee_id": "V-100"}
KEYS = {n: generate_voter_keypair() for n in ("operator", "planner", "payer", "thief")}


def config(**extra):
    return {
        "audience": AUDIENCE,
        "roots": {"operator": KEYS["operator"]["public_key"]},
        "agents": {n: KEYS[n]["public_key"] for n in ("planner", "payer")},
        "required_agents": ["payer"],
        **extra,
    }


def chain(amount=200.0, caps=(CAP,), to="payer"):
    root = issue_link(
        KEYS["operator"]["signing_key"],
        delegator="operator",
        delegate="planner",
        capabilities=["payments."],
        max_amount=500.0,
        may_delegate=True,
    )
    leaf = issue_link(
        KEYS["planner"]["signing_key"],
        delegator="planner",
        delegate=to,
        capabilities=list(caps),
        max_amount=amount,
        parent=root,
    )
    return [root, leaf]


def evidence(links=None, *, signer="payer", agent="payer", args=ARGS, cap=CAP, **kw):
    links = links if links is not None else chain()
    kw.setdefault("audience", AUDIENCE)
    return {
        "delegation": {
            "chain": links,
            "presentation": sign_presentation(
                KEYS[signer]["signing_key"],
                chain_hash=link_hash(links[-1]),
                action_id=delegated_action_id(agent, cap, args),
                **kw,
            ),
        }
    }


class _Scorer:
    def score(self, action, prev=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def engine(ledger=None, **extra):
    gate = DelegationGate(DelegationPolicy.from_dict(config(**extra)), ledger=ledger)
    return DecisionEngine(
        scorer=_Scorer(), authorizer=OpenAuthorizer(), delegation=gate
    )


def decide(eng, ev=None, agent="payer", cap=CAP, args=ARGS):
    action = AgentAction(
        agent_id=agent, capability=cap, timestamp=time.time(), arguments=dict(args)
    )
    return eng.decide(action, evidence=ev)


def held(result, fragment):
    assert result.decision is Decision.REQUIRE_APPROVAL, result.reason
    assert "delegation" in result.also_fired
    assert fragment in result.reason, result.reason


# ---- the honest path -------------------------------------------------------


def test_valid_chain_and_presentation_allow_and_are_sealed_in_the_reason():
    links = chain()
    result = decide(engine(), evidence(links))
    assert result.decision is Decision.ALLOW, result.reason
    assert link_hash(links[-1])[:16] in result.reason
    assert "holder proven" in result.reason


def test_agents_outside_the_policy_are_untouched():
    assert decide(engine(), agent="reporting-bot", cap="crm.read").decision is (
        Decision.ALLOW
    )


# ---- a chain is required where the operator says so ------------------------


def test_required_agent_without_a_chain_is_held():
    held(decide(engine()), "delegation_required")


def test_required_capability_without_a_chain_is_held_for_any_agent():
    eng = engine(required_agents=[], required_for=["payments."])
    held(decide(eng, agent="reporting-bot"), "delegation_required")
    assert decide(eng, agent="reporting-bot", cap="crm.read").decision is (
        Decision.ALLOW
    )


# ---- the chain's limits are the action's limits ----------------------------


def test_over_the_ceiling_and_out_of_scope_are_held():
    over = {**ARGS, "amount": 450}  # planner held 500, handed on 200
    held(decide(engine(), evidence(args=over), args=over), "delegation_over_ceiling")
    held(
        decide(engine(), evidence(cap="payments.refund"), cap="payments.refund"),
        "delegation_out_of_scope",
    )


def test_a_widening_chain_is_held():
    greedy = chain(amount=50_000.0, caps=["payments."])
    held(decide(engine(), evidence(greedy)), "widens")


# ---- holder binding: a copied chain is not enough --------------------------


def test_copied_chain_without_the_holders_key_is_held():
    """The thief has payer's chain, byte for byte, and its own key."""
    held(
        decide(engine(), evidence(signer="thief")),
        "signature does not verify under 'payer'",
    )


def test_chain_presented_by_another_agent_is_held():
    eng = engine(required_agents=["payer", "planner"])
    ev = evidence(signer="planner", agent="planner")
    held(decide(eng, ev, agent="planner"), "delegation_not_yours")


def test_presentation_is_bound_to_the_exact_arguments():
    signed_for = {**ARGS, "payee_id": "V-100"}
    sent = {**ARGS, "payee_id": "ATTACKER"}
    held(decide(engine(), evidence(args=signed_for), args=sent), "different action")


def test_presentation_for_another_deployment_is_held():
    held(decide(engine(), evidence(audience="pv-staging")), "audience mismatch")


def test_presentation_for_another_chain_is_held():
    ev = evidence(chain())
    ev["delegation"]["chain"] = chain()  # a second, equally valid chain
    held(decide(engine(), ev), "different chain")


def test_presentation_is_single_use():
    eng = engine()
    ev = evidence()
    assert decide(eng, ev).decision is Decision.ALLOW
    held(decide(eng, ev), "presentation already used")


def test_presentation_is_single_use_across_replicas_and_restarts(tmp_path):
    ev = evidence()
    first = engine(ledger=SqliteNonceLedger(tmp_path / "v.db"))
    second = engine(ledger=SqliteNonceLedger(tmp_path / "v.db"))
    assert decide(first, ev).decision is Decision.ALLOW
    held(decide(second, ev), "presentation already used")


def test_stale_and_overlong_presentations_are_held():
    held(decide(engine(), evidence(now=time.time() - 600)), "expired")
    held(decide(engine(), evidence(ttl=3600)), "lifetime")
    held(decide(engine(), evidence(now=time.time() + 600)), "issued in the future")


def test_garbage_does_not_burn_a_real_presentation():
    eng = engine()
    good = evidence()
    forged = json.loads(json.dumps(good))
    forged["delegation"]["presentation"]["signature"] = "0" * 128
    held(decide(eng, forged), "signature does not verify")
    assert decide(eng, good).decision is Decision.ALLOW


@pytest.mark.parametrize(
    "delegation",
    [
        [],
        "x",
        {},
        {"chain": []},
        {"chain": [], "presentation": {}},
        {"chain": "x", "presentation": None},
        {"chain": [{}], "presentation": {}, "extra": 1},
    ],
)
def test_malformed_delegation_evidence_is_held_never_a_crash(delegation):
    held(decide(engine(), {"delegation": delegation}), "delegation_invalid")


def test_malformed_presentation_is_held():
    ev = evidence()
    ev["delegation"]["presentation"] = {"spec": "x"}
    held(decide(engine(), ev), "malformed presentation")


# ---- it only restricts -----------------------------------------------------


def test_a_valid_chain_grants_nothing_the_agents_own_grant_does_not():
    from agent_dna.grants import GrantRegistry

    gate = DelegationGate(DelegationPolicy.from_dict(config()))
    eng = DecisionEngine(scorer=_Scorer(), authorizer=GrantRegistry(), delegation=gate)
    result = decide(eng, evidence())
    assert result.decision is not Decision.ALLOW
    assert result.triggered_by == "authorization"
    assert "delegation" not in result.also_fired  # the chain itself was fine


def test_a_delegation_refusal_cannot_be_approved_away(tmp_path):
    from tests.test_approval_bridge import World, _execution_action

    world = World(tmp_path)
    world.engine.delegation = DelegationGate(
        DelegationPolicy.from_dict(
            config(required_agents=[], required_for=["payments."])
        )
    )
    action = _execution_action()
    result = world.engine.decide(
        world.action(),
        approval=world.approver.approve(action, request_id="req-inv-1"),
        approval_context=world.context(action),
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert "delegation escalations are not satisfiable by an approval" in result.reason


# ---- configuration ---------------------------------------------------------


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda c: c.pop("audience"), "audience"),
        (lambda c: c.update(roots={}), "roots"),
        (lambda c: c.update(surprise=1), "unknown field"),
        (lambda c: c.update(required_for=["*"]), "required_for"),
        (lambda c: c.update(revoked=["nope"]), "link hashes"),
        (
            lambda c: c["agents"].update(clone=c["agents"]["payer"]),
            "share one public key",
        ),
        (
            lambda c: c["agents"].update(operator=KEYS["thief"]["public_key"]),
            "both a root and an agent",
        ),
        (lambda c: c["roots"].update(operator="zz"), "64 lowercase hex"),
    ],
)
def test_unusable_configuration_refuses_to_load(mutate, message):
    raw = config()
    mutate(raw)
    with pytest.raises(DelegationConfigError, match=message):
        DelegationPolicy.from_dict(raw)


def test_revoking_an_identity_stops_reissued_links():
    """Revoking one link hash does not stop its signer issuing it again
    under a new nonce; revoking the identity does."""
    first = chain()
    eng = engine(revoked=[link_hash(first[-1])])
    held(decide(eng, evidence(first)), "revoked")
    assert decide(eng, evidence(chain())).decision is Decision.ALLOW  # re-issued
    eng = engine(revoked_agents=["planner"])
    held(decide(eng, evidence(chain())), "'planner' is revoked")


# ---- on the real server ----------------------------------------------------

SERVER_KEYS = generate_keypair()


def _client(tmp_path, monkeypatch, raw=None):
    grants = tmp_path / "grants.json"
    grants.write_text(
        json.dumps([{"agent_id": "payer", "capability": CAP, "granted_by": "ops"}])
    )
    (tmp_path / "delegation.json").write_text(json.dumps(raw or config()))
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_GRANTS_FILE", str(grants))
    monkeypatch.setenv("PV_BASELINE_CAPABILITIES", CAP)
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    monkeypatch.delenv("PV_CONSENSUS_FILE", raising=False)
    monkeypatch.setenv("PV_ALLOW_NO_AUTH", "1")
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", SERVER_KEYS["signing_key"])
    monkeypatch.setenv("PV_TRUSTED_PUBLIC_KEYS", SERVER_KEYS["public_key"])
    monkeypatch.setenv("PV_DELEGATION_FILE", str(tmp_path / "delegation.json"))
    monkeypatch.setenv("PV_CONSENSUS_NONCE_DB", str(tmp_path / "votes.db"))
    import api.server as server

    importlib.reload(server)
    return TestClient(server.app)


def _post(client, ev=None, args=ARGS):
    extra = {"evidence": ev} if ev is not None else {}
    return client.post(
        "/v1/decide", json=decide_json("payer", CAP, arguments=args, **extra)
    )


def test_server_enforces_delegation_on_every_decide(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        bare = _post(client)
        assert bare.status_code == 202
        assert "delegation_required" in bare.json()["reason"]

        ev = evidence()
        ok = _post(client, ev)
        assert ok.status_code == 200, ok.text
        assert "holder proven" in ok.json()["reason"]
        assert "holder proven" in ok.json()["record"]["reason"]  # sealed

        replay = _post(client, ev)
        assert replay.status_code == 202
        assert "presentation already used" in replay.json()["reason"]

        stolen = _post(client, evidence(signer="thief"))
        assert stolen.status_code == 202
        assert "delegation_holder_unproven" in stolen.json()["reason"]

        detail = client.get("/v1/runtime").json()["composition"]["delegation"]
        assert detail["status"] == "attached"
        assert "single-use: shared ledger" in detail["detail"]


def test_server_without_a_delegation_file_reports_it(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        pass
    monkeypatch.delenv("PV_DELEGATION_FILE")
    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as client:
        comp = client.get("/v1/runtime").json()["composition"]["delegation"]
        assert comp["status"] == "not attached"
        assert _post(client).status_code == 200


def test_invalid_delegation_file_refuses_startup(tmp_path, monkeypatch):
    bad = config()
    bad["agents"]["clone"] = bad["agents"]["payer"]
    with pytest.raises(DelegationConfigError, match="share one public key"):
        with _client(tmp_path, monkeypatch, bad):
            pass
