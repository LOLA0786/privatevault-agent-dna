"""Delegation enforced inside /v1/decide: chains are checked on every call,
the holder must prove its key for the action exactly as it will run, and a
refusal is a BLOCK."""

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
from agent_dna.multi_agent_security.gate import sealed_dispatch
from agent_dna.open_authorizer import OpenAuthorizer
from agent_dna.signer import generate_keypair
from agent_dna.trace import AgentAction
from tests.decide_binding import decide_json, dispatch_context_for

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
    """A delegation refusal is a BLOCK, never a hold a user could wave through."""
    assert result.decision is Decision.BLOCK, result.reason
    assert result.triggered_by == "authorization"
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
    assert result.decision is Decision.BLOCK
    assert "delegation_required" in result.reason
    assert result.approval_artifact_digest is None


def test_a_forged_presentation_is_a_block_not_a_question():
    """As a hold, the Claude Code hook would have shown this as an "ask"
    the user could answer with allow."""
    result = decide(engine(), evidence(signer="thief"))
    assert result.decision is Decision.BLOCK
    assert result.decision is not Decision.REQUIRE_APPROVAL


# ---- the presentation covers where the action runs -------------------------

BOUND = {
    "destination": "payments.bank.example",
    "operation": "POST /v1/transfers",
    "transport": "https",
    "wire_content_type": "application/json",
    "resource": "account:ops-eur",
    "subject_principal": "payer@bank.example",
    "action": CAP,
}


def bound_evidence(signed_for, sent):
    links = chain()
    return {
        "bound": sent,
        "delegation": {
            "chain": links,
            "presentation": sign_presentation(
                KEYS["payer"]["signing_key"],
                audience=AUDIENCE,
                chain_hash=link_hash(links[-1]),
                action_id=delegated_action_id("payer", CAP, ARGS, signed_for),
            ),
        },
    }


def test_presentation_signed_for_the_sealed_dispatch_is_allowed():
    result = decide(engine(), bound_evidence(BOUND, BOUND))
    assert result.decision is Decision.ALLOW, result.reason


@pytest.mark.parametrize(
    "field, value",
    [
        ("resource", "account:attacker"),
        ("subject_principal", "cfo@bank.example"),
        ("destination", "payments.evil.example"),
        ("operation", "POST /v1/refunds"),
        ("transport", "http"),
    ],
)
def test_changing_where_the_action_runs_voids_the_presentation(field, value):
    """Same agent, tool and arguments; a different resource, principal,
    destination or operation. Each was an ALLOW before 2026-11-11."""
    held(
        decide(engine(), bound_evidence(BOUND, {**BOUND, field: value})),
        "different action",
    )


def test_presentation_without_a_dispatch_is_not_valid_for_one_and_vice_versa():
    held(decide(engine(), bound_evidence(None, BOUND)), "different action")
    ev = bound_evidence(BOUND, BOUND)
    del ev["bound"]
    held(decide(engine(), ev), "different action")


def test_ledger_failure_in_the_gate_is_a_named_block():
    from agent_dna.multi_agent_security import LedgerUnavailable

    class Broken:
        def seen(self, *a):
            raise LedgerUnavailable("disk is read-only")

        def consume(self, *a):
            raise LedgerUnavailable("disk is read-only")

        def health(self):
            return "disk is read-only"

    eng = engine(ledger=Broken())
    held(decide(eng, evidence()), "delegation_ledger_unavailable")
    assert eng.delegation.health() == "disk is read-only"


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


def _request(ev=None, args=ARGS, **binding):
    extra = {"evidence": ev} if ev is not None else {}
    return decide_json("payer", CAP, arguments=args, **binding, **extra)


def _server_evidence(signer="payer", **binding):
    """Evidence whose presentation covers the request exactly as sent."""
    body = _request(**binding)
    bound = sealed_dispatch(body["execution_action"], body["dispatch_context"])
    links = chain()
    return {
        "delegation": {
            "chain": links,
            "presentation": sign_presentation(
                KEYS[signer]["signing_key"],
                audience=AUDIENCE,
                chain_hash=link_hash(links[-1]),
                action_id=delegated_action_id("payer", CAP, ARGS, bound),
            ),
        }
    }


def _post(client, ev=None, **binding):
    return client.post("/v1/decide", json=_request(ev, **binding))


def test_server_enforces_delegation_on_every_decide(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        bare = _post(client)
        assert bare.status_code == 403
        assert "delegation_required" in bare.json()["reason"]

        ev = _server_evidence()
        ok = _post(client, ev)
        assert ok.status_code == 200, ok.text
        assert "holder proven" in ok.json()["reason"]
        assert "holder proven" in ok.json()["record"]["reason"]  # sealed

        replay = _post(client, ev)
        assert replay.status_code == 403
        assert "presentation already used" in replay.json()["reason"]

        stolen = _post(client, _server_evidence(signer="thief"))
        assert stolen.status_code == 403
        assert "delegation_holder_unproven" in stolen.json()["reason"]

        detail = client.get("/v1/runtime").json()["composition"]["delegation"]
        assert detail["status"] == "attached"
        assert "single-use: shared ledger" in detail["detail"]


@pytest.mark.parametrize(
    "changed",
    [
        {"resource": "account:attacker"},
        {"org": "evil.example"},  # the principal acted as
        {"dispatch_context": dispatch_context_for(destination="evil.example")},
        {"dispatch_context": dispatch_context_for(operation="POST /v1/refunds")},
    ],
)
def test_server_refuses_a_valid_proof_moved_to_another_target(
    tmp_path, monkeypatch, changed
):
    """The reviewer's finding: with a valid proof, the resource, the person
    acted as and the destination could each be changed and still allow."""
    with _client(tmp_path, monkeypatch) as client:
        signed_for_default = _server_evidence()
        moved = _post(client, signed_for_default, **changed)
        assert moved.status_code == 403, moved.text
        assert "different action" in moved.json()["reason"]
        # the same presentation, sent unchanged, is still good: the refusal
        # did not burn it
        assert _post(client, signed_for_default).status_code == 200


def test_caller_cannot_supply_the_sealed_dispatch_itself(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        body = _request({"bound": {"resource": "x"}})
        del body["execution_action"], body["dispatch_context"]
        assert client.post("/v1/decide", json=body).status_code == 422


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


# ---- review of #223/#224: what a sealed ALLOW carries to the mint -----------


def test_an_allow_seals_when_its_delegated_authority_ends_and_who_it_rests_on():
    from agent_dna.multi_agent_security.gate import sealed_delegation

    links = chain()
    result = decide(engine(), evidence(links))
    sealed = sealed_delegation(result.reason)
    assert sealed["chain"] == link_hash(links[-1])
    assert sealed["links"] == [link_hash(link) for link in links]
    assert sealed["parties"] == ["operator", "planner", "payer"]
    assert sealed["expires_at"] == min(link["expires_at"] for link in links)
    assert sealed_delegation("Behavior matches trusted profile.") is None


@pytest.mark.parametrize(
    "reason",
    [
        "ok; delegation=",
        "ok; delegation={not json",
        'ok; delegation={"chain":"x"}',
        'ok; delegation={"chain":"' + "0" * 64 + '","depth":1,"expires_at":"soon",'
        '"links":[],"parties":["a"]}',
    ],
)
def test_an_unreadable_seal_is_an_error_never_treated_as_absent(reason):
    from agent_dna.multi_agent_security.gate import sealed_delegation

    with pytest.raises(ValueError, match="sealed delegation"):
        sealed_delegation(reason)


def test_only_the_final_seal_counts():
    """Text earlier in a reason cannot stand in for the engine's seal."""
    from agent_dna.multi_agent_security.gate import sealed_delegation

    result = decide(engine(), evidence())
    real = sealed_delegation(result.reason)
    forged = '; delegation={"chain":"' + "f" * 64 + '","depth":1,"expires_at":9e12,'
    forged += '"links":[],"parties":["x"]}'
    assert sealed_delegation("note" + forged + result.reason) == real


def test_the_adapter_and_serialization_are_covered_too():
    base = {**BOUND, "adapter": "https", "serialization": "pv-json-parameters/0.1"}
    assert decide(engine(), bound_evidence(base, base)).decision is Decision.ALLOW
    held(
        decide(engine(), bound_evidence(base, {**base, "adapter": "shell"})),
        "different action",
    )
    held(
        decide(engine(), bound_evidence(base, {**base, "serialization": "form"})),
        "different action",
    )


@pytest.mark.parametrize("name", ["payer ", " payer", "pay\ter", "payer\u200b"])
def test_identity_names_that_only_look_alike_refuse_to_load(name):
    raw = config()
    raw["agents"][name] = KEYS["thief"]["public_key"]
    with pytest.raises(DelegationConfigError, match="whitespace or non-printable"):
        DelegationPolicy.from_dict(raw)


def test_arguments_and_bound_parameters_must_be_the_same_values(tmp_path, monkeypatch):
    """1 == True in Python. A request stating amount 1 in ``arguments`` and
    true in the parameters the permit binds used to pass the equality check,
    so a proof signed for one covered the other."""
    with _client(tmp_path, monkeypatch) as client:
        body = _request()
        body["arguments"] = {"amount": 1, "payee_id": "V-100"}
        body["execution_action"]["parameters"] = {"amount": True, "payee_id": "V-100"}
        refused = client.post("/v1/decide", json=body)
        assert refused.status_code == 422
        assert "must match arguments" in refused.text
        body["execution_action"]["parameters"] = {"amount": 1.0, "payee_id": "V-100"}
        assert client.post("/v1/decide", json=body).status_code == 422


# ---- review of #225: names in lists, duplicate keys, sealed keys -------------


@pytest.mark.parametrize(
    "field, name, hint",
    [
        ("revoked_agents", " planner", "did you mean 'planner'"),
        ("revoked_agents", "Planner", "did you mean 'planner'"),
        ("revoked_agents", "nobody", "not a pinned identity"),
        ("required_agents", "Payer", "did you mean 'payer'"),
        (
            "required_agents",
            "operator",
            "not a pinned identity",
        ),  # a root, not an agent
    ],
)
def test_a_name_that_matches_no_identity_refuses_to_load(field, name, hint):
    """A revoked name with a leading space or other capitalization used to
    load silently and revoke no one."""
    with pytest.raises(DelegationConfigError, match=hint):
        DelegationPolicy.from_dict(config(**{field: [name]}))


def test_duplicate_keys_in_the_file_refuse_to_load(tmp_path):
    """json.loads keeps the last value: a second, empty "revoked_agents"
    lower in the file would silently undo the first."""
    good = json.dumps(config(revoked_agents=["planner"]))
    path = tmp_path / "delegation.json"
    path.write_text(good[:-1] + ', "revoked_agents": []}')
    with pytest.raises(DelegationConfigError, match="duplicate key 'revoked_agents'"):
        DelegationPolicy.from_file(path)


def test_the_seal_records_the_key_each_party_verified_under():
    from agent_dna.multi_agent_security.gate import sealed_delegation

    sealed = sealed_delegation(decide(engine(), evidence()).reason)
    assert sealed["keys"] == {
        name: KEYS[name]["public_key"] for name in ("operator", "planner", "payer")
    }


# ---- review of #226 (Medium): a different spelling walked past required_for --


@pytest.mark.parametrize(
    "capability",
    [
        "CRM.read_contact",
        "Crm.Read_Contact",
        "crm .read_contact",
        " crm.read_contact",
        "ｃｒｍ.read_contact",  # fullwidth letters
        "сrm.read_contact",  # Cyrillic с
        "crm.read\u200b_contact",
    ],
)
def test_a_respelled_capability_still_needs_a_chain(capability):
    """With required_for ["crm."], CRM.read_contact was held for a missing
    grant, approved and allowed with no seal, then minted for the same real
    request. A variant now needs a chain, and no chain covers it."""
    policy = DelegationPolicy.from_dict(
        config(required_agents=[], required_for=["crm."])
    )
    assert policy.requires("anyone", capability), capability
    eng = engine(required_agents=[], required_for=["crm."])
    held(decide(eng, agent="reporting-bot", cap=capability), "delegation_required")


def test_capabilities_outside_the_requirement_are_untouched():
    policy = DelegationPolicy.from_dict(
        config(required_agents=[], required_for=["crm."])
    )
    assert not policy.requires("anyone", "billing.read")
    assert not policy.requires("anyone", "crmx.read")
    assert policy.requires("anyone", "crm.read_contact")
    # with no required_for in use, odd names are not swept up
    plain = DelegationPolicy.from_dict(config(required_agents=[]))
    assert not plain.requires("anyone", "сrm.read_contact")


def test_a_chain_is_still_matched_exactly_not_by_folding():
    """Folding decides that a chain is REQUIRED. What a chain grants is
    compared exactly, so a variant is never covered by a chain for the
    real name."""
    eng = engine(required_agents=[], required_for=["payments."])
    variant = "PAYMENTS.pay_invoice"
    ev = evidence(cap=variant)
    held(decide(eng, ev, cap=variant), "delegation_out_of_scope")


# ---- review of #227 (L-G): a revoked agent with no chain still got an allow --


def test_a_revoked_agent_gets_nothing_with_or_without_a_chain():
    eng = engine(required_agents=[], revoked_agents=["planner"])
    # no chain presented, and nothing requires one for this capability
    held(decide(eng, agent="planner", cap="crm.read"), "delegation_revoked")
    # other agents are untouched
    assert decide(eng, agent="reporting-bot", cap="crm.read").decision is (
        Decision.ALLOW
    )
