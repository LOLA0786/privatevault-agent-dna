"""pv-delegation/2: cumulative budgets, argument constraints, depth limits
(ADR 0042). Found by probing: per-call max_amount let a delegate repeat
refunds without limit and siblings outspend their parent's pool (Rs 27,000
from Rs 10,000); a link could not restrict argument values (merchant M-999
passed); and the only depth bound was a fixed eight links.

Claims -> tests:
  - A link without the new limits is a pv-delegation/1 link, byte for byte;
    v2 links verify; malformed v2 fields are refused
    -> test_v1_links_are_unchanged, test_v2_shape_is_checked[*]
  - Each limit narrows like max_amount: a child may not raise or drop it;
    a v1 child cannot sit under a limited v2 parent; a v2 child may narrow a
    v1 parent
    -> test_limits_only_narrow[*], test_mixed_versions
  - Constraints bind argument values; a missing argument refuses
    -> test_constraints_bind_arguments
  - The budget ledger charges every budgeted link at once, all or nothing,
    in minor units; release gives a charge back; concurrent charges never
    exceed a shared parent budget
    -> test_ledger_charges_all_or_nothing, test_ledger_concurrent_siblings
  - Through /v1/decide: repeated refunds stop at the budget, a blocked
    attempt is not charged, the spend survives a restart; siblings and their
    parent racing cannot exceed the parent's pool; merchant/currency
    constraints hold; max_depth stops a further hop
    -> test_server_budget_is_cumulative, test_server_sibling_race,
       test_server_constraints, test_server_max_depth
"""

from __future__ import annotations

import importlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from agent_dna.consensus.signing import generate_voter_keypair
from agent_dna.multi_agent_security import (
    SPEC_V2,
    DelegationBudgets,
    Exhausted,
    TrustAnchors,
    chain_budgets,
    delegated_action_id,
    issue_link,
    link_hash,
    sign_presentation,
    verify_chain,
    within_scope,
)
from agent_dna.multi_agent_security.delegation import SPEC, DelegationError
from agent_dna.multi_agent_security.gate import sealed_dispatch
from agent_dna.signer import generate_keypair
from tests.decide_binding import decide_json

AUD, CAP = "pv-production", "payments.issue_refund"
NAMES = ("operator", "A", "B", "B1", "B2", "C", "D")
K = {n: generate_voter_keypair() for n in NAMES}
SERVER = generate_keypair()
ANCHORS = TrustAnchors(
    roots={"operator": K["operator"]["public_key"]},
    agents={n: K[n]["public_key"] for n in NAMES[1:]},
)


def link(frm, to, parent=None, caps=(CAP,), **kw):
    return issue_link(
        K[frm]["signing_key"],
        delegator=frm,
        delegate=to,
        capabilities=list(caps),
        parent=parent,
        **kw,
    )


# ------------------------------------------------------------------ library


def test_v1_links_are_unchanged():
    v1 = link("operator", "A", max_amount=10.0)
    assert v1["spec"] == SPEC and "budget" not in v1 and "max_depth" not in v1
    v2 = link("operator", "A", budget=10.0)
    assert v2["spec"] == SPEC_V2
    assert (v2["budget"], v2["constraints"], v2["max_depth"]) == (10.0, {}, None)
    for chain in ([v1], [v2]):
        verify_chain(chain, ANCHORS)


@pytest.mark.parametrize(
    "field, value",
    [
        ("budget", -1),
        ("budget", "100"),
        ("max_depth", 9),
        ("max_depth", True),
        ("constraints", {"merchant_id": []}),
        ("constraints", {"merchant_id": ["*"]}),
        ("constraints", {"merchant_id": [True]}),
        ("constraints", ["merchant_id"]),
    ],
)
def test_v2_shape_is_checked(field, value):
    v2 = link("operator", "A", budget=10.0)
    v2[field] = value
    v2["signature"] = "0" * 128  # shape is checked before the signature
    with pytest.raises(DelegationError):
        verify_chain([v2], ANCHORS)


@pytest.mark.parametrize(
    "parent_kw, child_kw, message",
    [
        ({"budget": 5000.0}, {"budget": 6000.0}, "budget 6000.0 widens"),
        ({"budget": 5000.0}, {"max_amount": 100.0}, "budget None widens"),
        (
            {"constraints": {"m": ["M-101"]}},
            {"constraints": {"m": ["M-101", "M-999"]}},
            "constraint 'm'",
        ),
        (
            {"constraints": {"m": ["M-101"]}},
            {"constraints": {"c": ["INR"]}},
            "constraint 'm' None",
        ),
        ({"max_depth": 0}, {"max_depth": 0}, "may not delegate further"),
        (
            {"max_depth": 2},
            {"max_depth": 2},
            "max_depth 2 widens the parent's remaining 1",
        ),
        ({"max_depth": 2}, {"budget": 1.0}, "max_depth None widens"),
    ],
    ids=[
        "budget-raised",
        "budget-dropped",
        "constraint-widened",
        "constraint-dropped",
        "depth-zero",
        "depth-not-lowered",
        "depth-dropped",
    ],
)
def test_limits_only_narrow(parent_kw, child_kw, message):
    root = link("operator", "A", may_delegate=True, **parent_kw)
    child = link("A", "B", parent=root, **child_kw)
    with pytest.raises(DelegationError, match=message):
        verify_chain([root, child], ANCHORS)
    ok_child = {"budget": 4000.0} if "budget" in parent_kw else {}
    if "constraints" in parent_kw:
        ok_child = {"constraints": {"m": ["M-101"], "c": ["INR"]}}
    if parent_kw.get("max_depth", 0) >= 1:
        ok_child = {"max_depth": parent_kw["max_depth"] - 1}
    if parent_kw.get("max_depth") != 0:
        verify_chain([root, link("A", "B", parent=root, **ok_child)], ANCHORS)


def test_mixed_versions():
    v1_root = link("operator", "A", may_delegate=True, max_amount=100.0)
    verify_chain(
        [v1_root, link("A", "B", parent=v1_root, max_amount=50.0, budget=80.0)], ANCHORS
    )
    v2_root = link("operator", "A", may_delegate=True, budget=100.0)
    with pytest.raises(DelegationError, match="budget None widens"):
        verify_chain(
            [v2_root, link("A", "B", parent=v2_root, max_amount=50.0)], ANCHORS
        )


def test_constraints_bind_arguments():
    root = link(
        "operator", "A", constraints={"merchant_id": ["M-101"], "currency": ["INR"]}
    )
    good = {"amount": 10, "merchant_id": "M-101", "currency": "INR"}

    def scope(args):
        return within_scope(
            [root], ANCHORS, agent_id="A", capability=CAP, arguments=args
        )

    assert scope(good).allowed
    for bad in (
        {**good, "merchant_id": "M-999"},
        {**good, "currency": "USD"},
        {"amount": 10, "currency": "INR"},
        {**good, "merchant_id": ["M-101"]},
        None,
    ):
        decision = scope(bad)
        assert (
            not decision.allowed and "delegation_constraint_violated" in decision.reason
        )


def _budget_chain():
    root = link("operator", "A", may_delegate=True, budget=10000.0)
    return (
        root,
        link("A", "B1", parent=root, budget=5000.0),
        link("A", "B2", parent=root, budget=5000.0),
    )


def test_ledger_charges_all_or_nothing(tmp_path):
    ledger = DelegationBudgets(tmp_path / "b.db")
    root, b1, b2 = _budget_chain()
    assert chain_budgets([root, b1]) == [
        (link_hash(root), 10000.0),
        (link_hash(b1), 5000.0),
    ]
    first = ledger.charge(chain_budgets([root, b1]), 4999.99)
    assert not isinstance(first, Exhausted)
    over = ledger.charge(chain_budgets([root, b1]), 0.02)
    assert isinstance(over, Exhausted) and over.link_hash == link_hash(b1)
    assert ledger.spent(link_hash(root)) == 499999  # nothing charged to the root either
    for _ in range(10):
        assert not isinstance(ledger.charge(chain_budgets([root]), 0.1), Exhausted)
    assert ledger.spent(link_hash(root)) == 499999 + 100  # exact, no drift
    ledger.release(first)
    assert ledger.spent(link_hash(b1)) == 0 and ledger.spent(link_hash(root)) == 100


def test_ledger_concurrent_siblings(tmp_path):
    ledger = DelegationBudgets(tmp_path / "b.db")
    root, b1, b2 = _budget_chain()
    chains = [[root]] * 4 + [[root, b1]] * 4 + [[root, b2]] * 4
    barrier = threading.Barrier(len(chains))

    def go(chain):
        barrier.wait()
        return not isinstance(ledger.charge(chain_budgets(chain), 2000.0), Exhausted)

    with ThreadPoolExecutor(len(chains)) as pool:
        ok = list(pool.map(go, chains))
    assert ok.count(True) == 5  # 5 x 2,000 = the root's 10,000, never more
    assert ledger.spent(link_hash(root)) == 1000000


# ------------------------------------------------------------------ server


@pytest.fixture()
def server(tmp_path, monkeypatch):
    def start():
        (tmp_path / "delegation.json").write_text(
            json.dumps(
                {
                    "audience": AUD,
                    "roots": {"operator": K["operator"]["public_key"]},
                    "agents": {n: K[n]["public_key"] for n in NAMES[1:]},
                    "required_for": ["payments."],
                }
            )
        )
        (tmp_path / "grants.json").write_text(
            json.dumps(
                [
                    {"agent_id": a, "capability": CAP, "granted_by": "ops"}
                    for a in NAMES[1:]
                ]
            )
        )
        for name, value in {
            "PV_DB_PATH": tmp_path / "pv.db",
            "PV_GRANTS_FILE": tmp_path / "grants.json",
            "PV_BASELINE_CAPABILITIES": CAP,
            "PV_ALLOW_NO_AUTH": "1",
            "PV_RECEIPT_SIGNING_KEY": SERVER["signing_key"],
            "PV_TRUSTED_PUBLIC_KEYS": SERVER["public_key"],
            "PV_DELEGATION_FILE": tmp_path / "delegation.json",
            "PV_CONSENSUS_NONCE_DB": tmp_path / "nonces.db",
        }.items():
            monkeypatch.setenv(name, str(value))
        for name in ("PV_API_KEYS_FILE", "PV_CONSENSUS_FILE", "PV_DATABASE_URL"):
            monkeypatch.delenv(name, raising=False)
        import api.server as srv

        importlib.reload(srv)
        return TestClient(srv.app)

    return start


def decide(client, agent, amount, chain, **args):
    body = decide_json(agent, CAP, arguments={"amount": amount, **args})
    bound = sealed_dispatch(body["execution_action"], body["dispatch_context"])
    body["evidence"] = {
        "delegation": {
            "chain": chain,
            "presentation": sign_presentation(
                K[agent]["signing_key"],
                audience=AUD,
                chain_hash=link_hash(chain[-1]),
                action_id=delegated_action_id(agent, CAP, body["arguments"], bound),
            ),
        }
    }
    response = client.post("/v1/decide", json=body)
    return response.json()["decision"], response.json()["reason"]


def test_server_budget_is_cumulative(server):
    root = link("operator", "A", may_delegate=True, budget=10000.0, max_amount=10000.0)
    ab = link("A", "B", parent=root, budget=5000.0, max_amount=5000.0)
    with server() as client:
        assert decide(client, "B", 3000, [root, ab])[0] == "allow"
        verdict, reason = decide(client, "B", 3000, [root, ab])
        assert verdict == "block" and "delegation_budget_exceeded: link 1" in reason
        assert "spent 3000 of its 5000" in reason
        assert decide(client, "B", 2000, [root, ab])[0] == "allow"  # exactly the budget
        assert decide(client, "B", 1, [root, ab])[0] == "block"
        assert (
            decide(client, "A", 5000, [root])[0] == "allow"
        )  # the root had 5,000 left
        assert decide(client, "A", 1, [root])[0] == "block"
    with server() as client:  # spend survives a restart
        assert "delegation_budget_exceeded" in decide(client, "B", 1, [root, ab])[1]


def test_server_sibling_race(server):
    """A, B1 and B2 each spend Rs 4,500 at the same instant from A's Rs 10,000
    pool: two fit, the third would make Rs 13,500. One request per agent:
    concurrent decides for the SAME agent on SQLite can fail to seal a record
    (fails closed; predates ADR 0042), which is not what this test is about."""
    root = link("operator", "A", may_delegate=True, budget=10000.0)
    b1 = link("A", "B1", parent=root, budget=5000.0)
    b2 = link("A", "B2", parent=root, budget=5000.0)
    jobs = [("A", [root]), ("B1", [root, b1]), ("B2", [root, b2])]
    with server() as client:
        barrier = threading.Barrier(len(jobs))

        def go(job):
            barrier.wait()
            return decide(client, job[0], 4500, job[1])

        with ThreadPoolExecutor(len(jobs)) as pool:
            results = list(pool.map(go, jobs))
    verdicts = [v for v, _ in results]
    assert verdicts.count("allow") == 2, results
    [refused] = [r for v, r in results if v == "block"]
    assert "delegation_budget_exceeded: link 0" in refused  # A's pool, not a sibling's


def test_server_constraints(server):
    scope = {"merchant_id": ["M-101"], "currency": ["INR"]}
    root = link("operator", "A", may_delegate=True, constraints=scope)
    ab = link("A", "B", parent=root, constraints=scope)
    wide = link(
        "A",
        "B",
        parent=root,
        constraints={"merchant_id": ["M-101", "M-999"], "currency": ["INR"]},
    )
    with server() as client:
        assert (
            decide(client, "B", 100, [root, ab], merchant_id="M-101", currency="INR")[0]
            == "allow"
        )
        for args, why in (
            ({"merchant_id": "M-999", "currency": "INR"}, "merchant_id='M-999'"),
            ({"merchant_id": "M-101", "currency": "USD"}, "currency='USD'"),
            ({"currency": "INR"}, "merchant_id=None"),
        ):
            verdict, reason = decide(client, "B", 100, [root, ab], **args)
            assert verdict == "block" and why in reason, reason
        verdict, reason = decide(
            client, "B", 100, [root, wide], merchant_id="M-999", currency="INR"
        )
        assert verdict == "block" and "widens the parent's" in reason


def test_server_max_depth(server):
    root = link("operator", "A", may_delegate=True, max_depth=2)
    ab = link("A", "B", parent=root, may_delegate=True, max_depth=1)
    bc = link("B", "C", parent=ab, may_delegate=True, max_depth=0)
    cd = link("C", "D", parent=bc, max_depth=0)
    with server() as client:
        assert decide(client, "C", 100, [root, ab, bc])[0] == "allow"
        verdict, reason = decide(client, "D", 100, [root, ab, bc, cd])
        assert verdict == "block" and "'C' may not delegate further" in reason
