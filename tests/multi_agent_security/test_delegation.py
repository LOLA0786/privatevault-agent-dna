"""Delegation can only shrink: authority handed agent to agent never grows,
and the receiver proves that offline from operator-pinned keys."""

import time

import pytest

from agent_dna.consensus.signing import generate_voter_keypair
from agent_dna.multi_agent_security import (
    DelegationError,
    TrustAnchors,
    authorize,
    issue_link,
    link_hash,
    verify_chain,
)

KEYS = {name: generate_voter_keypair() for name in ("operator", "A", "B", "C", "M")}
ANCHORS = TrustAnchors(
    roots={"operator": KEYS["operator"]["public_key"]},
    agents={n: KEYS[n]["public_key"] for n in ("A", "B", "C")},
)


def link(frm, to, caps=("payments.",), amount=1000.0, parent=None, **kw):
    kw.setdefault("may_delegate", True)
    return issue_link(
        KEYS[frm]["signing_key"],
        delegator=frm,
        delegate=to,
        capabilities=list(caps),
        max_amount=amount,
        parent=parent,
        **kw,
    )


def chain_abc():
    root = link("operator", "A")
    a_b = link("A", "B", caps=["payments.pay_invoice"], amount=500.0, parent=root)
    b_c = link("B", "C", caps=["payments.pay_invoice"], amount=100.0, parent=a_b)
    return [root, a_b, b_c]


def refused(chain, match):
    with pytest.raises(DelegationError, match=match):
        verify_chain(chain, ANCHORS)


# ---- an honest chain -------------------------------------------------------


def test_three_hop_chain_verifies_and_authorizes_within_scope():
    chain = chain_abc()
    assert verify_chain(chain, ANCHORS)["delegate"] == "C"
    ok = authorize(
        chain, ANCHORS, agent_id="C", capability="payments.pay_invoice", amount=80
    )
    assert ok.allowed and ok.depth == 3
    assert ok.chain_hash == link_hash(chain[-1])


def test_authority_at_the_end_is_the_narrowest_along_the_way():
    chain = chain_abc()

    def decide(**kw):
        return authorize(chain, ANCHORS, agent_id="C", **kw)

    over = decide(capability="payments.pay_invoice", amount=101)
    assert not over.allowed and "delegation_over_ceiling" in over.reason
    # the operator gave A all of payments.; C was handed pay_invoice only
    wide = decide(capability="payments.refund", amount=1)
    assert not wide.allowed and "delegation_out_of_scope" in wide.reason
    silent = decide(capability="payments.pay_invoice")
    assert not silent.allowed and "delegation_amount_required" in silent.reason


def test_chain_is_bound_to_its_last_delegate():
    stolen = authorize(
        chain_abc(), ANCHORS, agent_id="A", capability="payments.pay_invoice", amount=1
    )
    assert not stolen.allowed and "delegation_not_yours" in stolen.reason


# ---- widening is refused: this is the laundering attack --------------------


def test_delegate_cannot_widen_capabilities():
    root = link("operator", "A", caps=["payments.pay_invoice"])
    refused(
        [root, link("A", "B", caps=["payments."], parent=root)],
        "widens what 'A' was given",
    )
    refused(
        [root, link("A", "B", caps=["secrets.read"], parent=root)],
        "widens what 'A' was given",
    )


def test_delegate_cannot_raise_or_remove_the_ceiling():
    root = link("operator", "A", amount=500.0)
    refused([root, link("A", "B", amount=501.0, parent=root)], "widens the parent")
    refused([root, link("A", "B", amount=None, parent=root)], "widens the parent")


def test_delegate_cannot_outlive_its_parent():
    root = link("operator", "A", ttl=60)
    refused(
        [root, link("A", "B", ttl=600, parent=root, clamp_to_parent=False)],
        "outlives",
    )


def test_no_onward_delegation_without_permission():
    root = link("operator", "A", may_delegate=False)
    refused([root, link("A", "B", parent=root)], "not allowed to delegate further")


def test_narrowing_at_every_hop_is_enforced_not_just_the_first():
    root = link("operator", "A")
    a_b = link("A", "B", amount=100.0, parent=root)
    b_c = link("B", "C", amount=900.0, parent=a_b)  # under the root's, over B's
    refused([root, a_b, b_c], "link 2: max_amount 900.0 widens")


# ---- forgery, splicing and substitution ------------------------------------


def test_only_a_pinned_root_can_start_a_chain():
    rogue = link("M", "A")
    refused([rogue], "not a pinned root authority")
    # an agent that is pinned as an agent is still not a root
    refused([link("A", "B")], "not a pinned root authority")


def test_link_signed_by_someone_other_than_the_holder_is_refused():
    root = link("operator", "A")
    refused(
        [root, link("B", "C", parent=root)],
        "signed by 'B', but the authority was held by 'A'",
    )


def test_forged_signature_is_refused():
    root = link("operator", "A")
    forged = issue_link(
        KEYS["M"]["signing_key"],  # M signs while claiming to be A
        delegator="A",
        delegate="B",
        capabilities=["payments."],
        max_amount=10.0,
        parent=root,
    )
    refused([root, forged], "signature does not verify under 'A'")


def test_edited_link_is_refused():
    chain = chain_abc()
    chain[2] = {**chain[2], "max_amount": 100000.0}
    refused(chain, "widens the parent|signature does not verify")
    chain = chain_abc()
    chain[0] = {**chain[0], "max_amount": 10**9}
    refused(chain, "signature does not verify")


def test_links_from_two_chains_cannot_be_spliced():
    generous = link("operator", "A", amount=10**6)
    modest = link("operator", "A", amount=10.0)
    child_of_modest = link("A", "B", amount=10.0, parent=modest)
    refused([generous, child_of_modest], "does not name the link before it")


def test_dropping_the_middle_of_a_chain_is_refused():
    chain = chain_abc()
    refused([chain[0], chain[2]], "signed by 'B', but the authority was held by 'A'")


def test_cycles_and_self_delegation_are_refused():
    root = link("operator", "A")
    a_b = link("A", "B", parent=root)
    refused([root, a_b, link("B", "A", parent=a_b)], "already appears in the chain")
    with pytest.raises(DelegationError, match="cannot delegate to itself"):
        verify_chain([link("operator", "operator")], ANCHORS)


def test_expired_future_and_overlong_links_are_refused():
    now = time.time()
    refused([link("operator", "A", now=now - 3600, ttl=60)], "expired")
    refused([link("operator", "A", now=now + 3600)], "issued in the future")
    refused([link("operator", "A", ttl=10**7)], "lifetime")


def test_revoked_link_voids_everything_after_it():
    chain = chain_abc()
    revoked = TrustAnchors(
        roots=ANCHORS.roots,
        agents=ANCHORS.agents,
        revoked=frozenset({link_hash(chain[1])}),
    )
    decision = authorize(
        chain, revoked, agent_id="C", capability="payments.pay_invoice", amount=1
    )
    assert not decision.allowed and "revoked" in decision.reason


def test_no_match_everything_pattern():
    refused([link("operator", "A", caps=["*"])], "capabilities")
    refused([link("operator", "A", caps=["payments.*"])], "capabilities")


@pytest.mark.parametrize(
    "chain",
    [None, [], "x", [1], [{}], [{"spec": "pv-delegation/1"}], [[]]],
)
def test_malformed_chains_are_a_refusal_never_a_crash(chain):
    decision = authorize(chain, ANCHORS, agent_id="C", capability="payments.x")
    assert not decision.allowed
    assert decision.reason.startswith("delegation_invalid")


def test_depth_is_bounded():
    names = [f"n{i}" for i in range(10)]
    keys = {n: generate_voter_keypair() for n in names}
    anchors = TrustAnchors(
        roots={"operator": KEYS["operator"]["public_key"]},
        agents={n: k["public_key"] for n, k in keys.items()},
    )
    chain = [link("operator", "n0")]
    for a, b in zip(names, names[1:], strict=False):
        chain.append(
            issue_link(
                keys[a]["signing_key"],
                delegator=a,
                delegate=b,
                capabilities=["payments."],
                max_amount=1000.0,
                may_delegate=True,
                parent=chain[-1],
            )
        )
    with pytest.raises(DelegationError, match="deeper than"):
        verify_chain(chain, anchors)
