"""Delegation can only shrink: authority handed agent to agent never grows,
and the receiver proves that offline from operator-pinned keys."""

import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from agent_dna.consensus.signing import generate_voter_keypair
from agent_dna.multi_agent_security import (
    DelegationChallenges,
    DelegationError,
    TrustAnchors,
    authorize,
    issue_link,
    link_hash,
    sign_possession,
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


def proof_for(
    chain,
    *,
    signer="C",
    capability="payments.pay_invoice",
    amount=80,
    request_hash="a" * 64,
    challenges=None,
    ttl=60,
):
    challenges = challenges or DelegationChallenges("payments-api")
    challenge = challenges.issue(
        chain_hash=link_hash(chain[-1]),
        agent_id="C",
        capability=capability,
        amount=amount,
        request_hash=request_hash,
        ttl=ttl,
    )
    return {
        "agent_id": "C",
        "capability": capability,
        "amount": amount,
        "request_hash": request_hash,
        "challenges": challenges,
        "proof": sign_possession(KEYS[signer]["signing_key"], challenge),
    }


# ---- an honest chain -------------------------------------------------------


def test_three_hop_chain_verifies_and_authorizes_within_scope():
    chain = chain_abc()
    assert verify_chain(chain, ANCHORS)["delegate"] == "C"
    ok = authorize(chain, ANCHORS, **proof_for(chain))
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


@pytest.mark.parametrize("field", ["max_amount", "issued_at", "expires_at"])
@pytest.mark.parametrize(
    "value", [10**400, -(10**400), float("inf"), float("nan"), True]
)
def test_hostile_numbers_are_refused_before_signature_verification(field, value):
    chain = chain_abc()
    chain[0][field] = value  # attacker needs no signing key
    decision = authorize(
        chain, ANCHORS, agent_id="C", capability="payments.pay_invoice", amount=1
    )
    assert not decision.allowed and "delegation_invalid" in decision.reason


@pytest.mark.parametrize("amount", [10**400, float("nan"), float("inf"), True, "1", -1])
def test_invalid_request_amount_refused_even_without_ceiling(amount):
    chain = [link("operator", "C", amount=None)]
    decision = authorize(
        chain, ANCHORS, agent_id="C", capability="payments.pay_invoice", amount=amount
    )
    assert not decision.allowed and "invalid amount" in decision.reason


@pytest.mark.parametrize("now", [10**400, float("nan"), float("inf"), True, "tomorrow"])
def test_invalid_verification_time_fails_closed(now):
    decision = authorize(
        chain_abc(), ANCHORS, agent_id="C", capability="payments.pay_invoice", now=now
    )
    assert not decision.allowed and "verification time" in decision.reason


def test_copied_chain_and_claimed_final_identity_are_not_enough():
    decision = authorize(
        chain_abc(), ANCHORS, agent_id="C", capability="payments.pay_invoice", amount=80
    )
    assert not decision.allowed and decision.reason == "delegation_proof_required"


@pytest.mark.parametrize("signer", ["operator", "A", "B", "M"])
def test_only_final_delegate_key_can_sign_request(signer):
    chain = chain_abc()
    decision = authorize(chain, ANCHORS, **proof_for(chain, signer=signer))
    assert not decision.allowed and "final delegate's pinned key" in decision.reason


@pytest.mark.parametrize(
    "changes",
    [
        {"amount": 81},
        {"request_hash": "b" * 64},
        {"request_hash": None},
        {"challenges": None},
        {"capability": None},
    ],
)
def test_proof_cannot_be_moved_to_a_different_request(changes):
    chain = chain_abc()
    params = proof_for(chain)
    decision = authorize(chain, ANCHORS, **(params | changes))
    assert not decision.allowed
    assert authorize(
        chain, ANCHORS, **params
    ).allowed  # failed attempt did not spend it


def test_proof_is_bound_to_chain_even_when_authority_matches():
    first, second = chain_abc(), chain_abc()
    params = proof_for(first)
    assert not authorize(second, ANCHORS, **params).allowed
    assert authorize(first, ANCHORS, **params).allowed


def test_proof_cannot_change_capability_even_within_delegated_scope():
    chain = [link("operator", "C")]
    params = proof_for(chain)
    result = authorize(chain, ANCHORS, **(params | {"capability": "payments.refund"}))
    assert not result.allowed and "does not cover" in result.reason
    assert authorize(chain, ANCHORS, **params).allowed


def test_bad_signature_does_not_consume_holder_challenge():
    chain = chain_abc()
    params = proof_for(chain)
    forged = params | {"proof": params["proof"] | {"signature": "0" * 128}}
    assert not authorize(chain, ANCHORS, **forged).allowed
    assert authorize(chain, ANCHORS, **params).allowed


@pytest.mark.parametrize("audience", ["payments-api", "another-api"])
def test_proof_is_refused_by_other_receiver_or_after_restart(audience):
    chain = chain_abc()
    params = proof_for(chain)
    other = params | {"challenges": DelegationChallenges(audience)}
    assert not authorize(chain, ANCHORS, **other).allowed
    assert authorize(chain, ANCHORS, **params).allowed


def test_replayed_proof_is_single_use_even_under_racing_threads():
    chain = chain_abc()
    params = proof_for(chain)
    barrier = Barrier(16)

    def attempt(_):
        barrier.wait()
        return authorize(chain, ANCHORS, **params).allowed

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(16)))
    assert sum(results) == 1
    assert not authorize(chain, ANCHORS, **params).allowed


def test_expired_proof_refused_even_when_wall_clock_moves_back(monkeypatch):
    chain = chain_abc()
    clock = [100.0]
    monkeypatch.setattr(
        "agent_dna.multi_agent_security.possession.time.monotonic", lambda: clock[0]
    )
    params = proof_for(chain, ttl=1)
    clock[0] += 2
    # Wall-clock rollback cannot extend the receiver's monotonic deadline.
    earlier = time.time() - 1
    monkeypatch.setattr(
        "agent_dna.multi_agent_security.possession.time.time", lambda: earlier
    )
    decision = authorize(chain, ANCHORS, **params)
    assert not decision.allowed and "expired" in decision.reason


@pytest.mark.parametrize(
    "field,value", [("audience", "other"), ("expires_at", 10**100), ("amount", 81)]
)
def test_holder_cannot_edit_and_resign_receiver_challenge(field, value):
    chain = chain_abc()
    params = proof_for(chain)
    edited = params["proof"]["challenge"] | {field: value}
    forged = params | {"proof": sign_possession(KEYS["C"]["signing_key"], edited)}
    assert not authorize(chain, ANCHORS, **forged).allowed
    assert authorize(chain, ANCHORS, **params).allowed


def test_missing_pinned_final_delegate_key_refuses_proof():
    chain = chain_abc()
    anchors = TrustAnchors(
        roots=ANCHORS.roots,
        agents={k: v for k, v in ANCHORS.agents.items() if k != "C"},
    )
    result = authorize(chain, anchors, **proof_for(chain))
    assert not result.allowed and "final delegate has no pinned key" in result.reason


@pytest.mark.parametrize(
    "proof",
    [
        None,
        [],
        {},
        {"challenge": [], "signature": "x"},
        {"challenge": {"nonce": "a" * 64}, "signature": "z" * 128},
    ],
)
def test_malformed_possession_proof_refused(proof):
    chain = chain_abc()
    params = proof_for(chain)
    assert not authorize(chain, ANCHORS, **(params | {"proof": proof})).allowed


def test_pending_challenge_limit_refuses_without_evicting_live_request():
    chain = chain_abc()
    receiver = DelegationChallenges("payments-api", max_pending=1)
    params = proof_for(chain, challenges=receiver)
    with pytest.raises(ValueError, match="too many pending"):
        proof_for(chain, challenges=receiver)
    assert authorize(chain, ANCHORS, **params).allowed
    assert authorize(chain, ANCHORS, **proof_for(chain, challenges=receiver)).allowed
