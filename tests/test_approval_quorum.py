"""Quorum and roles for human approvals (ADR 0031).

ADR 0020 let one signed approval satisfy REQUIRE_APPROVAL, with one pinned
approver. Retest 5 (20 October 2026) lists "no quorum, roles, SSO" as the
first enterprise gap.

Claims -> tests:
  - Two approvers holding the policy's roles turn REQUIRE_APPROVAL into
    ALLOW; the record seals one digest naming the set; minting is bounded
    by the earliest approval's expiry
    -> test_two_of_two_with_roles_allows_and_seals_the_set
  - Too few approvals, an approver without a role, the same person twice,
    a required role not covered by a distinct person: refused, and nothing
    is consumed -> test_quorum_refusals_consume_nothing
  - The requester can never be one of the approvers
    -> test_requester_cannot_count_towards_the_quorum
  - All-or-nothing claim: a set containing a used approval burns none of
    the others (SQLite and PostgreSQL)
    -> test_a_used_approval_burns_none_of_the_others[*]
  - Two decisions racing with overlapping approval sets: one ALLOW
    -> test_overlapping_sets_race_to_one_allow
  - Without a policy, one approval still suffices and several are refused
    -> test_without_a_policy_one_approval_suffices
  - Policy: rule selection (exact, longest prefix, default, none),
    distinct-person role matching, malformed files refused
    -> test_rule_selection, test_roles_need_distinct_people[*],
       test_malformed_policies_are_refused[*]
  - Composition: a policy without approver keys, or a bad policy, stops
    start-up; the manifest names the policy digest
    -> test_composition_*
  - HTTP: a quorum decide mints a permit naming the set digest; the policy
    file is part of the sealed decision configuration
    -> test_api_quorum_mints_a_permit_naming_the_set
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta

import pytest

from agent_dna.approval_bridge import (
    APPROVAL_ALREADY_USED,
    APPROVAL_QUORUM_NOT_MET,
    APPROVAL_SEPARATION_OF_DUTIES,
    APPROVAL_SET_SPEC,
    ApprovalBridge,
)
from agent_dna.approval_policy import (
    APPROVAL_POLICY_SPEC,
    ApprovalPolicy,
    ApprovalPolicyError,
)
from agent_dna.approval_v01 import approval_artifact_digest
from agent_dna.authority_v01 import sha256_digest
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.grants import GrantRegistry
from agent_dna.sqlite_store import SQLiteDecisionStore
from tests.approval_world import ApproverWorld
from tests.pg_support import ADMIN_URL
from tests.test_approval_bridge import AGENT, CAP, ORG, World, _execution_action

POLICY = {
    "spec": APPROVAL_POLICY_SPEC,
    "approvers": {
        "alice@lender.example": {"roles": ["treasury"]},
        "bob@lender.example": {"roles": ["treasury", "controller"]},
        "chen@lender.example": {"roles": ["controller"]},
        "dana@lender.example": {"roles": ["auditor"]},
        f"{AGENT}@{ORG}": {"roles": ["treasury"]},
    },
    "rules": [
        {
            "capability": CAP,
            "min_approvals": 2,
            "roles": ["treasury", "controller"],
            "require": {"controller": 1},
        },
        {"capability": "payments.*", "min_approvals": 2, "roles": ["treasury"]},
    ],
    "default": {"min_approvals": 1, "roles": ["treasury", "controller"]},
}


def _policy(document=None) -> ApprovalPolicy:
    return ApprovalPolicy(POLICY if document is None else document, digest="sha256:x")


class Quorum:
    """Four approvers in one bundle; the engine runs the policy above."""

    def __init__(self, tmp_path, *, policy=True, store=None):
        self.w = World(tmp_path, bridge=False)
        base = self.w.approver
        self.alice = base.add_approver("alice@lender.example", "k-alice")
        self.bob = base.add_approver("bob@lender.example", "k-bob")
        self.chen = base.add_approver("chen@lender.example", "k-chen")
        self.dana = base.add_approver("dana@lender.example", "k-dana")
        self.store = store or self.w.store
        self.w.engine.approvals = ApprovalBridge(
            trust_bundle=base.bundle,
            ledger=self.store,
            policy=_policy() if policy else None,
        )

    def approve(self, who, **kw):
        return who.approve(_execution_action(), request_id="req-inv-1", **kw)

    def decide(self, *approvals):
        block = approvals[0] if len(approvals) == 1 else {"approvals": list(approvals)}
        return self.w.decide(block)


def _digest(approval):
    return approval_artifact_digest(approval["artifact"])


def test_two_of_two_with_roles_allows_and_seals_the_set(tmp_path):
    q = Quorum(tmp_path)
    a = q.approve(q.alice)
    c = q.approve(q.chen, artifact_ttl_s=120)
    result = q.decide(a, c)
    assert result.decision is Decision.ALLOW, result.reason
    assert result.triggered_by == "approval"
    expected = sha256_digest(
        {"spec": APPROVAL_SET_SPEC, "artifacts": sorted([_digest(a), _digest(c)])}
    )
    assert result.approval_artifact_digest == expected
    assert "alice@lender.example" in result.reason
    assert "chen@lender.example" in result.reason
    # the set carries the earlier expiry; each artifact is spent
    assert q.store.approval_not_after(expected) == c["artifact"]["expires_at"]
    assert q.store.is_approval_consumed(_digest(a))
    assert q.store.is_approval_consumed(_digest(c))
    again = q.decide(a, c)
    assert again.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_ALREADY_USED in again.reason


def _refused_and_unspent(q, approvals, why):
    result = q.decide(*approvals)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_QUORUM_NOT_MET in result.reason
    assert why in result.reason
    for approval in approvals:
        assert not q.store.is_approval_consumed(_digest(approval))


def _rebind(q, document=None):
    q.w.engine.approvals = ApprovalBridge(
        trust_bundle=q.w.approver.bundle, ledger=q.store, policy=_policy(document)
    )


def test_quorum_refusals_consume_nothing(tmp_path):
    q = Quorum(tmp_path)
    alice_again = q.w.approver.add_approver("ALICE@lender.example", "k-alice-2")
    erin = q.w.approver.add_approver("erin@lender.example", "k-erin")
    document = json.loads(json.dumps(POLICY))
    document["approvers"]["erin@lender.example"] = {"roles": ["treasury"]}
    _rebind(q, document)
    # too few
    _refused_and_unspent(q, [q.approve(q.alice)], "1 of 2 required")
    # an approver whose roles cannot approve this capability
    _refused_and_unspent(
        q, [q.approve(q.alice), q.approve(q.dana)], "holds none of the roles"
    )
    # the same person twice, through a second key (case-folded principal)
    _refused_and_unspent(q, [q.approve(q.alice), q.approve(alice_again)], "same person")
    # two treasury people: the count is met, the controller slot is not
    _refused_and_unspent(
        q, [q.approve(q.alice), q.approve(erin)], "do not cover 1 controller"
    )


def test_requester_cannot_count_towards_the_quorum(tmp_path):
    q = Quorum(tmp_path)
    selfish = q.w.approver.add_approver(f"{AGENT}@{ORG}", "k-self")
    _rebind(q)
    a, s = q.approve(q.chen), q.approve(selfish)
    result = q.decide(a, s)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_SEPARATION_OF_DUTIES in result.reason
    assert not q.store.is_approval_consumed(_digest(a))


@pytest.fixture(params=["sqlite", "postgres"])
def any_store(request, tmp_path):
    if request.param == "sqlite":
        yield SQLiteDecisionStore(str(tmp_path / "q.db"))
        return
    if not ADMIN_URL:
        pytest.skip("set TEST_DATABASE_URL to run the PostgreSQL tests")
    from agent_dna.pg_store import PostgresDecisionStore

    store = PostgresDecisionStore(request.getfixturevalue("dsn"), max_size=4)
    yield store
    store.close()


def test_a_used_approval_burns_none_of_the_others(tmp_path, any_store):
    q = Quorum(tmp_path, store=any_store)
    a, b, c = q.approve(q.alice), q.approve(q.bob), q.approve(q.chen)
    assert q.decide(a, b).decision is Decision.ALLOW  # a and b are spent
    mixed = q.decide(c, b)  # the unused one first: a claim in order would burn it
    assert APPROVAL_ALREADY_USED in mixed.reason
    assert not any_store.is_approval_consumed(_digest(c))
    # c is still good with a fresh treasury approval
    assert q.decide(q.approve(q.alice), c).decision is Decision.ALLOW


def test_overlapping_sets_race_to_one_allow(tmp_path):
    q = Quorum(tmp_path)
    a, b, c = q.approve(q.alice), q.approve(q.bob), q.approve(q.chen)
    results = []
    barrier = threading.Barrier(2)

    def run(approvals):
        engine = DecisionEngine(
            scorer=q.w.engine.scorer,
            authorizer=GrantRegistry(),
            approvals=ApprovalBridge(
                trust_bundle=q.w.approver.bundle,
                ledger=SQLiteDecisionStore(str(q.w.path)),
                policy=_policy(),
            ),
        )
        barrier.wait()
        results.append(
            engine.decide(
                q.w.action(),
                approval={"approvals": approvals},
                approval_context=q.w.context(_execution_action()),
            )
        )

    threads = [
        threading.Thread(target=run, args=([a, c],)),
        threading.Thread(target=run, args=([b, c],)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(r.decision.value for r in results) == ["allow", "require_approval"]


def test_without_a_policy_one_approval_suffices(tmp_path):
    q = Quorum(tmp_path, policy=False)
    two = q.decide(q.approve(q.alice), q.approve(q.chen))
    assert APPROVAL_QUORUM_NOT_MET in two.reason
    assert q.decide(q.approve(q.alice)).decision is Decision.ALLOW


# ------------------------------------------------------------------ policy


def test_rule_selection():
    p = _policy()
    assert p.rule_for(CAP).selector == CAP
    assert p.rule_for("payments.refund").selector == "payments.*"
    assert p.rule_for("crm.read").selector == "default"
    document = {k: v for k, v in POLICY.items() if k != "default"}
    assert _policy(document).rule_for("crm.read") is None
    assert not _policy(document).evaluate("crm.read", ["bob@lender.example"]).ok


@pytest.mark.parametrize(
    "people,require,ok",
    [
        (["bob", "alice"], {"controller": 1, "treasury": 1}, True),
        (["bob", "chen"], {"controller": 1, "treasury": 1}, True),
        (["chen", "chen2"], {"controller": 1, "treasury": 1}, False),
        (["bob", "dana"], {"controller": 1, "treasury": 1}, False),
        (["alice", "chen"], {"controller": 2}, False),
        (["bob", "chen"], {"controller": 2}, True),
    ],
)
def test_roles_need_distinct_people(people, require, ok):
    document = json.loads(json.dumps(POLICY))
    document["approvers"]["chen2@lender.example"] = {"roles": ["controller"]}
    document["rules"][0] = {
        "capability": CAP,
        "min_approvals": 2,
        "roles": ["treasury", "controller", "auditor"],
        "require": require,
    }
    principals = [f"{p}@lender.example" for p in people]
    assert _policy(document).evaluate(CAP, principals).ok is ok


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(spec="other"),
        lambda d: d.update(extra=1),
        lambda d: d.update(approvers={}),
        lambda d: d["approvers"].update({"ALICE@lender.example": {"roles": ["x"]}}),
        lambda d: d["rules"][0].update(min_approvals=0),
        lambda d: d["rules"][0].update(min_approvals=11),
        lambda d: d["rules"][0].update(roles=[]),
        lambda d: d["rules"][0].update(require={"auditor": 1}),
        lambda d: d["rules"][0].update(require={"controller": 3}),
        lambda d: d["rules"][0].update(capability="pay*ments"),
        lambda d: d["rules"].append(dict(d["rules"][0])),
        lambda d: d["rules"][1].update(roles=["nobody-has-this"]),
    ],
    ids=[
        "spec",
        "unknown-field",
        "no-approvers",
        "repeated-approver",
        "zero",
        "eleven",
        "no-roles",
        "require-outside-roles",
        "require-exceeds-min",
        "bad-wildcard",
        "repeated-rule",
        "unholdable-role",
    ],
)
def test_malformed_policies_are_refused(mutate):
    document = json.loads(json.dumps(POLICY))
    mutate(document)
    with pytest.raises(ApprovalPolicyError):
        _policy(document)


# ------------------------------------------------------------- composition


def _write(tmp_path, name, document):
    path = tmp_path / name
    path.write_text(json.dumps(document))
    return path


def test_composition_refuses_a_policy_without_approver_keys(tmp_path, monkeypatch):
    from agent_dna import composition

    monkeypatch.delenv("PV_APPROVER_TRUST_BUNDLE", raising=False)
    monkeypatch.setenv(
        "PV_APPROVAL_POLICY_FILE", str(_write(tmp_path, "p.json", POLICY))
    )
    cfg = composition.RuntimeConfig.from_env()
    with pytest.raises(RuntimeError, match="a quorum needs approver keys"):
        composition._attach_approvals(
            cfg, object(), SQLiteDecisionStore(str(tmp_path / "x.db"))
        )


def test_composition_refuses_a_bad_policy_and_names_a_good_one(tmp_path, monkeypatch):
    from agent_dna import composition

    approver = ApproverWorld(ORG)
    monkeypatch.setenv(
        "PV_APPROVER_TRUST_BUNDLE", str(_write(tmp_path, "b.json", approver.bundle))
    )
    monkeypatch.setenv(
        "PV_APPROVAL_POLICY_FILE", str(_write(tmp_path, "bad.json", {"spec": "x"}))
    )
    store = SQLiteDecisionStore(str(tmp_path / "x.db"))

    class Core:
        approvals = None

    with pytest.raises(RuntimeError, match="PV_APPROVAL_POLICY_FILE"):
        composition._attach_approvals(
            composition.RuntimeConfig.from_env(), Core(), store
        )
    good = _write(tmp_path, "good.json", POLICY)
    monkeypatch.setenv("PV_APPROVAL_POLICY_FILE", str(good))
    core = Core()
    entry = composition._attach_approvals(
        composition.RuntimeConfig.from_env(), core, store
    )
    assert core.approvals.policy is not None
    assert core.approvals.policy.digest in entry["detail"]


# ------------------------------------------------------------------ HTTP


def test_api_quorum_mints_a_permit_naming_the_set(tmp_path, monkeypatch):
    from tests.test_api_approval_bridge import (
        PEER,
        WIRE,
        _decide,
        _dispatch,
    )
    from tests.test_api_approval_bridge import _execution_action as api_action
    from tests.test_authorize_mint_claim import _authorize_body, build_mint_env

    approver = ApproverWorld(ORG)
    alice = approver.add_approver("alice@lender.example", "k-alice")
    chen = approver.add_approver("chen@lender.example", "k-chen")
    monkeypatch.setenv(
        "PV_APPROVER_TRUST_BUNDLE", str(_write(tmp_path, "b.json", approver.bundle))
    )
    policy_path = _write(tmp_path, "approval-policy.json", POLICY)
    monkeypatch.setenv("PV_APPROVAL_POLICY_FILE", str(policy_path))
    gen = build_mint_env(tmp_path, monkeypatch)
    env = next(gen)
    try:
        client, key = env["client"], env["key"]
        one = alice.approve(api_action(), request_id="req-inv-1")
        partial = _decide(client, key, one)
        assert partial.status_code == 202, partial.text
        assert APPROVAL_QUORUM_NOT_MET in partial.json()["reason"]

        a = alice.approve(api_action(), request_id="req-inv-1")
        c = chen.approve(api_action(), request_id="req-inv-1")
        approved = _decide(client, key, {"approvals": [a, c]})
        assert approved.status_code == 200, approved.text
        record = approved.json()["record"]
        set_digest = sha256_digest(
            {"spec": APPROVAL_SET_SPEC, "artifacts": sorted([_digest(a), _digest(c)])}
        )
        assert record["approval_ref"] == set_digest
        body = _authorize_body(
            record, wire=WIRE, peer=PEER, dispatch=_dispatch(), action=api_action()
        )
        body["approval_artifact_digest"] = set_digest
        minted = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
        assert minted.status_code == 200, minted.text
        permit = minted.json()["authorization"]
        assert permit["approval_artifact_digest"] == set_digest
        assert datetime.fromisoformat(permit["expires_at"].replace("Z", "+00:00")) <= (
            datetime.now(UTC) + timedelta(seconds=300)
        )
        runtime = client.get("/v1/runtime", headers={"X-API-Key": key}).json()
        assert "quorum and roles" in json.dumps(runtime)
    finally:
        gen.close()


def test_policy_file_changes_the_sealed_configuration(monkeypatch, tmp_path):
    from agent_dna.permit_evidence import policy_bundle_digest

    base = policy_bundle_digest({}, operations_digest=None)
    path = _write(tmp_path, "p.json", POLICY)
    with_policy = policy_bundle_digest(
        {"PV_APPROVAL_POLICY_FILE": str(path)}, operations_digest=None
    )
    document = json.loads(json.dumps(POLICY))
    document["rules"][0]["min_approvals"] = 1
    document["rules"][0]["require"] = {}
    path.write_text(json.dumps(document))
    loosened = policy_bundle_digest(
        {"PV_APPROVAL_POLICY_FILE": str(path)}, operations_digest=None
    )
    assert len({base, with_policy, loosened}) == 3


def test_the_example_policy_is_valid():
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "examples/config/approval-policy.json"
    policy = ApprovalPolicy.load(path)
    assert policy.rule_for("payments.pay_invoice").require == {"controller": 1}
    assert policy.evaluate(
        "payments.pay_invoice",
        ["priya.shah@lender.example", "neha.rao@lender.example"],
    ).ok
    assert not policy.evaluate(
        "payments.pay_invoice",
        ["priya.shah@lender.example", "arjun.mehta@lender.example"],
    ).ok
