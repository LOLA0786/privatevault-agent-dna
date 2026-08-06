"""Policy mining: derive candidate controls from sealed history."""

import time

from agent_dna.decision import Decision, DecisionResult, Severity
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.policy_miner import mine
from agent_dna.policy_replay import ReplayInputStore
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction

BASE = 1_760_000_000.0


def _mk(tmp_path, fields=("amount",)):
    store = SQLiteDecisionStore(tmp_path / "pv.db")
    replay = ReplayInputStore(
        path=str(tmp_path / "replay.db"), retain_fields=list(fields)
    )
    rec = DecisionRecorder(store=store)
    rec.replay_capture = replay.capture
    return store, replay, rec


def _decide(rec, agent, cap, verdict, trigger, args=None, ts=None):
    action = AgentAction(
        agent_id=agent,
        capability=cap,
        timestamp=ts or time.time(),
        arguments=args or {},
    )
    result = DecisionResult(
        decision=verdict,
        triggered_by=trigger,
        reason="test",
        capability=cap,
        agent_id=agent,
        drift_score=0.0,
        severity=list(Severity)[0],
    )
    return rec.record(action, result)


def test_mines_threshold_the_org_already_enforces_by_hand(tmp_path):
    store, replay, rec = _mk(tmp_path)
    for amt in (5_000, 20_000, 50_000, 90_000, 100_000):
        _decide(
            rec,
            "ap-1",
            "payments.initiate_wire",
            Decision.ALLOW,
            "baseline",
            {"amount": amt},
        )
    for amt in (250_000, 300_000):
        _decide(
            rec,
            "ap-1",
            "payments.initiate_wire",
            Decision.REQUIRE_APPROVAL,
            "drift",
            {"amount": amt},
        )

    cands = mine(store, replay, min_support=3)
    caps = [c for c in cands if c.id.startswith("cap-")]
    assert caps, [c.id for c in cands]
    c = caps[0]
    assert c.kind == "policy" and c.severity == "HIGH"
    rule = c.policy_document["policies"][0]
    assert rule["condition"]["value"] == 100_000
    assert rule["condition"]["operator"] == ">"
    # assertions derive from OBSERVED data
    names = [a["expect"] for a in c.policy_document["assertions"]]
    assert names == ["block", "allow"]
    assert len(c.evidence["sample_refused"][0]["record_hash"]) == 64
    assert all(len(value) == 64 for value in c.evidence["record_hashes"])


def test_suggested_cap_blocks_nothing_previously_approved(tmp_path):
    """The mined rule must survive its own gate at budget 0 -- it is set
    at the highest APPROVED amount, so no approved decision moves."""
    import json

    from agent_dna.policy_gate import (
        counterfactual_from_fixture,
        load_candidate,
        run_assertions,
    )

    store, replay, rec = _mk(tmp_path)
    for amt in (1_000, 40_000, 100_000):
        _decide(
            rec,
            "ap-1",
            "payments.initiate_wire",
            Decision.ALLOW,
            "baseline",
            {"amount": amt},
        )
    for amt in (400_000,):
        _decide(
            rec,
            "ap-1",
            "payments.initiate_wire",
            Decision.BLOCK,
            "uaal_constraint",
            {"amount": amt},
        )

    cand = [
        c
        for c in mine(store, replay, min_support=3)
        if c.kind == "policy" and c.id.startswith("cap-")
    ][0]
    rule_path = tmp_path / "mined.json"
    rule_path.write_text(json.dumps(cand.policy_document))

    fixture = tmp_path / "corpus.jsonl"
    fixture.write_text(
        "\n".join(
            json.dumps(
                {
                    "decision_id": f"d{i}",
                    "agent_id": "ap-1",
                    "capability": "payments.initiate_wire",
                    "arguments": {"amount": amt},
                    "decision": "allow",
                }
            )
            for i, amt in enumerate((1_000, 40_000, 100_000))
        )
    )

    checker, assertions = load_candidate(str(rule_path))
    assert all(a.passed for a in run_assertions(checker, assertions))
    cf = counterfactual_from_fixture(checker, str(fixture))
    assert cf["would_newly_block"] == 0


def test_overlap_reports_advisory_not_an_invented_threshold(tmp_path):
    store, replay, rec = _mk(tmp_path)
    for amt in (10_000, 500_000):  # approved high
        _decide(
            rec,
            "ap-1",
            "payments.initiate_wire",
            Decision.ALLOW,
            "baseline",
            {"amount": amt},
        )
    for amt in (20_000, 30_000):  # refused low -> overlap
        _decide(
            rec,
            "ap-1",
            "payments.initiate_wire",
            Decision.REQUIRE_APPROVAL,
            "drift",
            {"amount": amt},
        )

    cands = mine(store, replay, min_support=3)
    overlap = [c for c in cands if c.id.startswith("advisory-overlap")]
    assert overlap and overlap[0].policy_document is None
    assert "does not separate" in overlap[0].rationale


def test_mines_capability_refused_only_by_the_learned_layer(tmp_path):
    store, replay, rec = _mk(tmp_path)
    for _ in range(6):
        _decide(rec, "bot-1", "storage.bulk_export", Decision.REQUIRE_APPROVAL, "drift")
    cands = [
        c
        for c in mine(store, replay, min_support=5)
        if c.id == "deny-storage-bulk_export"
    ]
    assert cands, "a never-allowed capability with no rule must surface"
    assert cands[0].policy_document["policies"][0]["outcome"] == "block"
    assert "silently permit" in cands[0].rationale


def test_existing_policy_rule_is_not_re_suggested(tmp_path):
    store, replay, rec = _mk(tmp_path)
    for _ in range(6):
        _decide(rec, "bot-1", "storage.bulk_export", Decision.BLOCK, "policy")
    assert not [
        c for c in mine(store, replay, min_support=5) if c.id.startswith("deny-")
    ]


def test_mines_missing_standing_grant(tmp_path):
    store, replay, rec = _mk(tmp_path)
    for _ in range(5):
        _decide(
            rec,
            "treasury-bot",
            "payments.transfer",
            Decision.REQUIRE_APPROVAL,
            "authorization",
        )
    grants = [c for c in mine(store, replay, min_support=5) if c.kind == "grant"]
    assert grants
    assert "NAMED APPROVER" in grants[0].note
    assert grants[0].evidence["agent_id"] == "treasury-bot"


def test_mines_rapid_self_dealing_sequence_as_advisory(tmp_path):
    store, replay, rec = _mk(tmp_path)
    for i in range(5):
        t = BASE + i * 10_000
        _decide(rec, "ap-1", "vendor.onboard", Decision.ALLOW, "baseline", ts=t)
        _decide(
            rec, "ap-1", "payments.pay_invoice", Decision.ALLOW, "baseline", ts=t + 60
        )
    seq = [
        c
        for c in mine(store, replay, min_support=5)
        if c.id.startswith("advisory-sequence")
    ]
    assert seq
    assert seq[0].policy_document is None
    assert "cross-agent invariant" in seq[0].note


def test_nothing_is_auto_applied(tmp_path):
    """Suggestions never mutate the runtime or the audit trail."""
    store, replay, rec = _mk(tmp_path)
    for _ in range(6):
        _decide(rec, "bot-1", "storage.bulk_export", Decision.BLOCK, "drift")
    before = len(list(store.iter_decisions()))
    mine(store, replay, min_support=5)
    assert len(list(store.iter_decisions())) == before
