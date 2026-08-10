"""drp/0.2: a signed decision commits to action + dispatch-context digests.

A permit names an execution action and dispatch context and carries their
digests. Digests are derive-only. Missing bindings on a v0.2 record are
a rejection, not a downgrade. Exact wire bytes are not sealed here.
"""

import inspect
import json
import time

import pytest

from agent_dna.action_v01 import execution_action_digest
from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_record import (
    DRP_V01,
    DRP_V02,
    DecisionRecord,
    build_record,
    build_record_v02,
)
from agent_dna.decision_store import DecisionStore
from agent_dna.dispatch_context_v01 import dispatch_context_digest
from agent_dna.execution_record import build_execution_event
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
DISPATCH_DIGEST = "sha256:" + "c" * 64
OTHER_DISPATCH_DIGEST = "sha256:" + "d" * 64

ACTION = {
    "subject_principal": "service-agent@retail.example",
    "subject_key_id": "service-agent-07",
    "action": "refunds.issue",
    "resource": "account:CUST-88213",
    "parameters": {"amount": 240000, "currency": "USD"},
}

DISPATCH = {
    "adapter": "https",
    "transport": "https",
    "operation": "POST /v2/refunds",
    "destination": "refunds.cardnetwork.example",
    "wire_content_type": "application/json",
}


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def _decide(cap="refunds.issue"):
    engine = DecisionEngine(scorer=StubScorer())
    action = AgentAction(
        agent_id="agent-1",
        capability=cap,
        timestamp=time.time(),
        arguments={},
    )
    return action, engine.decide(action)


def _fields(**overrides):
    base = dict(
        decision_id="d-1",
        parent_decision=None,
        agent_id="a",
        capability="refunds.issue",
        decision="allow",
        triggered_by="baseline",
        reason="",
        severity="info",
        drift_score=0.0,
        evidence=[],
        evidence_strength=0.0,
        arguments_digest="x",
        outcome="pending",
        timestamp=1785000000.0,
    )
    base.update(overrides)
    return base


def _v02(**overrides):
    return DecisionRecord(
        protocol_version=DRP_V02,
        action_digest=DIGEST,
        dispatch_context_digest=DISPATCH_DIGEST,
        **_fields(**overrides),
    )


# --- 1-5: the invariant -------------------------------------------------


def test_protocol_version_is_mandatory():
    """Omission must not silently produce a legacy record."""
    with pytest.raises(TypeError, match="protocol_version"):
        DecisionRecord(**_fields())


def test_v01_carries_no_binding_digests():
    rec = DecisionRecord(protocol_version=DRP_V01, **_fields()).seal()
    assert rec.verify()
    assert "action_digest" not in rec.payload()
    assert "dispatch_context_digest" not in rec.payload()


def test_v01_with_action_digest_is_rejected():
    with pytest.raises(ValueError, match="drp/0.1 records carry no action_digest"):
        DecisionRecord(protocol_version=DRP_V01, action_digest=DIGEST, **_fields())


def test_v01_with_dispatch_context_digest_is_rejected():
    with pytest.raises(
        ValueError, match="drp/0.1 records carry no dispatch_context_digest"
    ):
        DecisionRecord(
            protocol_version=DRP_V01,
            dispatch_context_digest=DISPATCH_DIGEST,
            **_fields(),
        )


def test_v02_without_action_digest_is_rejected():
    with pytest.raises(ValueError, match="not\\s+a downgrade"):
        DecisionRecord(
            protocol_version=DRP_V02,
            dispatch_context_digest=DISPATCH_DIGEST,
            **_fields(),
        )


def test_v02_without_dispatch_context_digest_is_rejected():
    with pytest.raises(ValueError, match="dispatch_context_digest"):
        DecisionRecord(protocol_version=DRP_V02, action_digest=DIGEST, **_fields())


@pytest.mark.parametrize(
    "bad",
    [
        "a" * 64,
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 63,
        "sha256:zz",
        "",
    ],
)
def test_malformed_action_digest_is_rejected(bad):
    with pytest.raises(ValueError, match="malformed action_digest"):
        DecisionRecord(
            protocol_version=DRP_V02,
            action_digest=bad,
            dispatch_context_digest=DISPATCH_DIGEST,
            **_fields(),
        )


@pytest.mark.parametrize("version", ["drp/0.3", "drp/9.9", "", "DRP/0.2"])
def test_unknown_version_is_rejected(version):
    with pytest.raises(ValueError, match="unknown protocol_version"):
        DecisionRecord(protocol_version=version, **_fields())


# --- 6-8: sealing, payload, mutation -----------------------------------


def test_v02_seals_verifies_and_carries_both_digests():
    rec = _v02().seal()
    assert rec.verify()
    assert rec.payload()["action_digest"] == DIGEST
    assert rec.payload()["dispatch_context_digest"] == DISPATCH_DIGEST


def test_changing_action_digest_changes_record_hash():
    a = _v02().seal()
    b = DecisionRecord(
        protocol_version=DRP_V02,
        action_digest=OTHER_DIGEST,
        dispatch_context_digest=DISPATCH_DIGEST,
        **_fields(),
    ).seal()
    assert a.record_hash != b.record_hash


def test_changing_dispatch_context_digest_changes_record_hash():
    a = _v02().seal()
    b = DecisionRecord(
        protocol_version=DRP_V02,
        action_digest=DIGEST,
        dispatch_context_digest=OTHER_DISPATCH_DIGEST,
        **_fields(),
    ).seal()
    assert a.record_hash != b.record_hash


def test_v01_and_v02_of_the_same_decision_hash_differently():
    v01 = DecisionRecord(protocol_version=DRP_V01, **_fields()).seal()
    v02 = _v02().seal()
    assert v01.record_hash != v02.record_hash


def test_invalid_post_seal_mutation_fails_verification_without_raising():
    rec = DecisionRecord(protocol_version=DRP_V01, **_fields()).seal()
    rec.action_digest = DIGEST
    assert rec.verify() is False


@pytest.mark.parametrize("method", ["payload", "seal"])
def test_invalid_post_seal_mutation_makes_payload_and_seal_raise(method):
    rec = DecisionRecord(protocol_version=DRP_V01, **_fields()).seal()
    rec.action_digest = DIGEST
    with pytest.raises(ValueError):
        getattr(rec, method)()


# --- 9-10: the builder --------------------------------------------------


def test_build_record_v02_takes_no_caller_supplied_digest():
    params = inspect.signature(build_record_v02).parameters
    assert "action_digest" not in params
    assert "dispatch_context_digest" not in params
    assert "execution_action" in params
    assert "dispatch_context" in params


def test_build_record_v02_computes_both_digests_itself():
    action, result = _decide()
    rec = build_record_v02(
        action,
        result,
        execution_action=ACTION,
        dispatch_context=DISPATCH,
    )
    assert rec.protocol_version == DRP_V02
    assert rec.action_digest == execution_action_digest(ACTION)
    assert rec.dispatch_context_digest == dispatch_context_digest(DISPATCH)
    assert rec.verify()


def test_build_record_stays_on_v01():
    action, result = _decide()
    rec = build_record(action, result)
    assert rec.protocol_version == DRP_V01
    assert rec.action_digest is None
    assert rec.dispatch_context_digest is None


def test_a_different_execution_action_changes_the_record_hash():
    action, result = _decide()
    other = dict(ACTION, resource="account:CUST-00001")
    a = build_record_v02(
        action, result, execution_action=ACTION, dispatch_context=DISPATCH
    )
    b = build_record_v02(
        action, result, execution_action=other, dispatch_context=DISPATCH
    )
    assert a.action_digest != b.action_digest
    assert a.record_hash != b.record_hash


def test_a_different_dispatch_context_changes_the_record_hash():
    action, result = _decide()
    other = dict(DISPATCH, destination="evil.example")
    a = build_record_v02(
        action, result, execution_action=ACTION, dispatch_context=DISPATCH
    )
    b = build_record_v02(
        action, result, execution_action=ACTION, dispatch_context=other
    )
    assert a.dispatch_context_digest != b.dispatch_context_digest
    assert a.record_hash != b.record_hash


# --- 11: mixed chains ---------------------------------------------------


def test_v01_then_v02_chain_verifies():
    first = DecisionRecord(protocol_version=DRP_V01, **_fields()).seal()
    second = _v02(decision_id="d-2", parent_decision="d-1")
    second.prev_hash = first.record_hash
    second.seal()
    assert first.verify() and second.verify()
    assert second.prev_hash == first.record_hash


def test_v02_then_v01_chain_verifies():
    first = _v02().seal()
    second = DecisionRecord(
        protocol_version=DRP_V01,
        **_fields(decision_id="d-2", parent_decision="d-1"),
    )
    second.prev_hash = first.record_hash
    second.seal()
    assert first.verify() and second.verify()
    assert second.prev_hash == first.record_hash


# --- 12-14: persistence -------------------------------------------------


def _both_versions():
    action, result = _decide()
    v01 = build_record(action, result)
    v02 = build_record_v02(
        action,
        result,
        execution_action=ACTION,
        dispatch_context=DISPATCH,
        parent_decision=v01.decision_id,
        prev_hash=v01.record_hash,
    )
    return [v01, v02]


def test_jsonl_round_trip_preserves_version_and_digest(tmp_path):
    store = DecisionStore(tmp_path / "d.jsonl")
    written = _both_versions()
    for rec in written:
        store.append(rec)

    loaded = store.load()
    assert [r.protocol_version for r in loaded] == [DRP_V01, DRP_V02]
    assert [r.action_digest for r in loaded] == [None, execution_action_digest(ACTION)]
    assert [r.dispatch_context_digest for r in loaded] == [
        None,
        dispatch_context_digest(DISPATCH),
    ]
    assert all(r.verify() for r in loaded)
    assert [r.record_hash for r in loaded] == [r.record_hash for r in written]


def test_sqlite_round_trip_preserves_version_and_digest(tmp_path):
    store = SQLiteDecisionStore(tmp_path / "d.db")
    written = _both_versions()
    for rec in written:
        store.append(rec)

    loaded = store.load()
    assert [r.protocol_version for r in loaded] == [DRP_V01, DRP_V02]
    assert [r.action_digest for r in loaded] == [None, execution_action_digest(ACTION)]
    assert all(r.verify() for r in loaded)
    store.close()


def test_load_rejects_a_record_with_no_protocol_version(tmp_path):
    rec = build_record(*_decide())
    body = rec.to_dict()
    del body["protocol_version"]
    path = tmp_path / "d.jsonl"
    path.write_text(json.dumps(body) + "\n")

    with pytest.raises(ValueError, match="missing required protocol_version"):
        DecisionStore(path).load()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.update(action_digest=DIGEST),
        lambda b: b.update(protocol_version=DRP_V02),
        lambda b: b.update(protocol_version="drp/9.9"),
    ],
    ids=["v01_with_digest", "v02_without_digest", "unknown_version"],
)
def test_load_rejects_invalid_version_digest_combinations(tmp_path, mutate):
    rec = build_record(*_decide())
    body = rec.to_dict()
    mutate(body)
    path = tmp_path / "d.jsonl"
    path.write_text(json.dumps(body) + "\n")

    with pytest.raises(ValueError):
        DecisionStore(path).load()


def test_execution_event_persistence_is_unchanged(tmp_path):
    store = DecisionStore(tmp_path / "d.jsonl")
    decision = build_record(*_decide())
    store.append(decision)
    event = build_execution_event(
        agent_id=decision.agent_id,
        decision_id=decision.decision_id,
        decision_hash=decision.record_hash,
        status="ok",
    )
    store.append(event)

    loaded = store.load()
    assert loaded[1].kind == "execution"
    assert loaded[1].verify()
    assert not hasattr(loaded[1], "action_digest")
