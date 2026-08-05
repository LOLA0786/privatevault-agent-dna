"""drp/0.2: a signed decision commits to the exact action it authorized.

A permit names an execution action and carries its digest. Until v0.2
nothing tied that digest to the decision -- the permit proved what was
authorized, not that a decision authorized it. These tests pin the
record half of that binding.

The version is explicit data, never inferred from field presence. A
missing action_digest on a v0.2 record is a rejection, not a downgrade.
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
from agent_dna.execution_record import build_execution_event
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64

ACTION = {
    "subject_principal": "service-agent@retail.example",
    "subject_key_id": "service-agent-07",
    "action": "refunds.issue",
    "resource": "account:CUST-88213",
    "parameters": {"amount": 240000, "currency": "USD"},
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


# --- 1-5: the invariant -------------------------------------------------


def test_protocol_version_is_mandatory():
    """Omission must not silently produce a legacy record."""
    with pytest.raises(TypeError, match="protocol_version"):
        DecisionRecord(**_fields())


def test_v01_carries_no_action_digest():
    rec = DecisionRecord(protocol_version=DRP_V01, **_fields()).seal()
    assert rec.verify()
    assert "action_digest" not in rec.payload()


def test_v01_with_action_digest_is_rejected():
    with pytest.raises(ValueError, match="drp/0.1 records carry no action_digest"):
        DecisionRecord(
            protocol_version=DRP_V01, action_digest=DIGEST, **_fields()
        )


def test_v02_without_action_digest_is_rejected():
    """The rejection message states the intent: not a downgrade."""
    with pytest.raises(ValueError, match="not\\s+a downgrade"):
        DecisionRecord(protocol_version=DRP_V02, **_fields())


@pytest.mark.parametrize(
    "bad",
    [
        "a" * 64,                    # unprefixed
        "sha256:" + "A" * 64,        # uppercase hex
        "sha256:" + "a" * 63,        # short
        "sha256:zz",                 # not hex
        "",
    ],
)
def test_malformed_action_digest_is_rejected(bad):
    with pytest.raises(ValueError, match="malformed action_digest"):
        DecisionRecord(protocol_version=DRP_V02, action_digest=bad, **_fields())


@pytest.mark.parametrize("version", ["drp/0.3", "drp/9.9", "", "DRP/0.2"])
def test_unknown_version_is_rejected(version):
    with pytest.raises(ValueError, match="unknown protocol_version"):
        DecisionRecord(protocol_version=version, **_fields())


# --- 6-8: sealing, payload, mutation -----------------------------------


def test_v02_seals_verifies_and_carries_the_digest():
    rec = DecisionRecord(
        protocol_version=DRP_V02, action_digest=DIGEST, **_fields()
    ).seal()
    assert rec.verify()
    assert rec.payload()["action_digest"] == DIGEST


def test_changing_action_digest_changes_record_hash():
    a = DecisionRecord(
        protocol_version=DRP_V02, action_digest=DIGEST, **_fields()
    ).seal()
    b = DecisionRecord(
        protocol_version=DRP_V02, action_digest=OTHER_DIGEST, **_fields()
    ).seal()
    assert a.record_hash != b.record_hash


def test_v01_and_v02_of_the_same_decision_hash_differently():
    v01 = DecisionRecord(protocol_version=DRP_V01, **_fields()).seal()
    v02 = DecisionRecord(
        protocol_version=DRP_V02, action_digest=DIGEST, **_fields()
    ).seal()
    assert v01.record_hash != v02.record_hash


def test_invalid_post_seal_mutation_fails_verification_without_raising():
    """A caller checking someone else's record deserves a verdict."""
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
    """A caller must not be able to present a digest for one action
    while the permit later names another."""
    params = inspect.signature(build_record_v02).parameters
    assert "action_digest" not in params
    assert "execution_action" in params


def test_build_record_v02_computes_the_digest_itself():
    action, result = _decide()
    rec = build_record_v02(action, result, execution_action=ACTION)
    assert rec.protocol_version == DRP_V02
    assert rec.action_digest == execution_action_digest(ACTION)
    assert rec.verify()


def test_build_record_stays_on_v01():
    action, result = _decide()
    rec = build_record(action, result)
    assert rec.protocol_version == DRP_V01
    assert rec.action_digest is None


def test_a_different_execution_action_changes_the_record_hash():
    action, result = _decide()
    other = dict(ACTION, resource="account:CUST-00001")
    a = build_record_v02(action, result, execution_action=ACTION)
    b = build_record_v02(action, result, execution_action=other)
    assert a.action_digest != b.action_digest
    assert a.record_hash != b.record_hash


# --- 11: mixed chains ---------------------------------------------------


def test_v01_then_v02_chain_verifies():
    first = DecisionRecord(protocol_version=DRP_V01, **_fields()).seal()
    second = DecisionRecord(
        protocol_version=DRP_V02,
        action_digest=DIGEST,
        **_fields(decision_id="d-2", parent_decision="d-1"),
    )
    second.prev_hash = first.record_hash
    second.seal()
    assert first.verify() and second.verify()
    assert second.prev_hash == first.record_hash


def test_v02_then_v01_chain_verifies():
    """The chain link is version-independent, so a deployment can move
    back and forth without breaking continuity."""
    first = DecisionRecord(
        protocol_version=DRP_V02, action_digest=DIGEST, **_fields()
    ).seal()
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
    """A v0.1 record and its v0.2 child, in one agent chain.

    Deliberately chained rather than two genesis records: the store
    enforces one origin per agent, and a mixed-version chain is the
    thing worth proving survives a round trip.
    """
    action, result = _decide()
    v01 = build_record(action, result)
    v02 = build_record_v02(
        action,
        result,
        execution_action=ACTION,
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
    """Never defaulted: defaulting to v0.1 is the downgrade the design
    exists to prevent."""
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
        lambda b: b.update(action_digest=DIGEST),           # v0.1 + digest
        lambda b: b.update(protocol_version=DRP_V02),       # v0.2, no digest
        lambda b: b.update(protocol_version="drp/9.9"),     # unknown
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
    """ExecutionEvent has no action and did not move to v0.2."""
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
