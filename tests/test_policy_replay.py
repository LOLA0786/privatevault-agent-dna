"""Part B: retrospective replay is opt-in, field-scoped, separate from
the audit trail, and reports the counterfactual against sealed records."""

import time

from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.decision import Decision, DecisionResult, Severity
from agent_dna.policy.checker import PolicyChecker
from agent_dna.policy.schema import parse_policy_dict
from agent_dna.policy_replay import PolicyReplay
from agent_dna.trace import AgentAction


def _runtime(tmp_path, fields=None):
    return build_production_runtime(RuntimeConfig(
        db_path=str(tmp_path / "pv.db"),
        replay_fields=fields,
        replay_db=str(tmp_path / "replay.db"),
    ))


def _record(rt, cap, arguments):
    action = AgentAction(agent_id="replay-agent", capability=cap,
                         timestamp=time.time(), arguments=arguments)
    result = DecisionResult(
        decision=Decision.ALLOW, triggered_by="baseline", reason="ok",
        capability=cap, agent_id="replay-agent", drift_score=0.0,
        severity=list(Severity)[0])
    return rt.recorder.record(action, result)


def _candidate(rule_id, cap):
    return PolicyChecker(parse_policy_dict({"policies": [{
        "id": rule_id, "capability": cap,
        "outcome": "block", "reason": f"{rule_id} fired"}]}))


def test_replay_off_by_default(tmp_path):
    rt = _runtime(tmp_path, fields=None)
    assert rt.replay is None
    assert rt.composition["policy_replay"]["status"] == "not_configured"


def test_replay_reports_counterfactual_when_opted_in(tmp_path):
    rt = _runtime(tmp_path, fields=["amount", "currency"])
    assert rt.replay is not None and rt.replay.enabled
    for _ in range(3):
        _record(rt, "payments.initiate_wire",
                {"amount": 60000.0, "currency": "AED", "memo": "secret"})

    replay = PolicyReplay(store=rt.replay, decision_store=rt.store)
    rep = replay.replay(_candidate("PROP-WIRE", "payments.initiate_wire"))
    assert rep["status"] == "ok"
    assert rep["replayed"] == 3
    assert rep["would_newly_block"] == 3
    assert rep["newly_blocked_by_capability"] == {"payments.initiate_wire": 3}
    assert rep["field_scope"] == ["amount", "currency"]
    assert rep["sample_newly_blocked"][0]["rule"] == "PROP-WIRE"


def test_only_allowlisted_fields_are_retained(tmp_path):
    rt = _runtime(tmp_path, fields=["amount"])
    rec = _record(rt, "payments.initiate_wire",
                  {"amount": 999.0, "iban": "SENSITIVE", "memo": "PII"})
    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "replay.db"))
    (retained,) = conn.execute(
        "SELECT retained FROM replay_inputs WHERE decision_id = ?",
        (rec.decision_id,)).fetchone()
    import json
    kept = json.loads(retained)
    assert kept == {"amount": 999.0}
    assert "iban" not in retained and "memo" not in retained


def test_replay_unavailable_message_when_off(tmp_path):
    rt = _runtime(tmp_path, fields=None)
    from agent_dna.policy_replay import ReplayInputStore, PolicyReplay
    empty = ReplayInputStore(path=str(tmp_path / "e.db"), retain_fields=[])
    rep = PolicyReplay(store=empty, decision_store=rt.store).replay(
        _candidate("X", "y"))
    assert rep["status"] == "unavailable"
    assert "opt-in" in rep["reason"]


def test_purge_removes_inputs_not_audit_trail(tmp_path):
    rt = _runtime(tmp_path, fields=["amount"])
    rec = _record(rt, "payments.initiate_wire", {"amount": 1.0})
    removed = rt.replay.purge_before(time.time() + 1)
    assert removed == 1
    # the sealed decision itself is untouched in the authoritative store
    assert rt.store.get_decision(rec.decision_id) is not None


def test_replay_joins_live_decision_from_sealed_record(tmp_path):
    """The verdict comes from the immutable record, the inputs from the
    sidecar -- replay cannot fabricate a live decision."""
    rt = _runtime(tmp_path, fields=["amount"])
    _record(rt, "crm.read_contact", {"amount": 5.0})   # live=allow
    replay = PolicyReplay(store=rt.replay, decision_store=rt.store)
    # candidate that fires on a DIFFERENT capability -> no divergence
    rep = replay.replay(_candidate("OTHER", "payments.initiate_wire"))
    assert rep["would_newly_block"] == 0
    assert rep["unchanged"] == 1
