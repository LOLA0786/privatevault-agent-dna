"""Contract tests for the offline, proposal-only PrivateVault Discovery Loop."""

from __future__ import annotations

import copy
import hashlib
import json
import time
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agent_dna.cli import EXIT_OK, EXIT_USAGE, main
from agent_dna.decision import Decision, DecisionResult, Severity
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.discovery import (
    ADVERSARIAL_ROW_SPEC,
    CandidateDisposition,
    DiscoveryConfig,
    DiscoveryInputError,
    DiscoveryStatus,
    load_adversarial_fixture,
    run_discovery,
)
from agent_dna.policy_replay import ReplayInputStore
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction
from tools.verify_discovery import VerificationError, verify

ROOT = Path(__file__).parents[1]


def _stores(tmp_path, fields=("amount",)):
    store = SQLiteDecisionStore(tmp_path / "history.db")
    replay = ReplayInputStore(str(tmp_path / "replay.db"), list(fields))
    recorder = DecisionRecorder(store=store)
    recorder.replay_capture = replay.capture
    return store, replay, recorder


def _decision(recorder, amount: int, verdict: Decision, *, capability=None):
    capability = capability or "payments.initiate_wire"
    action = AgentAction(
        agent_id="treasury-agent",
        capability=capability,
        timestamp=time.time(),
        arguments={"amount": amount},
    )
    return recorder.record(
        action,
        DecisionResult(
            decision=verdict,
            triggered_by="baseline" if verdict is Decision.ALLOW else "drift",
            reason="test evidence",
            capability=capability,
            agent_id="treasury-agent",
            drift_score=0.0,
            severity=list(Severity)[0],
        ),
    )


def _row(
    row_id: str,
    label: str,
    amount: int,
    *,
    capability: str = "payments.initiate_wire",
    baseline: str = "allow",
):
    return {
        "spec": ADVERSARIAL_ROW_SPEC,
        "id": row_id,
        "label": label,
        "agent_id": "treasury-agent",
        "capability": capability,
        "arguments": {"amount": amount},
        "evidence": None,
        "baseline_decision": baseline,
    }


def _populated(tmp_path):
    store, replay, recorder = _stores(tmp_path)
    for amount in (1_000, 20_000, 100_000):
        _decision(recorder, amount, Decision.ALLOW)
    for amount in (250_000, 900_000):
        _decision(recorder, amount, Decision.REQUIRE_APPROVAL)
    return store, replay


def _cap_experiment(result):
    return next(
        item
        for item in result.envelope["body"]["experiments"]
        if item["candidate_id"].startswith("cap-")
    )


def test_mine_replay_evaluate_and_propose_without_applying(tmp_path):
    store, replay = _populated(tmp_path)
    rows = [
        _row("attack-over-cap", "attack", 800_000),
        _row("benign-at-cap", "benign", 100_000),
        _row("benign-read", "benign", 0, capability="ledger.read"),
    ]
    result = run_discovery(
        store,
        replay,
        adversarial_rows=rows,
        config=DiscoveryConfig(min_support=3, as_of=1_700_000_000),
    )

    experiment = _cap_experiment(result)
    assert result.status is DiscoveryStatus.PROPOSALS_READY
    assert experiment["disposition"] == CandidateDisposition.PROPOSE
    assert experiment["history"]["new_escalations"] == 0
    assert experiment["adversarial"]["attack_covered"] == 1
    assert experiment["adversarial"]["benign_escalations"] == 0
    assert all(len(value) == 64 for value in experiment["evidence_record_hashes"])
    assert verify(result.envelope)["ok"] is True


def test_additive_semantics_never_claim_candidate_non_fire_newly_allows(tmp_path):
    store, replay = _populated(tmp_path)
    result = run_discovery(
        store,
        replay,
        adversarial_rows=[
            _row(
                "unrelated-existing-block",
                "attack",
                0,
                capability="storage.delete",
                baseline="block",
            ),
            _row("benign-at-cap", "benign", 100_000),
        ],
        config=DiscoveryConfig(min_support=3),
    )
    experiment = _cap_experiment(result)
    assert experiment["history"]["semantics"].startswith("additive_candidate")
    assert "would_newly_allow" not in experiment["history"]
    assert experiment["history"]["covered_refusals"] == 2


def test_missing_retained_fields_cannot_produce_a_proposal(tmp_path):
    store, replay = _populated(tmp_path)
    replay._conn.execute(
        "UPDATE replay_inputs SET retained = '{}' WHERE decision_id IN "
        "(SELECT decision_id FROM replay_inputs LIMIT 1)"
    )
    replay._conn.commit()
    result = run_discovery(
        store,
        replay,
        adversarial_rows=[_row("benign-at-cap", "benign", 100_000)],
        config=DiscoveryConfig(min_support=3),
    )
    experiment = _cap_experiment(result)
    assert experiment["disposition"] != CandidateDisposition.PROPOSE
    assert experiment["history"]["state"] == "incomplete"


def test_benign_breakage_rejects_candidate_at_zero_budget(tmp_path):
    store, replay = _populated(tmp_path)
    result = run_discovery(
        store,
        replay,
        adversarial_rows=[_row("benign-over-cap", "benign", 500_000)],
        config=DiscoveryConfig(min_support=3, max_new_blocks=0),
    )
    experiment = _cap_experiment(result)
    assert experiment["disposition"] == CandidateDisposition.REJECT
    assert experiment["adversarial"]["benign_escalations"] == 1


def test_structural_authority_loop_is_a_hard_filter(tmp_path):
    store, replay = _populated(tmp_path)
    loop_event = {
        "spec": "pv-agent-security-event/1.0",
        "event_id": "approval-1",
        "trace_id": "trace-1",
        "occurred_at": "2026-08-06T10:00:00Z",
        "source_agent_id": "treasury-agent",
        "target_agent_id": "treasury-agent",
        "relation": "APPROVES",
        "action_digest": "sha256:" + "a" * 64,
        "authorization_id": "authorization-1",
        "authorization_state": "VERIFIED",
        "parent_event_id": None,
    }
    result = run_discovery(
        store,
        replay,
        adversarial_rows=[_row("benign-at-cap", "benign", 100_000)],
        loop_events=[loop_event],
        config=DiscoveryConfig(min_support=3),
    )
    assert result.status is DiscoveryStatus.STRUCTURAL_BLOCK
    assert _cap_experiment(result)["disposition"] == CandidateDisposition.REJECT
    assert verify(result.envelope)["ok"] is True


def test_same_inputs_and_as_of_produce_same_sealed_report(tmp_path):
    store, replay = _populated(tmp_path)
    kwargs = {
        "adversarial_rows": [_row("benign-at-cap", "benign", 100_000)],
        "config": DiscoveryConfig(min_support=3, as_of=1_700_000_000),
    }
    first = run_discovery(store, replay, **kwargs)
    second = run_discovery(store, replay, **kwargs)
    assert first.envelope == second.envelope


def test_only_proposed_candidates_emit_pr_ready_files(tmp_path):
    store, replay = _populated(tmp_path)
    result = run_discovery(
        store,
        replay,
        adversarial_rows=[_row("benign-at-cap", "benign", 100_000)],
        config=DiscoveryConfig(min_support=3),
    )
    paths = result.write_proposals(tmp_path / "proposals")
    assert len(paths) == 2
    assert {path.suffix for path in paths} == {".json", ".md"}
    note = next(path for path in paths if path.suffix == ".md").read_text()
    assert "Human approval is required" in note
    assert result.report_hash in note


def test_fixture_loader_rejects_duplicates_unknown_fields_and_nonfinite(tmp_path):
    duplicate = tmp_path / "duplicate.jsonl"
    row = _row("same", "attack", 10)
    duplicate.write_text(json.dumps(row) + "\n" + json.dumps(row))
    with pytest.raises(DiscoveryInputError, match="duplicate"):
        load_adversarial_fixture(duplicate)

    unknown = tmp_path / "unknown.jsonl"
    unknown.write_text(json.dumps({**row, "surprise": True}))
    with pytest.raises(DiscoveryInputError, match="fields must be exactly"):
        load_adversarial_fixture(unknown)

    nonfinite = tmp_path / "nonfinite.jsonl"
    nonfinite.write_text(json.dumps(row).replace("10", "NaN", 1))
    with pytest.raises(DiscoveryInputError, match="non-finite"):
        load_adversarial_fixture(nonfinite)


def test_independent_verifier_rejects_tampering(tmp_path):
    store, replay = _populated(tmp_path)
    result = run_discovery(
        store,
        replay,
        adversarial_rows=[_row("benign-at-cap", "benign", 100_000)],
        config=DiscoveryConfig(min_support=3),
    )
    tampered = copy.deepcopy(result.envelope)
    tampered["body"]["experiments"][0]["priority_score"] += 1
    with pytest.raises(VerificationError, match="digest mismatch"):
        verify(tampered)

    # Re-sealing an internally impossible report does not make it valid.
    tampered["body"]["experiments"][0]["history"]["candidate_errors"] = 999
    body_bytes = json.dumps(
        tampered["body"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    tampered["report_hash"] = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
    with pytest.raises(VerificationError, match="fired counts exceed"):
        verify(tampered)


def test_wire_schemas_accept_emitted_report_and_committed_corpus(tmp_path):
    store, replay = _populated(tmp_path)
    rows = [_row("benign-at-cap", "benign", 100_000)]
    result = run_discovery(
        store,
        replay,
        adversarial_rows=rows,
        config=DiscoveryConfig(min_support=3),
    )
    schema_dir = ROOT / "spec" / "discovery-loop-v1"
    report_schema = json.loads((schema_dir / "report.schema.json").read_text())
    row_schema = json.loads((schema_dir / "adversarial-row.schema.json").read_text())
    Draft202012Validator(report_schema).validate(result.envelope)
    Draft202012Validator(row_schema).validate(rows[0])


def test_independent_verifier_does_not_import_the_runtime():
    source = (ROOT / "tools" / "verify_discovery.py").read_text()
    assert "from agent_dna" not in source
    assert "import agent_dna" not in source


def test_canonical_no_change_vector_is_pinned_and_verifiable():
    vector = json.loads(
        (
            ROOT / "spec" / "discovery-loop-v1" / "vectors" / "no-change-report.json"
        ).read_text()
    )
    assert (
        vector["report_hash"]
        == "sha256:10bb7bf0db07eeed41af4a3fd69eeedb0031c49c393cecbcec5b3f603ae55a8e"
    )
    assert verify(vector)["status"] == "NO_CHANGE"


def test_cli_writes_report_and_proposals(tmp_path, capsys):
    store, replay = _populated(tmp_path)
    store.close()
    replay.close()
    fixture = tmp_path / "adversarial.jsonl"
    fixture.write_text(json.dumps(_row("benign-at-cap", "benign", 100_000)))
    report = tmp_path / "report.json"
    proposals = tmp_path / "proposals"

    rc = main(
        [
            "discover",
            "run",
            "--history-db",
            str(tmp_path / "history.db"),
            "--replay-db",
            str(tmp_path / "replay.db"),
            "--replay-fields",
            "amount",
            "--adversarial-fixture",
            str(fixture),
            "--since-days",
            "0",
            "--min-support",
            "3",
            "--json",
            str(report),
            "--out-dir",
            str(proposals),
        ]
    )
    assert rc == EXIT_OK
    assert "Nothing was applied" in capsys.readouterr().out
    assert verify(json.loads(report.read_text()))["ok"] is True
    assert list(proposals.glob("*.proposal.md"))


def test_cli_refuses_nonexistent_history(tmp_path):
    assert (
        main(["discover", "run", "--history-db", str(tmp_path / "missing.db")])
        == EXIT_USAGE
    )


def test_replay_scope_tampering_refuses_the_run(tmp_path):
    store, replay = _populated(tmp_path)
    replay._conn.execute("UPDATE replay_inputs SET field_scope = '[\"currency\"]'")
    replay._conn.commit()
    with pytest.raises(DiscoveryInputError, match="field scope"):
        run_discovery(
            store,
            replay,
            adversarial_rows=[_row("benign", "benign", 100_000)],
            config=DiscoveryConfig(min_support=3),
        )


def test_untrusted_candidate_id_cannot_escape_proposal_directory(tmp_path):
    store, replay, recorder = _stores(tmp_path)
    capability = "../../outside"
    for _ in range(3):
        _decision(recorder, 0, Decision.REQUIRE_APPROVAL, capability=capability)
    result = run_discovery(
        store,
        replay,
        adversarial_rows=[
            _row("attack", "attack", 0, capability=capability, baseline="allow")
        ],
        config=DiscoveryConfig(min_support=3),
    )
    target = tmp_path / "safe"
    paths = result.write_proposals(target)
    assert paths
    assert all(path.resolve().parent == target.resolve() for path in paths)
    assert not (tmp_path / "outside.json").exists()


def test_configured_resource_bounds_refuse_oversized_windows(tmp_path):
    store, replay = _populated(tmp_path)
    with pytest.raises(DiscoveryInputError, match="history contains"):
        run_discovery(
            store,
            replay,
            config=DiscoveryConfig(min_support=3, max_history_records=1),
        )
    with pytest.raises(DiscoveryInputError, match="adversarial corpus contains"):
        run_discovery(
            store,
            replay,
            adversarial_rows=[_row("one", "attack", 1), _row("two", "benign", 2)],
            config=DiscoveryConfig(min_support=3, max_adversarial_rows=1),
        )
