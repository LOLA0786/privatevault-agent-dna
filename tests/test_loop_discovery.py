"""Adversarial contract tests for deterministic agent-loop discovery."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agent_dna.cli import EXIT_FAIL, EXIT_OK, EXIT_USAGE, main
from agent_dna.security.loop_discovery import (
    LOOP_EVENT_SPEC,
    LOOP_REPORT_SPEC,
    LoopDecision,
    LoopEvent,
    LoopFormatError,
    LoopPolicy,
    discover_loops,
)


def _event(
    event_id: str,
    source: str,
    target: str,
    *,
    relation: str = "INVOKES",
    parent: str | None = None,
    trace: str = "trace-1",
    second: int = 0,
    digest_byte: str = "a",
    authorization_id: str | None = "default",
    authorization_state: str = "VERIFIED",
) -> dict[str, object]:
    auth_id = (
        f"authorization-{event_id}"
        if authorization_id == "default"
        else authorization_id
    )
    return {
        "spec": LOOP_EVENT_SPEC,
        "event_id": event_id,
        "trace_id": trace,
        "occurred_at": f"2026-08-06T10:00:{second:02d}Z",
        "source_agent_id": source,
        "target_agent_id": target,
        "relation": relation,
        "action_digest": "sha256:" + digest_byte * 64,
        "authorization_id": auth_id,
        "authorization_state": authorization_state,
        "parent_event_id": parent,
    }


def _codes(report) -> set[str]:
    return {finding.reason_code for finding in report.findings}


def test_clean_verified_chain_is_allowed() -> None:
    report = discover_loops(
        [
            _event("e-1", "planner", "worker", digest_byte="a"),
            _event(
                "e-2",
                "worker",
                "payment-api",
                relation="DISPATCHES",
                parent="e-1",
                second=1,
                digest_byte="b",
            ),
        ]
    )
    assert report.decision is LoopDecision.ALLOW
    assert report.findings == ()


def test_self_approval_is_circular_authority() -> None:
    report = discover_loops(
        [_event("e-1", "treasury", "treasury", relation="APPROVES")]
    )
    assert report.decision is LoopDecision.BLOCK
    assert _codes(report) == {"CIRCULAR_AUTHORITY"}


def test_reciprocal_approval_is_blocked_with_witness() -> None:
    report = discover_loops(
        [
            _event("e-1", "a", "b", relation="APPROVES"),
            _event("e-2", "b", "a", relation="APPROVES", parent="e-1", second=1),
        ]
    )
    finding = next(
        item for item in report.findings if item.reason_code == "CIRCULAR_AUTHORITY"
    )
    assert finding.event_ids == ("e-1", "e-2")
    assert finding.agent_ids == ("a", "b")


def test_mixed_delegation_approval_cycle_is_blocked() -> None:
    report = discover_loops(
        [
            _event("e-1", "root", "ops", relation="DELEGATES"),
            _event(
                "e-2",
                "ops",
                "root",
                relation="APPROVES",
                parent="e-1",
                second=1,
            ),
        ]
    )
    assert report.decision is LoopDecision.BLOCK
    assert "CIRCULAR_AUTHORITY" in _codes(report)


def test_bidirectional_invocation_is_review_not_authority_block() -> None:
    report = discover_loops(
        [
            _event("e-1", "planner", "worker", digest_byte="a"),
            _event(
                "e-2",
                "worker",
                "planner",
                parent="e-1",
                second=1,
                digest_byte="b",
            ),
        ]
    )
    assert report.decision is LoopDecision.REVIEW
    assert _codes(report) == {"AGENT_INVOCATION_CYCLE"}


def test_second_identical_action_in_lineage_requires_review() -> None:
    report = discover_loops(
        [
            _event("e-1", "a", "b", digest_byte="a"),
            _event("e-2", "b", "c", parent="e-1", second=1, digest_byte="b"),
            _event("e-3", "a", "b", parent="e-2", second=2, digest_byte="a"),
        ]
    )
    assert report.decision is LoopDecision.REVIEW
    assert "REPEATED_ACTION_IN_LINEAGE" in _codes(report)


def test_third_identical_action_in_lineage_is_blocked() -> None:
    events = [
        _event("e-1", "a", "b", digest_byte="a"),
        _event("e-2", "a", "b", parent="e-1", second=1, digest_byte="a"),
        _event("e-3", "a", "b", parent="e-2", second=2, digest_byte="a"),
    ]
    report = discover_loops(events)
    assert report.decision is LoopDecision.BLOCK
    assert "RECURSIVE_ACTION_LOOP" in _codes(report)


def test_single_use_authorization_replay_is_blocked() -> None:
    events = [
        _event("e-1", "a", "tool", relation="DISPATCHES", authorization_id="permit-1"),
        _event(
            "e-2",
            "a",
            "tool",
            relation="DISPATCHES",
            parent="e-1",
            second=1,
            digest_byte="b",
            authorization_id="permit-1",
        ),
    ]
    report = discover_loops(events)
    assert report.decision is LoopDecision.BLOCK
    assert "AUTHORIZATION_REUSE" in _codes(report)


def test_verified_state_without_authorization_id_is_invalid() -> None:
    report = discover_loops([_event("e-1", "a", "b", authorization_id=None)])
    assert report.decision is LoopDecision.BLOCK
    assert "VERIFIED_AUTHORIZATION_ID_ABSENT" in _codes(report)


def test_missing_dispatch_authority_fails_closed() -> None:
    report = discover_loops(
        [
            _event(
                "e-1",
                "a",
                "payment-api",
                relation="DISPATCHES",
                authorization_id=None,
                authorization_state="ABSENT",
            )
        ]
    )
    assert report.decision is LoopDecision.BLOCK
    assert _codes(report) == {"AUTHORIZATION_ABSENT"}


def test_unverified_invocation_requires_review() -> None:
    report = discover_loops(
        [
            _event(
                "e-1",
                "a",
                "b",
                authorization_id=None,
                authorization_state="UNVERIFIABLE",
            )
        ]
    )
    assert report.decision is LoopDecision.REVIEW
    assert _codes(report) == {"AUTHORIZATION_UNVERIFIABLE"}


def test_missing_causal_parent_fails_closed() -> None:
    report = discover_loops([_event("e-1", "a", "b", parent="missing")])
    assert report.decision is LoopDecision.BLOCK
    assert "CAUSAL_PARENT_ABSENT" in _codes(report)


def test_missing_parent_can_be_advisory_window_boundary() -> None:
    report = discover_loops(
        [_event("e-1", "a", "b", parent="outside-window")],
        LoopPolicy(require_complete_lineage=False),
    )
    assert report.decision is LoopDecision.ALLOW


def test_cross_trace_parent_is_blocked() -> None:
    report = discover_loops(
        [
            _event("e-1", "a", "b", trace="trace-a"),
            _event(
                "e-2",
                "b",
                "c",
                parent="e-1",
                trace="trace-b",
                second=1,
                digest_byte="b",
            ),
        ]
    )
    assert "CROSS_TRACE_PARENT" in _codes(report)
    assert report.decision is LoopDecision.BLOCK


def test_child_cannot_predate_parent() -> None:
    report = discover_loops(
        [
            _event("e-1", "a", "b", second=2),
            _event("e-2", "b", "c", parent="e-1", second=1, digest_byte="b"),
        ]
    )
    assert "CAUSAL_TIME_REGRESSION" in _codes(report)


def test_parent_pointer_cycle_is_blocked() -> None:
    report = discover_loops(
        [
            _event("e-1", "a", "b", parent="e-2"),
            _event("e-2", "b", "c", parent="e-1", digest_byte="b"),
        ]
    )
    assert "CAUSAL_LINEAGE_CYCLE" in _codes(report)
    assert report.decision is LoopDecision.BLOCK


def test_causal_depth_is_bounded() -> None:
    report = discover_loops(
        [
            _event("e-1", "a", "b"),
            _event("e-2", "b", "c", parent="e-1", second=1, digest_byte="b"),
            _event("e-3", "c", "d", parent="e-2", second=2, digest_byte="c"),
        ],
        LoopPolicy(max_causal_depth=2),
    )
    assert "CAUSAL_DEPTH_EXCEEDED" in _codes(report)


def test_identical_duplicate_event_is_idempotent() -> None:
    event = _event("e-1", "a", "b")
    report = discover_loops([event, copy.deepcopy(event)])
    assert report.events_analyzed == 1
    assert report.decision is LoopDecision.ALLOW


def test_event_id_collision_is_rejected() -> None:
    first = _event("e-1", "a", "b")
    second = _event("e-1", "a", "c")
    with pytest.raises(LoopFormatError, match="conflicting bodies"):
        discover_loops([first, second])


def test_output_is_independent_of_input_order() -> None:
    events = [
        _event("e-1", "a", "b", relation="APPROVES"),
        _event("e-2", "b", "a", relation="APPROVES", parent="e-1", second=1),
    ]
    forward = discover_loops(events)
    reverse = discover_loops(reversed(events))
    assert forward.to_dict() == reverse.to_dict()


def test_unknown_fields_are_rejected() -> None:
    event = _event("e-1", "a", "b")
    event["model_says_safe"] = True
    with pytest.raises(LoopFormatError, match="unknown fields"):
        LoopEvent.from_dict(event)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("spec", "pv-agent-security-event/0.9", "unsupported spec"),
        ("occurred_at", "2026-08-06 10:00:00", "RFC 3339"),
        ("action_digest", "sha256:abcd", "sha256 digest"),
        ("relation", "RESPONDS", "unsupported value"),
        ("authorization_state", "MODEL_APPROVED", "unsupported value"),
    ],
)
def test_strict_event_validation(field: str, value: object, message: str) -> None:
    event = _event("e-1", "a", "b")
    event[field] = value
    with pytest.raises(LoopFormatError, match=message):
        LoopEvent.from_dict(event)


def test_empty_and_oversized_batches_are_rejected() -> None:
    with pytest.raises(LoopFormatError, match="at least one"):
        discover_loops([])
    with pytest.raises(LoopFormatError, match="exceeds limit"):
        discover_loops(
            [_event("e-1", "a", "b"), _event("e-2", "b", "c")],
            LoopPolicy(max_events=1),
        )


def test_report_contract_is_self_describing() -> None:
    report = discover_loops([_event("e-1", "a", "b")]).to_dict()
    assert report["spec"] == LOOP_REPORT_SPEC
    assert str(report["report_id"]).startswith("sha256:")
    assert str(report["input_digest"]).startswith("sha256:")
    assert report["summary"] == {"MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}


def test_committed_schemas_validate_runtime_contracts() -> None:
    schema_root = Path("spec/loop-discovery-v1")
    event_schema = json.loads((schema_root / "event.schema.json").read_text())
    report_schema = json.loads((schema_root / "report.schema.json").read_text())

    Draft202012Validator.check_schema(event_schema)
    Draft202012Validator.check_schema(report_schema)
    Draft202012Validator(event_schema).validate(_event("e-1", "a", "b"))
    Draft202012Validator(report_schema).validate(
        discover_loops([_event("e-1", "a", "b")]).to_dict()
    )


def test_policy_rejects_unsafe_thresholds() -> None:
    with pytest.raises(ValueError, match="below"):
        LoopPolicy(action_review_occurrences=3, action_block_occurrences=3)
    with pytest.raises(ValueError, match=">= 1"):
        LoopPolicy(max_events=0)


def test_cli_emits_machine_readable_report(tmp_path, capsys) -> None:
    source = tmp_path / "events.jsonl"
    destination = tmp_path / "report.json"
    source.write_text(json.dumps(_event("e-1", "a", "b")) + "\n")

    exit_code = main(
        [
            "loop",
            "discover",
            "--input",
            str(source),
            "--json",
            str(destination),
        ]
    )

    assert exit_code == EXIT_OK
    assert "Decision          ALLOW" in capsys.readouterr().out
    assert json.loads(destination.read_text())["decision"] == "ALLOW"


def test_cli_returns_failure_for_review_or_block(tmp_path) -> None:
    source = tmp_path / "events.jsonl"
    events = [
        _event("e-1", "a", "b", relation="APPROVES"),
        _event("e-2", "b", "a", relation="APPROVES", parent="e-1", second=1),
    ]
    source.write_text("\n".join(json.dumps(event) for event in events) + "\n")
    assert main(["loop", "discover", "--input", str(source)]) == EXIT_FAIL


def test_cli_returns_usage_for_malformed_input(tmp_path, capsys) -> None:
    source = tmp_path / "events.jsonl"
    source.write_text('{"spec":"wrong"}\n')
    assert main(["loop", "discover", "--input", str(source)]) == EXIT_USAGE
    assert "error:" in capsys.readouterr().err
