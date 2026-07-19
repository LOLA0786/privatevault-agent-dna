use pyo3::prelude::*;

use pv_runtime::runtime::decision_graph::DecisionGraph;
use pv_runtime::runtime::decision_record::DecisionRecord;
use pv_runtime::runtime::decision_recorder::DecisionRecorder;
use pv_runtime::runtime::execution_record::ExecutionEvent;

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn make_record(
    decision_id: &str,
    agent_id: &str,
    capability: &str,
    decision: &str,
    parent_decision: Option<&str>,
    prev_hash: &str,
) -> DecisionRecord {
    DecisionRecord::new(
        decision_id.to_string(),
        agent_id.to_string(),
        capability.to_string(),
        decision.to_string(),
        "user-request".to_string(),
        12345.0,
        parent_decision.map(str::to_string),
        prev_hash.to_string(),
    )
}

/* -------------------------------------------------------------------------- */
/* DecisionRecord tests                                                       */
/* -------------------------------------------------------------------------- */

#[test]
fn decision_record_hash_and_verify() {
    let mut record = make_record("decision-1", "agent-1", "payments", "allow", None, "");

    record.seal().expect("seal must succeed");

    assert!(!record.record_hash.is_empty());
    assert!(record.verify());
}

#[test]
fn decision_record_detects_decision_tampering() {
    let mut record = make_record("decision-1", "agent-1", "payments", "allow", None, "");

    record.seal().expect("seal must succeed");
    record.decision = "block".to_string();

    assert!(!record.verify());
}

#[test]
fn decision_record_detects_agent_tampering() {
    let mut record = make_record("decision-1", "agent-1", "payments", "allow", None, "");

    record.seal().expect("seal must succeed");
    record.agent_id = "attacker-agent".to_string();

    assert!(!record.verify());
}

#[test]
fn decision_record_detects_capability_tampering() {
    let mut record = make_record("decision-1", "agent-1", "payments", "allow", None, "");

    record.seal().expect("seal must succeed");
    record.capability = "admin".to_string();

    assert!(!record.verify());
}

#[test]
fn decision_record_detects_parent_tampering() {
    let mut record = make_record(
        "decision-2",
        "agent-1",
        "payments",
        "allow",
        Some("decision-1"),
        "",
    );

    record.seal().expect("seal must succeed");
    record.parent_decision = Some("different-parent".to_string());

    assert!(!record.verify());
}

#[test]
fn identical_records_produce_identical_hashes() {
    let mut first = make_record("decision-1", "agent-1", "payments", "allow", None, "");

    let mut second = make_record("decision-1", "agent-1", "payments", "allow", None, "");

    first.seal().expect("seal must succeed");
    second.seal().expect("seal must succeed");

    assert_eq!(first.record_hash, second.record_hash);
}

#[test]
fn changing_prev_hash_changes_record_hash() {
    let mut first = make_record("decision-1", "agent-1", "payments", "allow", None, "");

    let mut second = make_record(
        "decision-1",
        "agent-1",
        "payments",
        "allow",
        None,
        "previous-record-hash",
    );

    first.seal().expect("seal must succeed");
    second.seal().expect("seal must succeed");

    assert_ne!(first.record_hash, second.record_hash);
}

#[test]
fn verify_rejects_unsealed_decision_record() {
    let record = make_record("decision-1", "agent-1", "payments", "allow", None, "");

    assert!(record.record_hash.is_empty());
    assert!(!record.verify());
}

/* -------------------------------------------------------------------------- */
/* ExecutionEvent tests                                                       */
/* -------------------------------------------------------------------------- */

fn make_execution_event(event_id: &str, status: &str, decision_hash: &str) -> ExecutionEvent {
    ExecutionEvent::new(
        event_id.to_string(),
        "agent-1".to_string(),
        "decision-1".to_string(),
        status.to_string(),
        "execution result".to_string(),
        r#"[{"type":"resulted_in","target":"decision-1"}]"#.to_string(),
        12345.0,
        decision_hash.to_string(),
    )
}

#[test]
fn execution_event_hash_and_verify() {
    let mut event = make_execution_event("event-1", "ok", "decision-record-hash");

    event.seal().expect("seal must succeed");

    assert!(!event.record_hash.is_empty());
    assert!(event.verify());
}

#[test]
fn execution_event_detects_status_tampering() {
    let mut event = make_execution_event("event-1", "ok", "decision-record-hash");

    event.seal().expect("seal must succeed");
    event.status = "error".to_string();

    assert!(!event.verify());
}

#[test]
fn execution_event_detects_anchor_tampering() {
    let mut event = make_execution_event("event-1", "ok", "decision-record-hash");

    event.seal().expect("seal must succeed");
    event.prev_hash = "different-decision-hash".to_string();

    assert!(!event.verify());
}

#[test]
fn execution_event_detects_edge_tampering() {
    let mut event = make_execution_event("event-1", "ok", "decision-record-hash");

    event.seal().expect("seal must succeed");

    event.edges = serde_json::from_str(r#"[{"type":"resulted_in","target":"different-decision"}]"#)
        .expect("test fixture edges must be valid JSON");

    assert!(!event.verify());
}

#[test]
fn identical_execution_events_produce_identical_hashes() {
    let mut first = make_execution_event("event-1", "ok", "decision-record-hash");

    let mut second = make_execution_event("event-1", "ok", "decision-record-hash");

    first.seal().expect("seal must succeed");
    second.seal().expect("seal must succeed");

    assert_eq!(first.record_hash, second.record_hash);
}

#[test]
fn verify_rejects_unsealed_execution_event() {
    let event = make_execution_event("event-1", "ok", "decision-record-hash");

    assert!(event.record_hash.is_empty());
    assert!(!event.verify());
}

/* -------------------------------------------------------------------------- */
/* DecisionGraph tests                                                        */
/* -------------------------------------------------------------------------- */

#[test]
fn decision_graph_starts_empty() {
    let graph = DecisionGraph::new();

    assert_eq!(graph.len(), 0);
}

#[test]
fn decision_graph_adds_and_gets_sealed_record() {
    Python::attach(|py| {
        let mut graph = DecisionGraph::new();

        let mut record = make_record("decision-1", "agent-1", "payments", "allow", None, "");

        record.seal().expect("seal must succeed");

        let python_record = Py::new(py, record).expect("failed to create Python record");

        graph
            .add(py, python_record)
            .expect("sealed record should be accepted");

        assert_eq!(graph.len(), 1);

        let stored = graph
            .get(py, "decision-1".to_string())
            .expect("stored decision should be found");

        let stored_ref = stored.borrow(py);

        assert_eq!(stored_ref.decision_id, "decision-1");
        assert_eq!(stored_ref.agent_id, "agent-1");
        assert_eq!(stored_ref.capability, "payments");
        assert_eq!(stored_ref.decision, "allow");
        assert!(stored_ref.verify());
    });
}

#[test]
fn decision_graph_rejects_unsealed_record() {
    Python::attach(|py| {
        let mut graph = DecisionGraph::new();

        let record = make_record("decision-1", "agent-1", "payments", "allow", None, "");

        let python_record = Py::new(py, record).expect("failed to create Python record");

        let result = graph.add(py, python_record);

        assert!(result.is_err());
        assert_eq!(graph.len(), 0);

        let message = result.expect_err("unsealed record must fail").to_string();

        assert!(message.contains("record is not sealed"));
    });
}

#[test]
fn decision_graph_rejects_duplicate_decision_id() {
    Python::attach(|py| {
        let mut graph = DecisionGraph::new();

        let mut first = make_record("decision-1", "agent-1", "payments", "allow", None, "");

        let mut duplicate = make_record("decision-1", "agent-2", "admin", "block", None, "");

        first.seal().expect("seal must succeed");
        duplicate.seal().expect("seal must succeed");

        graph
            .add(
                py,
                Py::new(py, first).expect("failed to create first Python record"),
            )
            .expect("first record should be accepted");

        let result = graph.add(
            py,
            Py::new(py, duplicate).expect("failed to create duplicate Python record"),
        );

        assert!(result.is_err());
        assert_eq!(graph.len(), 1);

        let message = result
            .expect_err("duplicate decision must fail")
            .to_string();

        assert!(message.contains("duplicate decision_id"));
    });
}

#[test]
fn decision_graph_rejects_missing_parent() {
    Python::attach(|py| {
        let mut graph = DecisionGraph::new();

        let mut child = make_record(
            "decision-2",
            "agent-1",
            "payments",
            "allow",
            Some("missing-parent"),
            "",
        );

        child.seal().expect("seal must succeed");

        let result = graph.add(
            py,
            Py::new(py, child).expect("failed to create child Python record"),
        );

        assert!(result.is_err());
        assert_eq!(graph.len(), 0);

        let message = result.expect_err("missing parent must fail").to_string();

        assert!(message.contains("parent decision missing"));
    });
}

#[test]
fn decision_graph_accepts_child_after_parent() {
    Python::attach(|py| {
        let mut graph = DecisionGraph::new();

        let mut parent = make_record("decision-1", "agent-1", "payments", "allow", None, "");

        parent.seal().expect("seal must succeed");

        let parent_hash = parent.record_hash.clone();

        graph
            .add(
                py,
                Py::new(py, parent).expect("failed to create parent Python record"),
            )
            .expect("parent should be accepted");

        let mut child = make_record(
            "decision-2",
            "agent-1",
            "payments",
            "block",
            Some("decision-1"),
            &parent_hash,
        );

        child.seal().expect("seal must succeed");

        graph
            .add(
                py,
                Py::new(py, child).expect("failed to create child Python record"),
            )
            .expect("child should be accepted");

        assert_eq!(graph.len(), 2);

        let stored_child = graph
            .get(py, "decision-2".to_string())
            .expect("child should be retrievable");

        let child_ref = stored_child.borrow(py);

        assert_eq!(child_ref.parent_decision.as_deref(), Some("decision-1"));

        assert_eq!(child_ref.prev_hash, parent_hash);
        assert!(child_ref.verify());
    });
}

#[test]
fn decision_graph_get_rejects_unknown_decision() {
    Python::attach(|py| {
        let graph = DecisionGraph::new();

        let result = graph.get(py, "unknown-decision".to_string());

        assert!(result.is_err());

        let message = result.expect_err("unknown decision must fail").to_string();

        assert!(message.contains("decision not found"));
    });
}

/* -------------------------------------------------------------------------- */
/* DecisionRecorder tests                                                     */
/* -------------------------------------------------------------------------- */

#[test]
fn decision_recorder_seals_record_and_assigns_zero_hash() {
    Python::attach(|py| {
        let mut recorder = DecisionRecorder::new();

        let record = make_record(
            "decision-1",
            "agent-1",
            "payments",
            "allow",
            None,
            "incorrect-existing-hash",
        );

        let python_record = Py::new(py, record).expect("failed to create Python record");

        recorder
            .record(python_record.borrow_mut(py))
            .expect("record must succeed");

        let recorded = python_record.borrow(py);

        assert_eq!(recorded.prev_hash, ZERO_HASH);
        assert!(!recorded.record_hash.is_empty());
        assert!(recorded.verify());
    });
}

#[test]
fn decision_recorder_chains_second_record_to_first_hash() {
    Python::attach(|py| {
        let mut recorder = DecisionRecorder::new();

        let first = Py::new(
            py,
            make_record("decision-1", "agent-1", "payments", "allow", None, ""),
        )
        .expect("failed to create first Python record");

        recorder
            .record(first.borrow_mut(py))
            .expect("record must succeed");

        let first_hash = first.borrow(py).record_hash.clone();

        let second = Py::new(
            py,
            make_record(
                "decision-2",
                "agent-1",
                "payments",
                "block",
                Some("decision-1"),
                "",
            ),
        )
        .expect("failed to create second Python record");

        recorder
            .record(second.borrow_mut(py))
            .expect("record must succeed");

        let second_ref = second.borrow(py);

        assert_eq!(second_ref.prev_hash, first_hash);
        assert!(second_ref.verify());
        assert_ne!(second_ref.record_hash, first_hash);
    });
}

#[test]
fn decision_recorder_maintains_independent_agent_chains() {
    Python::attach(|py| {
        let mut recorder = DecisionRecorder::new();

        let agent_one_record = Py::new(
            py,
            make_record(
                "agent-one-decision",
                "agent-1",
                "payments",
                "allow",
                None,
                "",
            ),
        )
        .expect("failed to create agent-one record");

        let agent_two_record = Py::new(
            py,
            make_record(
                "agent-two-decision",
                "agent-2",
                "payments",
                "allow",
                None,
                "",
            ),
        )
        .expect("failed to create agent-two record");

        recorder
            .record(agent_one_record.borrow_mut(py))
            .expect("record must succeed");
        recorder
            .record(agent_two_record.borrow_mut(py))
            .expect("record must succeed");

        let agent_one_ref = agent_one_record.borrow(py);
        let agent_two_ref = agent_two_record.borrow(py);

        assert_eq!(agent_one_ref.prev_hash, ZERO_HASH);
        assert_eq!(agent_two_ref.prev_hash, ZERO_HASH);

        assert!(agent_one_ref.verify());
        assert!(agent_two_ref.verify());

        assert_ne!(agent_one_ref.record_hash, agent_two_ref.record_hash);
    });
}

#[test]
fn decision_recorder_overwrites_untrusted_prev_hash() {
    Python::attach(|py| {
        let mut recorder = DecisionRecorder::new();

        let record = Py::new(
            py,
            make_record(
                "decision-1",
                "agent-1",
                "payments",
                "allow",
                None,
                "attacker-controlled-prev-hash",
            ),
        )
        .expect("failed to create Python record");

        recorder
            .record(record.borrow_mut(py))
            .expect("record must succeed");

        let record_ref = record.borrow(py);

        assert_eq!(record_ref.prev_hash, ZERO_HASH);
        assert_ne!(record_ref.prev_hash, "attacker-controlled-prev-hash");

        assert!(record_ref.verify());
    });
}

#[test]
fn decision_recorder_reseals_previously_sealed_record() {
    Python::attach(|py| {
        let mut recorder = DecisionRecorder::new();

        let mut record = make_record(
            "decision-1",
            "agent-1",
            "payments",
            "allow",
            None,
            "wrong-prev-hash",
        );

        record.seal().expect("seal must succeed");

        let old_hash = record.record_hash.clone();

        let python_record = Py::new(py, record).expect("failed to create Python record");

        recorder
            .record(python_record.borrow_mut(py))
            .expect("record must succeed");

        let recorded = python_record.borrow(py);

        assert_eq!(recorded.prev_hash, ZERO_HASH);
        assert_ne!(recorded.record_hash, old_hash);
        assert!(recorded.verify());
    });
}

#[test]
fn recorder_output_can_be_added_to_graph() {
    Python::attach(|py| {
        let mut recorder = DecisionRecorder::new();
        let mut graph = DecisionGraph::new();

        let record = Py::new(
            py,
            make_record("decision-1", "agent-1", "payments", "allow", None, ""),
        )
        .expect("failed to create Python record");

        recorder
            .record(record.borrow_mut(py))
            .expect("record must succeed");

        graph
            .add(py, record.clone_ref(py))
            .expect("recorder output should be accepted by graph");

        assert_eq!(graph.len(), 1);

        let stored = graph
            .get(py, "decision-1".to_string())
            .expect("record should be in graph");

        assert!(stored.borrow(py).verify());
    });
}
