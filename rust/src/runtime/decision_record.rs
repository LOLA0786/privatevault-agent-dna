//! DecisionRecord -- Rust mirror of agent_dna/decision_record.py.
//!
//! PARITY CONTRACT: payload() covers the hash-covered fields of the
//! Python dataclass (24 on drp/0.1; drp/0.2 also seals action_digest
//! and dispatch_context_digest), hashed as sha256(canonical_json(payload))
//! where canonical_json is byte-identical to CPython json.dumps(...,
//! sort_keys=True, separators=(",", ":")). A record sealed here MUST
//! verify under tools/verify_records.py with zero modifications.
//!
//! evidence / edges cross the FFI boundary as JSON strings and are
//! parsed STRICTLY at set time -- invalid JSON is an error, never a
//! silent default (that would let two different stored strings hash
//! identically: a tamper-evidence hole).

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::runtime::canonical_json::canonical;

pub const DRP_V01: &str = "drp/0.1";
pub const DRP_V02: &str = "drp/0.2";

/// Retained: existing Rust callers refer to this name.
pub const PROTOCOL_VERSION: &str = DRP_V01;

/// The only legal version/digest combinations. Mirrors
/// agent_dna/decision_record.py::check_version_invariant, including its
/// messages: a divergence between the two would be a fork in the
/// protocol, not a cosmetic difference.
///
/// The version is never inferred from the digest. A drp/0.2 record
/// missing either binding is rejected, not downgraded.
fn check_sha256_prefixed(label: &str, digest: &str) -> Result<(), String> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("malformed {label} {digest:?}"))?;
    if hex.len() != 64
        || !hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(format!("malformed {label} {digest:?}"));
    }
    Ok(())
}

fn check_version_invariant(
    protocol_version: &str,
    action_digest: Option<&str>,
    dispatch_context_digest: Option<&str>,
) -> Result<(), String> {
    match protocol_version {
        DRP_V01 => {
            if action_digest.is_some() {
                return Err("drp/0.1 records carry no action_digest; a bound record \
                     must declare drp/0.2"
                    .into());
            }
            if dispatch_context_digest.is_some() {
                return Err("drp/0.1 records carry no dispatch_context_digest; a bound \
                     record must declare drp/0.2"
                    .into());
            }
            Ok(())
        }
        DRP_V02 => {
            match action_digest {
                None => {
                    return Err(
                        "drp/0.2 requires an action_digest; a missing binding is not \
                         a downgrade to drp/0.1"
                            .into(),
                    );
                }
                Some(digest) => check_sha256_prefixed("action_digest", digest)?,
            }
            match dispatch_context_digest {
                None => {
                    return Err(
                        "drp/0.2 requires a dispatch_context_digest; a missing binding \
                         is not a downgrade to drp/0.1"
                            .into(),
                    );
                }
                Some(digest) => check_sha256_prefixed("dispatch_context_digest", digest)?,
            }
            Ok(())
        }
        other => Err(format!(
            "unknown protocol_version {other:?}; this build implements \
             [\"drp/0.1\", \"drp/0.2\"]"
        )),
    }
}
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn parse_json_array(label: &str, raw: &str) -> PyResult<Value> {
    let v: Value = serde_json::from_str(raw)
        .map_err(|e| PyValueError::new_err(format!("{label} is not valid JSON: {e}")))?;
    if !v.is_array() {
        return Err(PyValueError::new_err(format!(
            "{label} must be a JSON array, got {v}"
        )));
    }
    Ok(v)
}

// skip_from_py_object: records cross the FFI by reference
// (Py<T>) only. An implicit by-value FromPyObject would clone a
// sealed record out of its chain context -- explicitly opted out.
#[pyclass(skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    // identity / lineage
    #[pyo3(get)]
    pub kind: String,
    #[pyo3(get)]
    pub protocol_version: String,
    #[pyo3(get, set)]
    pub decision_id: String,
    #[pyo3(get, set)]
    pub parent_decision: Option<String>,
    #[pyo3(get, set)]
    pub agent_id: String,
    #[pyo3(get, set)]
    pub capability: String,

    // the decision itself
    #[pyo3(get, set)]
    pub decision: String,
    #[pyo3(get, set)]
    pub triggered_by: String,
    #[pyo3(get, set)]
    pub reason: String,
    #[pyo3(get, set)]
    pub severity: String,
    #[pyo3(get, set)]
    pub drift_score: f64,
    pub evidence: Value, // JSON array; string-typed at the FFI boundary
    #[pyo3(get, set)]
    pub evidence_strength: f64,

    // execution context
    #[pyo3(get, set)]
    pub arguments_digest: String,
    #[pyo3(get, set)]
    pub outcome: String,

    // schema-reserved (Python: produced by nothing yet -- honesty)
    #[pyo3(get, set)]
    pub request_id: Option<String>,
    #[pyo3(get, set)]
    pub goal: Option<String>,
    #[pyo3(get, set)]
    pub intent: Option<String>,
    #[pyo3(get, set)]
    pub policy_id: Option<String>,
    #[pyo3(get, set)]
    pub approval_ref: Option<String>,
    #[pyo3(get, set)]
    pub receipt_ref: Option<String>,

    // graph edges -- hash-covered
    pub edges: Value, // JSON array; string-typed at the FFI boundary

    // chain
    #[pyo3(get, set)]
    pub timestamp: f64,
    #[pyo3(get, set)]
    pub prev_hash: String,
    #[pyo3(get)]
    pub record_hash: String,
    /// Read-only from Python, like protocol_version: neither may be
    /// mutated into an invalid pair after construction.
    #[pyo3(get)]
    pub action_digest: Option<String>,
    #[pyo3(get)]
    pub dispatch_context_digest: Option<String>,
}

#[pymethods]
impl DecisionRecord {
    /// Python-facing constructor. Mirrors the Python dataclass field
    /// set; evidence_json / edges_json take canonical JSON arrays.
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        protocol_version,
        decision_id,
        agent_id,
        capability,
        decision,
        triggered_by,
        timestamp,
        parent_decision = None,
        prev_hash = GENESIS_HASH.to_string(),
        reason = String::new(),
        severity = String::from("none"),
        drift_score = 0.0,
        evidence_json = String::from("[]"),
        evidence_strength = 0.0,
        arguments_digest = String::new(),
        outcome = String::from("pending"),
        request_id = None,
        goal = None,
        intent = None,
        policy_id = None,
        approval_ref = None,
        receipt_ref = None,
        edges_json = String::from("[]"),
        action_digest = None,
        dispatch_context_digest = None,
    ))]
    pub fn py_new(
        protocol_version: String,
        decision_id: String,
        agent_id: String,
        capability: String,
        decision: String,
        triggered_by: String,
        timestamp: f64,
        parent_decision: Option<String>,
        prev_hash: String,
        reason: String,
        severity: String,
        drift_score: f64,
        evidence_json: String,
        evidence_strength: f64,
        arguments_digest: String,
        outcome: String,
        request_id: Option<String>,
        goal: Option<String>,
        intent: Option<String>,
        policy_id: Option<String>,
        approval_ref: Option<String>,
        receipt_ref: Option<String>,
        edges_json: String,
        action_digest: Option<String>,
        dispatch_context_digest: Option<String>,
    ) -> PyResult<Self> {
        check_version_invariant(
            &protocol_version,
            action_digest.as_deref(),
            dispatch_context_digest.as_deref(),
        )
        .map_err(PyValueError::new_err)?;
        Ok(Self {
            kind: "decision".into(),
            protocol_version,
            decision_id,
            parent_decision,
            agent_id,
            capability,
            decision,
            triggered_by,
            reason,
            severity,
            drift_score,
            evidence: parse_json_array("evidence_json", &evidence_json)?,
            evidence_strength,
            arguments_digest,
            outcome,
            request_id,
            goal,
            intent,
            policy_id,
            approval_ref,
            receipt_ref,
            edges: parse_json_array("edges_json", &edges_json)?,
            timestamp,
            prev_hash,
            record_hash: String::new(),
            action_digest,
            dispatch_context_digest,
        })
    }

    #[getter]
    fn evidence_json(&self) -> PyResult<String> {
        canonical(&self.evidence).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    #[setter]
    fn set_evidence_json(&mut self, raw: &str) -> PyResult<()> {
        self.evidence = parse_json_array("evidence_json", raw)?;
        Ok(())
    }

    #[getter]
    fn edges_json(&self) -> PyResult<String> {
        canonical(&self.edges).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    #[setter]
    fn set_edges_json(&mut self, raw: &str) -> PyResult<()> {
        self.edges = parse_json_array("edges_json", raw)?;
        Ok(())
    }

    /// Seal = compute the canonical hash. Errors (non-finite float,
    /// canonicalization fault) propagate: a record that cannot
    /// canonicalize cannot seal -- fail-closed, never a panic.
    pub fn seal(&mut self) -> PyResult<()> {
        self.record_hash = self.compute_hash().map_err(PyRuntimeError::new_err)?;
        Ok(())
    }

    /// verify() is infallible by design: any internal fault verifies
    /// FALSE (a record we cannot re-canonicalize is not a verified
    /// record). Same fail-closed posture as the Python engine.
    pub fn verify(&self) -> bool {
        if self.record_hash.is_empty() {
            return false;
        }
        match self.compute_hash() {
            Ok(h) => h == self.record_hash,
            Err(_) => false,
        }
    }

    /// Full canonical body incl. record_hash -- exactly
    /// Python DecisionRecord.to_dict() serialized canonically. This
    /// line is what tools/verify_records.py consumes.
    pub fn to_canonical_json(&self) -> PyResult<String> {
        let mut payload = self.payload_value();
        if let Value::Object(map) = &mut payload {
            map.insert(
                "record_hash".into(),
                Value::String(self.record_hash.clone()),
            );
        }
        canonical(&payload).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    fn __repr__(&self) -> String {
        format!(
            "DecisionRecord(decision_id='{}', decision='{}')",
            self.decision_id, self.decision
        )
    }
}

impl DecisionRecord {
    /// Rust-side compat constructor -- SAME 8-arg signature the
    /// existing test suite uses. Fills the remaining DRP fields with
    /// the Python dataclass defaults. Chain/seal/verify semantics of
    /// every existing test are preserved.
    ///
    /// Always drp/0.1: this builds a record with no execution action to
    /// bind. A bound record is constructed through py_new with an
    /// explicit version, so nothing can reach drp/0.2 by default.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        decision_id: String,
        agent_id: String,
        capability: String,
        decision: String,
        triggered_by: String,
        timestamp: f64,
        parent_decision: Option<String>,
        prev_hash: String,
    ) -> Self {
        Self {
            kind: "decision".into(),
            protocol_version: DRP_V01.into(),
            action_digest: None,
            dispatch_context_digest: None,
            decision_id,
            parent_decision,
            agent_id,
            capability,
            decision,
            triggered_by,
            reason: String::new(),
            severity: "none".into(),
            drift_score: 0.0,
            evidence: json!([]),
            evidence_strength: 0.0,
            arguments_digest: String::new(),
            outcome: "pending".into(),
            request_id: None,
            goal: None,
            intent: None,
            policy_id: None,
            approval_ref: None,
            receipt_ref: None,
            edges: json!([]),
            timestamp,
            prev_hash,
            record_hash: String::new(),
        }
    }

    /// The hash-covered fields, mirroring Python payload().
    /// Key order here is irrelevant: canonical() sorts.
    fn payload_value(&self) -> Value {
        let mut payload = json!({
            "kind": self.kind,
            "protocol_version": self.protocol_version,
            "decision_id": self.decision_id,
            "parent_decision": self.parent_decision,
            "agent_id": self.agent_id,
            "capability": self.capability,
            "decision": self.decision,
            "triggered_by": self.triggered_by,
            "reason": self.reason,
            "severity": self.severity,
            "drift_score": self.drift_score,
            "evidence": self.evidence,
            "evidence_strength": self.evidence_strength,
            "arguments_digest": self.arguments_digest,
            "outcome": self.outcome,
            "request_id": self.request_id,
            "goal": self.goal,
            "intent": self.intent,
            "policy_id": self.policy_id,
            "approval_ref": self.approval_ref,
            "receipt_ref": self.receipt_ref,
            "edges": self.edges,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
        });

        // drp/0.2 adds action_digest and dispatch_context_digest, so a
        // v0.1 payload is byte-identical to what it was before v0.2
        // existed. Keyed on the declared version, never on whether a
        // digest happens to be present. canonical() sorts, so insertion
        // order is irrelevant.
        if self.protocol_version == DRP_V02 {
            if let Some(map) = payload.as_object_mut() {
                if let Some(digest) = self.action_digest.as_ref() {
                    map.insert("action_digest".into(), json!(digest));
                }
                if let Some(digest) = self.dispatch_context_digest.as_ref() {
                    map.insert("dispatch_context_digest".into(), json!(digest));
                }
            }
        }

        payload
    }

    fn compute_hash(&self) -> Result<String, String> {
        // Struct fields are pub, so Rust code can mutate a sealed record
        // into an invalid version/digest pair. Checked here rather than
        // only at construction: seal() and verify() both route through
        // this, so neither can act on a record the invariant rejects.
        check_version_invariant(
            &self.protocol_version,
            self.action_digest.as_deref(),
            self.dispatch_context_digest.as_deref(),
        )?;

        // json!() silently coerces non-finite f64 to null, which
        // would BOTH bypass the canonicalizer's NonFinite guard AND
        // diverge from CPython (json.dumps emits a NaN token).
        // Reject at the source: a record with a non-finite float
        // cannot seal. Fail-closed.
        for (name, v) in [
            ("drift_score", self.drift_score),
            ("evidence_strength", self.evidence_strength),
            ("timestamp", self.timestamp),
        ] {
            if !v.is_finite() {
                return Err(format!("non-finite {name} cannot be sealed"));
            }
        }
        let canonical_str = canonical(&self.payload_value()).map_err(|e| e.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(canonical_str.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<DecisionRecord>()?;
    Ok(())
}
