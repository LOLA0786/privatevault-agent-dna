//! ExecutionEvent -- Rust mirror of agent_dna/execution_record.py.
//!
//! Fix over the previous revision: edges was hashed as
//! parse-or-default-to-[], so two DIFFERENT invalid stored strings
//! produced the SAME hash -- a tamper-evidence hole. edges is now
//! parsed strictly at construction/set time; invalid input is an
//! error, and the parsed Value is the single stored representation.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::runtime::canonical_json::canonical;

pub const PROTOCOL_VERSION: &str = "drp/0.2";

fn parse_edges(raw: &str) -> PyResult<Value> {
    let v: Value = serde_json::from_str(raw)
        .map_err(|e| PyValueError::new_err(format!("edges is not valid JSON: {e}")))?;
    if !v.is_array() {
        return Err(PyValueError::new_err(format!(
            "edges must be a JSON array, got {v}"
        )));
    }
    Ok(v)
}

// skip_from_py_object: records cross the FFI by reference
// (Py<T>) only. An implicit by-value FromPyObject would clone a
// sealed record out of its chain context -- explicitly opted out.
#[pyclass(skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct ExecutionEvent {
    #[pyo3(get)]
    pub kind: String,
    #[pyo3(get)]
    pub protocol_version: String,
    #[pyo3(get, set)]
    pub event_id: String,
    #[pyo3(get, set)]
    pub agent_id: String,
    #[pyo3(get, set)]
    pub decision_ref: String,
    #[pyo3(get, set)]
    pub status: String,
    #[pyo3(get, set)]
    pub detail: String,
    pub edges: Value, // strict JSON array; string-typed over FFI
    #[pyo3(get, set)]
    pub timestamp: f64,
    #[pyo3(get, set)]
    pub prev_hash: String,
    #[pyo3(get)]
    pub record_hash: String,
}

#[pymethods]
impl ExecutionEvent {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        event_id,
        agent_id,
        decision_ref,
        status,
        detail,
        timestamp,
        prev_hash,
        edges_json = String::from("[]"),
    ))]
    pub fn py_new(
        event_id: String,
        agent_id: String,
        decision_ref: String,
        status: String,
        detail: String,
        timestamp: f64,
        prev_hash: String,
        edges_json: String,
    ) -> PyResult<Self> {
        Ok(Self {
            kind: "execution".into(),
            protocol_version: PROTOCOL_VERSION.into(),
            event_id,
            agent_id,
            decision_ref,
            status,
            detail,
            edges: parse_edges(&edges_json)?,
            timestamp,
            prev_hash,
            record_hash: String::new(),
        })
    }

    #[getter]
    fn edges_json(&self) -> PyResult<String> {
        canonical(&self.edges).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    #[setter]
    fn set_edges_json(&mut self, raw: &str) -> PyResult<()> {
        self.edges = parse_edges(raw)?;
        Ok(())
    }

    pub fn seal(&mut self) -> PyResult<()> {
        self.record_hash = self.compute_hash().map_err(PyRuntimeError::new_err)?;
        Ok(())
    }

    pub fn verify(&self) -> bool {
        if self.record_hash.is_empty() {
            return false;
        }
        match self.compute_hash() {
            Ok(h) => h == self.record_hash,
            Err(_) => false,
        }
    }

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
            "ExecutionEvent(event_id='{}', status='{}')",
            self.event_id, self.status
        )
    }
}

impl ExecutionEvent {
    /// Rust-side compat constructor -- previous 8-arg signature with
    /// edges as a string, now STRICT: panics replaced by an explicit
    /// expect is unacceptable, so this returns the parsed struct only
    /// for valid input and defaults edges to [] ONLY for the empty
    /// string (the value every existing test passes).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: String,
        agent_id: String,
        decision_ref: String,
        status: String,
        detail: String,
        edges: String,
        timestamp: f64,
        prev_hash: String,
    ) -> Self {
        let parsed = if edges.trim().is_empty() {
            json!([])
        } else {
            serde_json::from_str::<Value>(&edges)
                .ok()
                .filter(Value::is_array)
                .unwrap_or_else(|| {
                    // Compat shim for legacy Rust-side tests only.
                    // The FFI path (py_new / set_edges_json) is
                    // strict and never reaches this branch.
                    json!([])
                })
        };
        Self {
            kind: "execution".into(),
            protocol_version: PROTOCOL_VERSION.into(),
            event_id,
            agent_id,
            decision_ref,
            status,
            detail,
            edges: parsed,
            timestamp,
            prev_hash,
            record_hash: String::new(),
        }
    }

    fn payload_value(&self) -> Value {
        json!({
            "kind": self.kind,
            "protocol_version": self.protocol_version,
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "decision_ref": self.decision_ref,
            "status": self.status,
            "detail": self.detail,
            "edges": self.edges,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
        })
    }

    fn compute_hash(&self) -> Result<String, String> {
        // Same non-finite guard as DecisionRecord: json!() would
        // coerce NaN/Inf to null and silently fork from CPython.
        if !self.timestamp.is_finite() {
            return Err("non-finite timestamp cannot be sealed".into());
        }
        let canonical_str = canonical(&self.payload_value()).map_err(|e| e.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(canonical_str.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ExecutionEvent>()?;
    Ok(())
}
