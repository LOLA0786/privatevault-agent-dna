use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    #[pyo3(get, set)]
    pub decision_id: String,

    #[pyo3(get, set)]
    pub agent_id: String,

    #[pyo3(get, set)]
    pub capability: String,

    #[pyo3(get, set)]
    pub decision: String,

    #[pyo3(get, set)]
    pub prev_hash: String,

    #[pyo3(get)]
    pub record_hash: String,
}

#[pymethods]
impl DecisionRecord {
    #[new]
    pub fn new(
        decision_id: String,
        agent_id: String,
        capability: String,
        decision: String,
        prev_hash: String,
    ) -> Self {
        Self {
            decision_id,
            agent_id,
            capability,
            decision,
            prev_hash,
            record_hash: String::new(),
        }
    }

    pub fn seal(&mut self) {
        self.record_hash = self.compute_hash();
    }

    pub fn verify(&self) -> bool {
        self.record_hash == self.compute_hash()
    }

    fn __repr__(&self) -> String {
        format!(
            "DecisionRecord(decision_id='{}', decision='{}')",
            self.decision_id,
            self.decision
        )
    }
}

impl DecisionRecord {
    fn compute_hash(&self) -> String {
        let payload = json!({
            "decision_id": self.decision_id,
            "agent_id": self.agent_id,
            "capability": self.capability,
            "decision": self.decision,
            "prev_hash": self.prev_hash,
        });

        let canonical = serde_json::to_string(&payload).unwrap();

        let mut h = Sha256::new();
        h.update(canonical.as_bytes());

        hex::encode(h.finalize())
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<DecisionRecord>()?;
    Ok(())
}
