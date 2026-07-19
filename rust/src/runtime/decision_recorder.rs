//! DecisionRecorder -- per-agent chain state, in-memory.
//!
//! Unchanged semantics: prev_hash is OWNED by the recorder (caller
//! values are overwritten -- the chain head is not caller-supplied),
//! genesis is 64 zeros, one chain per agent_id.
//!
//! Changed: record() now propagates seal errors instead of the seal
//! being infallible. Chain state advances ONLY on successful seal --
//! a failed seal leaves the chain head untouched.

use pyo3::prelude::*;

use std::collections::HashMap;

use crate::runtime::decision_record::DecisionRecord;

const GENESIS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone)]
struct ChainState {
    last_decision_id: Option<String>,
    last_hash: String,
}

#[pyclass]
pub struct DecisionRecorder {
    chains: HashMap<String, ChainState>,
}

#[pymethods]
impl DecisionRecorder {
    #[new]
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
        }
    }

    pub fn record(
        &mut self,
        mut record: PyRefMut<'_, DecisionRecord>,
    ) -> PyResult<()> {
        let head = self
            .chains
            .get(&record.agent_id)
            .map(|c| c.last_hash.clone())
            .unwrap_or_else(|| GENESIS.to_string());

        record.prev_hash = head;
        record.seal()?; // on failure: chain state NOT advanced

        let sealed_hash = record.record_hash.clone();
        let decision_id = record.decision_id.clone();

        self.chains.insert(
            record.agent_id.clone(),
            ChainState {
                last_decision_id: Some(decision_id),
                last_hash: sealed_hash,
            },
        );
        Ok(())
    }

    /// Current chain head hash for an agent (genesis if unseen).
    pub fn chain_head(&self, agent_id: &str) -> String {
        self.chains
            .get(agent_id)
            .map(|c| c.last_hash.clone())
            .unwrap_or_else(|| GENESIS.to_string())
    }

    /// Last recorded decision_id for an agent, if any.
    pub fn last_decision_id(&self, agent_id: &str) -> Option<String> {
        self.chains
            .get(agent_id)
            .and_then(|c| c.last_decision_id.clone())
    }
}

impl Default for DecisionRecorder {
    fn default() -> Self {
        Self::new()
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<DecisionRecorder>()?;
    Ok(())
}
