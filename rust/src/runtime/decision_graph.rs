use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use std::collections::HashMap;

use crate::runtime::decision_record::DecisionRecord;

#[pyclass]
pub struct DecisionGraph {
    records: HashMap<String, Py<DecisionRecord>>,
    order: Vec<String>,
    children: HashMap<String, Vec<String>>,
    by_agent: HashMap<String, Vec<String>>,
    by_capability: HashMap<String, Vec<String>>,
    by_decision: HashMap<String, Vec<String>>,
}

#[pymethods]
impl DecisionGraph {

    #[new]
    pub fn new() -> Self {

        Self {
            records: HashMap::new(),
            order: Vec::new(),
            children: HashMap::new(),
            by_agent: HashMap::new(),
            by_capability: HashMap::new(),
            by_decision: HashMap::new(),
        }
    }

    pub fn add(
        &mut self,
        py: Python<'_>,
        record: Py<DecisionRecord>,
    ) -> PyResult<()> {

        let rec = record.borrow(py);

        if !rec.verify() {
            return Err(
                PyValueError::new_err(
                    "record is not sealed"
                )
            );
        }

        if self.records.contains_key(&rec.decision_id) {
            return Err(
                PyValueError::new_err(
                    "duplicate decision_id"
                )
            );
        }

        if let Some(parent) = &rec.parent_decision {

            if !self.records.contains_key(parent) {

                return Err(
                    PyValueError::new_err(
                        "parent decision missing"
                    )
                );
            }

            self.children
                .entry(parent.clone())
                .or_default()
                .push(rec.decision_id.clone());
        }

        self.by_agent
            .entry(rec.agent_id.clone())
            .or_default()
            .push(rec.decision_id.clone());

        self.by_capability
            .entry(rec.capability.clone())
            .or_default()
            .push(rec.decision_id.clone());

        self.by_decision
            .entry(rec.decision.clone())
            .or_default()
            .push(rec.decision_id.clone());

        self.order.push(rec.decision_id.clone());

        self.records
            .insert(rec.decision_id.clone(), record.clone_ref(py));

        Ok(())
    }

    pub fn get(
        &self,
        py: Python<'_>,
        decision_id: String,
    ) -> PyResult<Py<DecisionRecord>> {

        self.records
            .get(&decision_id)
            .map(|r| r.clone_ref(py))
            .ok_or_else(|| {
                PyValueError::new_err(
                    "decision not found"
                )
            })
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn __repr__(&self) -> String {

        format!(
            "DecisionGraph(records={})",
            self.records.len()
        )
    }
}

impl Default for DecisionGraph {
    fn default() -> Self {
        Self::new()
    }
}

pub fn register(
    m: &Bound<'_, PyModule>,
) -> PyResult<()> {

    m.add_class::<DecisionGraph>()?;

    Ok(())
}
