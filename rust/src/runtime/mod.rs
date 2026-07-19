pub mod canonical_json;
pub mod decision_record;
pub mod execution_record;
pub mod decision_graph;
pub mod decision_recorder;

use pyo3::prelude::*;

pub fn register(
    m: &Bound<'_, PyModule>,
) -> PyResult<()> {
    decision_record::register(m)?;
    execution_record::register(m)?;
    decision_graph::register(m)?;
    decision_recorder::register(m)?;
    Ok(())
}
