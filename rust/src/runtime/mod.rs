pub mod canonical_json;
pub mod decision_record;

use pyo3::prelude::*;

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    decision_record::register(m)?;
    Ok(())
}
