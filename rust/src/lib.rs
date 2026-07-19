mod errors;
mod runtime;
mod signer;

use pyo3::prelude::*;

#[pyfunction]
fn hello() -> String {
    "PrivateVault Rust Runtime Loaded".to_string()
}

#[pymodule]
fn pv_runtime(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello, m)?)?;

    signer::register(m)?;
    runtime::register(m)?;

    Ok(())
}
