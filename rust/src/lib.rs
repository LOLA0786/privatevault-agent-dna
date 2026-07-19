//! Enforcement-path panic ban: a panic in this crate crosses the
//! FFI as PyPanicException -- a crash, not a BLOCK. Fail-closed means
//! errors are VALUES here. Integration tests (tests/) are a separate
//! crate and may unwrap freely.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unimplemented)]
#![deny(clippy::todo)]

mod errors;
pub mod runtime;
pub mod signer;

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
