use pyo3::PyErr;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    #[error("invalid signing key")]
    InvalidSigningKey,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("{0}")]
    Internal(String),
}

impl From<RuntimeError> for PyErr {
    fn from(err: RuntimeError) -> Self {
        match err {
            RuntimeError::InvalidHex(e) => PyValueError::new_err(e),
            RuntimeError::InvalidSigningKey => PyRuntimeError::new_err("invalid signing key"),
            RuntimeError::InvalidPublicKey => PyRuntimeError::new_err("invalid public key"),
            RuntimeError::InvalidSignature => PyRuntimeError::new_err("invalid signature"),
            RuntimeError::Internal(e) => PyRuntimeError::new_err(e),
        }
    }
}
