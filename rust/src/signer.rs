use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rand_core::OsRng;

#[pyclass]
pub struct RustReceiptSigner {
    signing_key: SigningKey,
    public_key_hex: String,
}

#[pymethods]
impl RustReceiptSigner {
    #[new]
    fn new(seed_hex: &str) -> PyResult<Self> {
        let seed =
            hex::decode(seed_hex)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;

        if seed.len() != 32 {
            return Err(PyValueError::new_err(
                "Signing key must be exactly 32 bytes.",
            ));
        }

        let signing_key = SigningKey::from_bytes(
            &seed
                .try_into()
                .map_err(|_| PyRuntimeError::new_err("invalid signing key"))?,
        );

        let public_key_hex =
            hex::encode(signing_key.verifying_key().to_bytes());

        Ok(Self {
            signing_key,
            public_key_hex,
        })
    }

    fn sign_hash(&self, hash_hex: &str) -> String {
        let sig = self.signing_key.sign(hash_hex.as_bytes());

        hex::encode(sig.to_bytes())
    }

    #[getter]
    fn public_key(&self) -> String {
        self.public_key_hex.clone()
    }
}

#[pyfunction]
fn generate_keypair(py: Python<'_>) -> PyResult<PyObject> {
    let signing_key = SigningKey::generate(&mut OsRng);

    let dict = pyo3::types::PyDict::new(py);

    dict.set_item(
        "signing_key",
        hex::encode(signing_key.to_bytes()),
    )?;

    dict.set_item(
        "public_key",
        hex::encode(signing_key.verifying_key().to_bytes()),
    )?;

    Ok(dict.into())
}

#[pyfunction]
fn verify_signature(
    public_key_hex: &str,
    hash_hex: &str,
    signature_hex: &str,
) -> PyResult<bool> {
    let pk =
        hex::decode(public_key_hex)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let sig =
        hex::decode(signature_hex)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let verify_key = VerifyingKey::from_bytes(
        &pk.try_into()
            .map_err(|_| PyRuntimeError::new_err("invalid public key"))?,
    )
    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    let signature = Signature::from_bytes(
        &sig.try_into()
            .map_err(|_| PyRuntimeError::new_err("invalid signature"))?,
    );

    Ok(
        verify_key
            .verify(hash_hex.as_bytes(), &signature)
            .is_ok(),
    )
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RustReceiptSigner>()?;

    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;

    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;

    Ok(())
}
