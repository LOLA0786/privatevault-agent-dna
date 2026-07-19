//! Ed25519 receipt signer.
//!
//! Rule 1 (drp-spec SIGNING.md): sign the record_hash ASCII hex
//! bytes, never a re-canonicalized body. Ed25519 is deterministic
//! (RFC 8032), so for the same seed + hash this produces signatures
//! byte-identical to the PyNaCl implementation -- proven by
//! tests/test_rust_signer_parity.py.
//!
//! Key hygiene: the decoded seed is held in a Zeroizing buffer and
//! wiped on drop, on BOTH the success and error paths. The SigningKey
//! itself is zeroized on drop by ed25519-dalek (zeroize feature).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rand_core::OsRng;
use zeroize::Zeroizing;

#[pyclass]
pub struct RustReceiptSigner {
    signing_key: SigningKey,
    public_key_hex: String,
}

#[pymethods]
impl RustReceiptSigner {
    #[new]
    fn new(seed_hex: &str) -> PyResult<Self> {
        let seed = Zeroizing::new(
            hex::decode(seed_hex)
                .map_err(|e| PyValueError::new_err(e.to_string()))?,
        );

        if seed.len() != 32 {
            return Err(PyValueError::new_err(
                "Signing key must be exactly 32 bytes.",
            ));
        }

        let mut seed_arr = Zeroizing::new([0u8; 32]);
        seed_arr.copy_from_slice(&seed);

        let signing_key = SigningKey::from_bytes(&seed_arr);

        let public_key_hex =
            hex::encode(signing_key.verifying_key().to_bytes());

        Ok(Self {
            signing_key,
            public_key_hex,
        })
    }

    /// Sign a hex-encoded hash. Releases the GIL: signing is pure
    /// Rust compute and must not serialize the Python process.
    fn sign_hash(&self, py: Python<'_>, hash_hex: &str) -> String {
        py.detach(|| {
            let sig = self.signing_key.sign(hash_hex.as_bytes());
            hex::encode(sig.to_bytes())
        })
    }

    #[getter]
    fn public_key(&self) -> String {
        self.public_key_hex.clone()
    }
}

#[pyfunction]
fn generate_keypair(py: Python<'_>) -> PyResult<Py<pyo3::types::PyDict>> {
    let signing_key = SigningKey::generate(&mut OsRng);

    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("signing_key", hex::encode(signing_key.to_bytes()))?;
    dict.set_item(
        "public_key",
        hex::encode(signing_key.verifying_key().to_bytes()),
    )?;
    Ok(dict.unbind())
}

#[pyfunction]
fn verify_signature(
    py: Python<'_>,
    public_key_hex: &str,
    hash_hex: &str,
    signature_hex: &str,
) -> PyResult<bool> {
    let pk = hex::decode(public_key_hex)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let sig = hex::decode(signature_hex)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let pk_arr: [u8; 32] = pk
        .try_into()
        .map_err(|_| PyRuntimeError::new_err("invalid public key"))?;
    let sig_arr: [u8; 64] = sig
        .try_into()
        .map_err(|_| PyRuntimeError::new_err("invalid signature"))?;

    let verify_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let signature = Signature::from_bytes(&sig_arr);

    let hash = hash_hex.to_owned();
    Ok(py.detach(move || {
        verify_key.verify(hash.as_bytes(), &signature).is_ok()
    }))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RustReceiptSigner>()?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    Ok(())
}
