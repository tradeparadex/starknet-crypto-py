use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use starknet_crypto::{
    FieldElement,
    pedersen_hash as pedersen_hash_rs,
    sign as sign_rs,
    rfc6979_generate_k as rfc6979_generate_k_rs,
    VerifyError,
};

fn _fe_from_str(s: &str) -> PyResult<FieldElement> {
    FieldElement::from_hex_be(s)
        .map_err(|e| PyValueError::new_err(format!("invalid field element: {e}")))
}

// The GIL is held on purpose: these calls take microseconds, and releasing it
// makes each one wait up to the interpreter switch interval to reacquire it
// whenever another Python thread is busy.

#[pyfunction]
fn rs_get_public_key(private_key: &str) -> PyResult<String> {
    let private_key: FieldElement = _fe_from_str(private_key)?;
    let public_key: String = starknet_crypto::get_public_key(&private_key).to_string();
    Ok(public_key)
}

#[pyfunction]
fn rs_pedersen_hash(left: &str, right: &str) -> PyResult<String> {
    let left: FieldElement = _fe_from_str(left)?;
    let right: FieldElement = _fe_from_str(right)?;
    let hash: String = pedersen_hash_rs(&left, &right).to_string();
    Ok(hash)
}

#[pyfunction]
fn rs_sign(priv_key: &str, msg_hash: &str, seed: &str) -> PyResult<(String, String)> {
    let msg_hash: FieldElement = _fe_from_str(msg_hash)?;
    let priv_key: FieldElement = _fe_from_str(priv_key)?;
    let seed: FieldElement = _fe_from_str(seed)?;
    let k: FieldElement = rfc6979_generate_k_rs(&msg_hash, &priv_key, Some(&seed));
    let hash: starknet_crypto::ExtendedSignature = sign_rs(&priv_key, &msg_hash, &k)
        .map_err(|e| PyValueError::new_err(format!("signing failed: {e}")))?;
    let r: String = hash.r.to_string();
    let s: String = hash.s.to_string();
    Ok((r, s))
}

#[pyfunction]
fn rs_verify(public_key: &str, msg_hash: &str, r: &str, s: &str) -> PyResult<bool> {
    let public_key: FieldElement = _fe_from_str(public_key)?;
    let message: FieldElement = _fe_from_str(msg_hash)?;
    let r: FieldElement = _fe_from_str(r)?;
    let s: FieldElement = _fe_from_str(s)?;
    // An out-of-range message hash, r or s means the signature is not valid,
    // not that the call was malformed; only an unusable public key raises.
    match starknet_crypto::verify(&public_key, &message, &r, &s) {
        Ok(result) => Ok(result),
        Err(
            VerifyError::InvalidMessageHash | VerifyError::InvalidR | VerifyError::InvalidS,
        ) => Ok(false),
        Err(e @ VerifyError::InvalidPublicKey) => {
            Err(PyValueError::new_err(format!("verification failed: {e}")))
        }
    }
}

// A Python module implemented in Rust
#[pymodule]
fn starknet_crypto_py(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(rs_pedersen_hash, m)?)?;
    m.add_function(wrap_pyfunction!(rs_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rs_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rs_get_public_key, m)?)?;
    Ok(())
}
