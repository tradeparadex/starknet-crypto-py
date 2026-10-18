use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use starknet_crypto::{
    FieldElement,
    pedersen_hash as pedersen_hash_rs,
    sign as sign_rs,
    rfc6979_generate_k as rfc6979_generate_k_rs,
};

fn _fe_from_str(s: &str) -> PyResult<FieldElement> {
    FieldElement::from_hex_be(s)
        .map_err(|e| PyValueError::new_err(format!("invalid field element {s:?}: {e}")))
}

#[pyfunction]
fn rs_get_public_key(py: Python<'_>, private_key: &str) -> PyResult<String> {
    let private_key: FieldElement = _fe_from_str(private_key)?;
    let public_key: String = py.detach(|| starknet_crypto::get_public_key(&private_key).to_string());
    Ok(public_key)
}

#[pyfunction]
fn rs_pedersen_hash(py: Python<'_>, left: &str, right: &str) -> PyResult<String> {
    let left: FieldElement = _fe_from_str(left)?;
    let right: FieldElement = _fe_from_str(right)?;
    let hash: String = py.detach(|| pedersen_hash_rs(&left, &right).to_string());
    Ok(hash)
}

#[pyfunction]
fn rs_sign(py: Python<'_>, priv_key: &str, msg_hash: &str, seed: &str) -> PyResult<(String, String)> {
    let msg_hash: FieldElement = _fe_from_str(msg_hash)?;
    let priv_key: FieldElement = _fe_from_str(priv_key)?;
    let seed: FieldElement = _fe_from_str(seed)?;
    let hash: starknet_crypto::ExtendedSignature = py
        .detach(|| {
            let k: FieldElement = rfc6979_generate_k_rs(&msg_hash, &priv_key, Some(&seed));
            sign_rs(&priv_key, &msg_hash, &k)
        })
        .map_err(|e| PyValueError::new_err(format!("signing failed: {e}")))?;
    let r: String = hash.r.to_string();
    let s: String = hash.s.to_string();
    Ok((r, s))
}

#[pyfunction]
fn rs_verify(py: Python<'_>, public_key: &str, msg_hash: &str, r: &str, s: &str) -> PyResult<bool> {
    let public_key: FieldElement = _fe_from_str(public_key)?;
    let message: FieldElement = _fe_from_str(msg_hash)?;
    let r: FieldElement = _fe_from_str(r)?;
    let s: FieldElement = _fe_from_str(s)?;
    let result: bool = py
        .detach(|| starknet_crypto::verify(&public_key, &message, &r, &s))
        .map_err(|e| PyValueError::new_err(format!("verification failed: {e}")))?;
    Ok(result)
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
