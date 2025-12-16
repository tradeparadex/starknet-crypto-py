use pyo3::prelude::*;
use starknet_crypto::{
    Felt, pedersen_hash as pedersen_hash_rs, rfc6979_generate_k as rfc6979_generate_k_rs,
    sign as sign_rs,
};

fn _fe_from_str(s: &str) -> Felt {
    Felt::from_hex_unchecked(s)
}

#[pyfunction]
fn rs_get_public_key(private_key: &str) -> PyResult<String> {
    let private_key: Felt = _fe_from_str(private_key);
    let public_key: String = starknet_crypto::get_public_key(&private_key).to_string();
    Ok(public_key)
}

#[pyfunction]
fn rs_pedersen_hash(left: &str, right: &str) -> PyResult<String> {
    let left: Felt = _fe_from_str(left);
    let right: Felt = _fe_from_str(right);
    let hash: String = pedersen_hash_rs(&left, &right).to_string();
    Ok(hash)
}

#[pyfunction]
fn rs_sign(priv_key: &str, msg_hash: &str, seed: &str) -> PyResult<(String, String)> {
    let msg_hash: Felt = _fe_from_str(msg_hash);
    let priv_key: Felt = _fe_from_str(priv_key);
    let seed: Felt = _fe_from_str(seed);
    let k: Felt = rfc6979_generate_k_rs(&msg_hash, &priv_key, Some(&seed));
    let hash: starknet_crypto::ExtendedSignature = sign_rs(&priv_key, &msg_hash, &k).unwrap();
    let r: String = hash.r.to_string();
    let s: String = hash.s.to_string();
    Ok((r, s))
}

#[pyfunction]
fn rs_verify(public_key: &str, msg_hash: &str, r: &str, s: &str) -> PyResult<bool> {
    let public_key: Felt = _fe_from_str(public_key);
    let message: Felt = _fe_from_str(msg_hash);
    let r: Felt = _fe_from_str(r);
    let s: Felt = _fe_from_str(s);
    let result: bool = starknet_crypto::verify(&public_key, &message, &r, &s).unwrap();
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
