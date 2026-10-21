use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use starknet_crypto::{
    Felt,
    pedersen_hash as pedersen_hash_rs,
    sign as sign_rs,
    rfc6979_generate_k as rfc6979_generate_k_rs,
    VerifyError,
};
use starknet_curve::curve_params::{ALPHA, BETA, EC_ORDER, GENERATOR};
use starknet_types_core::curve::{AffinePoint, ProjectivePoint};
use starknet_types_core::felt::NonZeroFelt;

const EC_ORDER_NZ: NonZeroFelt = NonZeroFelt::from_felt_unchecked(EC_ORDER);

// Parses big-endian hex the way starknet-ff's `FieldElement::from_hex_be` did.
// `Felt::from_hex` reduces values >= the field prime instead of rejecting
// them, so the range check is done here. Errors never include the input.
fn _fe_from_str(s: &str) -> PyResult<Felt> {
    let invalid = |reason: &str| PyValueError::new_err(format!("invalid field element: {reason}"));

    let digits = s.trim_start_matches("0x").as_bytes();
    if digits.len() > 64 {
        return Err(invalid("number out of range"));
    }
    let mut padded = [b'0'; 64];
    padded[64 - digits.len()..].copy_from_slice(digits);

    let mut bytes = [0u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(padded.chunks_exact(2)) {
        let (Some(hi), Some(lo)) = (char::from(pair[0]).to_digit(16), char::from(pair[1]).to_digit(16))
        else {
            return Err(invalid("invalid character"));
        };
        *byte = ((hi << 4) | lo) as u8;
    }

    if bytes > Felt::MAX.to_bytes_be() {
        return Err(invalid("number out of range"));
    }
    Ok(Felt::from_bytes_be(&bytes))
}

// The GIL is held on purpose: these calls take microseconds, and releasing it
// makes each one wait up to the interpreter switch interval to reacquire it
// whenever another Python thread is busy.

#[pyfunction]
fn rs_get_public_key(private_key: &str) -> PyResult<String> {
    let private_key: Felt = _fe_from_str(private_key)?;
    // k*G is the point at infinity when k is a multiple of the curve order,
    // i.e. 0 or EC_ORDER in the field. starknet-crypto 0.8 panics there (and
    // panic = "abort" would kill the interpreter); 0.6 returned 0 for key 0.
    if private_key == Felt::ZERO || private_key == EC_ORDER {
        return Ok(Felt::ZERO.to_string());
    }
    let public_key: String = starknet_crypto::get_public_key(&private_key).to_string();
    Ok(public_key)
}

#[pyfunction]
fn rs_pedersen_hash(left: &str, right: &str) -> PyResult<String> {
    let left: Felt = _fe_from_str(left)?;
    let right: Felt = _fe_from_str(right)?;
    let hash: String = pedersen_hash_rs(&left, &right).to_string();
    Ok(hash)
}

#[pyfunction]
fn rs_sign(priv_key: &str, msg_hash: &str, seed: &str) -> PyResult<(String, String)> {
    let msg_hash: Felt = _fe_from_str(msg_hash)?;
    let priv_key: Felt = _fe_from_str(priv_key)?;
    let seed: Felt = _fe_from_str(seed)?;
    let k: Felt = rfc6979_generate_k_rs(&msg_hash, &priv_key, Some(&seed));
    let hash: starknet_crypto::ExtendedSignature = sign_rs(&priv_key, &msg_hash, &k)
        .map_err(|e| PyValueError::new_err(format!("signing failed: {e}")))?;
    let r: String = hash.r.to_string();
    let s: String = hash.s.to_string();
    Ok((r, s))
}

#[pyfunction]
fn rs_verify(public_key: &str, msg_hash: &str, r: &str, s: &str) -> PyResult<bool> {
    let public_key: Felt = _fe_from_str(public_key)?;
    let message: Felt = _fe_from_str(msg_hash)?;
    let r: Felt = _fe_from_str(r)?;
    let s: Felt = _fe_from_str(s)?;
    // An out-of-range message hash, r or s means the signature is not valid,
    // not that the call was malformed; only an unusable public key raises.
    match _verify(&public_key, &message, &r, &s) {
        Ok(result) => Ok(result),
        Err(
            VerifyError::InvalidMessageHash | VerifyError::InvalidR | VerifyError::InvalidS,
        ) => Ok(false),
        Err(e @ VerifyError::InvalidPublicKey) => {
            Err(PyValueError::new_err(format!("verification failed: {e}")))
        }
    }
}

// Same steps as `starknet_crypto::verify` 0.8.1, which unwraps `to_affine()`
// and so panics when zw*G +/- rw*Q is the point at infinity; inputs can force
// that. Such a signature is reported as invalid, as 0.6 did.
fn _verify(public_key: &Felt, message: &Felt, r: &Felt, s: &Felt) -> Result<bool, VerifyError> {
    if message >= &Felt::ELEMENT_UPPER_BOUND {
        return Err(VerifyError::InvalidMessageHash);
    }
    if r == &Felt::ZERO || r >= &Felt::ELEMENT_UPPER_BOUND {
        return Err(VerifyError::InvalidR);
    }
    if s == &Felt::ZERO || s >= &Felt::ELEMENT_UPPER_BOUND {
        return Err(VerifyError::InvalidS);
    }

    let y = (public_key.square() * public_key + ALPHA * public_key + BETA)
        .sqrt()
        .ok_or(VerifyError::InvalidPublicKey)?;
    let full_public_key =
        AffinePoint::new(*public_key, y).map_err(|_| VerifyError::InvalidPublicKey)?;

    // Unlike upstream, a zero message hash never verifies: StarkWare's
    // crypto-cpp rejects it, and so did 0.6. Checked after the public key so an
    // invalid key still raises, as it did in 0.6.
    if message == &Felt::ZERO {
        return Err(VerifyError::InvalidMessageHash);
    }

    let w = s.mod_inverse(&EC_ORDER_NZ).ok_or(VerifyError::InvalidS)?;
    if w == Felt::ZERO || w >= Felt::ELEMENT_UPPER_BOUND {
        return Err(VerifyError::InvalidS);
    }

    let zw = message.mul_mod(&w, &EC_ORDER_NZ);
    let zw_g = _mul_by_bits(&GENERATOR, &zw);

    let rw = r.mul_mod(&w, &EC_ORDER_NZ);
    let rw_q = _mul_by_bits(&full_public_key, &rw);

    let x_is_r = |point: ProjectivePoint| point.to_affine().is_ok_and(|p| p.x() == *r);
    Ok(x_is_r(&zw_g + &rw_q) || x_is_r(&zw_g - &rw_q))
}

fn _mul_by_bits(point: &AffinePoint, scalar: &Felt) -> ProjectivePoint {
    &ProjectivePoint::from_affine_unchecked(point.x(), point.y()) * *scalar
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
