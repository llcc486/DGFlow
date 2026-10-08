//! Batched first messages for the ciphertext/registered-key Sigma relations.
//!
//! This research prover uses the same variable-time arkworks multiplication
//! family as the existing Python backend. It makes no constant-time claim and
//! introduces no secret-indexed fixed-base table or retained nonce cache.
//! Network bases and big-endian scalar encodings are checked before arithmetic.

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};

const MAX_DIMENSION: usize = 20_000;
const MAX_WORKERS: usize = 4;
type EncodedMessages = (Vec<Vec<u8>>, Vec<Vec<u8>>);

fn encode<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut raw = Vec::new();
    value.serialize_compressed(&mut raw).expect("serialization to Vec cannot fail");
    raw
}

fn checked_base(raw: &[u8]) -> Result<G1Affine, &'static str> {
    if raw.len() != 48 {
        return Err("noncanonical G1 encoding length");
    }
    let point = G1Affine::deserialize_compressed(raw)
        .map_err(|_| "invalid G1 encoding or subgroup")?;
    if point.is_zero() || encode(&point) != raw {
        return Err("invalid or noncanonical Sigma base");
    }
    Ok(point)
}

fn checked_scalar(raw: &[u8]) -> Result<Fr, &'static str> {
    if raw.len() != 32 {
        return Err("noncanonical scalar length");
    }
    let value = Fr::from_be_bytes_mod_order(raw);
    let mut canonical = encode(&value);
    canonical.reverse();
    if canonical != raw {
        return Err("noncanonical scalar outside field");
    }
    Ok(value)
}

fn messages_for_chunk(
    f: G1Affine,
    g: G1Affine,
    h: G1Affine,
    a: &[Fr],
    u: &[Fr],
    v: &[Fr],
) -> (Vec<G1Projective>, Vec<G1Projective>) {
    let mut ct = Vec::with_capacity(a.len());
    let mut key = Vec::with_capacity(a.len());
    for ((a, u), v) in a.iter().zip(u).zip(v) {
        ct.push(f.mul_bigint(u.into_bigint()) + g.mul_bigint(a.into_bigint()));
        key.push(g.mul_bigint(u.into_bigint()) + h.mul_bigint(v.into_bigint()));
    }
    (ct, key)
}

fn first_messages(
    f: &[u8],
    g: &[u8],
    h: &[u8],
    a_raw: &[Vec<u8>],
    u_raw: &[Vec<u8>],
    v_raw: &[Vec<u8>],
    workers: usize,
) -> Result<EncodedMessages, &'static str> {
    let count = a_raw.len();
    if count == 0 || count > MAX_DIMENSION || u_raw.len() != count || v_raw.len() != count {
        return Err("invalid Sigma dimensions");
    }
    if !(1..=MAX_WORKERS).contains(&workers) {
        return Err("Sigma workers must be between 1 and 4");
    }
    let f = checked_base(f)?;
    let g = checked_base(g)?;
    let h = checked_base(h)?;
    let a = a_raw.iter().map(|x| checked_scalar(x)).collect::<Result<Vec<_>, _>>()?;
    let u = u_raw.iter().map(|x| checked_scalar(x)).collect::<Result<Vec<_>, _>>()?;
    let v = v_raw.iter().map(|x| checked_scalar(x)).collect::<Result<Vec<_>, _>>()?;
    let available = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let workers = workers.min(count).min(available);
    let (ct, key) = if workers == 1 {
        messages_for_chunk(f, g, h, &a, &u, &v)
    } else {
        std::thread::scope(|scope| {
            let chunk = (count + workers - 1) / workers;
            let mut handles = Vec::with_capacity(workers);
            for start in (0..count).step_by(chunk) {
                let end = (start + chunk).min(count);
                let a = &a[start..end];
                let u = &u[start..end];
                let v = &v[start..end];
                handles.push(scope.spawn(move || messages_for_chunk(f, g, h, a, u, v)));
            }
            let mut ct = Vec::with_capacity(count);
            let mut key = Vec::with_capacity(count);
            // Join in the input order so scheduling never changes the transcript.
            for handle in handles {
                let (ct_chunk, key_chunk) = handle.join().map_err(|_| "Sigma worker failed")?;
                ct.extend(ct_chunk);
                key.extend(key_chunk);
            }
            Ok::<_, &'static str>((ct, key))
        })?
    };
    // Keep projective points in Rust; pay one inversion for all output points.
    let affine = G1Projective::normalize_batch(&[ct, key].concat());
    let ct_raw = affine[..count].iter().map(encode).collect();
    let key_raw = affine[count..].iter().map(encode).collect();
    Ok((ct_raw, key_raw))
}

/// A_ct[j] = f*u[j] + G*a[j]; A_key[j] = G*u[j] + H*v[j].
/// Scalars are canonical 32-byte big-endian values; outputs are checked-
/// compatible canonical 48-byte compressed G1 encodings in input order.
#[pyfunction]
#[pyo3(signature = (f, g, h, a, u, v, workers=1))]
pub fn sigma_first_messages(
    py: Python<'_>,
    f: Vec<u8>,
    g: Vec<u8>,
    h: Vec<u8>,
    a: Vec<Vec<u8>>,
    u: Vec<Vec<u8>>,
    v: Vec<Vec<u8>>,
    workers: usize,
) -> PyResult<(Vec<Py<PyBytes>>, Vec<Py<PyBytes>>)> {
    let (ct, key) = py.allow_threads(|| first_messages(&f, &g, &h, &a, &u, &v, workers))
        .map_err(PyValueError::new_err)?;
    Ok((
        ct.iter().map(|raw| PyBytes::new(py, raw).unbind()).collect(),
        key.iter().map(|raw| PyBytes::new(py, raw).unbind()).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fq;
    use ark_ff::{BigInteger, Zero};

    fn scalar(value: u64) -> Vec<u8> {
        let mut raw = encode(&Fr::from(value));
        raw.reverse();
        raw
    }

    fn bases() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let g = G1Affine::generator();
        (encode(&(g * Fr::from(7u64)).into_affine()), encode(&g),
         encode(&(g * Fr::from(11u64)).into_affine()))
    }

    #[test]
    fn messages_match_relations_and_parallel_order() {
        let (f_raw, g_raw, h_raw) = bases();
        let a = [0, 1, 19, 100_000, u64::MAX].map(scalar).to_vec();
        let u = [9, 0, 31, u64::MAX, 87].map(scalar).to_vec();
        let v = [10, 14, 0, 73, 89].map(scalar).to_vec();
        let serial = first_messages(&f_raw, &g_raw, &h_raw, &a, &u, &v, 1).unwrap();
        let parallel = first_messages(&f_raw, &g_raw, &h_raw, &a, &u, &v, 4).unwrap();
        assert_eq!(serial, parallel);
        let f = checked_base(&f_raw).unwrap();
        let g = checked_base(&g_raw).unwrap();
        let h = checked_base(&h_raw).unwrap();
        for i in 0..a.len() {
            let a = checked_scalar(&a[i]).unwrap();
            let u = checked_scalar(&u[i]).unwrap();
            let v = checked_scalar(&v[i]).unwrap();
            assert_eq!(serial.0[i], encode(&(f * u + g * a).into_affine()));
            assert_eq!(serial.1[i], encode(&(g * u + h * v).into_affine()));
        }
    }

    #[test]
    fn reject_noncanonical_inputs_and_subgroup_points() {
        let (f, g, h) = bases();
        let s = vec![scalar(1)];
        assert!(first_messages(&f, &g, &h, &s, &[], &s, 1).is_err());
        assert!(first_messages(&f, &g, &h, &[], &[], &[], 1).is_err());
        assert!(first_messages(&f, &g, &h, &s, &s, &s, 0).is_err());
        assert!(first_messages(&f, &g, &h, &s, &s, &s, 5).is_err());
        assert!(checked_scalar(&[0u8; 31]).is_err());
        assert!(checked_scalar(&Fr::MODULUS.to_bytes_be()).is_err());
        assert!(checked_base(&[0u8; 47]).is_err());
        assert!(checked_base(&[255u8; 48]).is_err());
        assert!(checked_base(&encode(&G1Affine::identity())).is_err());
        let torsion = G1Affine::new_unchecked(Fq::zero(), Fq::from(2u64));
        assert!(torsion.is_on_curve());
        assert!(!torsion.is_in_correct_subgroup_assuming_on_curve());
        assert!(checked_base(&encode(&torsion)).is_err());
    }
}
