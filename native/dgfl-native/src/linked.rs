//! Checked full Lego ciphertext/registered-key linkage and local point reuse.
//!
//! The Python caller pins the CRS and computes the existing Fiat--Shamir
//! challenge from the exact protocol transcript. No point or scalar supplied
//! on the wire is trusted here. Random weights are sampled only after every
//! wire element has been checked, and a failed batch is rechecked exactly.
use crate::{decode, encode, invalid};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use legogroth16::{verify_proof, PreparedVerifyingKey, Proof};
use pyo3::{prelude::*, types::PyBytes};
use rand::rngs::OsRng;
use rayon::{prelude::*, ThreadPool};
use std::sync::Arc;

pub(crate) struct WireLinked {
    pub f: Vec<u8>, pub g: Vec<u8>, pub h: Vec<u8>,
    pub ciphertext: Vec<Vec<u8>>, pub public: Vec<Vec<u8>>,
    pub first_ct: Vec<Vec<u8>>, pub first_key: Vec<Vec<u8>>,
    pub zx: Vec<Vec<u8>>, pub zs: Vec<Vec<u8>>, pub zk: Vec<Vec<u8>>,
    pub snark: Vec<u8>, pub norm: u64, pub commitment_a: Vec<u8>,
    pub commitment_response: Vec<u8>, pub challenge: Vec<u8>,
    pub binding: Vec<u8>, pub randomized: bool,
}

fn scalar(raw: &[u8]) -> PyResult<Fr> {
    if raw.len() != 32 { return Err(invalid("noncanonical linked scalar length")); }
    let value = Fr::from_be_bytes_mod_order(raw);
    let mut canonical = encode(&value); canonical.reverse();
    if canonical != raw { return Err(invalid("noncanonical linked scalar")); }
    Ok(value)
}

// Preserve the existing public-scalar centering before Ark's native MSM.
// Already-checked affine inputs are retained throughout this call.
fn msm(points: &[G1Affine], scalars: &[Fr]) -> G1Projective {
    debug_assert_eq!(points.len(), scalars.len());
    let mut half = Fr::MODULUS; half.div2();
    let mut bases = Vec::with_capacity(points.len());
    let mut centered = Vec::with_capacity(points.len());
    for (point, value) in points.iter().zip(scalars) {
        if value.into_bigint() > half {
            bases.push(-*point); centered.push(-*value);
        } else {
            bases.push(*point); centered.push(*value);
        }
    }
    G1Projective::msm_unchecked(&bases, &centered)
}

struct Row { ct: G1Affine, public: G1Affine, a_ct: G1Affine, a_key: G1Affine,
             zx: Fr, zs: Fr, zk: Fr }

fn deterministic(rows: &[Row], f: G1Affine, g: G1Affine, h: G1Affine,
                 challenge: Fr, bases: &[G1Affine], commitment_a: G1Affine,
                 d: G1Affine, commitment_response: Fr) -> bool {
    let check_row = |row: &Row| {
        msm(&[f, g, row.ct, row.a_ct], &[row.zs, row.zx, -challenge, -Fr::from(1u64)]).is_zero()
            && msm(&[g, h, row.public, row.a_key],
                   &[row.zs, row.zk, -challenge, -Fr::from(1u64)]).is_zero()
    };
    // Run only inside the verifier's bounded Rayon pool. Small proofs avoid
    // task overhead, while every coordinate relation remains independently
    // checked (there is no deterministic sum that could cancel bad rows).
    let valid = if rows.len() < 64 { rows.iter().all(check_row) }
                else { rows.par_iter().all(check_row) };
    if !valid { return false; }
    let mut points = bases.to_vec(); points.extend([d, commitment_a]);
    let mut values: Vec<Fr> = rows.iter().map(|row| row.zx).collect();
    values.extend([commitment_response, -challenge, -Fr::from(1u64)]);
    msm(&points, &values).is_zero()
}

fn weight() -> Fr {
    loop { let value = Fr::rand(&mut OsRng); if !value.is_zero() { return value; } }
}

fn randomized(rows: &[Row], f: G1Affine, g: G1Affine, h: G1Affine,
              challenge: Fr, bases: &[G1Affine], commitment_a: G1Affine,
              d: G1Affine, commitment_response: Fr) -> bool {
    let mut points = Vec::with_capacity(5 * rows.len() + 6);
    let mut scalars = Vec::with_capacity(points.capacity());
    let (mut cf, mut cg, mut ch) = (Fr::zero(), Fr::zero(), Fr::zero());
    for row in rows {
        // Fresh, independent nonzero weights for both original equations.
        let wc = weight(); let wk = weight();
        cf += wc * row.zs; cg += wc * row.zx + wk * row.zs; ch += wk * row.zk;
        points.extend([row.ct, row.a_ct, row.public, row.a_key]);
        scalars.extend([-wc * challenge, -wc, -wk * challenge, -wk]);
    }
    let opening = weight();
    points.extend_from_slice(bases);
    scalars.extend(rows.iter().map(|row| opening * row.zx));
    scalars.push(opening * commitment_response);
    points.extend([d, commitment_a, f, g, h]);
    scalars.extend([-opening * challenge, -opening, cf, cg, ch]);
    msm(&points, &scalars).is_zero()
}

/// A successful full verification's checked ciphertext, scoped to one exact
/// context/client/CRS/norm binding and wire ciphertext. There is deliberately
/// no Python constructor, serialization, or persistent cross-round cache.
#[pyclass(module = "dgfl_native", frozen)]
pub(crate) struct VerifiedLego {
    ciphertext: Vec<G1Affine>, wire_ciphertext: Vec<Vec<u8>>, binding: Vec<u8>,
    norm: u64, bits: usize, pool: Arc<ThreadPool>,
}

#[pymethods]
impl VerifiedLego {
    fn ciphertext_msm<'py>(&self, py: Python<'py>, binding: Vec<u8>,
                          ciphertext: Vec<Vec<u8>>, reference: Vec<i64>, norm: u64)
        -> PyResult<Bound<'py, PyBytes>>
    {
        let offset = 1i64 << (self.bits - 1);
        if binding.len() != 32 || binding != self.binding || norm != self.norm
            || ciphertext != self.wire_ciphertext || reference.len() != self.ciphertext.len()
            || reference.iter().any(|value| *value < -offset || *value >= offset)
        { return Err(invalid("verified Lego ciphertext/context/reference mismatch")); }
        let raw = py.allow_threads(|| self.pool.install(|| {
            let coefficients: Vec<Fr> = reference.iter().map(|value| {
                if *value < 0 { -Fr::from(value.unsigned_abs()) } else { Fr::from(*value as u64) }
            }).collect();
            encode(&msm(&self.ciphertext, &coefficients).into_affine())
        }));
        Ok(PyBytes::new(py, &raw))
    }
}

pub(crate) fn verify(wire: WireLinked, dimension: usize, bits: usize,
                     pvk: &PreparedVerifyingKey<Bls12_381>, bases: &[G1Affine],
                     pool: Arc<ThreadPool>) -> PyResult<Option<VerifiedLego>> {
    let n = dimension;
    let max_norm = (n as u64) * (1u64 << (bits - 1)).pow(2);
    if wire.binding.len() != 32 || wire.norm > max_norm || wire.snark.len() != 240
        || [&wire.ciphertext, &wire.public, &wire.first_ct, &wire.first_key,
            &wire.zx, &wire.zs, &wire.zk].iter().any(|values| values.len() != n)
    { return Err(invalid("linked proof dimension, norm or binding mismatch")); }
    let f: G1Affine = decode(&wire.f, 48)?;
    let g: G1Affine = decode(&wire.g, 48)?;
    let h: G1Affine = decode(&wire.h, 48)?;
    if f.is_zero() || g.is_zero() || h.is_zero() {
        return Err(invalid("degenerate linked public bases"));
    }
    let commitment_a: G1Affine = decode(&wire.commitment_a, 48)?;
    let commitment_response = scalar(&wire.commitment_response)?;
    let challenge = scalar(&wire.challenge)?;
    let proof: Proof<Bls12_381> = decode(&wire.snark, 240)?;
    let parse_row = |index: usize| -> PyResult<Row> {
        Ok(Row { ct: decode(&wire.ciphertext[index], 48)?,
                 public: decode(&wire.public[index], 48)?,
                 a_ct: decode(&wire.first_ct[index], 48)?,
                 a_key: decode(&wire.first_key[index], 48)?,
                 zx: scalar(&wire.zx[index])?, zs: scalar(&wire.zs[index])?,
                 zk: scalar(&wire.zk[index])? })
    };
    let rows: Vec<Row> = if n < 64 { (0..n).map(parse_row).collect::<PyResult<_>>()? }
                        else { (0..n).into_par_iter().map(parse_row).collect::<PyResult<_>>()? };
    // All wire points, including every A/B/C/D SNARK point, and all scalars
    // have now been checked. No random verifier coefficient exists earlier.
    if verify_proof(pvk, &proof, &[Fr::from(wire.norm)]).is_err() { return Ok(None); }
    let exact = || deterministic(&rows, f, g, h, challenge, bases,
                                 commitment_a, proof.d, commitment_response);
    let accepted = if wire.randomized {
        randomized(&rows, f, g, h, challenge, bases, commitment_a, proof.d,
                   commitment_response) || exact()
    } else { exact() };
    if !accepted { return Ok(None); }
    Ok(Some(VerifiedLego { ciphertext: rows.into_iter().map(|row| row.ct).collect(),
        wire_ciphertext: wire.ciphertext, binding: wire.binding,
        norm: wire.norm, bits, pool }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fq;

    fn honest() -> (Vec<Row>, G1Affine, G1Affine, G1Affine, Fr, Vec<G1Affine>, G1Affine, G1Affine, Fr) {
        let g = G1Affine::generator();
        let f = (g * Fr::from(7u64)).into_affine();
        let h = (g * Fr::from(11u64)).into_affine();
        let challenge = Fr::from(13u64);
        let bases: Vec<_> = [17u64, 19, 23, 29].iter()
            .map(|value| (g * Fr::from(*value)).into_affine()).collect();
        let mut rows = Vec::new();
        let mut values = Vec::new(); let mut nonces = Vec::new();
        for index in 0..3u64 {
            let x = Fr::from(index + 2); let s = Fr::from(index + 5); let k = Fr::from(index + 8);
            let a = Fr::from(index + 31); let u = Fr::from(index + 37); let v = Fr::from(index + 41);
            rows.push(Row { ct: (f * s + g * x).into_affine(), public: (g * s + h * k).into_affine(),
                a_ct: (f * u + g * a).into_affine(), a_key: (g * u + h * v).into_affine(),
                zx: a + challenge * x, zs: u + challenge * s, zk: v + challenge * k });
            values.push(x); nonces.push(a);
        }
        let blind = Fr::from(43u64); let nonce = Fr::from(47u64);
        values.push(blind); nonces.push(nonce);
        let d = msm(&bases, &values).into_affine();
        let a = msm(&bases, &nonces).into_affine();
        (rows, f, g, h, challenge, bases, a, d, nonce + challenge * blind)
    }

    #[test]
    fn complete_linkage_and_shared_opening_agree() {
        let (mut rows, f, g, h, e, bases, a, d, zr) = honest();
        assert!(deterministic(&rows, f, g, h, e, &bases, a, d, zr));
        assert!(randomized(&rows, f, g, h, e, &bases, a, d, zr));
        // A valid coordinate linkage cannot replace its committed witness.
        let changed_d = (d + g).into_affine();
        assert!(!deterministic(&rows, f, g, h, e, &bases, a, changed_d, zr));
        assert!(!randomized(&rows, f, g, h, e, &bases, a, changed_d, zr));
        rows[1].zs += Fr::from(1u64);
        assert!(!deterministic(&rows, f, g, h, e, &bases, a, d, zr));
        assert!(!randomized(&rows, f, g, h, e, &bases, a, d, zr));
    }

    #[test]
    fn deterministic_rows_cannot_cancel_each_other() {
        let (mut rows, f, g, h, e, bases, a, d, zr) = honest();
        rows[0].a_ct = (rows[0].a_ct + g).into_affine();
        rows[1].a_ct = (rows[1].a_ct - g).into_affine();
        assert!(!deterministic(&rows, f, g, h, e, &bases, a, d, zr));
        assert!(!randomized(&rows, f, g, h, e, &bases, a, d, zr));
    }

    #[test]
    fn wire_checks_reject_noncanonical_scalars_and_torsion() {
        assert!(scalar(&[0u8; 31]).is_err());
        assert!(scalar(&Fr::MODULUS.to_bytes_be()).is_err());
        assert_eq!(scalar(&[0u8; 32]).unwrap(), Fr::zero());
        let torsion = G1Affine::new_unchecked(Fq::zero(), Fq::from(2u64));
        assert!(torsion.is_on_curve());
        assert!(!torsion.is_in_correct_subgroup_assuming_on_curve());
        assert!(decode::<G1Affine>(&encode(&torsion), 48).is_err());
    }
}
