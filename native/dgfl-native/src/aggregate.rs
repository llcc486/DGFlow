//! Exact, checked aggregate pairing-image proof verification.
//!
//! Every original coordinate equation is evaluated independently. The local
//! polynomial handle retains checked coefficients and trusted DKG anchors;
//! it has no Python constructor, serialization or persistent-cache API.
//! The 4-bit GT table is indexed only by PUBLIC verification responses.
//! Generic NativeGT::pow_bytes and all secret/prover arithmetic are unchanged.
use crate::{decode, encode, invalid, NativeGT};
use ark_bls12_381::{Fq12, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, CyclotomicMultSubgroup, Field, One, PrimeField, Zero};
use pyo3::prelude::*;
use rayon::{prelude::*, ThreadPool};
use std::sync::Arc;

const MAX_DIMENSION: usize = 20_000;
const MAX_THRESHOLD: usize = 32;
const MAX_WORKERS: usize = 4;

fn scalar(raw: &[u8]) -> PyResult<Fr> {
    if raw.len() != 32 { return Err(invalid("noncanonical aggregate scalar length")); }
    let value = Fr::from_be_bytes_mod_order(raw);
    let mut canonical = encode(&value); canonical.reverse();
    if canonical != raw { return Err(invalid("noncanonical aggregate scalar")); }
    Ok(value)
}

fn gt(raw: &[u8]) -> PyResult<Fq12> {
    let value: Fq12 = decode(raw, 576)?;
    if !gt_subgroup(value) {
        return Err(invalid("invalid aggregate GT subgroup"));
    }
    Ok(value)
}

#[cfg(test)]
fn cyclotomic_member(value: Fq12) -> bool {
    // For NONZERO x, this exact Frobenius equation is equivalent to
    // x^(p^4-p^2+1)=1. It proves membership in Phi_12(p), before any
    // cyclotomic-specific arithmetic is used. Unitary membership alone
    // (x^(p^6+1)=1) is weaker and would not justify the fast squaring.
    crate::batch::cyclotomic_member(value)
}

fn gt_subgroup(value: Fq12) -> bool {
    // q divides Phi_12(p). The second condition remains the full, exact
    // q-order subgroup check; the preceding gate only enables its faster
    // arithmetic and does not replace it. Zero/canonical checks remain.
    crate::batch::gt_subgroup(value)
}

fn msm(points: &[G1Affine], coefficients: &[Fr]) -> G1Projective {
    debug_assert_eq!(points.len(), coefficients.len());
    let mut half = Fr::MODULUS; half.div2();
    let mut bases = Vec::with_capacity(points.len());
    let mut values = Vec::with_capacity(points.len());
    for (point, value) in points.iter().zip(coefficients) {
        if value.into_bigint() > half { bases.push(-*point); values.push(-*value); }
        else { bases.push(*point); values.push(*value); }
    }
    G1Projective::msm_unchecked(&bases, &values)
}

// A bounded table for one PUBLIC context base T. Its ~576 KiB allocation is
// independent of dimension; construction is included in cold measurements.
struct PublicGTTable { rows: Vec<Vec<Fq12>> }

impl PublicGTTable {
    fn new(base: Fq12) -> Self {
        let mut rows = Vec::with_capacity(64);
        let mut position = base;
        for _ in 0..64 {
            let mut row = Vec::with_capacity(16);
            let mut next = Fq12::one();
            for _ in 0..16 { row.push(next); next *= position; }
            rows.push(row);
            for _ in 0..4 { position.square_in_place(); }
        }
        Self { rows }
    }

    fn pow_public(&self, coefficient: Fr) -> Fq12 {
        let mut raw = encode(&coefficient); raw.reverse();
        let mut value = Fq12::one();
        for (index, byte) in raw.iter().rev().enumerate() {
            value *= self.rows[2 * index][(byte & 15) as usize];
            value *= self.rows[2 * index + 1][(byte >> 4) as usize];
        }
        value
    }
}

fn pow_public(base: Fq12, coefficient: Fr) -> Fq12 {
    let mut half = Fr::MODULUS; half.div2();
    if coefficient.into_bigint() > half {
        base.cyclotomic_inverse().expect("checked nonzero subgroup element")
            .cyclotomic_exp((-coefficient).into_bigint())
    } else { base.cyclotomic_exp(coefficient.into_bigint()) }
}

#[pyclass(module = "dgfl_native", frozen)]
pub(crate) struct AggregatePolynomial {
    coefficients: Arc<Vec<Vec<G1Affine>>>,
    // Reject handles created for another verifier's G/H/T, even when that
    // verifier was also constructed through this fully checked public API.
    g: G1Affine, h: G1Affine, base: Fq12,
}

#[pyclass(module = "dgfl_native", frozen)]
pub(crate) struct PublicAggregateVerifier {
    g: G1Affine, h: G1Affine, base: Fq12,
    table: PublicGTTable, pool: Arc<ThreadPool>,
}

struct Row { a: G1Affine, b: Fq12, e: Fq12, zs: Fr, zr: Fr }

#[pymethods]
impl PublicAggregateVerifier {
    #[new]
    #[pyo3(signature = (g, h, base, workers=1))]
    fn new(py: Python<'_>, g: Vec<u8>, h: Vec<u8>, base: Vec<u8>, workers: usize) -> PyResult<Self> {
        if !(1..=MAX_WORKERS).contains(&workers) {
            return Err(invalid("aggregate workers must be between 1 and 4"));
        }
        py.allow_threads(|| {
            let g: G1Affine = decode(&g, 48)?;
            let h: G1Affine = decode(&h, 48)?;
            let base = gt(&base)?;
            if g.is_zero() || h.is_zero() {
                return Err(invalid("degenerate aggregate public bases"));
            }
            let pool = crate::batch::bounded_pool(workers)?;
            Ok(Self { g, h, base, table: PublicGTTable::new(base), pool })
        })
    }

    fn polynomial(&self, py: Python<'_>, commitments: Vec<Vec<Vec<u8>>>,
                  constants: Vec<Vec<u8>>) -> PyResult<AggregatePolynomial> {
        let count = commitments.len();
        if count == 0 || count > MAX_DIMENSION || constants.len() != count {
            return Err(invalid("aggregate polynomial dimension mismatch"));
        }
        let threshold = commitments[0].len();
        if !(2..=MAX_THRESHOLD).contains(&threshold)
            || commitments.iter().any(|row| row.len() != threshold) {
            return Err(invalid("aggregate polynomial threshold mismatch"));
        }
        let coefficients = py.allow_threads(|| self.pool.install(|| {
            let parse = |index: usize| -> PyResult<Vec<G1Affine>> {
                let row = commitments[index].iter().map(|point| decode::<G1Affine>(point, 48))
                    .collect::<PyResult<Vec<_>>>()?;
                let constant: G1Affine = decode(&constants[index], 48)?;
                if row[0] != constant { return Err(invalid("aggregate key commitment violates trusted DKG")); }
                Ok(row)
            };
            if count < 64 { (0..count).map(parse).collect::<PyResult<Vec<_>>>() }
            else { (0..count).into_par_iter().map(parse).collect::<PyResult<Vec<_>>>() }
        }))?;
        Ok(AggregatePolynomial { coefficients: Arc::new(coefficients), g: self.g, h: self.h, base: self.base })
    }

    fn verify(&self, py: Python<'_>, polynomial: PyRef<'_, AggregatePolynomial>, cloud_id: usize,
              challenge: Vec<u8>, a: Vec<Vec<u8>>, b: Vec<Vec<u8>>, e: Vec<Vec<u8>>,
              responses: Vec<Vec<Vec<u8>>>) -> PyResult<Vec<NativeGT>> {
        let coefficients = Arc::clone(&polynomial.coefficients);
        let count = coefficients.len();
        if polynomial.g != self.g || polynomial.h != self.h || polynomial.base != self.base {
            return Err(invalid("aggregate polynomial/verifier binding mismatch"));
        }
        if !(1..=32).contains(&cloud_id) || a.len() != count || b.len() != count || e.len() != count
            || responses.len() != count || responses.iter().any(|row| row.len() != 2) {
            return Err(invalid("aggregate proof dimension or cloud mismatch"));
        }
        py.allow_threads(|| self.pool.install(|| {
            let challenge = scalar(&challenge)?;
            let cloud = Fr::from(cloud_id as u64);
            let mut power = Fr::one();
            let powers: Vec<Fr> = (0..coefficients[0].len()).map(|_| {
                let old = power; power *= cloud; old
            }).collect();
            let parse = |index: usize| -> PyResult<Row> {
                Ok(Row { a: decode(&a[index], 48)?, b: gt(&b[index])?, e: gt(&e[index])?,
                         zs: scalar(&responses[index][0])?, zr: scalar(&responses[index][1])? })
            };
            // Complete checked parsing precedes any acceptance. Canonical,
            // subgroup and scalar checks are retained even for later rows.
            let rows = if count < 64 { (0..count).map(parse).collect::<PyResult<Vec<_>>>()? }
                       else { (0..count).into_par_iter().map(parse).collect::<PyResult<Vec<_>>>()? };
            let verify_row = |index: usize| -> bool {
                let row = &rows[index];
                let commitment = msm(&coefficients[index], &powers).into_affine();
                let g1_valid = msm(&[self.g, self.h, row.a, commitment],
                                   &[row.zs, row.zr, -Fr::one(), -challenge]).is_zero();
                let gt_valid = self.table.pow_public(row.zs) == row.b * pow_public(row.e, challenge);
                g1_valid && gt_valid
            };
            let valid = if count < 64 { (0..count).all(verify_row) }
                        else { (0..count).into_par_iter().all(verify_row) };
            if !valid { return Err(invalid("aggregate pairing-image proof failed")); }
            Ok(rows.into_iter().map(|row| NativeGT { value: row.e }).collect())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, G2Affine};
    use ark_ec::pairing::Pairing;
    use ark_ff::UniformRand;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn public_gt_table_matches_unmodified_exponentiation() {
        let base = Bls12_381::pairing(G1Affine::generator(), G2Affine::generator()).0;
        let table = PublicGTTable::new(base);
        for coefficient in [Fr::zero(), Fr::one(), Fr::from(15u64), Fr::from(16u64),
                            Fr::from(255u64), Fr::from(256u64), Fr::from(2u64).pow([254u64]),
                            -Fr::one(), -Fr::from(1234567u64)] {
            assert_eq!(table.pow_public(coefficient), base.pow(coefficient.into_bigint()));
            assert_eq!(pow_public(base, coefficient), base.pow(coefficient.into_bigint()));
        }
    }

    #[test]
    fn scalar_encoding_rejects_modulus_and_wrong_lengths() {
        let mut modulus = Fr::MODULUS.to_bytes_be();
        assert!(scalar(&modulus).is_err());
        modulus.pop(); assert!(scalar(&modulus).is_err());
        assert_eq!(scalar(&[0u8;32]).unwrap(), Fr::zero());
    }

    #[test]
    fn exact_gt_guard_matches_generic_q_power_on_random_and_constructed_subgroups() {
        let generator = Bls12_381::pairing(G1Affine::generator(), G2Affine::generator()).0;
        let mut rng = StdRng::seed_from_u64(0xC1C10B1E);
        let mut cases = vec![Fq12::zero(), Fq12::one(), -Fq12::one(),
                             Fq12::one() + Fq12::one(), generator];
        // -1 is unitary of order 2, outside the odd-order Phi12 subgroup.
        assert!(((-Fq12::one()).frobenius_map(6) * (-Fq12::one())).is_one());
        assert!(!cyclotomic_member(-Fq12::one()));
        for _ in 0..32 {
            let raw = Fq12::rand(&mut rng);
            assert!(!raw.is_zero());
            // u=x^(p^6-1) is unitary, but not necessarily cyclotomic.
            let unitary = raw.frobenius_map(6) * raw.inverse().unwrap();
            assert!((unitary.frobenius_map(6) * unitary).is_one());
            assert!(!cyclotomic_member(unitary));
            // c=u^(p^2+1) is in Phi12(p), but not generally the q subgroup.
            let cyclotomic = unitary.frobenius_map(2) * unitary;
            assert!(cyclotomic_member(cyclotomic));
            assert_eq!(cyclotomic.cyclotomic_exp(Fr::MODULUS), cyclotomic.pow(Fr::MODULUS));
            assert!(!cyclotomic.pow(Fr::MODULUS).is_one());
            assert!(!gt_subgroup(cyclotomic)); // The q-order check is essential.
            let valid = generator.pow(Fr::rand(&mut rng).into_bigint());
            cases.extend([raw, unitary, cyclotomic, valid]);
        }
        for value in cases {
            let oracle = !value.is_zero() && value.pow(Fr::MODULUS).is_one();
            assert_eq!(gt_subgroup(value), oracle);
            assert_eq!(gt(&encode(&value)).is_ok(), oracle);
        }
    }

    #[test]
    fn public_cyclotomic_exponentiation_matches_generic_power_for_checked_gt() {
        let generator = Bls12_381::pairing(G1Affine::generator(), G2Affine::generator()).0;
        let mut rng = StdRng::seed_from_u64(0xCAFE0123);
        for _ in 0..32 {
            let value = generator.pow(Fr::rand(&mut rng).into_bigint());
            assert!(gt_subgroup(value));
            let exponent = Fr::rand(&mut rng);
            assert_eq!(pow_public(value, exponent), value.pow(exponent.into_bigint()));
        }
        for value in [Fq12::one(), generator] {
            for exponent in [Fr::zero(), Fr::one(), -Fr::one(), Fr::from(2u64).pow([254u64])] {
                assert_eq!(pow_public(value, exponent), value.pow(exponent.into_bigint()));
            }
        }
    }
}
