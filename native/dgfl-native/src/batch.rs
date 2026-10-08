//! Checked vector primitives, with projective outputs normalized together.
//!
//! Secret scalars live only in the current call. The shared pools retain only
//! worker threads; no scalar, nonce, coefficient image, or transcript is cached.
//! Like the existing research prover, arkworks multiplication is variable-time.
//! No secret is passed to PublicG1Table/PublicGTTable or another lookup table.
use crate::{decode, encode, invalid};
use ark_bls12_381::{Bls12_381, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{BigInteger, CyclotomicMultSubgroup, Field, PrimeField, Zero};
use pyo3::{prelude::*, types::PyBytes};
use rayon::{prelude::*, ThreadPool, ThreadPoolBuilder};
use std::{collections::HashMap, sync::{Arc, Mutex, OnceLock}};

const MAX_DIMENSION: usize = 20_000;
const MAX_THRESHOLD: usize = 32;
// Match the generic combine API's bound without retaining an unbounded point
// matrix in one native call. Real deployment policies currently allow 100.
const MAX_CIPHERTEXTS: usize = 1_000;
const MAX_MATRIX_POINTS: usize = MAX_DIMENSION * MAX_THRESHOLD;
const BLS_NEGATIVE_X_ABS: u64 = 0xd201_0000_0001_0000;
type Bytes = Vec<Vec<u8>>;
type CloudBytes = Vec<Bytes>;

/// A process-local bounded pool is reused by vector, Lego and aggregate calls.
/// Lego keeps its existing 1..8 worker compatibility; vector APIs accept 1..4.
pub(crate) fn bounded_pool(workers: usize) -> PyResult<Arc<ThreadPool>> {
    if !(1..=8).contains(&workers) {
        return Err(invalid("native worker count must be between 1 and 8"));
    }
    static POOLS: OnceLock<Mutex<HashMap<usize, Arc<ThreadPool>>>> = OnceLock::new();
    let mut pools = POOLS.get_or_init(|| Mutex::new(HashMap::new())).lock()
        .map_err(|_| invalid("native worker pool lock failed"))?;
    if let Some(pool) = pools.get(&workers) { return Ok(Arc::clone(pool)); }
    let pool = Arc::new(ThreadPoolBuilder::new().num_threads(workers).build()
        .map_err(|_| invalid("cannot create native worker pool"))?);
    pools.insert(workers, Arc::clone(&pool));
    Ok(pool)
}

fn run<T: Send>(py: Python<'_>, workers: usize,
               operation: impl FnOnce() -> PyResult<T> + Send) -> PyResult<T> {
    if !(1..=4).contains(&workers) {
        return Err(invalid("batch workers must be between 1 and 4"));
    }
    let pool = bounded_pool(workers)?;
    py.allow_threads(|| pool.install(operation))
}

pub(crate) fn ordered<T: Send>(count: usize,
                              operation: impl Fn(usize) -> T + Send + Sync) -> Vec<T> {
    if count < 64 { (0..count).map(operation).collect() }
    else { (0..count).into_par_iter().map(operation).collect() }
}

fn dimensions(count: usize, other: &[usize]) -> PyResult<()> {
    if !(1..=MAX_DIMENSION).contains(&count) || other.iter().any(|length| *length != count) {
        return Err(invalid("invalid native batch dimensions"));
    }
    Ok(())
}

fn scalars(raw: &[Vec<u8>]) -> PyResult<Vec<Fr>> {
    raw.iter().map(|value| {
        if value.len() != 32 { return Err(invalid("noncanonical batch scalar length")); }
        let decoded = Fr::from_be_bytes_mod_order(value);
        let mut canonical = encode(&decoded); canonical.reverse();
        if canonical != *value { return Err(invalid("noncanonical batch scalar outside field")); }
        Ok(decoded)
    }).collect()
}

fn g1_base(raw: &[u8]) -> PyResult<G1Affine> {
    let point: G1Affine = decode(raw, 48)?;
    if point.is_zero() { return Err(invalid("degenerate batch G1 base")); }
    Ok(point)
}

fn g2_base(raw: &[u8]) -> PyResult<G2Affine> {
    let point: G2Affine = decode(raw, 96)?;
    if point.is_zero() { return Err(invalid("degenerate batch G2 base")); }
    Ok(point)
}

pub(crate) fn cyclotomic_member(value: Fq12) -> bool {
    !value.is_zero() && value.frobenius_map(4) * value == value.frobenius_map(2)
}

/// Exact FULL q membership for the fixed BLS12-381 parameters, not a weaker
/// cyclotomic-only or unitary check. In the cyclic Phi12(p) group the second
/// relation is x^(p+|X|)=1, and gcd(Phi12(p), p+|X|) is exactly Fr::MODULUS.
/// The Phi12 gate is essential: nontrivial Fp cube roots also satisfy the
/// Frobenius-X relation, but are outside GT. Generic field pow stays unchanged.
pub(crate) fn gt_subgroup(value: Fq12) -> bool {
    cyclotomic_member(value) && value.cyclotomic_exp([BLS_NEGATIVE_X_ABS])
        .cyclotomic_inverse().map(|power| value.frobenius_map(1) == power).unwrap_or(false)
}

pub(crate) fn checked_gt(raw: &[u8]) -> PyResult<Fq12> {
    let value: Fq12 = decode(raw, 576)?;
    if !gt_subgroup(value) { return Err(invalid("invalid batch GT subgroup")); }
    Ok(value)
}

fn public_clouds(clouds: &[usize]) -> PyResult<()> {
    if clouds.is_empty() || clouds.len() > MAX_THRESHOLD
        || clouds.iter().any(|id| !(1..=MAX_THRESHOLD).contains(id))
        || clouds.iter().enumerate().any(|(i, id)| clouds[..i].contains(id)) {
        return Err(invalid("invalid or duplicate public cloud IDs"));
    }
    Ok(())
}

fn py_bytes(py: Python<'_>, raw: Bytes) -> Vec<Py<PyBytes>> {
    raw.iter().map(|value| PyBytes::new(py, value).unbind()).collect()
}
fn py_cloud_bytes(py: Python<'_>, raw: CloudBytes) -> Vec<Vec<Py<PyBytes>>> {
    raw.into_iter().map(|cloud| py_bytes(py, cloud)).collect()
}

fn pedersen(g: G1Affine, h: G1Affine, values: &[Fr], blindings: &[Fr]) -> Bytes {
    let projective = ordered(values.len(), |i|
        g.mul_bigint(values[i].into_bigint()) + h.mul_bigint(blindings[i].into_bigint()));
    G1Projective::normalize_batch(&projective).iter().map(encode).collect()
}

/// G*values[j]+H*blindings[j], with one batch normalization.
#[pyfunction]
#[pyo3(signature = (g, h, values, blindings, workers=1))]
pub fn pedersen_batch(py: Python<'_>, g: Vec<u8>, h: Vec<u8>, values: Bytes,
                      blindings: Bytes, workers: usize) -> PyResult<Vec<Py<PyBytes>>> {
    let raw = run(py, workers, || {
        dimensions(values.len(), &[blindings.len()])?;
        let g = g1_base(&g)?; let h = g1_base(&h)?;
        let values = scalars(&values)?; let blindings = scalars(&blindings)?;
        Ok(pedersen(g, h, &values, &blindings))
    })?;
    Ok(py_bytes(py, raw))
}

/// Independent exact Pedersen equations. ALL rows are parsed and subgroup
/// checked before arithmetic, including rows after an earlier false equation.
#[pyfunction]
#[pyo3(signature = (g, h, commitments, s, r, powers, workers=1))]
pub fn pedersen_verify_batch(py: Python<'_>, g: Vec<u8>, h: Vec<u8>, commitments: Vec<Bytes>,
    s: Bytes, r: Bytes, powers: Bytes, workers: usize) -> PyResult<Vec<bool>> {
    run(py, workers, || {
        dimensions(commitments.len(), &[s.len(), r.len()])?;
        if !(1..=MAX_THRESHOLD).contains(&powers.len())
            || commitments.iter().any(|row| row.len() != powers.len()) {
            return Err(invalid("native Pedersen polynomial length mismatch"));
        }
        let g = g1_base(&g)?; let h = g1_base(&h)?;
        let s = scalars(&s)?; let r = scalars(&r)?; let powers = scalars(&powers)?;
        let decoded = ordered(commitments.len(), |i|
            commitments[i].iter().map(|point| decode::<G1Affine>(point, 48)).collect::<PyResult<Vec<_>>>())
            .into_iter().collect::<PyResult<Vec<_>>>()?;
        Ok(ordered(decoded.len(), |i| {
            let mut expected = G1Projective::zero();
            // Powers are public. Private s/r use ordinary scalar multiplication.
            for (point, power) in decoded[i].iter().zip(&powers) {
                expected += point.mul_bigint(power.into_bigint());
            }
            expected == g.mul_bigint(s[i].into_bigint()) + h.mul_bigint(r[i].into_bigint())
        }))
    })
}

#[pyfunction]
#[pyo3(signature = (base, scalars_raw, workers=1))]
pub fn g2_mul_batch(py: Python<'_>, base: Vec<u8>, scalars_raw: Bytes,
                    workers: usize) -> PyResult<Vec<Py<PyBytes>>> {
    let raw = run(py, workers, || {
        dimensions(scalars_raw.len(), &[])?;
        let base = g2_base(&base)?; let values = scalars(&scalars_raw)?;
        let points = ordered(values.len(), |i| base.mul_bigint(values[i].into_bigint()));
        Ok(G2Projective::normalize_batch(&points).iter().map(encode).collect())
    })?;
    Ok(py_bytes(py, raw))
}

#[pyfunction]
#[pyo3(signature = (base, scalars_raw, workers=1))]
pub fn gt_pow_batch(py: Python<'_>, base: Vec<u8>, scalars_raw: Bytes,
                    workers: usize) -> PyResult<Vec<Py<PyBytes>>> {
    let raw = run(py, workers, || {
        dimensions(scalars_raw.len(), &[])?;
        let base = checked_gt(&base)?; let values = scalars(&scalars_raw)?;
        Ok(ordered(values.len(), |i| encode(&base.cyclotomic_exp(values[i].into_bigint()))))
    })?;
    Ok(py_bytes(py, raw))
}

/// A=G*u+H*v, E=T*s, B=T*u. u/v are supplied fresh for EACH proof; this
/// function cannot generate, retain, or reuse nonces across clouds or calls.
#[pyfunction]
#[pyo3(signature = (g, h, base, s, u, v, workers=1))]
pub fn aggregate_first_messages(py: Python<'_>, g: Vec<u8>, h: Vec<u8>, base: Vec<u8>,
    s: Bytes, u: Bytes, v: Bytes, workers: usize)
    -> PyResult<(Vec<Py<PyBytes>>, Vec<Py<PyBytes>>, Vec<Py<PyBytes>>)> {
    let (a, e, b) = run(py, workers, || {
        dimensions(s.len(), &[u.len(), v.len()])?;
        let g = g1_base(&g)?; let h = g1_base(&h)?; let base = checked_gt(&base)?;
        let s = scalars(&s)?; let u = scalars(&u)?; let v = scalars(&v)?;
        let rows = ordered(s.len(), |i| (
            g.mul_bigint(u[i].into_bigint()) + h.mul_bigint(v[i].into_bigint()),
            base.cyclotomic_exp(s[i].into_bigint()), base.cyclotomic_exp(u[i].into_bigint())));
        let affine = G1Projective::normalize_batch(&rows.iter().map(|row| row.0).collect::<Vec<_>>());
        Ok((affine.iter().map(encode).collect::<Bytes>(), rows.iter().map(|row| encode(&row.1)).collect::<Bytes>(),
            rows.iter().map(|row| encode(&row.2)).collect::<Bytes>()))
    })?;
    Ok((py_bytes(py, a), py_bytes(py, e), py_bytes(py, b)))
}

fn g2_images(base: G2Affine, c0: &[Fr], c1: &[Fr], clouds: &[usize]) -> CloudBytes {
    let rows = ordered(c0.len(), |i| {
        let constant = base.mul_bigint(c0[i].into_bigint());
        let linear = base.mul_bigint(c1[i].into_bigint());
        let twice = linear.double();
        clouds.iter().map(|id| constant + match *id {
            1 => linear, 2 => twice, 3 => twice + linear,
            _ => linear.mul_bigint([*id as u64]),
        }).collect::<Vec<_>>()
    });
    // Normalize all cloud outputs together; identity/cancellation is supported.
    let flat = (0..clouds.len()).flat_map(|cloud| rows.iter().map(move |row| row[cloud])).collect::<Vec<_>>();
    G2Projective::normalize_batch(&flat).chunks(c0.len())
        .map(|cloud| cloud.iter().map(encode).collect()).collect()
}

#[pyfunction]
#[pyo3(signature = (g2, c0, c1, cloud_ids, workers=1))]
pub fn g2_t2_polynomial_batch(py: Python<'_>, g2: Vec<u8>, c0: Bytes, c1: Bytes,
    cloud_ids: Vec<usize>, workers: usize) -> PyResult<Vec<Vec<Py<PyBytes>>>> {
    let raw = run(py, workers, || {
        dimensions(c0.len(), &[c1.len()])?; public_clouds(&cloud_ids)?;
        let base = g2_base(&g2)?; let c0 = scalars(&c0)?; let c1 = scalars(&c1)?;
        Ok(g2_images(base, &c0, &c1, &cloud_ids))
    })?;
    Ok(py_cloud_bytes(py, raw))
}

fn gt_images(base: Fq12, c0: &[Fr], c1: &[Fr], clouds: &[usize]) -> CloudBytes {
    let rows = ordered(c0.len(), |i| {
        let constant = base.cyclotomic_exp(c0[i].into_bigint());
        let linear = base.cyclotomic_exp(c1[i].into_bigint());
        let squared = linear.cyclotomic_square();
        clouds.iter().map(|id| encode(&(constant * match *id {
            1 => linear, 2 => squared, 3 => squared * linear,
            _ => linear.cyclotomic_exp([*id as u64]),
        }))).collect::<Bytes>()
    });
    (0..clouds.len()).map(|cloud| rows.iter().map(|row| row[cloud].clone()).collect()).collect()
}

/// Only E polynomial images are shared across clouds. Fresh proof B messages
/// must still use independent per-proof u, through gt_pow_batch or the combined API.
#[pyfunction]
#[pyo3(signature = (base, c0, c1, cloud_ids, workers=1))]
pub fn gt_t2_polynomial_batch(py: Python<'_>, base: Vec<u8>, c0: Bytes, c1: Bytes,
    cloud_ids: Vec<usize>, workers: usize) -> PyResult<Vec<Vec<Py<PyBytes>>>> {
    let raw = run(py, workers, || {
        dimensions(c0.len(), &[c1.len()])?; public_clouds(&cloud_ids)?;
        let base = checked_gt(&base)?; let c0 = scalars(&c0)?; let c1 = scalars(&c1)?;
        Ok(gt_images(base, &c0, &c1, &cloud_ids))
    })?;
    Ok(py_cloud_bytes(py, raw))
}

/// A vector of separate pairings with one checked/prepared fixed G2. This is
/// NOT multi_pairing: each original coordinate keeps its own final exponentiation.
#[pyfunction]
#[pyo3(signature = (g1s, g2, workers=1))]
pub fn pairing_vector(py: Python<'_>, g1s: Bytes, g2: Vec<u8>,
                      workers: usize) -> PyResult<Vec<Py<PyBytes>>> {
    let raw = run(py, workers, || {
        dimensions(g1s.len(), &[])?;
        // Identity is a valid pairing input; malformed/off-subgroup points are not.
        let fixed: G2Affine = decode(&g2, 96)?;
        let points = ordered(g1s.len(), |i| decode::<G1Affine>(&g1s[i], 48))
            .into_iter().collect::<PyResult<Vec<_>>>()?;
        let prepared = <Bls12_381 as Pairing>::G2Prepared::from(fixed);
        ordered(points.len(), |i| {
            Bls12_381::final_exponentiation(Bls12_381::miller_loop(points[i], prepared.clone()))
                .map(|value| encode(&value.0)).ok_or_else(|| invalid("pairing final exponentiation failed"))
        }).into_iter().collect::<PyResult<Bytes>>()
    })?;
    Ok(py_bytes(py, raw))
}

fn matrix_dimensions(rows: &[Bytes], width: usize, maximum_width: usize) -> PyResult<()> {
    dimensions(rows.len(), &[])?;
    if !(1..=maximum_width).contains(&width)
        || rows.iter().any(|row| row.len() != width)
        || rows.len().checked_mul(width).map_or(true, |count| count > MAX_MATRIX_POINTS) {
        return Err(invalid("invalid native point matrix dimensions"));
    }
    Ok(())
}

/// Decode and sum ciphertexts once in this actor, then return one independent
/// pairing per model coordinate. No result is reused across trust boundaries.
#[pyfunction]
#[pyo3(signature = (rows, g2, workers=1))]
pub fn g1_sum_pairing_vector(py: Python<'_>, rows: Vec<Bytes>, g2: Vec<u8>,
                             workers: usize) -> PyResult<Vec<Py<PyBytes>>> {
    let raw = run(py, workers, || {
        matrix_dimensions(&rows, rows.first().map_or(0, Vec::len), MAX_CIPHERTEXTS)?;
        let fixed: G2Affine = decode(&g2, 96)?;
        // Parse ALL sources, including identities and cancellation pairs,
        // before evaluating any row. Every source retains its subgroup check.
        let decoded = ordered(rows.len(), |i|
            rows[i].iter().map(|point| decode::<G1Affine>(point, 48)).collect::<PyResult<Vec<_>>>())
            .into_iter().collect::<PyResult<Vec<_>>>()?;
        let sums = ordered(decoded.len(), |i|
            decoded[i].iter().fold(G1Projective::zero(), |sum, point| sum + point));
        let affine = G1Projective::normalize_batch(&sums);
        let prepared = <Bls12_381 as Pairing>::G2Prepared::from(fixed);
        ordered(affine.len(), |i|
            Bls12_381::final_exponentiation(Bls12_381::miller_loop(affine[i], prepared.clone()))
                .map(|value| encode(&value.0)).ok_or_else(|| invalid("pairing final exponentiation failed")))
            .into_iter().collect::<PyResult<Bytes>>()
    })?;
    Ok(py_bytes(py, raw))
}

/// One checked G2 MSM and separate final-exponentiated pairing for EACH row.
/// Weights are PUBLIC interpolation coefficients. Centering their signs agrees
/// with the Python checked MSM and avoids full-width multiplies for -1/-2.
/// Secret key images, weights and prepared inputs remain local to this call.
#[pyfunction]
#[pyo3(signature = (g1, rows, weights, workers=1))]
pub fn g2_msm_pairing_vector(py: Python<'_>, g1: Vec<u8>, rows: Vec<Bytes>, weights: Bytes,
                             workers: usize) -> PyResult<Vec<Py<PyBytes>>> {
    let raw = run(py, workers, || {
        matrix_dimensions(&rows, weights.len(), MAX_THRESHOLD)?;
        let fixed: G1Affine = decode(&g1, 48)?;
        let values = scalars(&weights)?;
        let mut half = Fr::MODULUS; half.div2();
        let negative = values.iter().map(|value| value.into_bigint() > half).collect::<Vec<_>>();
        let centered = values.iter().zip(&negative)
            .map(|(value, negate)| if *negate { -*value } else { *value }).collect::<Vec<_>>();
        let decoded = ordered(rows.len(), |i|
            rows[i].iter().zip(&negative).map(|(point, negate)| {
                let point: G2Affine = decode(point, 96)?;
                Ok(if *negate { -point } else { point })
            }).collect::<PyResult<Vec<_>>>())
            .into_iter().collect::<PyResult<Vec<_>>>()?;
        let keys = ordered(decoded.len(), |i| {
            if centered.len() < 3 {
                decoded[i].iter().zip(&centered).fold(G2Projective::zero(), |sum, (point, value)|
                    sum + point.mul_bigint(value.into_bigint()))
            } else {
                // Length equality was checked before calling the unchecked MSM.
                G2Projective::msm_unchecked(&decoded[i], &centered)
            }
        });
        let affine = G2Projective::normalize_batch(&keys);
        let prepared = <Bls12_381 as Pairing>::G1Prepared::from(fixed);
        ordered(affine.len(), |i|
            Bls12_381::final_exponentiation(Bls12_381::miller_loop(prepared.clone(), affine[i]))
                .map(|value| encode(&value.0)).ok_or_else(|| invalid("pairing final exponentiation failed")))
            .into_iter().collect::<PyResult<Bytes>>()
    })?;
    Ok(py_bytes(py, raw))
}

/// Canonical, subgroup-checked GPU upload bytes. Infinity uses the existing
/// 96-zero-byte convention. No point/anchor validation is delegated to the GPU.
#[pyfunction]
#[pyo3(signature = (points, workers=1))]
pub fn checked_g1_coordinates_batch<'py>(py: Python<'py>, points: Bytes, workers: usize)
    -> PyResult<Bound<'py, PyBytes>> {
    let raw = run(py, workers, || {
        dimensions(points.len(), &[])?;
        let decoded = ordered(points.len(), |i| decode::<G1Affine>(&points[i], 48))
            .into_iter().collect::<PyResult<Vec<_>>>()?;
        let coordinates = ordered(decoded.len(), |i| {
            if decoded[i].is_zero() { vec![0u8; 96] }
            else {
                let mut bytes = encode(&decoded[i].x);
                bytes.extend(encode(&decoded[i].y));
                bytes
            }
        });
        Ok(coordinates.into_iter().flatten().collect::<Vec<_>>())
    })?;
    Ok(PyBytes::new(py, &raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fq, Fq2, Fq6};
    use ark_ff::{BigInteger, One, UniformRand};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn exact_gt_membership_matches_full_q_for_boundary_and_adversarial_elements() {
        let generator = Bls12_381::pairing(G1Affine::generator(), G2Affine::generator()).0;
        let mut rng = StdRng::seed_from_u64(0xF00B12381);
        let mut cases = vec![Fq12::zero(), Fq12::one(), -Fq12::one(), generator];
        for _ in 0..32 {
            let arbitrary = Fq12::rand(&mut rng);
            let unitary = arbitrary.frobenius_map(6) * arbitrary.inverse().unwrap();
            let cyclotomic = unitary.frobenius_map(2) * unitary;
            assert!(cyclotomic_member(cyclotomic));
            assert!(!gt_subgroup(cyclotomic));
            cases.extend([arbitrary, unitary, cyclotomic,
                          generator.pow(Fr::rand(&mut rng).into_bigint())]);
        }
        let third = [0x9354_ffff_ffff_e38e, 0x0a39_5554_e5c6_aaaa, 0xcd10_4635_a790_520c,
                     0xcc27_c3d6_fbd7_063f, 0x1909_37e7_6bc3_e447, 0x08ab_05f8_bdd5_4cde];
        let root = (2u64..100).map(|n| Fq::from(n).pow(third)).find(|v| !v.is_one()).unwrap();
        let cofactor = Fq12::new(Fq6::new(Fq2::new(root, Fq::zero()), Fq2::zero(), Fq2::zero()), Fq6::zero());
        assert!(cofactor.pow([3]).is_one());
        assert!(cofactor.frobenius_map(1) == cofactor.pow([BLS_NEGATIVE_X_ABS]).inverse().unwrap());
        assert!(!cyclotomic_member(cofactor));
        cases.push(cofactor);
        for value in cases {
            assert_eq!(gt_subgroup(value), !value.is_zero() && value.pow(Fr::MODULUS).is_one());
            assert_eq!(checked_gt(&encode(&value)).is_ok(), gt_subgroup(value));
        }
        let mut noncanonical = encode(&Fq12::one());
        noncanonical[..48].copy_from_slice(&encode(&Fq::MODULUS));
        assert!(checked_gt(&noncanonical).is_err());
        assert!(checked_gt(&noncanonical[..575]).is_err());
    }

    #[test]
    fn polynomial_images_match_direct_scalar_evaluations_and_zero_cancellation() {
        let g2 = G2Affine::generator();
        let base = Bls12_381::pairing(G1Affine::generator(), g2).0;
        let mut rng = StdRng::seed_from_u64(0xC0EFF12381);
        let mut c0 = vec![Fr::zero(), Fr::one(), -Fr::one()];
        let mut c1 = vec![Fr::zero(), -Fr::one(), Fr::one()];
        c0.extend((0..64).map(|_| Fr::rand(&mut rng)));
        c1.extend((0..64).map(|_| Fr::rand(&mut rng)));
        let clouds = [3, 1, 2, 32];
        let pool = bounded_pool(2).unwrap();
        let (g2_actual, gt_actual) = pool.install(|| (g2_images(g2, &c0, &c1, &clouds), gt_images(base, &c0, &c1, &clouds)));
        for (i, cloud) in clouds.iter().enumerate() {
            for j in 0..c0.len() {
                let value = c0[j] + Fr::from(*cloud as u64) * c1[j];
                assert_eq!(g2_actual[i][j], encode(&g2.mul_bigint(value.into_bigint()).into_affine()));
                assert_eq!(gt_actual[i][j], encode(&base.pow(value.into_bigint())));
            }
        }
        assert!(public_clouds(&[1, 1]).is_err());
        assert!(public_clouds(&[0]).is_err());
        assert!(public_clouds(&[33]).is_err());
        assert!(scalars(&[Fr::MODULUS.to_bytes_be()]).is_err());
        assert!(scalars(&[vec![0u8; 31]]).is_err());
    }

    #[test]
    fn pool_reuse_and_point_checks_do_not_retain_call_inputs() {
        assert!(Arc::ptr_eq(&bounded_pool(2).unwrap(), &bounded_pool(2).unwrap()));
        assert!(bounded_pool(0).is_err());
        assert!(bounded_pool(9).is_err());
        assert!(g1_base(&encode(&G1Affine::identity())).is_err());
        let torsion = G1Affine::new_unchecked(Fq::zero(), Fq::from(2u64));
        assert!(torsion.is_on_curve());
        assert!(!torsion.is_in_correct_subgroup_assuming_on_curve());
        assert!(g1_base(&encode(&torsion)).is_err());
        assert!(g2_base(&encode(&G2Affine::identity())).is_err());
    }
}
