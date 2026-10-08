//! Experimental committed-witness range and squared-norm LegoGroth16 backend.
//!
//! This verifies the numeric relation only. A caller must additionally prove
//! knowledge of the opening of `proof.d`, sharing all value responses with its
//! ciphertext/registered-key Sigma protocol. Development setup is a local,
//! single-party trusted setup, not a production multiparty ceremony. Proving
//! uses Ark's variable-time MSMs and does not claim side-channel resistance.

use crate::{decode, encode, invalid};
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
    SynthesisError, SynthesisMode,
};
use legogroth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key,
    verify_proof, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use pyo3::{prelude::*, types::PyBytes};
use rand::rngs::OsRng;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::sync::Arc;

const PROOF_BYTES: usize = 240;
const MAX_DIMENSION: usize = 20_000;

fn bounds(dimension: usize, bits: usize) -> PyResult<(i64, u64)> {
    if !(1..=MAX_DIMENSION).contains(&dimension) || !(2..=16).contains(&bits) {
        return Err(invalid("unsupported Lego dimension or range bits"));
    }
    let offset = 1i64 << (bits - 1);
    let max_norm = (dimension as u64)
        .checked_mul((offset as u64).pow(2))
        .ok_or_else(|| invalid("Lego integer bound overflow"))?;
    // All allowed bounds fit u64, much smaller than the 255-bit Fr modulus.
    if Fr::MODULUS_BIT_SIZE <= 64 || max_norm.checked_mul(2).is_none() {
        return Err(invalid("Lego integer range would wrap scalar field"));
    }
    Ok((offset, max_norm))
}

fn pool(workers: usize) -> PyResult<Arc<ThreadPool>> {
    if !(1..=8).contains(&workers) {
        return Err(invalid("Lego worker count must be between 1 and 8"));
    }
    ThreadPoolBuilder::new().num_threads(workers).build()
        .map(Arc::new).map_err(|_| invalid("cannot create Lego worker pool"))
}

fn signed_scalar(value: i64) -> Fr {
    if value < 0 { -Fr::from(value.unsigned_abs()) } else { Fr::from(value as u64) }
}

fn scalar_be(raw: &[u8]) -> PyResult<Fr> {
    if raw.len() != 32 { return Err(invalid("Lego scalar must have 32 bytes")); }
    let value = Fr::from_be_bytes_mod_order(raw);
    let mut canonical = encode(&value);
    canonical.reverse();
    if canonical != raw { return Err(invalid("noncanonical Lego scalar")); }
    Ok(value)
}

#[derive(Clone)]
struct RangeNormCircuit {
    dimension: usize,
    bits: usize,
    values: Option<Vec<i64>>,
    norm: Option<u64>,
}

impl ConstraintSynthesizer<Fr> for RangeNormCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let offset = 1u64 << (self.bits - 1);
        let norm = FpVar::new_input(cs.clone(), || {
            self.norm.map(Fr::from).ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Lego commits to the first `dimension` witness variables. Allocate
        // ALL signed values before allocating any bits or product witnesses.
        let mut values = Vec::with_capacity(self.dimension);
        for index in 0..self.dimension {
            values.push(FpVar::new_witness(cs.clone(), || {
                self.values.as_ref().and_then(|v| v.get(index)).copied()
                    .map(signed_scalar).ok_or(SynthesisError::AssignmentMissing)
            })?);
        }
        let mut squared_sum = FpVar::Constant(Fr::from(0u64));
        for (index, value) in values.iter().enumerate() {
            let mut reconstructed = FpVar::Constant(Fr::from(0u64));
            for bit_index in 0..self.bits {
                let bit = Boolean::new_witness(cs.clone(), || {
                    let raw = self.values.as_ref().and_then(|v| v.get(index))
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    let shifted = (*raw as i128) + (offset as i128);
                    Ok(((shifted >> bit_index) & 1) != 0)
                })?;
                reconstructed += FpVar::from(bit) * Fr::from(1u64 << bit_index);
            }
            (value + Fr::from(offset)).enforce_equal(&reconstructed)?;
            squared_sum += value.square()?;
        }
        squared_sum.enforce_equal(&norm)
    }
}

fn check_vk(vk: &VerifyingKey<Bls12_381>, dimension: usize) -> PyResult<Vec<G1Affine>> {
    if vk.commit_witness_count as usize != dimension || vk.gamma_abc_g1.len() != dimension + 2 {
        return Err(invalid("Lego verification key does not match numeric circuit layout"));
    }
    let bases = vk.get_commitment_key_for_witnesses();
    if bases.len() != dimension + 1 || bases.iter().any(AffineRepr::is_zero)
        || vk.alpha_g1.is_zero() || vk.beta_g2.is_zero()
        || vk.gamma_g2.is_zero() || vk.delta_g2.is_zero()
    {
        return Err(invalid("degenerate Lego verification key"));
    }
    Ok(bases)
}

/// Exact query dimensions from the pinned numeric circuit and QAP reduction.
/// Deriving these in setup mode detects changes to gadget/query dimensions.
/// Shape equality does not establish circuit identity; the caller pins the CRS
/// and circuit specification independently through a trusted manifest.
#[derive(Clone, Copy)]
struct KeyLayout {
    vk_bytes: usize,
    query_len: usize,
    h_len: usize,
    l_len: usize,
    pk_bytes: usize,
}

fn key_layout(dimension: usize, bits: usize) -> PyResult<KeyLayout> {
    bounds(dimension, bits)?;
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    RangeNormCircuit { dimension, bits, values: None, norm: None }
        .generate_constraints(cs.clone())
        .map_err(|_| invalid("cannot synthesize Lego key layout"))?;
    cs.finalize();
    let instances = cs.num_instance_variables();
    let witnesses = cs.num_witness_variables();
    if instances != 2 || witnesses < dimension {
        return Err(invalid("unexpected Lego numeric circuit layout"));
    }
    let domain = GeneralEvaluationDomain::<Fr>::new(cs.num_constraints() + instances)
        .ok_or_else(|| invalid("unsupported Lego evaluation domain"))?;
    let vk_bytes = 492 + 48 * dimension;
    let query_len = instances + witnesses;
    let h_len = domain.size() - 1;
    let l_len = witnesses - dimension;
    // VK, three fixed G1 points, then a/b-G1/b-G2/h/l vectors.
    // These sizes are bounded by MAX_DIMENSION/bits before any wire allocation.
    let pk_bytes = vk_bytes + 3 * 48 + 5 * 8
        + query_len * (48 + 48 + 96) + (h_len + l_len) * 48;
    Ok(KeyLayout { vk_bytes, query_len, h_len, l_len, pk_bytes })
}

/// Preflight all untrusted vector prefixes before Ark can allocate any Vec.
/// PK files are public parameters supplied by a trusted, hash-checked manifest,
/// but an accidental or hostile length prefix must still be rejected safely.
fn check_pk_encoding(raw: &[u8], dimension: usize, layout: KeyLayout) -> PyResult<()> {
    if raw.len() != layout.pk_bytes {
        return Err(invalid("noncanonical Lego proving key size"));
    }
    let vector_len = |position: usize| -> PyResult<usize> {
        let bytes: [u8; 8] = raw.get(position..position + 8)
            .ok_or_else(|| invalid("truncated Lego proving key vector"))?
            .try_into().map_err(|_| invalid("invalid Lego vector prefix"))?;
        usize::try_from(u64::from_le_bytes(bytes))
            .map_err(|_| invalid("Lego proving key vector size overflow"))
    };
    if vector_len(336)? != dimension + 2 {
        return Err(invalid("Lego proving key commitment vector layout mismatch"));
    }
    let count: [u8; 4] = raw[layout.vk_bytes - 4..layout.vk_bytes]
        .try_into().map_err(|_| invalid("invalid Lego committed witness count"))?;
    if u32::from_le_bytes(count) as usize != dimension {
        return Err(invalid("Lego proving key committed witness count mismatch"));
    }
    let mut cursor = layout.vk_bytes + 3 * 48;
    for (expected, point_bytes) in [(layout.query_len, 48), (layout.query_len, 48),
        (layout.query_len, 96), (layout.h_len, 48), (layout.l_len, 48)]
    {
        if vector_len(cursor)? != expected {
            return Err(invalid("Lego proving key query vector layout mismatch"));
        }
        cursor += 8 + expected * point_bytes;
    }
    if cursor != raw.len() {
        return Err(invalid("Lego proving key trailing bytes"));
    }
    Ok(())
}

fn check_pk(pk: &ProvingKey<Bls12_381>, dimension: usize, layout: KeyLayout)
    -> PyResult<Vec<G1Affine>>
{
    let bases = check_vk(&pk.vk, dimension)?;
    let common = &pk.common;
    if common.a_query.len() != layout.query_len || common.b_g1_query.len() != layout.query_len
        || common.b_g2_query.len() != layout.query_len || common.h_query.len() != layout.h_len
        || common.l_query.len() != layout.l_len || common.beta_g1.is_zero()
        || common.delta_g1.is_zero() || common.eta_delta_inv_g1.is_zero()
    {
        return Err(invalid("Lego proving key does not match numeric circuit queries"));
    }
    Ok(bases)
}

fn basis_bytes<'py>(py: Python<'py>, bases: &[G1Affine]) -> Vec<Py<PyBytes>> {
    bases.iter().map(|base| PyBytes::new(py, &encode(base)).unbind()).collect()
}

#[pyclass(module = "dgfl_native", frozen)]
pub(crate) struct LegoProver {
    dimension: usize,
    bits: usize,
    workers: usize,
    pk: Arc<ProvingKey<Bls12_381>>,
    pvk: Arc<PreparedVerifyingKey<Bls12_381>>,
    bases: Arc<Vec<G1Affine>>,
    pool: Arc<ThreadPool>,
}

#[pymethods]
impl LegoProver {
    #[staticmethod]
    #[pyo3(signature = (dimension, bits, workers=4))]
    fn development_setup(py: Python<'_>, dimension: usize, bits: usize, workers: usize) -> PyResult<Self> {
        bounds(dimension, bits)?;
        let pool = pool(workers)?;
        py.allow_threads(|| {
            let pk = pool.install(|| generate_random_parameters::<Bls12_381, _, _>(
                RangeNormCircuit { dimension, bits, values: None, norm: None },
                dimension as u32, &mut OsRng,
            )).map_err(|_| invalid("Lego development setup failed"))?;
            let bases = check_vk(&pk.vk, dimension)?;
            let pvk = prepare_verifying_key(&pk.vk);
            Ok(Self { dimension, bits, workers, pk: Arc::new(pk), pvk: Arc::new(pvk),
                bases: Arc::new(bases), pool })
        })
    }

    /// Load shared public proving parameters; no setup is performed here.
    /// The caller MUST authenticate the manifest's circuit specification and
    /// compare verifying_key_bytes() to its pinned VK/fingerprint. Key shape
    /// checks cannot establish that a CRS honestly encodes the intended circuit.
    #[staticmethod]
    #[pyo3(signature = (dimension, bits, proving_key, workers=4))]
    fn from_bytes(py: Python<'_>, dimension: usize, bits: usize, proving_key: Vec<u8>, workers: usize)
        -> PyResult<Self>
    {
        bounds(dimension, bits)?;
        let pool = pool(workers)?;
        py.allow_threads(|| pool.install(|| {
            let layout = key_layout(dimension, bits)?;
            check_pk_encoding(&proving_key, dimension, layout)?;
            // Validate::Yes checks every G1/G2 point and its prime subgroup;
            // decode also rejects any noncanonical serialization roundtrip.
            let pk: ProvingKey<Bls12_381> = decode(&proving_key, layout.pk_bytes)?;
            let bases = check_pk(&pk, dimension, layout)?;
            let pvk = prepare_verifying_key(&pk.vk);
            Ok(Self { dimension, bits, workers, pk: Arc::new(pk), pvk: Arc::new(pvk),
                bases: Arc::new(bases), pool: Arc::clone(&pool) })
        }))
    }

    #[getter]
    fn dimension(&self) -> usize { self.dimension }
    #[getter]
    fn bits(&self) -> usize { self.bits }
    #[getter]
    fn workers(&self) -> usize { self.workers }

    fn commitment_bases<'py>(&self, py: Python<'py>) -> Vec<Py<PyBytes>> {
        basis_bytes(py, &self.bases)
    }

    fn verifying_key_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &encode(&self.pk.vk))
    }

    /// Export public proving parameters only, never the setup trapdoor.
    fn proving_key_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let raw = py.allow_threads(|| encode(self.pk.as_ref()));
        PyBytes::new(py, &raw)
    }

    fn verifier(&self) -> LegoVerifier {
        LegoVerifier { dimension: self.dimension, bits: self.bits, workers: self.workers,
            pvk: Arc::clone(&self.pvk), bases: Arc::clone(&self.bases), pool: Arc::clone(&self.pool) }
    }

    fn prove<'py>(&self, py: Python<'py>, values: Vec<i64>, norm: u64, blinding: Vec<u8>)
        -> PyResult<Bound<'py, PyBytes>>
    {
        let (offset, max_norm) = bounds(self.dimension, self.bits)?;
        if values.len() != self.dimension || norm > max_norm
            || values.iter().any(|v| *v < -offset || *v >= offset)
            || values.iter().map(|v| v.unsigned_abs().pow(2)).sum::<u64>() != norm
        {
            return Err(invalid("Lego witness range, dimension, or squared norm mismatch"));
        }
        let blinding = scalar_be(&blinding)?;
        let raw = py.allow_threads(|| self.pool.install(|| {
            let circuit = RangeNormCircuit { dimension: self.dimension, bits: self.bits,
                values: Some(values), norm: Some(norm) };
            let proof = create_random_proof(circuit, blinding, self.pk.as_ref(), &mut OsRng)
                .map_err(|_| invalid("Lego proof generation failed"))?;
            let raw = encode(&proof);
            if raw.len() != PROOF_BYTES { return Err(invalid("unexpected Lego proof encoding")); }
            Ok(raw)
        }))?;
        Ok(PyBytes::new(py, &raw))
    }
}

#[pyclass(module = "dgfl_native", frozen)]
pub(crate) struct LegoVerifier {
    dimension: usize,
    bits: usize,
    workers: usize,
    pvk: Arc<PreparedVerifyingKey<Bls12_381>>,
    bases: Arc<Vec<G1Affine>>,
    pool: Arc<ThreadPool>,
}

#[pymethods]
impl LegoVerifier {
    #[staticmethod]
    #[pyo3(signature = (dimension, bits, verifying_key, workers=4))]
    fn from_bytes(py: Python<'_>, dimension: usize, bits: usize, verifying_key: Vec<u8>, workers: usize)
        -> PyResult<Self>
    {
        bounds(dimension, bits)?;
        // Four initial points occupy 336 bytes; the following vector length
        // must be fixed BEFORE deserializing to reject attacker-sized vectors.
        let expected_length = 492 + 48 * dimension;
        if verifying_key.len() != expected_length
            || u64::from_le_bytes(verifying_key[336..344].try_into().unwrap()) != (dimension + 2) as u64
        {
            return Err(invalid("noncanonical Lego verification key size or vector layout"));
        }
        let pool = pool(workers)?;
        py.allow_threads(|| {
            let vk: VerifyingKey<Bls12_381> = decode(&verifying_key, expected_length)?;
            let bases = check_vk(&vk, dimension)?;
            let pvk = prepare_verifying_key(&vk);
            Ok(Self { dimension, bits, workers, pvk: Arc::new(pvk), bases: Arc::new(bases), pool })
        })
    }

    #[getter]
    fn dimension(&self) -> usize { self.dimension }
    #[getter]
    fn bits(&self) -> usize { self.bits }
    #[getter]
    fn workers(&self) -> usize { self.workers }

    fn commitment_bases<'py>(&self, py: Python<'py>) -> Vec<Py<PyBytes>> {
        basis_bytes(py, &self.bases)
    }

    fn verifying_key_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &encode(&self.pvk.vk))
    }

    fn commitment<'py>(&self, py: Python<'py>, proof: Vec<u8>) -> PyResult<Bound<'py, PyBytes>> {
        let proof: Proof<Bls12_381> = decode(&proof, PROOF_BYTES)?;
        Ok(PyBytes::new(py, &encode(&proof.d)))
    }

    fn verify(&self, py: Python<'_>, proof: Vec<u8>, norm: u64) -> PyResult<bool> {
        let (_, max_norm) = bounds(self.dimension, self.bits)?;
        if norm > max_norm || proof.len() != PROOF_BYTES { return Ok(false); }
        Ok(py.allow_threads(|| self.pool.install(|| {
            let proof: Proof<Bls12_381> = match decode(&proof, PROOF_BYTES) {
                Ok(value) => value,
                Err(_) => return false,
            };
            verify_proof(self.pvk.as_ref(), &proof, &[Fr::from(norm)]).is_ok()
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn satisfied(values: Vec<i64>, bits: usize, norm: u64) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        RangeNormCircuit { dimension: values.len(), bits, values: Some(values), norm: Some(norm) }
            .generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    #[test]
    fn signed_boundaries_and_squared_norm() {
        assert!(satisfied(vec![-128, 127, 0], 8, 16_384 + 16_129));
        assert!(!satisfied(vec![-129, 0], 8, 16_641));
        assert!(!satisfied(vec![128, 0], 8, 16_384));
        assert!(!satisfied(vec![-128, 127, 0], 8, 16_384 + 16_129 + 1));
    }

    #[test]
    fn committed_values_precede_all_bit_and_product_witnesses() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        RangeNormCircuit { dimension: 3, bits: 8, values: Some(vec![-2, 0, 3]), norm: Some(13) }
            .generate_constraints(cs.clone()).unwrap();
        let borrowed = cs.borrow().unwrap();
        assert_eq!(&borrowed.witness_assignment[..3], &[signed_scalar(-2), signed_scalar(0), signed_scalar(3)]);
        assert_eq!(borrowed.instance_assignment, vec![Fr::from(1u64), Fr::from(13u64)]);
    }

    #[test]
    fn shared_proving_key_roundtrip_and_vector_prefix_rejection() {
        let (dimension, bits) = (3, 3);
        let layout = key_layout(dimension, bits).unwrap();
        let pk = generate_random_parameters::<Bls12_381, _, _>(
            RangeNormCircuit { dimension, bits, values: None, norm: None },
            dimension as u32, &mut OsRng,
        ).unwrap();
        let raw = encode(&pk);
        assert_eq!(raw.len(), layout.pk_bytes);
        check_pk_encoding(&raw, dimension, layout).unwrap();
        let loaded: ProvingKey<Bls12_381> = decode(&raw, layout.pk_bytes).unwrap();
        check_pk(&loaded, dimension, layout).unwrap();
        assert_eq!(encode(&loaded.vk), encode(&pk.vk));
        let values = vec![-4, 0, 3];
        let proof = create_random_proof(RangeNormCircuit {
            dimension, bits, values: Some(values), norm: Some(25),
        }, Fr::from(7u64), &loaded, &mut OsRng).unwrap();
        assert!(verify_proof(&prepare_verifying_key(&pk.vk), &proof, &[Fr::from(25u64)]).is_ok());
        let mut positions = vec![336];
        let mut cursor = layout.vk_bytes + 3 * 48;
        for (count, width) in [(layout.query_len, 48), (layout.query_len, 48),
            (layout.query_len, 96), (layout.h_len, 48), (layout.l_len, 48)]
        {
            positions.push(cursor);
            cursor += 8 + count * width;
        }
        for position in positions {
            let mut malformed = raw.clone();
            malformed[position..position + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(check_pk_encoding(&malformed, dimension, layout).is_err());
        }
        assert!(check_pk_encoding(&raw[..raw.len() - 1], dimension, layout).is_err());
        let mut trailing = raw.clone(); trailing.push(0);
        assert!(check_pk_encoding(&trailing, dimension, layout).is_err());
        assert!(check_pk_encoding(&raw, dimension, key_layout(dimension, bits + 1).unwrap()).is_err());
    }

    #[test]
    fn default_model_query_layout() {
        let layout = key_layout(650, 8).unwrap();
        assert_eq!(layout.query_len, 6502);
        assert_eq!(layout.h_len, 8191);
        assert_eq!(layout.l_len, 5850);
        assert_eq!(layout.vk_bytes, 31_692);
        assert_eq!(layout.pk_bytes, 1_954_228);
    }
}
