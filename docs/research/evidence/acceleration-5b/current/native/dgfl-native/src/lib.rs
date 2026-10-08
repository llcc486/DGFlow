//! Checked BLS12-381 GT operations and public fixed-base tables.
//! No secret witness multiplication uses the variable-time lookup table.
use ark_bls12_381::{Bls12_381, Fq12, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};
use std::{collections::hash_map::DefaultHasher, hash::{Hash, Hasher}};

fn invalid(message: &str) -> PyErr { PyValueError::new_err(message.to_owned()) }
fn encode<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut raw = Vec::new(); value.serialize_compressed(&mut raw).unwrap(); raw
}
fn decode<T: CanonicalDeserialize + CanonicalSerialize>(raw: &[u8], length: usize) -> PyResult<T> {
    if raw.len() != length { return Err(invalid("noncanonical encoding length")); }
    let value = T::deserialize_compressed(raw).map_err(|_| invalid("invalid group encoding"))?;
    if encode(&value) != raw { return Err(invalid("noncanonical group encoding")); }
    Ok(value)
}
fn wire(point: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    point.call_method0("to_compressed_bytes")?.extract()
}

#[pyclass(module = "dgfl_native", frozen)]
#[derive(Clone)]
struct NativeGT { value: Fq12 }

#[pymethods]
impl NativeGT {
    #[staticmethod]
    fn one() -> Self { Self { value: Fq12::one() } }
    #[staticmethod]
    fn zero() -> Self { Self { value: Fq12::zero() } }
    #[staticmethod]
    fn from_compressed_bytes(py: Python<'_>, raw: Vec<u8>) -> PyResult<Self> {
        py.allow_threads(|| {
            let value: Fq12 = decode(&raw, 576)?;
            if value.is_zero() || !value.pow(Fr::MODULUS).is_one() {
                return Err(invalid("invalid GT subgroup"));
            }
            Ok(Self { value })
        })
    }
    fn to_compressed_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &encode(&self.value))
    }
    #[staticmethod]
    fn pairing(py: Python<'_>, g1: &Bound<'_, PyAny>, g2: &Bound<'_, PyAny>) -> PyResult<Self> {
        let a = wire(g1)?; let b = wire(g2)?;
        py.allow_threads(|| {
            Ok(Self { value: Bls12_381::pairing(decode::<G1Affine>(&a,48)?, decode::<G2Affine>(&b,96)?).0 })
        })
    }
    #[staticmethod]
    fn multi_pairing(py: Python<'_>, g1s: Vec<Bound<'_, PyAny>>, g2s: Vec<Bound<'_, PyAny>>) -> PyResult<Self> {
        if g1s.len()!=g2s.len() { return Err(invalid("pairing length mismatch")); }
        let a: Vec<Vec<u8>> = g1s.iter().map(wire).collect::<PyResult<_>>()?;
        let b: Vec<Vec<u8>> = g2s.iter().map(wire).collect::<PyResult<_>>()?;
        py.allow_threads(|| {
            let aa = a.iter().map(|r|decode::<G1Affine>(r,48)).collect::<PyResult<Vec<_>>>()?;
            let bb = b.iter().map(|r|decode::<G2Affine>(r,96)).collect::<PyResult<Vec<_>>>()?;
            Ok(Self { value: Bls12_381::multi_pairing(aa,bb).0 })
        })
    }
    #[staticmethod]
    fn pairing_check(py: Python<'_>, g1s: Vec<Bound<'_, PyAny>>, g2s: Vec<Bound<'_, PyAny>>) -> PyResult<bool> {
        Ok(Self::multi_pairing(py,g1s,g2s)?.value.is_one())
    }
    fn pow_bytes(&self, py: Python<'_>, exponent: Vec<u8>) -> Self {
        let limbs: Vec<u64> = exponent.rchunks(8).map(|c| {
            let mut word=[0u8;8]; word[8-c.len()..].copy_from_slice(c); u64::from_be_bytes(word)
        }).collect();
        py.allow_threads(|| Self { value: self.value.pow(limbs) })
    }
    fn inverse(&self, py: Python<'_>) -> PyResult<Self> {
        py.allow_threads(|| self.value.inverse().map(|value|Self{value}).ok_or_else(||invalid("zero GT inverse")))
    }
    fn __add__(&self, rhs: &Self) -> Self { Self { value: self.value+rhs.value } }
    fn __sub__(&self, rhs: &Self) -> Self { Self { value: self.value-rhs.value } }
    fn __mul__(&self, rhs: &Self) -> Self { Self { value: self.value*rhs.value } }
    fn __neg__(&self) -> Self { Self { value: -self.value } }
    fn __str__(&self) -> String { hex::encode(encode(&self.value)) }
    fn __repr__(&self) -> String { format!("NativeGT({}...)", &self.__str__()[..16]) }
    fn __eq__(&self, rhs: &Self) -> bool { self.value==rhs.value }
    fn __ne__(&self, rhs: &Self) -> bool { self.value!=rhs.value }
    fn __hash__(&self) -> u64 { let mut h=DefaultHasher::new(); encode(&self.value).hash(&mut h); h.finish() }
}

#[pyclass(module = "dgfl_native", frozen)]
struct PublicG1Table { rows: Vec<Vec<G1Affine>> }

#[pymethods]
impl PublicG1Table {
    #[new]
    fn new(py: Python<'_>, raw: Vec<u8>) -> PyResult<Self> {
        let base: G1Affine = decode(&raw,48)?;
        py.allow_threads(|| {
            let mut base=base.into_group(); let mut rows=Vec::with_capacity(32);
            for _ in 0..32 {
                let mut row=Vec::with_capacity(256); let mut next=G1Projective::zero();
                for _ in 0..256 { row.push(next); next+=base; }
                rows.push(G1Projective::normalize_batch(&row));
                for _ in 0..8 { base.double_in_place(); }
            }
            Ok(Self { rows })
        })
    }
    fn mul_public<'py>(&self, py: Python<'py>, coefficient: Vec<u8>) -> PyResult<Bound<'py,PyBytes>> {
        if coefficient.len()!=32 { return Err(invalid("public scalar length")); }
        let value=Fr::from_be_bytes_mod_order(&coefficient);
        let mut canonical=encode(&value); canonical.reverse();
        if canonical!=coefficient { return Err(invalid("noncanonical public scalar")); }
        let raw=py.allow_threads(|| {
            let mut point=G1Projective::zero();
            for (i,digit) in coefficient.iter().rev().enumerate() { point+=self.rows[i][*digit as usize]; }
            encode(&point.into_affine())
        });
        Ok(PyBytes::new(py,&raw))
    }
}

#[pymodule]
fn dgfl_native(module: &Bound<'_,PyModule>) -> PyResult<()> {
    module.add_class::<NativeGT>()?; module.add_class::<PublicG1Table>()?; Ok(())
}
