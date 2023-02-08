use halo2::{
	arithmetic::{best_multiexp, Field},
	halo2curves::{
		group::{prime::PrimeCurveAffine, Curve, Group},
		pairing::{Engine, MillerLoopResult, MultiMillerLoop},
	},
	poly::kzg::commitment::ParamsKZG,
};
use std::fmt::Debug;

/// A multiscalar multiplication in the polynomial commitment scheme
#[derive(Clone, Default, Debug)]
pub struct MSMKZG<E: Engine> {
	pub(crate) scalars: Vec<E::Scalar>,
	pub(crate) bases: Vec<E::G1>,
}

impl<E: Engine> MSMKZG<E> {
	/// Create an empty MSM instance
	pub fn new() -> Self {
		MSMKZG { scalars: vec![], bases: vec![] }
	}

	/// Prepares all scalars in the MSM to linear combination
	pub fn combine_with_base(&mut self, base: E::Scalar) {
		let mut acc = E::Scalar::one();
		if !self.scalars.is_empty() {
			for scalar in self.scalars.iter_mut().rev() {
				*scalar *= &acc;
				acc *= base;
			}
		}
	}
}

impl<E: Engine + Debug> MSMKZG<E> {
	fn append_term(&mut self, scalar: E::Scalar, point: E::G1) {
		self.scalars.push(scalar);
		self.bases.push(point);
	}

	fn add_msm(&mut self, other: &Self) {
		self.scalars.extend(other.scalars().iter());
		self.bases.extend(other.bases().iter());
	}

	fn scale(&mut self, factor: E::Scalar) {
		if !self.scalars.is_empty() {
			for other_scalar in &mut self.scalars {
				*other_scalar *= &factor;
			}
		}
	}

	fn check(&self) -> bool {
		bool::from(self.eval().is_identity())
	}

	fn eval(&self) -> E::G1 {
		let mut bases = vec![E::G1Affine::identity(); self.scalars.len()];
		E::G1::batch_normalize(&self.bases, &mut bases);
		best_multiexp(&self.scalars, &bases)
	}

	fn bases(&self) -> Vec<E::G1> {
		self.bases.clone()
	}

	fn scalars(&self) -> Vec<E::Scalar> {
		self.scalars.clone()
	}
}

/// Two channel MSM accumulator
#[derive(Debug, Clone)]
pub struct DualMSM<'a, E: Engine> {
	pub(crate) params: &'a ParamsKZG<E>,
	pub(crate) left: MSMKZG<E>,
	pub(crate) right: MSMKZG<E>,
}

impl<'a, E: MultiMillerLoop + Debug> DualMSM<'a, E> {
	/// Create a new two channel MSM accumulator instance
	pub fn new(params: &'a ParamsKZG<E>) -> Self {
		Self { params, left: MSMKZG::new(), right: MSMKZG::new() }
	}

	/// Scale all scalars in the MSM by some scaling factor
	pub fn scale(&mut self, e: E::Scalar) {
		self.left.scale(e);
		self.right.scale(e);
	}

	/// Add another multiexp into this one
	pub fn add_msm(&mut self, other: Self) {
		self.left.add_msm(&other.left);
		self.right.add_msm(&other.right);
	}

	/// Performs final pairing check with given verifier params and two channel
	/// linear combination
	pub fn check(self) -> bool {
		let s_g2_prepared = E::G2Prepared::from(self.params.s_g2());
		let n_g2_prepared = E::G2Prepared::from(-self.params.g2());

		let left = self.left.eval();
		let right = self.right.eval();

		let (term_1, term_2) = (
			(&left.into(), &s_g2_prepared),
			(&right.into(), &n_g2_prepared),
		);
		let terms = &[term_1, term_2];

		bool::from(E::multi_miller_loop(&terms[..]).final_exponentiation().is_identity())
	}
}
