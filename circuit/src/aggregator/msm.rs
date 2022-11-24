use halo2wrong::{
	curves::{group::Curve, CurveAffine, FieldExt},
	halo2::arithmetic::Field,
};
use std::iter;

use crate::{ecc::native::EcPoint, integer::rns::RnsParams};

#[derive(Clone, Debug)]
pub struct MSM<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, R>
where
	R: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	scalar: Option<N>,
	bases: Vec<EcPoint<W, N, NUM_LIMBS, NUM_BITS, R>>,
	scalars: Vec<N>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, R> Default
	for MSM<W, N, NUM_LIMBS, NUM_BITS, R>
where
	R: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	fn default() -> Self {
		Self { scalar: None, scalars: Vec::new(), bases: Vec::new() }
	}
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, R>
	MSM<W, N, NUM_LIMBS, NUM_BITS, R>
where
	R: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	pub fn scalar(scalar: N) -> Self {
		Self { scalar: Some(scalar), ..Default::default() }
	}

	pub fn base(base: EcPoint<W, N, NUM_LIMBS, NUM_BITS, R>) -> Self {
		let one = N::one();
		MSM { scalars: vec![one], bases: vec![base], ..Default::default() }
	}

	pub fn scale(&mut self, factor: &N) {
		if let Some(scalar) = self.scalar.as_mut() {
			*scalar *= factor;
		}
		for scalar in self.scalars.iter_mut() {
			*scalar *= factor
		}
	}

	pub fn evaluate(
		self, gen: EcPoint<W, N, NUM_LIMBS, NUM_BITS, R>,
	) -> EcPoint<W, N, NUM_LIMBS, NUM_BITS, R> {
		let pairs = iter::empty()
			.chain(self.scalar.map(|scalar| (scalar, gen)))
			.chain(self.scalars.into_iter().zip(self.bases.into_iter()));
		pairs
			.into_iter()
			.map(|(scalar, base)| base.mul_scalar(scalar.to_repr().as_ref()))
			.reduce(|acc, value| acc.add(&value))
			.unwrap()
	}

	pub fn push(&mut self, scalar: N, base: EcPoint<W, N, NUM_LIMBS, NUM_BITS, R>) {
		if let Some(pos) = self.bases.iter().position(|exist| exist.is_eq(&base)) {
			self.scalars[pos] += scalar;
		} else {
			self.scalars.push(scalar);
			self.bases.push(base);
		}
	}

	pub fn extend(&mut self, mut other: Self) {
		match (self.scalar.as_mut(), other.scalar.as_ref()) {
			(Some(lhs), Some(rhs)) => *lhs += *rhs,
			(None, Some(_)) => self.scalar = other.scalar.take(),
			_ => {},
		};
		for (scalar, base) in other.scalars.into_iter().zip(other.bases) {
			self.push(scalar, base);
		}
	}
}
