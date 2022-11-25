use crate::{
	ecc::native::EcPoint,
	integer::{native::Integer, rns::RnsParams},
	params::RoundParams,
};

use super::{msm::MSM, protocol::Protocol, transcript::Transcript};
use halo2wrong::{
	curves::{group::Curve, Coordinates, CurveAffine, FieldExt},
	halo2::{arithmetic::Field, plonk::Error},
};
use std::{
	io::Read,
	iter,
	iter::Sum,
	marker::PhantomData,
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Clone, Debug)]
pub struct Accumulator<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	lhs: MSM<W, N, NUM_LIMBS, NUM_BITS, P>,
	rhs: MSM<W, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	Accumulator<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	pub fn new(
		lhs: MSM<W, N, NUM_LIMBS, NUM_BITS, P>, rhs: MSM<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { lhs, rhs }
	}

	pub fn scale(&mut self, scalar: &N) {
		self.lhs.scale(scalar);
		self.rhs.scale(scalar);
	}

	pub fn extend(&mut self, other: Self) {
		self.lhs.extend(other.lhs);
		self.rhs.extend(other.rhs);
	}

	pub fn evaluate(
		self, g1: EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> (
		EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
		EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
	) {
		(self.lhs.evaluate(g1.clone()), self.rhs.evaluate(g1))
	}

	pub fn random_linear_combine(scaled_accumulators: impl IntoIterator<Item = (N, Self)>) -> Self {
		let mut acc: Accumulator<W, N, NUM_LIMBS, NUM_BITS, P> = Accumulator::default();
		for (scalar, mut accumulator) in scaled_accumulators.into_iter() {
			accumulator.scale(&scalar);
			acc.extend(accumulator);
		}
		acc
	}
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Default
	for Accumulator<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	fn default() -> Self {
		Self { lhs: MSM::default(), rhs: MSM::default() }
	}
}

pub struct SameCurveAccumulation<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	pub accumulator: Accumulator<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	SameCurveAccumulation<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	pub fn finalize(
		self, g1: EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>,
	) -> (
		EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>,
		EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>,
	) {
		self.accumulator.evaluate(g1)
	}

	fn extract_accumulator(
		&self, challenges: Vec<C::ScalarExt>, statements: &[Vec<C::ScalarExt>],
		accumulator_indices: Vec<Vec<(usize, usize)>>,
	) -> Option<Accumulator<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>> {
		let accumulators: Vec<Accumulator<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>> =
			accumulator_indices
				.iter()
				.map(|indices| {
					assert_eq!(indices.len(), 4 * NUM_LIMBS);
					let assinged: Vec<C::ScalarExt> =
						indices.iter().map(|index| statements[index.0][index.1]).collect();
					let lhs_x =
						Integer::<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>::from_slice(
							&assinged[..NUM_LIMBS],
						);
					let lhs_y =
						Integer::<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>::from_slice(
							&assinged[NUM_LIMBS..2 * NUM_LIMBS],
						);
					let rhs_x =
						Integer::<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>::from_slice(
							&assinged[2 * NUM_LIMBS..3 * NUM_LIMBS],
						);
					let rhs_y =
						Integer::<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>::from_slice(
							&assinged[3 * NUM_LIMBS..],
						);

					let lhs = EcPoint::new(lhs_x, lhs_y);
					let rhs = EcPoint::new(rhs_x, rhs_y);
					Accumulator::new(MSM::base(lhs), MSM::base(rhs))
				})
				.collect();

		Some(Accumulator::random_linear_combine(
			challenges.into_iter().zip(accumulators),
		))
	}

	fn process(
		&mut self, challenge: C::ScalarExt,
		mut accumulator: Accumulator<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>,
	) {
		self.accumulator.scale(&challenge);
		accumulator.extend(self.accumulator.clone());
		self.accumulator = accumulator;
	}
}
