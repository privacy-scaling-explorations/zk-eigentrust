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
pub struct Accumulator<C: Curve> {
	lhs: MSM<C>,
	rhs: MSM<C>,
}

impl<C: Curve> Accumulator<C> {
	pub fn new(lhs: MSM<C>, rhs: MSM<C>) -> Self {
		Self { lhs, rhs }
	}

	pub fn scale(&mut self, scalar: &C::Scalar) {
		self.lhs *= scalar;
		self.rhs *= scalar;
	}

	pub fn extend(&mut self, other: Self) {
		self.lhs += other.lhs;
		self.rhs += other.rhs;
	}

	pub fn evaluate(self, g1: C) -> (C, C) {
		(self.lhs.evaluate(g1), self.rhs.evaluate(g1))
	}

	pub fn random_linear_combine(
		scaled_accumulators: impl IntoIterator<Item = (C::Scalar, Self)>,
	) -> Self {
		scaled_accumulators
			.into_iter()
			.map(|(scalar, accumulator)| accumulator * &scalar)
			.reduce(|acc, scaled_accumulator| acc + scaled_accumulator)
			.unwrap_or_default()
	}
}

impl<C: Curve> Default for Accumulator<C> {
	fn default() -> Self {
		Self { lhs: MSM::default(), rhs: MSM::default() }
	}
}

impl<C: Curve> Add<Self> for Accumulator<C> {
	type Output = Self;

	fn add(mut self, rhs: Self) -> Self::Output {
		self.extend(rhs);
		self
	}
}

impl<C: Curve> AddAssign<Self> for Accumulator<C> {
	fn add_assign(&mut self, rhs: Self) {
		self.extend(rhs);
	}
}

impl<C: Curve> Mul<&C::Scalar> for Accumulator<C> {
	type Output = Self;

	fn mul(mut self, rhs: &C::Scalar) -> Self::Output {
		self.scale(rhs);
		self
	}
}

impl<C: Curve> MulAssign<&C::Scalar> for Accumulator<C> {
	fn mul_assign(&mut self, rhs: &C::Scalar) {
		self.scale(rhs);
	}
}

pub struct SameCurveAccumulation<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	pub accumulator: Accumulator<C::Curve>,
	_rns: PhantomData<P>,
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	SameCurveAccumulation<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	pub fn finalize(
		self, g1: C::Curve,
	) -> Result<
		(
			EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>,
			EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>,
		),
		Error,
	> {
		let (lhs, rhs) = self.accumulator.evaluate(g1);
		let lhs_coord_opt: Option<Coordinates<C>> = lhs.to_affine().coordinates().into();
		let lhs_coord = lhs_coord_opt.ok_or(Error::Synthesis)?;
		let rhs_coord_opt: Option<Coordinates<C>> = rhs.to_affine().coordinates().into();
		let rhs_coord = rhs_coord_opt.ok_or(Error::Synthesis)?;

		let lhs_x =
			Integer::<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>::from_w(lhs_coord.x().clone());
		let lhs_y =
			Integer::<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>::from_w(lhs_coord.y().clone());
		let lhs_x_reduced = lhs_x.reduce().result;
		let lhs_y_reduced = lhs_y.reduce().result;
		let lhs_reduced = EcPoint::new(lhs_x_reduced, lhs_y_reduced);

		let rhs_x =
			Integer::<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>::from_w(rhs_coord.x().clone());
		let rhs_y =
			Integer::<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>::from_w(rhs_coord.y().clone());
		let rhs_x_reduced = rhs_x.reduce().result;
		let rhs_y_reduced = rhs_y.reduce().result;
		let rhs_reduced = EcPoint::new(rhs_x_reduced, rhs_y_reduced);
		Ok((lhs_reduced, rhs_reduced))
	}

	fn extract_accumulator(
		&self, challenges: Vec<C::ScalarExt>,
		statements: &[Vec<Integer<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, P>>],
		accumulator_indices: Vec<Vec<(usize, usize)>>,
	) -> Option<Accumulator<C::CurveExt>> {
		let accumulators = accumulator_indices
			.iter()
			.map(|indices| {
				assert_eq!(indices.len(), 4 * NUM_LIMBS);
				let assinged =
					indices.iter().map(|index| statements[index.0][index.1]).collect_vec();
				let lhs_x = Integer::from_limbs(assinged[..NUM_LIMBS].try_into().unwrap());
				let lhs_y =
					Integer::from_limbs(assinged[NUM_LIMBS..2 * NUM_LIMBS].try_into().unwrap());
				let rhs_x =
					Integer::from_limbs(assinged[2 * NUM_LIMBS..3 * NUM_LIMBS].try_into().unwrap());
				let rhs_y = Integer::from_limbs(assinged[3 * NUM_LIMBS..].try_into().unwrap());

				let lhs = EcPoint::new(lhs_x, lhs_y);
				let rhs = EcPoint::new(rhs_x, rhs_y);
				Accumulator::new(MSM::base(lhs), MSM::base(rhs))
			})
			.collect_vec();

		Some(Accumulator::random_linear_combine(
			challenges.into_iter().zip(accumulators),
		))
	}

	fn process(&mut self, challenge: C::ScalarExt, accumulator: Accumulator<C::CurveExt>) {
		self.accumulator = accumulator + self.accumulator * &challenge;
	}
}
