use super::msm::MSM;
use halo2wrong::{
	curves::{group::Curve, CurveAffine},
	halo2::arithmetic::Field,
};
use std::{
	iter,
	iter::Sum,
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
